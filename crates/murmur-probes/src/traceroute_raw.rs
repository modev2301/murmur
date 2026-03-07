//! Traceroute IPv4: ICMP (Linux) and UDP (macOS) methods.
//!
//! - **ICMP**: Send Echo Request with TTL, receive Time Exceeded (11) or Echo Reply (0).
//!   Works on Linux; on macOS the kernel often does not deliver these to raw ICMP sockets.
//! - **UDP** (macOS): Send UDP to port 33434 with TTL; receive Time Exceeded (11) or
//!   Port Unreachable (3/3) on a raw ICMP socket. Same as system traceroute on macOS.

#![allow(unsafe_code)] // required to interpret recv_from buffer as &[u8] for parsing

use super::{TracerouteHop, MAX_HOPS};
use socket2::{Domain, Protocol, SockAddr, Socket, Type as SockType};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// ICMP Echo Request type.
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP Echo Reply type.
const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP Destination Unreachable type.
const ICMP_DEST_UNREACHABLE: u8 = 3;
/// ICMP Port Unreachable code (destination reached for UDP traceroute).
const ICMP_CODE_PORT_UNREACHABLE: u8 = 3;
/// ICMP Time Exceeded type.
const ICMP_TIME_EXCEEDED: u8 = 11;

/// Default UDP base port for traceroute (same as system traceroute).
const TRACEROUTE_UDP_BASE_PORT: u16 = 33434;

/// Build an ICMPv4 Echo Request packet (type 8, code 0, checksum, id, seq).
fn build_icmp_echo_v4(ident: u16, seq: u16) -> Vec<u8> {
    let id_be = ident.to_be();
    let seq_be = seq.to_be();
    let mut buf = vec![
        ICMP_ECHO_REQUEST,
        0, // code
        0,
        0, // checksum (filled below)
        (id_be >> 8) as u8,
        (id_be & 0xff) as u8,
        (seq_be >> 8) as u8,
        (seq_be & 0xff) as u8,
    ];
    buf.extend_from_slice(&[0u8; 32]);

    let sum = icmp_checksum(&buf);
    buf[2] = (sum >> 8) as u8;
    buf[3] = (sum & 0xff) as u8;
    buf
}

fn icmp_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in buf.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parse received buffer. Returns (icmp_type, ident, seq).
/// Handles full IPv4 packet (ICMP at ihl) or raw ICMP (buffer starts with type).
fn parse_icmp_reply(buf: &[u8]) -> Option<(u8, u16, u16)> {
    if buf.len() < 8 {
        return None;
    }
    let (icmp_type, payload) = if buf.len() >= 20 && (buf[0] >> 4) == 4 {
        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if buf.len() < ihl + 8 {
            return None;
        }
        (buf[ihl], &buf[ihl..])
    } else {
        (buf[0], buf)
    };

    if icmp_type == ICMP_ECHO_REPLY {
        if payload.len() < 8 {
            return None;
        }
        let ident = u16::from_be_bytes([payload[4], payload[5]]);
        let seq = u16::from_be_bytes([payload[6], payload[7]]);
        return Some((icmp_type, ident, seq));
    }
    if icmp_type == ICMP_TIME_EXCEEDED {
        if payload.len() < 32 {
            return None;
        }
        let ident = u16::from_be_bytes([payload[28], payload[29]]);
        let seq = u16::from_be_bytes([payload[30], payload[31]]);
        return Some((icmp_type, ident, seq));
    }
    None
}

/// Parse ICMP type and code from received packet (full IP or raw ICMP).
/// Used for UDP traceroute: Time Exceeded (11/0) = hop, Port Unreachable (3/3) = destination.
fn parse_icmp_type_code(buf: &[u8]) -> Option<(u8, u8)> {
    if buf.len() < 8 {
        return None;
    }
    let (icmp_type, icmp_code) = if buf.len() >= 20 && (buf[0] >> 4) == 4 {
        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if buf.len() < ihl + 2 {
            return None;
        }
        (buf[ihl], buf[ihl + 1])
    } else {
        (buf[0], buf[1])
    };
    Some((icmp_type, icmp_code))
}

/// Run one hop: create socket with TTL, send probes, recv replies.
pub fn trace_hop_raw_v4(
    dest: Ipv4Addr,
    ttl: u8,
    timeout: Duration,
    probes: usize,
    ident: u16,
) -> TracerouteHop {
    let mut rtts: Vec<Option<Duration>> = vec![None; probes];
    let mut responding_addr: Option<IpAddr> = None;
    let mut destination_reached = false;

    let socket = match create_icmp_socket_v4(ttl) {
        Ok(s) => s,
        Err(_) => {
            return TracerouteHop {
                ttl,
                addr: None,
                hostname: None,
                min_rtt: None,
                max_rtt: None,
                avg_rtt: None,
                rtts: None,
                packet_loss: 100.0,
                probes_sent: probes,
                probes_received: 0,
            };
        }
    };

    let dest_sock = SockAddr::from(SocketAddrV4::new(dest, 0));
    let send_times: Vec<Instant> = (0..probes).map(|_| Instant::now()).collect();

    for seq in 0..probes {
        let pkt = build_icmp_echo_v4(ident, seq as u16);
        let _ = socket.send_to(&pkt, &dest_sock);
    }

    let deadline = Instant::now() + timeout;
    let mut recv_buf = [MaybeUninit::uninit(); 512];

    while Instant::now() < deadline && !destination_reached {
        let received_so_far = rtts.iter().filter_map(|r| *r).count();
        if received_so_far >= probes {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if let Ok(Some(Ok((n, source)))) = recv_with_timeout(&socket, &mut recv_buf, remaining) {
            let buf_ref: &[u8] =
                unsafe { std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, n) };
            if let Some((icmp_type, r_ident, r_seq)) = parse_icmp_reply(buf_ref) {
                if r_ident != ident || r_seq as usize >= probes {
                    continue;
                }
                if responding_addr.is_none() {
                    responding_addr = Some(IpAddr::V4(source));
                }
                if icmp_type == ICMP_ECHO_REPLY {
                    destination_reached = true;
                }
                let seq = r_seq as usize;
                if rtts[seq].is_none() {
                    rtts[seq] = Some(send_times[seq].elapsed());
                }
            }
        }
    }

    let rtts_collected: Vec<Duration> = rtts.iter().filter_map(|r| *r).collect();
    let (min_rtt, max_rtt, avg_rtt) = if rtts_collected.is_empty() {
        (None, None, None)
    } else {
        let min = rtts_collected.iter().min().copied();
        let max = rtts_collected.iter().max().copied();
        let sum: Duration = rtts_collected.iter().sum();
        let avg = Some(sum / rtts_collected.len() as u32);
        (min, max, avg)
    };

    TracerouteHop {
        ttl,
        addr: responding_addr,
        hostname: None,
        min_rtt,
        max_rtt,
        avg_rtt,
        rtts: Some(rtts),
        packet_loss: if probes > 0 {
            ((probes - rtts_collected.len()) as f64 / probes as f64) * 100.0
        } else {
            100.0
        },
        probes_sent: probes,
        probes_received: rtts_collected.len(),
    }
}

fn create_icmp_socket_v4(ttl: u8) -> io::Result<Socket> {
    // RAW is required to receive ICMP Time Exceeded (and Echo Reply). DGRAM on Linux
    // only supports echo; on macOS RAW may not deliver Time Exceeded (OS limitation).
    let socket = Socket::new(Domain::IPV4, SockType::RAW, Some(Protocol::ICMPV4))?;
    socket.set_ttl(ttl as u32)?;
    socket.set_nonblocking(false)?;
    Ok(socket)
}

/// Full UDP-based traceroute (macOS-style): send UDP to port 33434, receive
/// ICMP Time Exceeded (hop) or Port Unreachable (destination) on raw ICMP socket.
/// Returns (hops, destination_reached).
pub fn trace_udp_v4(
    dest: Ipv4Addr,
    timeout_per_hop: Duration,
    probes_per_hop: usize,
) -> (Vec<TracerouteHop>, bool) {
    let mut hops = Vec::with_capacity(MAX_HOPS as usize);
    let udp_socket = match Socket::new(Domain::IPV4, SockType::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return (hops, false),
    };
    let icmp_socket = match Socket::new(Domain::IPV4, SockType::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return (hops, false),
    };
    icmp_socket.set_nonblocking(false).ok();
    udp_socket.set_nonblocking(false).ok();

    let dest_addr = SockAddr::from(SocketAddrV4::new(dest, TRACEROUTE_UDP_BASE_PORT));
    let udp_payload = [0u8; 32]; // minimal payload

    for ttl in 1..=MAX_HOPS {
        udp_socket.set_ttl(ttl as u32).ok();
        let send_times: Vec<Instant> = (0..probes_per_hop).map(|_| Instant::now()).collect();
        for _ in 0..probes_per_hop {
            let _ = udp_socket.send_to(&udp_payload, &dest_addr);
        }

        let deadline = Instant::now() + timeout_per_hop;
        let mut rtts: Vec<Option<Duration>> = vec![None; probes_per_hop];
        let mut responding_addr: Option<IpAddr> = None;
        let mut destination_reached = false;
        let mut received = 0usize;

        let mut recv_buf = [MaybeUninit::uninit(); 512];
        while Instant::now() < deadline && received < probes_per_hop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            icmp_socket.set_read_timeout(Some(remaining)).ok();
            match icmp_socket.recv_from(&mut recv_buf) {
                Ok((n, addr)) => {
                    if let Some(v4) = addr.as_socket_ipv4() {
                        let source = *v4.ip();
                        let buf_ref: &[u8] = unsafe {
                            std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, n)
                        };
                        if let Some((icmp_type, icmp_code)) = parse_icmp_type_code(buf_ref) {
                            if icmp_type == ICMP_TIME_EXCEEDED {
                                if responding_addr.is_none() {
                                    responding_addr = Some(IpAddr::V4(source));
                                }
                                if received < probes_per_hop {
                                    rtts[received] = Some(send_times[received].elapsed());
                                    received += 1;
                                }
                            } else if icmp_type == ICMP_DEST_UNREACHABLE
                                && icmp_code == ICMP_CODE_PORT_UNREACHABLE
                            {
                                // Destination sent Port Unreachable
                                if responding_addr.is_none() {
                                    responding_addr = Some(IpAddr::V4(source));
                                }
                                destination_reached = true;
                                if received < probes_per_hop {
                                    rtts[received] = Some(send_times[received].elapsed());
                                    received += 1;
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        let rtts_collected: Vec<Duration> = rtts.iter().filter_map(|r| *r).collect();
        let (min_rtt, max_rtt, avg_rtt) = if rtts_collected.is_empty() {
            (None, None, None)
        } else {
            let min = rtts_collected.iter().min().copied();
            let max = rtts_collected.iter().max().copied();
            let sum: Duration = rtts_collected.iter().sum();
            let avg = Some(sum / rtts_collected.len() as u32);
            (min, max, avg)
        };

        hops.push(TracerouteHop {
            ttl,
            addr: responding_addr,
            hostname: None,
            min_rtt,
            max_rtt,
            avg_rtt,
            rtts: Some(rtts),
            packet_loss: if probes_per_hop > 0 {
                ((probes_per_hop - rtts_collected.len()) as f64 / probes_per_hop as f64) * 100.0
            } else {
                100.0
            },
            probes_sent: probes_per_hop,
            probes_received: rtts_collected.len(),
        });

        if destination_reached {
            return (hops, true);
        }
    }
    (hops, false)
}

/// Blocking recv with timeout. Returns (bytes_read, source_ipv4).
fn recv_with_timeout(
    socket: &Socket,
    buf: &mut [MaybeUninit<u8>],
    timeout: Duration,
) -> io::Result<Option<io::Result<(usize, Ipv4Addr)>>> {
    socket.set_read_timeout(Some(timeout))?;
    match socket.recv_from(buf) {
        Ok((n, addr)) => {
            if let Some(v4) = addr.as_socket_ipv4() {
                Ok(Some(Ok((n, *v4.ip()))))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                Ok(None)
            } else {
                Ok(Some(Err(e)))
            }
        }
    }
}
