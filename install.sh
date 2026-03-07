#!/bin/bash
# Murmur install script
# Builds, installs binaries, and sets Linux capabilities

set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BUILD_TYPE="${BUILD_TYPE:-release}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# SUDO: empty when root, "sudo" otherwise. Use $SUDO for install steps.
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        error "This script requires root or sudo for installation"
    fi
fi

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

# Install dependencies
install_deps() {
    local os=$(detect_os)
    
    if [ "$os" = "linux" ]; then
        if command -v apt-get &> /dev/null; then
            info "Installing libpcap-dev..."
            $SUDO apt-get update -qq
            $SUDO apt-get install -y -qq libpcap-dev
        elif command -v dnf &> /dev/null; then
            info "Installing libpcap-devel..."
            $SUDO dnf install -y -q libpcap-devel
        elif command -v pacman &> /dev/null; then
            info "Installing libpcap..."
            $SUDO pacman -S --noconfirm libpcap
        else
            warn "Could not detect package manager. Ensure libpcap is installed."
        fi
    fi
}

# Build the project
build() {
    info "Building murmur..."
    
    if [ "$BUILD_TYPE" = "release" ]; then
        cargo build --release --package murmur-cli --package murmur-agent
        BUILD_DIR="target/release"
    else
        cargo build --package murmur-cli --package murmur-agent
        BUILD_DIR="target/debug"
    fi
    
    if [ ! -f "$BUILD_DIR/murmur" ] || [ ! -f "$BUILD_DIR/murmur-agent" ]; then
        error "Build failed - binaries not found"
    fi
    
    info "Build complete"
}

# Install binaries
install_bins() {
    local os=$(detect_os)
    
    info "Installing to $INSTALL_DIR..."
    
    $SUDO mkdir -p "$INSTALL_DIR"
    $SUDO cp "$BUILD_DIR/murmur" "$INSTALL_DIR/"
    $SUDO cp "$BUILD_DIR/murmur-agent" "$INSTALL_DIR/"
    $SUDO chmod +x "$INSTALL_DIR/murmur" "$INSTALL_DIR/murmur-agent"
    
    info "Installed murmur and murmur-agent to $INSTALL_DIR"
}

# Set Linux capabilities
set_capabilities() {
    local os=$(detect_os)
    
    if [ "$os" != "linux" ]; then
        return
    fi
    
    if ! command -v setcap &> /dev/null; then
        warn "setcap not found - skipping capability setup"
        warn "ICMP probes (ping, traceroute) and DNS observation will require root"
        return
    fi
    
    info "Setting capabilities for ICMP and packet capture..."
    
    # CAP_NET_RAW: Required for ICMP ping, traceroute, and packet capture
    # CAP_NET_ADMIN: Required for some advanced network operations
    $SUDO setcap cap_net_raw,cap_net_admin=eip "$INSTALL_DIR/murmur-agent" || {
        warn "Failed to set capabilities. ICMP probes will require root."
        warn "You can manually run: sudo setcap cap_net_raw,cap_net_admin=eip $INSTALL_DIR/murmur-agent"
    }
    
    # Verify
    if getcap "$INSTALL_DIR/murmur-agent" | grep -q cap_net_raw; then
        info "Capabilities set successfully"
        info "murmur-agent can now use ICMP and packet capture without root"
    fi
}

# Create systemd service (optional)
create_service() {
    local os=$(detect_os)
    
    if [ "$os" != "linux" ]; then
        return
    fi
    
    if [ ! -d /etc/systemd/system ]; then
        return
    fi
    
    read -p "Create systemd service for murmur-agent? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    info "Creating systemd service..."
    
    $SUDO tee /etc/systemd/system/murmur-agent.service > /dev/null << EOF
[Unit]
Description=Murmur Network Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/murmur-agent
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Allow network capabilities
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    info "Service created. Enable with: sudo systemctl enable --now murmur-agent"
}

# Create config directory
create_config() {
    local config_dir="/etc/murmur"
    
    if [ -d "$config_dir" ]; then
        return
    fi
    
    info "Creating config directory..."
    $SUDO mkdir -p "$config_dir"
    
    # Create example config
    $SUDO tee "$config_dir/config.toml.example" > /dev/null << 'EOF'
# Murmur configuration

[probe]
interval_seconds = 60
timeout_seconds = 30
targets = [
    "https://api.example.com",
]

[collector]
enabled = true
endpoint = "http://localhost:4317"
export_interval_seconds = 15

[logging]
format = "pretty"
level = "info"
EOF
    
    info "Example config created at $config_dir/config.toml.example"
}

# Main
main() {
    echo "================================"
    echo "  Murmur Install Script"
    echo "================================"
    echo
    
    install_deps
    build
    install_bins
    set_capabilities
    create_config
    create_service
    
    echo
    echo "================================"
    info "Installation complete!"
    echo
    echo "Commands:"
    echo "  murmur probe <url>     Run a single probe"
    echo "  murmur-agent           Start the background agent"
    echo
    echo "Configuration:"
    echo "  /etc/murmur/config.toml"
    echo "  ~/.config/murmur/config.toml"
    echo "  MURMUR_* environment variables"
    echo "================================"
}

# Handle --help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: ./install.sh [options]"
    echo
    echo "Options:"
    echo "  --help, -h     Show this help"
    echo
    echo "Environment variables:"
    echo "  INSTALL_DIR    Installation directory (default: /usr/local/bin)"
    echo "  BUILD_TYPE     Build type: release or debug (default: release)"
    exit 0
fi

main "$@"
