#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Enhanced with Advanced UPnP Detection and ZeroTier Integration

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
PUBLIC_IP=""
UPNP_AVAILABLE=false
ROUTER_IP=""
PORTS_CONFIG=()

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

log_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
    fi
}

# Detect OS and verify Ubuntu 24.04 compatibility
detect_os() {
    log_info "Detecting operating system and checking compatibility..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_CODENAME=$VERSION_CODENAME
        OS_NAME=$NAME
    else
        log_error "Cannot detect operating system"
    fi
    
    # Verify Ubuntu 24.04
    if [ "$OS" != "ubuntu" ]; then
        log_error "This script is designed for Ubuntu systems only. Detected: $OS"
    fi
    
    if [ "$OS_VERSION" != "24.04" ]; then
        log_warning "This script is optimized for Ubuntu 24.04. You are running: $OS_VERSION"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installation cancelled."
            exit 0
        fi
    fi
    
    # Get server IP address
    SERVER_IP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi
    
    # Get hostname
    SERVER_HOSTNAME=$(hostname -s)
    
    log_info "Detected: $OS_NAME $OS_VERSION ($OS_CODENAME)"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
    
    log_success "System compatibility check passed"
}

# Get public IP address
get_public_ip() {
    log_info "Detecting public IP address..."
    
    local services=(
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://icanhazip.com"
        "https://ident.me"
    )
    
    for service in "${services[@]}"; do
        if PUBLIC_IP=$(curl -s -4 --connect-timeout 5 "$service" 2>/dev/null); then
            if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                log_success "Public IP detected: $PUBLIC_IP"
                return 0
            fi
        fi
    done
    
    PUBLIC_IP="Unable to detect"
    log_warning "Could not detect public IP address"
    return 1
}

# Advanced Router IP Detection
detect_router_ip() {
    log_info "Detecting router IP address..."
    
    # Method 1: Use ip route (most reliable)
    ROUTER_IP=$(ip route show default | awk '/default/ {print $3}' | head -1)
    
    # Method 2: Use network configuration
    if [ -z "$ROUTER_IP" ] || [ "$ROUTER_IP" = "0.0.0.0" ]; then
        ROUTER_IP=$(netstat -rn | grep 'UG' | awk '{print $2}' | head -1)
    fi
    
    # Method 3: Guess from local IP
    if [ -z "$ROUTER_IP" ]; then
        local network_part=$(echo "$SERVER_IP" | cut -d. -f1-3)
        ROUTER_IP="${network_part}.1"
    fi
    
    # Validate router IP
    if [[ "$ROUTER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "$ROUTER_IP" != "127.0.0.1" ]; then
        log_success "Router IP detected: $ROUTER_IP"
        return 0
    else
        log_warning "Could not detect router IP reliably"
        ROUTER_IP="192.168.1.1" # Common default
        return 1
    fi
}

# Enhanced UPnP Detection with Router Discovery
check_upnp() {
    log_info "Checking UPnP availability with advanced detection..."
    
    # Install miniupnpc if not available
    if ! command -v upnpc >/dev/null 2>&1; then
        log_info "Installing UPnP client..."
        if ! apt-get install -y miniupnpc >/dev/null 2>&1; then
            log_warning "Failed to install UPnP client"
            UPNP_AVAILABLE=false
            return 1
        fi
    fi
    
    # Detect router IP first
    detect_router_ip
    
    log_info "Testing UPnP on router: $ROUTER_IP"
    
    # Method 1: Standard UPnP discovery
    log_info "Method 1: Standard UPnP discovery..."
    if timeout 10 upnpc -s >/dev/null 2>&1; then
        UPNP_AVAILABLE=true
        log_success "✓ UPnP is available on your router"
        return 0
    fi
    
    # Method 2: Force specific router IP
    log_info "Method 2: Direct router communication..."
    if timeout 10 upnpc -u "http://$ROUTER_IP:5000/rootDesc.xml" -s >/dev/null 2>&1; then
        UPNP_AVAILABLE=true
        log_success "✓ UPnP is available (direct connection)"
        return 0
    fi
    
    # Method 3: Try different UPnP ports
    log_info "Method 3: Testing different UPnP ports..."
    local upnp_ports=("5000" "1900" "2869" "5351")
    for port in "${upnp_ports[@]}"; do
        log_info "Testing UPnP port: $port"
        if timeout 5 upnpc -u "http://$ROUTER_IP:$port/rootDesc.xml" -s >/dev/null 2>&1; then
            UPNP_AVAILABLE=true
            log_success "✓ UPnP is available on port $port"
            return 0
        fi
    done
    
    # Method 4: Network interface specific
    log_info "Method 4: Interface-specific discovery..."
    local interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v lo))
    for interface in "${interfaces[@]}"; do
        if [ -n "$interface" ] && [ "$interface" != "scope" ]; then
            log_info "Testing UPnP on interface: $interface"
            if timeout 10 upnpc -i "$interface" -s >/dev/null 2>&1; then
                UPNP_AVAILABLE=true
                log_success "✓ UPnP is available on interface $interface"
                return 0
            fi
        fi
    done
    
    UPNP_AVAILABLE=false
    log_warning "✗ UPnP is not available on your router"
    
    # Enhanced troubleshooting
    echo
    log_info "ADVANCED UPNP TROUBLESHOOTING:"
    log_info "1. Router Access: http://$ROUTER_IP"
    log_info "2. Enable UPnP in router settings under:"
    log_info "   - Advanced → NAT Forwarding → UPnP (TP-Link)"
    log_info "   - Advanced → Advanced Setup → UPnP (Netgear)" 
    log_info "   - WAN → NAT Passthrough (Asus)"
    log_info "3. Restart router after enabling UPnP"
    log_info "4. Some ISPs block UPnP for security"
    echo
    
    return 1
}

# Configure ports via UPnP with enhanced error handling
configure_upnp_ports() {
    if [ "$UPNP_AVAILABLE" != "true" ]; then
        log_warning "UPnP not available, skipping automatic port forwarding"
        return 1
    fi
    
    log_info "Configuring automatic UPnP port forwarding..."
    
    local ports_to_forward=(
        "$SSH_PORT:tcp:SSH"
        "$HTTP_PORT:tcp:HTTP"
        "$HTTPS_PORT:tcp:HTTPS" 
        "$OPENVPN_PORT:tcp:OpenVPN_Admin"
        "$OPENVPN_UDP_PORT:udp:OpenVPN_UDP"
    )
    
    local success_count=0
    local failed_count=0
    
    log_info "Starting UPnP port forwarding configuration..."
    
    for port_config in "${ports_to_forward[@]}"; do
        local port=$(echo "$port_config" | cut -d: -f1)
        local protocol=$(echo "$port_config" | cut -d: -f2)
        local service=$(echo "$port_config" | cut -d: -f3)
        
        log_info "Forwarding $service: $protocol port $port to $SERVER_IP"
        
        # Remove any existing mapping first
        upnpc -d "$port" "$protocol" >/dev/null 2>&1 || true
        sleep 1
        
        # Add new port mapping with retry logic
        local retry_count=0
        local max_retries=3
        
        while [ $retry_count -lt $max_retries ]; do
            if upnpc -a "$SERVER_IP" "$port" "$port" "$protocol" "OpenVPN_AS_$service" >/dev/null 2>&1; then
                log_success "✓ UPnP: Successfully forwarded $protocol port $port ($service)"
                ((success_count++))
                break
            else
                ((retry_count++))
                if [ $retry_count -eq $max_retries ]; then
                    log_warning "✗ UPnP: Failed to forward $protocol port $port ($service) after $max_retries attempts"
                    ((failed_count++))
                else
                    log_info "Retrying $service port forwarding (attempt $((retry_count + 1))/$max_retries)..."
                    sleep 2
                fi
            fi
        done
        
        sleep 1
    done
    
    # Display summary
    echo
    if [ $success_count -gt 0 ]; then
        log_success "UPnP port forwarding completed: $success_count ports forwarded successfully"
        
        # Display external access URLs
        if [ "$PUBLIC_IP" != "Unable to detect" ]; then
            echo
            log_info "=== EXTERNAL ACCESS URLs (via UPnP) ==="
            log_success "Admin Interface: https://$PUBLIC_IP:$HTTPS_PORT/admin"
            log_success "Client Interface: https://$PUBLIC_IP:$HTTPS_PORT/"
            log_success "OpenVPN UDP: $PUBLIC_IP:$OPENVPN_UDP_PORT"
            echo
        fi
    fi
    
    if [ $failed_count -gt 0 ]; then
        log_warning "$failed_count ports failed UPnP forwarding"
    fi
    
    return $((success_count > 0 ? 0 : 1))
}

# ZeroTier Integration (Alternative to UPnP)
setup_zerotier() {
    log_info "Setting up ZeroTier as UPnP alternative..."
    
    echo
    echo "=== ZEROTIER SETUP ==="
    echo "ZeroTier creates a secure virtual network that bypasses port forwarding."
    echo "It works like a VPN that connects all your devices securely."
    echo
    
    read -p "Do you want to set up ZeroTier? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [ -n "$REPLY" ]; then
        log_info "Skipping ZeroTier setup."
        return 1
    fi
    
    # Install ZeroTier
    log_info "Installing ZeroTier..."
    if curl -s https://install.zerotier.com | bash >/dev/null 2>&1; then
        log_success "ZeroTier installed successfully"
    else
        log_warning "Failed to install ZeroTier using official script, trying package manager..."
        apt-get install -y zerotier-one >/dev/null 2>&1 || {
            log_error "Failed to install ZeroTier"
            return 1
        }
    fi
    
    # Start and enable ZeroTier
    systemctl enable zerotier-one >/dev/null 2>&1
    systemctl start zerotier-one >/dev/null 2>&1
    
    # Join network
    echo
    log_info "To join a ZeroTier network:"
    echo "1. Go to https://my.zerotier.com"
    echo "2. Create a new network or use existing one"
    echo "3. Note the 16-character Network ID"
    echo
    
    read -p "Enter your ZeroTier Network ID (or press Enter to skip): " ZEROTIER_NETWORK_ID
    
    if [ -n "$ZEROTIER_NETWORK_ID" ]; then
        log_info "Joining ZeroTier network: $ZEROTIER_NETWORK_ID"
        if zerotier-cli join "$ZEROTIER_NETWORK_ID" >/dev/null 2>&1; then
            log_success "Successfully joined ZeroTier network"
            log_info "Please authorize this device in your ZeroTier Central dashboard"
            log_info "Then your OpenVPN AS will be accessible via ZeroTier IP"
            
            # Wait for IP assignment
            log_info "Waiting for ZeroTier IP assignment..."
            sleep 10
            
            # Get ZeroTier IP
            ZEROTIER_IP=$(zerotier-cli listnetworks | grep "$ZEROTIER_NETWORK_ID" | awk '{print $9}')
            if [ -n "$ZEROTIER_IP" ] && [ "$ZEROTIER_IP" != "-" ]; then
                log_success "ZeroTier IP assigned: $ZEROTIER_IP"
                
                # Update OpenVPN AS configuration for ZeroTier
                /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$ZEROTIER_IP" ConfigPut >/dev/null 2>&1 || true
                /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "0.0.0.0" ConfigPut >/dev/null 2>&1 || true
                
                log_success "OpenVPN AS configured for ZeroTier access"
                echo
                log_info "=== ZEROTIER ACCESS URLs ==="
                log_success "Admin Interface: https://$ZEROTIER_IP:$HTTPS_PORT/admin"
                log_success "Client Interface: https://$ZEROTIER_IP:$HTTPS_PORT/"
                echo
                
                return 0
            else
                log_warning "ZeroTier IP not assigned yet. Check ZeroTier Central to authorize this device."
            fi
        else
            log_warning "Failed to join ZeroTier network"
        fi
    else
        log_info "ZeroTier setup skipped. You can manually join a network later with:"
        log_info "zerotier-cli join <NetworkID>"
    fi
    
    return 1
}

# Display network information
display_network_info() {
    echo
    echo "=== NETWORK INFORMATION ==="
    echo -e "${CYAN}Local IP Address:${NC} $SERVER_IP"
    echo -e "${CYAN}Public IP Address:${NC} $PUBLIC_IP"
    echo -e "${CYAN}Router IP:${NC} $ROUTER_IP"
    echo -e "${CYAN}Hostname:${NC} $SERVER_HOSTNAME"
    echo -e "${CYAN}Domain:${NC} $DOMAIN_NAME"
    echo -e "${CYAN}UPnP Status:${NC} $([ "$UPNP_AVAILABLE" = "true" ] && echo "Enabled" || echo "Disabled")"
    echo
    
    echo "=== CONFIGURED PORTS ==="
    echo -e "${CYAN}SSH:${NC} $SSH_PORT/tcp"
    echo -e "${CYAN}HTTP:${NC} $HTTP_PORT/tcp"
    echo -e "${CYAN}HTTPS:${NC} $HTTPS_PORT/tcp"
    echo -e "${CYAN}OpenVPN Admin:${NC} $OPENVPN_PORT/tcp"
    echo -e "${CYAN}OpenVPN UDP:${NC} $OPENVPN_UDP_PORT/udp"
    echo
}

# [Rest of the functions remain the same as your original script...]
# configure_ports(), validate_domain(), generate_domain_suggestions(), get_user_input(), 
# configure_hosts_file(), install_dependencies(), install_pyovpn(), install_openvpn_as(),
# verify_openvpn_installation(), wait_for_openvpn_ready(), configure_openvpn_as(),
# generate_ssl_certificates(), configure_nginx(), configure_firewall(), verify_installation()

# Generate manual port forwarding instructions
generate_port_forwarding_instructions() {
    log_info "Generating manual port forwarding instructions..."
    
    echo
    echo "=== MANUAL PORT FORWARDING INSTRUCTIONS ==="
    echo
    echo "Since UPnP is unavailable, manually forward these ports on your router:"
    echo
    echo "┌─────────────────┬──────────┬────────────┬─────────────────┐"
    echo "│     Service     │  Port    │ Protocol   │    Internal IP  │"
    echo "├─────────────────┼──────────┼────────────┼─────────────────┤"
    echo "│ SSH             │ $SSH_PORT    │ TCP        │ $SERVER_IP │"
    echo "│ HTTP            │ $HTTP_PORT    │ TCP        │ $SERVER_IP │"
    echo "│ HTTPS           │ $HTTPS_PORT   │ TCP        │ $SERVER_IP │"
    echo "│ OpenVPN Admin   │ $OPENVPN_PORT │ TCP        │ $SERVER_IP │"
    echo "│ OpenVPN UDP     │ $OPENVPN_UDP_PORT │ UDP      │ $SERVER_IP │"
    echo "└─────────────────┴──────────┴────────────┴─────────────────┘"
    echo
    echo "STEP-BY-STEP GUIDE:"
    echo "1. Access your router: http://$ROUTER_IP"
    echo "2. Find 'Port Forwarding' or 'Virtual Servers'"
    echo "3. Add each port pointing to $SERVER_IP"
    echo "4. Save and restart router if needed"
    echo
}

# Main installation function with enhanced UPnP/ZeroTier handling
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS Installer for Ubuntu 24.04"
    echo "  Enhanced with Advanced UPnP & ZeroTier Support"
    echo "=================================================="
    echo
    
    # Trap to handle script interruption
    trap 'log_error "Script interrupted by user"; exit 1' INT TERM
    
    check_root
    detect_os
    get_public_ip
    
    # Enhanced UPnP detection
    check_upnp
    
    get_user_input
    configure_hosts_file
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    verify_openvpn_installation
    wait_for_openvpn_ready
    configure_openvpn_as
    configure_nginx
    configure_firewall
    
    # Smart port forwarding solution
    if [ "$UPNP_AVAILABLE" = "true" ]; then
        log_info "Attempting automatic UPnP port forwarding..."
        if configure_upnp_ports; then
            log_success "UPnP port forwarding successful!"
        else
            log_warning "UPnP port forwarding partially failed"
            generate_port_forwarding_instructions
        fi
    else
        log_warning "UPnP not available - offering alternatives..."
        echo
        echo "=== NETWORK ACCESS SOLUTIONS ==="
        echo "1. Enable UPnP on router: http://$ROUTER_IP"
        echo "2. Use ZeroTier (recommended - no port forwarding)"
        echo "3. Manual port forwarding"
        echo
        
        read -p "Choose option [2]: " -n 1 -r
        echo
        
        case $REPLY in
            1)
                log_info "Please enable UPnP in your router settings and re-run the script"
                ;;
            2|"")
                setup_zerotier
                ;;
            3)
                generate_port_forwarding_instructions
                ;;
            *)
                setup_zerotier
                ;;
        esac
    fi
    
    verify_installation
    
    log_success "OpenVPN Access Server installation completed successfully!"
    echo
    log_info "Important Notes:"
    log_info "1. Services may take 2-3 minutes to be fully operational"
    log_info "2. Primary access: https://$DOMAIN_NAME:$HTTPS_PORT/admin"
    log_info "3. UPnP Status: $([ "$UPNP_AVAILABLE" = "true" ] && echo "Enabled" || echo "Disabled")"
    log_info "4. Router Access: http://$ROUTER_IP"
    log_info "5. Manual password reset if needed:"
    log_info "   /usr/local/openvpn_as/scripts/sacli --user $ADMIN_USER --new_pass 'YOUR_PASSWORD' SetLocalPassword"
    echo
}

# Run main function
main "$@"
