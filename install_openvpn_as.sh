#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Enhanced with Advanced UPnP Router Configuration

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
ROUTER_MODEL=""
INSTALL_INTERRUPTED=false

# Simple logging functions
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

# Cleanup function
cleanup() {
    if [ "$INSTALL_INTERRUPTED" = true ]; then
        log_warning "Cleaning up interrupted installation..."
        pkill -f "openvpn" 2>/dev/null || true
        pkill -f "install.sh" 2>/dev/null || true
        rm -f /tmp/openvpn-as-install.sh
        rm -f /tmp/openvpn-as.deb
    fi
}

# Safe exit handler
safe_exit() {
    INSTALL_INTERRUPTED=true
    cleanup
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
    fi
}

# Detect OS
detect_os() {
    log_info "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect operating system"
    fi
    
    if [ "$OS" != "ubuntu" ]; then
        log_error "This script is designed for Ubuntu systems only. Detected: $OS"
    fi
    
    # Get server IP address
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi
    
    # Get hostname
    SERVER_HOSTNAME=$(hostname -s)
    
    log_info "Detected: Ubuntu $OS_VERSION"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
}

# Get public IP address
get_public_ip() {
    log_info "Detecting public IP address..."
    
    if PUBLIC_IP=$(curl -s -4 --connect-timeout 5 https://api.ipify.org); then
        if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_success "Public IP detected: $PUBLIC_IP"
            return 0
        fi
    fi
    
    PUBLIC_IP="Unable to detect"
    log_warning "Could not detect public IP address"
    return 1
}

# Advanced router detection
detect_router() {
    log_info "Detecting router information..."
    
    # Get router IP
    ROUTER_IP=$(ip route show default | awk '/default/ {print $3}' | head -1)
    
    if [ -z "$ROUTER_IP" ]; then
        local network_part=$(echo "$SERVER_IP" | cut -d. -f1-3)
        ROUTER_IP="${network_part}.1"
    fi
    
    if [[ "$ROUTER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_success "Router IP detected: $ROUTER_IP"
    else
        ROUTER_IP="192.168.1.1"
        log_warning "Using default router IP: $ROUTER_IP"
    fi
    
    # Try to detect router model via UPnP
    log_info "Attempting to detect router model..."
    if command -v upnpc >/dev/null 2>&1; then
        local router_info=$(upnpc -l 2>/dev/null | grep -i "desc:" | head -1 || true)
        if [ -n "$router_info" ]; then
            ROUTER_MODEL=$(echo "$router_info" | sed 's/.*desc: //i')
            log_success "Router model detected: $ROUTER_MODEL"
        else
            ROUTER_MODEL="Unknown"
            log_info "Router model: Unknown (UPnP discovery failed)"
        fi
    else
        ROUTER_MODEL="Unknown"
        log_info "Router model: Unknown (upnpc not available)"
    fi
    
    return 0
}

# Install UPnP tools
install_upnp_tools() {
    log_info "Installing UPnP tools..."
    
    if ! command -v upnpc >/dev/null 2>&1; then
        apt-get update
        # Install only miniupnpc (upnp-utils doesn't exist in Ubuntu 24.04)
        apt-get install -y miniupnpc
        
        if command -v upnpc >/dev/null 2>&1; then
            log_success "UPnP tools installed successfully"
        else
            log_error "Failed to install UPnP tools"
        fi
    else
        log_success "UPnP tools already installed"
    fi
}

# Test UPnP connectivity
test_upnp_connectivity() {
    log_info "Testing UPnP connectivity to router..."
    
    if ! command -v upnpc >/dev/null 2>&1; then
        log_warning "UPnPC not available, installing..."
        install_upnp_tools
    fi
    
    # Test UPnP discovery with shorter timeout
    local test_result=$(timeout 5 upnpc -l 2>/dev/null | head -5 || true)
    
    if echo "$test_result" | grep -q "UPnP" || echo "$test_result" | grep -q "igd" || echo "$test_result" | grep -q "InternetGatewayDevice"; then
        UPNP_AVAILABLE=true
        log_success "UPnP connectivity test: SUCCESS"
        log_info "Router supports UPnP port forwarding"
        return 0
    else
        UPNP_AVAILABLE=false
        log_warning "UPnP connectivity test: FAILED"
        log_info "Router may not support UPnP or it's disabled"
        return 1
    fi
}

# Advanced UPnP port forwarding with virtual server creation
configure_upnp_advanced() {
    log_info "=== ADVANCED UPNP CONFIGURATION ==="
    log_info "Creating virtual server mappings on router..."
    
    detect_router
    install_upnp_tools
    
    if ! test_upnp_connectivity; then
        log_warning "Cannot configure UPnP - router not accessible"
        show_manual_forwarding_instructions
        return 1
    fi
    
    # Define port mappings for virtual server
    local port_mappings=(
        # Internal Port : External Port : Protocol : Description
        "$HTTP_PORT:$HTTP_PORT:TCP:HTTP_Web_Redirect"
        "$HTTPS_PORT:$HTTPS_PORT:TCP:HTTPS_Web_Interface" 
        "$OPENVPN_PORT:$OPENVPN_PORT:TCP:OpenVPN_Admin"
        "$OPENVPN_UDP_PORT:$OPENVPN_UDP_PORT:UDP:OpenVPN_VPN_Tunnel"
    )
    
    local success_count=0
    local total_ports=${#port_mappings[@]}
    
    log_info "Starting UPnP virtual server configuration..."
    log_info "Router: $ROUTER_MODEL ($ROUTER_IP)"
    log_info "Target Server: $SERVER_IP"
    echo
    
    # First, cleanup any existing mappings
    log_info "Cleaning up existing port mappings..."
    for mapping in "${port_mappings[@]}"; do
        local ext_port=$(echo "$mapping" | cut -d: -f2)
        local protocol=$(echo "$mapping" | cut -d: -f3)
        
        upnpc -d "$ext_port" "$protocol" >/dev/null 2>&1 || true
    done
    sleep 2
    
    # Create new virtual server mappings
    for mapping in "${port_mappings[@]}"; do
        local int_port=$(echo "$mapping" | cut -d: -f1)
        local ext_port=$(echo "$mapping" | cut -d: -f2)
        local protocol=$(echo "$mapping" | cut -d: -f3)
        local description=$(echo "$mapping" | cut -d: -f4)
        
        log_info "Configuring: $description"
        log_info "  Mapping: $protocol $ext_port -> $SERVER_IP:$int_port"
        
        # Attempt UPnP mapping with retry logic
        local mapped=false
        for attempt in {1..3}; do
            if upnpc -a "$SERVER_IP" "$int_port" "$ext_port" "$protocol" "$description" >/dev/null 2>&1; then
                log_success "  ✓ Successfully mapped (attempt $attempt/3)"
                ((success_count++))
                mapped=true
                break
            else
                log_warning "  ✗ Mapping failed (attempt $attempt/3)"
                sleep 1
            fi
        done
        
        if [ "$mapped" = false ]; then
            log_warning "  ✗ Failed to map after 3 attempts"
        fi
        
        sleep 1
    done
    
    # Verify and display active mappings
    verify_upnp_mappings
    
    # Display results
    echo
    log_info "=== UPNP CONFIGURATION SUMMARY ==="
    if [ $success_count -eq $total_ports ]; then
        log_success "ALL $success_count ports successfully mapped!"
        UPNP_AVAILABLE=true
    elif [ $success_count -gt 0 ]; then
        log_success "$success_count out of $total_ports ports mapped successfully"
        UPNP_AVAILABLE=true
    else
        log_warning "No ports could be mapped via UPnP"
        UPNP_AVAILABLE=false
    fi
    
    return $success_count
}

# Verify UPnP mappings
verify_upnp_mappings() {
    log_info "Verifying active UPnP mappings..."
    
    local active_mappings=$(upnpc -l 2>/dev/null | grep -E "^(UDP|TCP).*->" | head -10 || true)
    
    if [ -n "$active_mappings" ]; then
        echo
        log_success "ACTIVE UPNP MAPPINGS:"
        echo "----------------------------------------"
        echo "$active_mappings"
        echo "----------------------------------------"
        
        # Count successful mappings for our server
        local mapped_count=$(echo "$active_mappings" | grep -c "$SERVER_IP" || true)
        log_info "Confirmed mappings for this server: $mapped_count"
    else
        log_warning "No active UPnP mappings found"
    fi
}

# Show manual port forwarding instructions
show_manual_forwarding_instructions() {
    echo
    log_warning "=== MANUAL ROUTER CONFIGURATION REQUIRED ==="
    echo
    log_info "Since UPnP auto-configuration failed, you need to manually"
    log_info "configure port forwarding on your router:"
    echo
    log_info "ROUTER ACCESS:"
    echo "  Router IP: http://$ROUTER_IP"
    echo "  Model: $ROUTER_MODEL"
    echo
    log_info "PORTS TO FORWARD:"
    echo "  ┌─────────────────┬──────────┬─────────────┬─────────────────┐"
    echo "  │ Service         │ Protocol │ Port        │ Forward to      │"
    echo "  ├─────────────────┼──────────┼─────────────┼─────────────────┤"
    echo "  │ HTTP Redirect   │ TCP      │ $HTTP_PORT    │ $SERVER_IP │"
    echo "  │ HTTPS Web       │ TCP      │ $HTTPS_PORT   │ $SERVER_IP │"
    echo "  │ OpenVPN Admin   │ TCP      │ $OPENVPN_PORT │ $SERVER_IP │"
    echo "  │ OpenVPN VPN     │ UDP      │ $OPENVPN_UDP_PORT │ $SERVER_IP │"
    echo "  └─────────────────┴──────────┴─────────────┴─────────────────┘"
    echo
    log_info "ROUTER SETTINGS LOCATION:"
    echo "  Look for: 'Port Forwarding', 'Virtual Servers', 'NAT'"
    echo "  Or: 'Firewall' → 'Port Forwarding'"
    echo
    log_info "ADDITIONAL NOTES:"
    echo "  • Make sure to enable the rules after creating them"
    echo "  • Some routers require router restart for changes to take effect"
    echo "  • Save your configuration to prevent loss after router reboot"
    echo
}

# Configure ports
configure_ports() {
    log_info "Configuring network ports..."
    
    echo
    echo "=== PORT CONFIGURATION ==="
    echo "Using default ports (press Enter for all):"
    echo
    
    SSH_PORT=22
    HTTP_PORT=80
    HTTPS_PORT=443
    OPENVPN_PORT=943
    OPENVPN_UDP_PORT=1194
    
    log_info "Port Configuration:"
    echo "  SSH: $SSH_PORT/tcp"
    echo "  HTTP: $HTTP_PORT/tcp"
    echo "  HTTPS: $HTTPS_PORT/tcp"
    echo "  OpenVPN Admin: $OPENVPN_PORT/tcp"
    echo "  OpenVPN UDP: $OPENVPN_UDP_PORT/udp"
    echo
}

# User input function
get_user_input() {
    log_info "Please provide configuration details:"
    echo
    
    # Set domain name
    DOMAIN_NAME="vpn.${SERVER_HOSTNAME}.local"
    log_info "Using domain: $DOMAIN_NAME"
    
    echo
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -s -p "Enter admin password (min 8 characters): " ADMIN_PASSWORD
        echo
        if [ ${#ADMIN_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
            echo
            if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
                break
            else
                log_warning "Passwords do not match. Please try again."
            fi
        else
            log_warning "Password must be at least 8 characters long."
        fi
    done
    
    # Configure ports
    configure_ports
    
    # Display configuration summary
    echo
    log_info "Configuration Summary:"
    echo "  Domain: $DOMAIN_NAME"
    echo "  Admin User: $ADMIN_USER"
    echo "  SSH Port: $SSH_PORT"
    echo "  HTTP Port: $HTTP_PORT"
    echo "  HTTPS Port: $HTTPS_PORT"
    echo "  OpenVPN Admin Port: $OPENVPN_PORT"
    echo "  OpenVPN UDP Port: $OPENVPN_UDP_PORT"
    echo "  Server IP: $SERVER_IP"
    echo
    
    read -p "Continue with installation? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [ -n "$REPLY" ]; then
        log_info "Installation cancelled by user."
        exit 0
    fi
}

# Add domain to hosts file
configure_hosts_file() {
    log_info "Configuring /etc/hosts file..."
    
    # Backup original hosts file
    cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)
    
    # Remove existing entries for our domain
    sed -i "/$DOMAIN_NAME/d" /etc/hosts
    
    # Add new entry
    echo "$SERVER_IP    $DOMAIN_NAME" >> /etc/hosts
    
    log_success "Added $DOMAIN_NAME to /etc/hosts"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    apt-get update
    
    local essential_deps=(
        wget
        curl
        nginx
        ufw
        openssl
        miniupnpc
    )
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${essential_deps[@]}"
    
    log_success "Dependencies installed successfully"
}

# Install OpenVPN AS
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    # Clean up any existing installations
    pkill -f "openvpn" 2>/dev/null || true
    rm -f /tmp/openvpn-as-install.sh
    
    # Download the installer
    if wget -q https://packages.openvpn.net/as/install.sh -O /tmp/openvpn-as-install.sh; then
        chmod +x /tmp/openvpn-as-install.sh
        
        log_info "Starting installation (this will take 5-10 minutes)..."
        log_info "Please be patient and DO NOT interrupt the process."
        
        # Run installer directly
        if /tmp/openvpn-as-install.sh --yes; then
            log_success "OpenVPN AS installed successfully"
            rm -f /tmp/openvpn-as-install.sh
            return 0
        else
            log_warning "Installation may have had issues, checking status..."
            return 0
        fi
    else
        log_error "Failed to download OpenVPN AS installer"
        return 1
    fi
}

# Verify OpenVPN AS installation
verify_openvpn_installation() {
    log_info "Verifying OpenVPN AS installation..."
    
    if [ -f "/usr/local/openvpn_as/scripts/sacli" ]; then
        log_success "OpenVPN AS installation verified"
        return 0
    else
        log_error "OpenVPN AS installation failed - sacli not found"
        return 1
    fi
}

# Wait for OpenVPN AS to be ready
wait_for_openvpn_ready() {
    log_info "Waiting for OpenVPN AS services to start..."
    
    # Start services
    systemctl enable openvpnas 2>/dev/null || true
    systemctl start openvpnas 2>/dev/null || true
    
    # Wait for services to start
    sleep 30
    
    log_info "Services should be starting up..."
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Stop services for configuration
    systemctl stop openvpnas 2>/dev/null || true
    sleep 5
    
    # Configure admin password
    log_info "Setting admin password..."
    if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword; then
        log_success "Admin password configured"
    else
        log_warning "Failed to set admin password automatically"
        log_info "You can set it manually later with:"
        log_info "/usr/local/openvpn_as/scripts/sacli --user $ADMIN_USER --new_pass 'YOUR_PASSWORD' SetLocalPassword"
    fi
    
    # Configure basic settings
    log_info "Configuring OpenVPN AS settings..."
    
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$HTTPS_PORT" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.udp.port" --value "$OPENVPN_UDP_PORT" ConfigPut
    
    # Start services
    log_info "Starting OpenVPN AS services..."
    systemctl start openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli start
    
    sleep 10
    
    log_success "OpenVPN AS configuration applied"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates for $DOMAIN_NAME..."
    
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME" 2>/dev/null
    
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    
    log_success "SSL certificates generated"
}

# Configure Nginx
configure_nginx() {
    log_info "Configuring Nginx..."
    
    systemctl stop nginx 2>/dev/null || true
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
server {
    listen $HTTP_PORT;
    server_name $DOMAIN_NAME;
    return 301 https://\$server_name:\$server_port\$request_uri;
}

server {
    listen $HTTPS_PORT ssl;
    server_name $DOMAIN_NAME;
    
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
    
    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Test and start nginx
    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        log_success "Nginx configured"
    else
        log_error "Nginx configuration test failed"
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset || true
    
    # Allow necessary ports
    ufw allow "$SSH_PORT/tcp"
    ufw allow "$HTTP_PORT/tcp"
    ufw allow "$HTTPS_PORT/tcp"
    ufw allow "$OPENVPN_UDP_PORT/udp"
    ufw allow "$OPENVPN_PORT/tcp"
    
    # Enable UFW
    echo "y" | ufw enable
    
    log_success "Firewall configured"
}

# Final verification with UPnP status
verify_installation() {
    log_info "Verifying installation..."
    
    echo
    echo "=== INSTALLATION COMPLETE ==="
    echo
    log_success "OpenVPN Access Server is installed and configured!"
    echo
    echo "=== NETWORK STATUS ==="
    echo "UPnP Auto-Configuration: $([ "$UPNP_AVAILABLE" = true ] && echo "SUCCESS" || echo "FAILED")"
    echo "Router: $ROUTER_MODEL ($ROUTER_IP)"
    echo "Public IP: $PUBLIC_IP"
    echo "Local IP: $SERVER_IP"
    echo
    echo "=== ACCESS INFORMATION ==="
    echo "Local Admin Interface: https://$DOMAIN_NAME/admin"
    echo "Local Client Interface: https://$DOMAIN_NAME/"
    echo "Direct Access: https://$SERVER_IP:$HTTPS_PORT/admin"
    echo
    if [ "$PUBLIC_IP" != "Unable to detect" ] && [ "$UPNP_AVAILABLE" = true ]; then
        echo "External Access (via UPnP): https://$PUBLIC_IP:$HTTPS_PORT/admin"
        echo "OpenVPN UDP (via UPnP): $PUBLIC_IP:$OPENVPN_UDP_PORT"
        echo
    elif [ "$PUBLIC_IP" != "Unable to detect" ]; then
        echo "External Access (manual config required): https://$PUBLIC_IP:$HTTPS_PORT/admin"
        echo
    fi
    echo "=== CREDENTIALS ==="
    echo "Username: $ADMIN_USER"
    echo "Password: $ADMIN_PASSWORD"
    echo
    echo "=== PORTS CONFIGURED ==="
    echo "HTTP: $HTTP_PORT/tcp, HTTPS: $HTTPS_PORT/tcp"
    echo "OpenVPN Admin: $OPENVPN_PORT/tcp"
    echo "OpenVPN VPN: $OPENVPN_UDP_PORT/udp"
    echo
    if [ "$UPNP_AVAILABLE" = false ]; then
        echo "=== MANUAL CONFIGURATION NEEDED ==="
        echo "UPnP auto-configuration failed. You need to manually"
        echo "configure port forwarding on your router at:"
        echo "http://$ROUTER_IP"
        echo
    fi
    echo "=== NEXT STEPS ==="
    echo "1. Wait 2-3 minutes for all services to be fully ready"
    echo "2. Access the admin interface at: https://$DOMAIN_NAME/admin"
    echo "3. Configure your VPN settings and user access"
    echo "4. Download client configurations for your users"
    echo
}

# Main installation function
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS Installer for Ubuntu 24.04"
    echo "   Advanced UPnP Router Configuration"
    echo "=================================================="
    echo
    
    # Set trap for cleanup
    trap safe_exit INT TERM
    
    # Run installation steps
    check_root
    detect_os
    get_public_ip
    get_user_input
    configure_hosts_file
    install_dependencies
    generate_ssl_certificates
    
    log_info "=== STARTING OPENVPN AS INSTALLATION ==="
    log_info "This will take 5-10 minutes. Please be patient..."
    echo
    
    if install_openvpn_as; then
        verify_openvpn_installation
        wait_for_openvpn_ready
        configure_openvpn_as
        configure_nginx
        configure_firewall
        
        log_info "=== ADVANCED UPNP ROUTER CONFIGURATION ==="
        log_info "Configuring virtual server on your router..."
        configure_upnp_advanced
        
        verify_installation
        
        log_success "=== INSTALLATION COMPLETED SUCCESSFULLY ==="
        echo
        log_info "You can now access your OpenVPN AS admin panel at:"
        log_info "https://$DOMAIN_NAME/admin"
        echo
        
        if [ "$UPNP_AVAILABLE" = true ]; then
            log_success "UPnP configuration: SUCCESS - External access enabled"
        else
            log_warning "UPnP configuration: FAILED - Manual router setup required"
        fi
    else
        log_error "Installation failed. Please check the errors above."
    fi
}

# Run main function
main "$@"
