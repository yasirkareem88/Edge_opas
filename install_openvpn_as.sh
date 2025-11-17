#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Enhanced with UPnP Automatic Port Forwarding and Network Diagnostics

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

# Enhanced UPnP checking with diagnostics
check_upnp() {
    log_info "Checking UPnP availability on your router..."
    
    # Install miniupnpc if not available
    if ! command -v upnpc >/dev/null 2>&1; then
        log_info "Installing UPnP client..."
        if ! apt-get install -y miniupnpc >/dev/null 2>&1; then
            log_warning "Failed to install UPnP client"
            UPNP_AVAILABLE=false
            return 1
        fi
    fi
    
    # Test UPnP with more detailed diagnostics
    log_info "Discovering UPnP-enabled router..."
    
    # Method 1: Basic UPnP discovery
    if timeout 10 upnpc -s >/dev/null 2>&1; then
        UPNP_AVAILABLE=true
        log_success "✓ UPnP is available and enabled on your router"
        
        # Get router information
        local router_info=$(upnpc -s 2>/dev/null | grep -i "desc:" | head -1)
        if [ -n "$router_info" ]; then
            log_info "Router detected: $router_info"
        fi
        return 0
    fi
    
    # Method 2: Try different discovery methods
    log_info "Trying alternative UPnP discovery methods..."
    
    # Try with specific interface
    local interfaces=($(ip addr show 2>/dev/null | grep -E "inet [0-9]" | awk '{print $7}' | grep -v "lo"))
    for interface in "${interfaces[@]}"; do
        if [ -n "$interface" ]; then
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
    
    # Provide specific troubleshooting advice
    echo
    log_info "UPnP TROUBLESHOOTING GUIDE:"
    log_info "1. Enable UPnP in your router settings:"
    log_info "   - Access router admin (usually 192.168.1.1 or 192.168.0.1)"
    log_info "   - Look for 'UPnP' or 'NAT-PMP' in Advanced settings"
    log_info "   - Enable UPnP and save settings"
    log_info "2. Restart your router after enabling UPnP"
    log_info "3. Some ISPs block UPnP for security reasons"
    log_info "4. Manual port forwarding will be configured as fallback"
    echo
    
    return 1
}

# Configure ports via UPnP
configure_upnp_ports() {
    if [ "$UPNP_AVAILABLE" != "true" ]; then
        log_warning "UPnP not available, skipping automatic port forwarding"
        return 1
    fi
    
    log_info "Configuring automatic UPnP port forwarding on your router..."
    
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
        upnpc -d "$port" "$protocol" 2>/dev/null || true
        sleep 1
        
        # Add new port mapping
        if upnpc -a "$SERVER_IP" "$port" "$port" "$protocol" "OpenVPN_AS_$service" 2>/dev/null; then
            log_success "✓ UPnP: Successfully forwarded $protocol port $port ($service)"
            ((success_count++))
        else
            log_warning "✗ UPnP: Failed to forward $protocol port $port ($service)"
            ((failed_count++))
        fi
        
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

# Display network information
display_network_info() {
    echo
    echo "=== NETWORK INFORMATION ==="
    echo -e "${CYAN}Local IP Address:${NC} $SERVER_IP"
    echo -e "${CYAN}Public IP Address:${NC} $PUBLIC_IP"
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

# Display listening ports
display_listening_ports() {
    echo "=== LISTENING PORTS ==="
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn | head -1
        ss -tulpn | grep -E ":$SSH_PORT|:$HTTP_PORT|:$HTTPS_PORT|:$OPENVPN_PORT|:$OPENVPN_UDP_PORT" || true
    else
        netstat -tulpn | head -2
        netstat -tulpn 2>/dev/null | grep -E ":$SSH_PORT|:$HTTP_PORT|:$HTTPS_PORT|:$OPENVPN_PORT|:$OPENVPN_UDP_PORT" || true
    fi
    echo
}

# Display firewall status
display_firewall_status() {
    echo "=== FIREWALL STATUS ==="
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose | head -10
    else
        echo "UFW not installed or configured"
    fi
    echo
}

# Interactive port configuration
configure_ports() {
    log_info "Configuring network ports..."
    
    echo
    echo "=== PORT CONFIGURATION ==="
    echo "Please configure the following ports (press Enter for defaults):"
    echo
    
    # SSH Port
    read -p "Enter SSH port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # HTTP Port
    read -p "Enter HTTP port [80]: " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-80}
    
    # HTTPS Port
    read -p "Enter HTTPS port [443]: " HTTPS_PORT
    HTTPS_PORT=${HTTPS_PORT:-443}
    
    # OpenVPN Admin Port
    read -p "Enter OpenVPN AS Admin port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    
    # OpenVPN UDP Port
    read -p "Enter OpenVPN UDP port [1194]: " OPENVPN_UDP_PORT
    OPENVPN_UDP_PORT=${OPENVPN_UDP_PORT:-1194}
    
    # Display port summary
    echo
    log_info "Port Configuration Summary:"
    echo "  SSH: $SSH_PORT/tcp"
    echo "  HTTP: $HTTP_PORT/tcp"
    echo "  HTTPS: $HTTPS_PORT/tcp"
    echo "  OpenVPN Admin: $OPENVPN_PORT/tcp"
    echo "  OpenVPN UDP: $OPENVPN_UDP_PORT/udp"
    echo
    
    read -p "Continue with these port settings? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [ -n "$REPLY" ]; then
        log_info "Port configuration cancelled by user."
        exit 0
    fi
}

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
    echo "1. Access your router admin panel:"
    echo "   - Usually http://192.168.1.1 or http://192.168.0.1"
    echo "   - Check router manual for exact address"
    echo "2. Find 'Port Forwarding' or 'Virtual Servers' section"
    echo "3. Add each port with protocol (TCP/UDP) pointing to $SERVER_IP"
    echo "4. Save settings and restart router if needed"
    echo "5. Test external access: https://$PUBLIC_IP:$HTTPS_PORT/admin"
    echo
    echo "Router-specific locations:"
    echo "• TP-Link: Advanced → NAT Forwarding → Virtual Servers"
    echo "• Netgear: Advanced → Advanced Setup → Port Forwarding"
    echo "• Asus: WAN → Virtual Server/Port Forwarding"
    echo "• Linksys: Security → Apps and Gaming → Single Port Forwarding"
    echo "• D-Link: Advanced → Port Forwarding"
    echo
}

# Validate domain name
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || 
       [[ "$domain" =~ \.\. ]] || 
       [[ "$domain" =~ ^- ]] || 
       [[ "$domain" =~ -$ ]] ||
       [[ ${#domain} -gt 253 ]]; then
        return 1
    fi
    return 0
}

# Generate suggested local domains
generate_domain_suggestions() {
    local suggestions=()
    
    suggestions+=("vpn.$SERVER_HOSTNAME.local")
    suggestions+=("$SERVER_HOSTNAME.local")
    suggestions+=("openvpn.$SERVER_HOSTNAME.local")
    suggestions+=("vpn.local")
    suggestions+=("openvpn.local")
    suggestions+=("$SERVER_HOSTNAME.lan")
    suggestions+=("vpn.$SERVER_HOSTNAME.lan")
    
    echo "${suggestions[@]}"
}

# User input function with validation
get_user_input() {
    log_info "Please provide the following configuration details:"
    echo
    
    # Generate domain suggestions
    DOMAIN_SUGGESTIONS=($(generate_domain_suggestions))
    
    echo "=== LOCAL DOMAIN SUGGESTIONS ==="
    for i in "${!DOMAIN_SUGGESTIONS[@]}"; do
        echo "$((i+1)). ${DOMAIN_SUGGESTIONS[$i]}"
    done
    echo
    
    while true; do
        read -p "Choose a domain (1-${#DOMAIN_SUGGESTIONS[@]}) or enter custom domain: " domain_choice
        
        if [[ "$domain_choice" =~ ^[0-9]+$ ]] && [ "$domain_choice" -ge 1 ] && [ "$domain_choice" -le "${#DOMAIN_SUGGESTIONS[@]}" ]; then
            DOMAIN_NAME="${DOMAIN_SUGGESTIONS[$((domain_choice-1))]}"
            break
        elif [ -n "$domain_choice" ]; then
            if validate_domain "$domain_choice"; then
                DOMAIN_NAME="$domain_choice"
                break
            else
                log_warning "Invalid domain name. Please enter a valid domain (e.g., vpn.example.com)."
            fi
        else
            DOMAIN_NAME="${DOMAIN_SUGGESTIONS[0]}"
            log_info "Using default domain: $DOMAIN_NAME"
            break
        fi
    done
    
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
    log_info "Configuring /etc/hosts file for local domain resolution..."
    
    # Backup original hosts file
    cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)
    
    # Remove existing entries for our domain
    sed -i "/$DOMAIN_NAME/d" /etc/hosts
    
    # Add new entry
    echo "$SERVER_IP    $DOMAIN_NAME" >> /etc/hosts
    
    log_success "Added $DOMAIN_NAME to /etc/hosts pointing to $SERVER_IP"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    # Update package list
    if ! apt-get update; then
        log_error "Failed to update package lists"
    fi
    
    # Install essential packages
    log_info "Installing essential packages..."
    local essential_deps=(
        wget
        curl
        gnupg
        lsb-release
        software-properties-common
        apt-transport-https
        ca-certificates
        sqlite3
        python3
        python3-pip
        python3-venv
        net-tools
        iproute2
        pkg-config
        build-essential
        nginx
        ufw
        openssl
        miniupnpc
        jq
        netcat
        dnsutils
    )
    
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${essential_deps[@]}"; then
        log_error "Failed to install essential dependencies"
    fi
    
    log_success "All dependencies installed successfully"
}

# Install OpenVPN AS using official method
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server using official method..."
    
    # Use the official installation script
    log_info "Downloading and running official OpenVPN AS installation script..."
    
    # Download the installer first for better error handling
    local installer_url="https://packages.openvpn.net/as/install.sh"
    local installer_path="/tmp/openvpn-as-install.sh"
    
    if wget -q "$installer_url" -O "$installer_path"; then
        chmod +x "$installer_path"
        
        # Run installer with timeout
        if timeout 300 bash "$installer_path" --yes; then
            log_success "OpenVPN AS installed successfully using official method"
            rm -f "$installer_path"
        else
            log_error "Official installation method failed or timed out"
        fi
    else
        log_error "Failed to download OpenVPN AS installer"
    fi
}

# Verify OpenVPN AS installation
verify_openvpn_installation() {
    log_info "Verifying OpenVPN AS installation..."
    
    local issues_found=0
    
    # Check if OpenVPN AS is installed
    if [ ! -f "/usr/local/openvpn_as/scripts/sacli" ]; then
        log_error "OpenVPN AS installation incomplete - sacli not found"
    fi
    
    # Check if pyovpn.zip exists and is valid
    local pyovpn_zip="/usr/local/openvpn_as/lib/python/pyovpn.zip"
    if [ ! -f "$pyovpn_zip" ]; then
        log_warning "pyovpn.zip is missing - this may cause issues"
        issues_found=1
    else
        if ! unzip -t "$pyovpn_zip" >/dev/null 2>&1; then
            log_warning "pyovpn.zip is corrupted"
            issues_found=1
        else
            log_success "pyovpn.zip is present and valid"
        fi
    fi
    
    # Check if services are installed
    if ! systemctl is-enabled openvpnas >/dev/null 2>&1; then
        log_warning "OpenVPN AS service not enabled"
        issues_found=1
    fi
    
    if [ $issues_found -eq 0 ]; then
        log_success "OpenVPN AS installation verified successfully"
    else
        log_warning "Some issues were found during verification"
    fi
}

# Wait for OpenVPN AS to be fully ready
wait_for_openvpn_ready() {
    log_info "Waiting for OpenVPN AS services to be fully ready..."
    
    local max_attempts=60
    local attempt=1
    
    # Ensure services are started
    systemctl enable openvpnas 2>/dev/null || true
    systemctl start openvpnas 2>/dev/null || true
    
    while [ $attempt -le $max_attempts ]; do
        # Check if services are running
        if systemctl is-active --quiet openvpnas 2>/dev/null; then
            # Additional check - try to connect to the admin interface
            if curl -k -s -f https://localhost:$OPENVPN_PORT/admin >/dev/null 2>&1; then
                log_success "OpenVPN AS is fully ready (attempt $attempt/$max_attempts)"
                return 0
            fi
        fi
        
        # Progress indicators
        if [ $((attempt % 10)) -eq 0 ]; then
            log_info "Still waiting for services... (attempt $attempt/$max_attempts)"
            
            # Restart services if stuck for too long
            if [ $attempt -eq 30 ]; then
                log_info "Restarting services to help initialization..."
                systemctl restart openvpnas 2>/dev/null || true
            fi
        fi
        
        sleep 3
        attempt=$((attempt + 1))
    done
    
    log_warning "OpenVPN AS services are taking longer than expected to start"
    log_info "Checking service status for debugging..."
    systemctl status openvpnas --no-pager -l 2>/dev/null || true
    
    # Try to start manually
    log_info "Attempting manual start..."
    /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
    log_info "Continuing with configuration..."
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Stop services for configuration
    systemctl stop openvpnas 2>/dev/null || true
    sleep 5
    
    # Configure admin password with multiple retry attempts
    local password_set=0
    for i in {1..10}; do
        log_info "Setting admin password (attempt $i/10)..."
        
        if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
            log_success "Admin password configured successfully"
            password_set=1
            break
        else
            log_warning "Failed to set admin password, retrying in 5 seconds..."
            sleep 5
        fi
    done
    
    if [ $password_set -eq 0 ]; then
        log_warning "Failed to set admin password after multiple attempts"
        log_info "You may need to set it manually later"
    fi
    
    # Configure other settings
    log_info "Configuring OpenVPN AS settings..."
    
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser" --value "$ADMIN_USER" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set superuser property"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set host name"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set HTTPS port"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set HTTPS IP"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set port sharing service"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$HTTPS_PORT" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set port sharing port"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "vpn.daemon.0.client.network" --value "172.27.224.0" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set client network"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "vpn.daemon.0.server.ip_address" --value "172.27.224.1" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set server IP"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.udp.port" --value "$OPENVPN_UDP_PORT" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to set UDP port"
    }
    
    /usr/local/openvpn_as/scripts/sacli --key "cs.daemon.enable" --value "true" ConfigPut >/dev/null 2>&1 || {
        log_warning "Failed to enable daemon mode"
    }
    
    # Start services
    log_info "Starting OpenVPN AS services..."
    systemctl start openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
    log_success "OpenVPN AS configuration applied"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates for $DOMAIN_NAME..."
    
    # Create directory if it doesn't exist
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    # Generate certificate with the domain name
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME" 2>/dev/null
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    
    log_warning "Using self-signed certificates for $DOMAIN_NAME"
}

# Configure Nginx with virtual host
configure_nginx() {
    log_info "Configuring Nginx virtual host for $DOMAIN_NAME..."
    
    # Stop Nginx first
    systemctl stop nginx 2>/dev/null || true
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
# OpenVPN AS configuration for Ubuntu 24.04
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
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
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
        
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
EOF
    
    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Test configuration
    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        log_success "Nginx virtual host configured"
    else
        log_error "Nginx configuration test failed"
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Enable and configure UFW
    ufw --force enable || true
    ufw --force reset || true
    
    # Allow necessary ports
    ufw allow "$SSH_PORT/tcp"
    ufw allow "$HTTP_PORT/tcp"
    ufw allow "$HTTPS_PORT/tcp"
    ufw allow "$OPENVPN_UDP_PORT/udp"
    ufw allow "$OPENVPN_PORT/tcp"
    
    # Enable UFW (non-interactive)
    echo "y" | ufw enable
    
    log_success "Firewall configured successfully"
}

# Final verification and summary
verify_installation() {
    log_info "Verifying installation..."
    
    echo
    echo "=== SERVICE STATUS ==="
    systemctl status openvpnas --no-pager -l 2>/dev/null || {
        log_warning "OpenVPN AS service not running"
        echo "Attempting to start service..."
        systemctl start openvpnas 2>/dev/null || true
    }
    
    echo
    echo "=== NETWORK DIAGNOSTICS ==="
    display_network_info
    display_listening_ports
    display_firewall_status
    
    echo
    echo "=== ACCESS INFORMATION ==="
    log_success "Local Admin Interface: https://$DOMAIN_NAME:$HTTPS_PORT/admin"
    log_success "Local Client Interface: https://$DOMAIN_NAME:$HTTPS_PORT/"
    log_success "Direct Access: https://$SERVER_IP:$HTTPS_PORT/admin"
    
    if [ "$PUBLIC_IP" != "Unable to detect" ]; then
        if [ "$UPNP_AVAILABLE" = "true" ]; then
            log_success "External Admin Interface (via UPnP): https://$PUBLIC_IP:$HTTPS_PORT/admin"
            log_success "External Client Interface (via UPnP): https://$PUBLIC_IP:$HTTPS_PORT/"
        else
            log_success "External Admin Interface (after port forwarding): https://$PUBLIC_IP:$HTTPS_PORT/admin"
            log_success "External Client Interface (after port forwarding): https://$PUBLIC_IP:$HTTPS_PORT/"
        fi
    fi
    
    echo
    echo "=== CREDENTIALS ==="
    echo "Username: $ADMIN_USER"
    echo "Password: [The password you set during installation]"
    echo
    echo "=== VERIFICATION TESTS ==="
    
    # Test if services are running
    if systemctl is-active --quiet openvpnas 2>/dev/null; then
        log_success "✓ OpenVPN AS service is running"
    else
        log_warning "⚠ OpenVPN AS service is not running"
    fi
    
    # Test if Nginx is running
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_success "✓ Nginx service is running"
    else
        log_warning "⚠ Nginx service is not running"
    fi
    
    # Test pyovpn import
    if python3 -c "import sys; sys.path.insert(0, '/usr/local/openvpn_as/lib/python'); import pyovpn" 2>/dev/null; then
        log_success "✓ pyovpn module imports successfully"
    else
        log_warning "⚠ pyovpn module import failed"
    fi
    
    # Test port accessibility
    if nc -z localhost "$HTTPS_PORT" 2>/dev/null; then
        log_success "✓ HTTPS port $HTTPS_PORT is accessible locally"
    else
        log_warning "⚠ HTTPS port $HTTPS_PORT is not accessible locally"
    fi
    
    echo
    echo "=== TROUBLESHOOTING ==="
    echo "If you cannot access the web interface:"
    echo "1. Wait 2-3 minutes for services to fully initialize"
    echo "2. Check service status: systemctl status openvpnas"
    echo "3. View logs: journalctl -u openvpnas -f"
    echo "4. Restart services: systemctl restart openvpnas"
    echo "5. Manual password reset: /usr/local/openvpn_as/scripts/sacli --user $ADMIN_USER --new_pass 'yourpassword' SetLocalPassword"
    echo
    
    if [ "$UPNP_AVAILABLE" = "false" ]; then
        generate_port_forwarding_instructions
    fi
}

# Main installation function
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS Installer for Ubuntu 24.04"
    echo "      Enhanced with UPnP Automatic Port Forwarding"
    echo "=================================================="
    echo
    
    # Trap to handle script interruption
    trap 'log_error "Script interrupted by user"; exit 1' INT TERM
    
    check_root
    detect_os
    get_public_ip
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
    
    # Configure UPnP port forwarding if available
    if [ "$UPNP_AVAILABLE" = "true" ]; then
        configure_upnp_ports
    else
        log_warning "UPnP not available - manual port forwarding required for external access"
        generate_port_forwarding_instructions
    fi
    
    verify_installation
    
    log_success "OpenVPN Access Server installation completed successfully!"
    echo
    log_info "Important Notes:"
    log_info "1. It may take 2-3 minutes for all services to be fully operational"
    log_info "2. Access your VPN administration at: https://$DOMAIN_NAME:$HTTPS_PORT/admin"
    log_info "3. UPnP Status: $([ "$UPNP_AVAILABLE" = "true" ] && echo "Enabled - Ports forwarded automatically" || echo "Disabled - Manual port forwarding required")"
    log_info "4. If password setup failed, run manually:"
    log_info "   /usr/local/openvpn_as/scripts/sacli --user $ADMIN_USER --new_pass 'YOUR_PASSWORD' SetLocalPassword"
    echo
}

# Run main function
main "$@"
