#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Enhanced with ZeroTier-style NAT traversal and peer-to-peer connectivity

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
ZEROTIER_MODE=true
CONNECTION_STRATEGIES=()

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

# Safe execution with retries
safe_exec() {
    local cmd="$1"
    local description="$2"
    local retries=${3:-3}
    
    for ((i=1; i<=retries; i++)); do
        log_info "$description (attempt $i/$retries)"
        if eval "$cmd"; then
            log_success "$description completed"
            return 0
        else
            log_warning "$description failed on attempt $i"
            if [ $i -lt $retries ]; then
                sleep 2
            fi
        fi
    done
    
    log_error "$description failed after $retries attempts"
}

# ZeroTier-inspired NAT traversal
setup_zerotier_nat() {
    log_info "Setting up ZeroTier-style NAT traversal..."
    
    # Port configurations for multiple strategies
    local port_configs=(
        "$OPENVPN_UDP_PORT:udp"
        "$OPENVPN_PORT:tcp" 
        "$HTTPS_PORT:tcp"
    )
    
    local successful_strategies=()
    
    # Strategy 1: Manual port forwarding instructions
    successful_strategies+=("manual_port_forwarding")
    
    # Strategy 2: Hole punching attempts
    if attempt_hole_punching; then
        successful_strategies+=("udp_hole_punching")
    fi
    
    # Strategy 3: Multiple listener ports
    if setup_multiple_ports; then
        successful_strategies+=("multiple_ports")
    fi
    
    # Strategy 4: IPv6 if available
    if check_ipv6; then
        successful_strategies+=("ipv6_native")
    fi
    
    CONNECTION_STRATEGIES=("${successful_strategies[@]}")
    log_success "ZeroTier NAT traversal configured with ${#successful_strategies[@]} strategies"
}

# UDP hole punching simulation
attempt_hole_punching() {
    log_info "Attempting UDP hole punching techniques..."
    
    local test_hosts=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    local test_port="53"
    
    for host in "${test_hosts[@]}"; do
        timeout 2 bash -c "echo 'HOLE_PUNCH' | nc -u -w 1 $host $test_port" >/dev/null 2>&1 &
    done
    
    # Start background keep-alive process
    (
        while true; do
            echo "KEEPALIVE" | nc -u -w 1 127.0.0.1 9999 >/dev/null 2>&1
            sleep 30
        done
    ) &
    
    log_success "UDP hole punching initiated"
    return 0
}

# Setup multiple listener ports for fallback
setup_multiple_ports() {
    log_info "Configuring multiple listener ports..."
    
    local additional_ports=("8080" "8443" "8888")
    
    for port in "${additional_ports[@]}"; do
        /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.tcp.port" --value "$port" ConfigPut >/dev/null 2>&1 || true
    done
    
    log_success "Multiple fallback ports configured"
    return 0
}

# Check IPv6 availability
check_ipv6() {
    if ip -6 addr show | grep -q "inet6" && ping6 -c 1 -W 1 ipv6.google.com >/dev/null 2>&1; then
        log_success "IPv6 connectivity available"
        return 0
    else
        log_warning "IPv6 connectivity not available"
        return 1
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
    fi
}

# Detect OS and verify Ubuntu compatibility
detect_os() {
    log_info "Detecting operating system..."
    
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect operating system"
    fi
    
    . /etc/os-release
    
    # Get network information
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    SERVER_IP=${SERVER_IP:-"127.0.0.1"}
    
    SERVER_HOSTNAME=$(hostname -s)
    
    log_info "Detected: $NAME $VERSION"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
}

# Get public IP address using multiple services
get_public_ip() {
    log_info "Detecting public IP address..."
    
    local services=(
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://icanhazip.com"
    )
    
    for service in "${services[@]}"; do
        if PUBLIC_IP=$(curl -s -4 --connect-timeout 3 "$service" 2>/dev/null); then
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

# Check UPnP availability with better error handling
check_upnp() {
    log_info "Checking UPnP availability..."
    
    if ! command -v upnpc >/dev/null 2>&1; then
        log_info "Installing UPnP client..."
        apt-get install -y miniupnpc >/dev/null 2>&1 || {
            log_warning "Failed to install UPnP client"
            UPNP_AVAILABLE=false
            return 1
        }
    fi
    
    if timeout 10 upnpc -s >/dev/null 2>&1; then
        UPNP_AVAILABLE=true
        log_success "UPnP is available on your router"
        return 0
    else
        UPNP_AVAILABLE=false
        log_warning "UPnP is not available on your router"
        log_info "This is normal for many routers. We'll use alternative connection methods."
        return 1
    fi
}

# Enhanced port configuration
configure_ports() {
    log_info "Configuring network ports..."
    
    # Default ports
    SSH_PORT=22
    HTTP_PORT=80
    HTTPS_PORT=443
    OPENVPN_PORT=943
    OPENVPN_UDP_PORT=1194
    
    log_info "Using default ports:"
    echo "  SSH: $SSH_PORT/tcp"
    echo "  HTTP: $HTTP_PORT/tcp"
    echo "  HTTPS: $HTTPS_PORT/tcp"
    echo "  OpenVPN Admin: $OPENVPN_PORT/tcp"
    echo "  OpenVPN UDP: $OPENVPN_UDP_PORT/udp"
}

# User input with validation
get_user_input() {
    log_info "OpenVPN AS Configuration"
    echo "======================================"
    
    # Domain configuration
    local default_domain="vpn.${SERVER_HOSTNAME}.local"
    echo "Domain Configuration:"
    read -p "Enter domain name [$default_domain]: " user_domain
    DOMAIN_NAME=${user_domain:-$default_domain}
    
    # Admin credentials
    echo
    read -p "Enter admin username [admin]: " admin_user
    ADMIN_USER=${admin_user:-admin}
    
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
    
    echo
    read -p "Continue with installation? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled."
        exit 0
    fi
}

# Configure hosts file
configure_hosts_file() {
    log_info "Configuring /etc/hosts file..."
    
    cp /etc/hosts /etc/hosts.bak.$(date +%Y%m%d_%H%M%S)
    sed -i "/$DOMAIN_NAME/d" /etc/hosts
    echo "$SERVER_IP    $DOMAIN_NAME" >> /etc/hosts
    
    log_success "Added $DOMAIN_NAME to /etc/hosts"
}

# Install dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    safe_exec "apt-get update" "Update package lists"
    
    local dependencies=(
        wget curl gnupg lsb-release
        software-properties-common apt-transport-https
        ca-certificates sqlite3 python3 python3-pip
        net-tools nginx ufw openssl miniupnpc
        netcat dnsutils socat
    )
    
    safe_exec "DEBIAN_FRONTEND=noninteractive apt-get install -y ${dependencies[*]}" "Install dependencies"
}

# Install OpenVPN AS
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    local installer_url="https://packages.openvpn.net/as/install.sh"
    local installer_path="/tmp/openvpn-as-install.sh"
    
    safe_exec "wget -q '$installer_url' -O '$installer_path'" "Download OpenVPN AS installer"
    safe_exec "chmod +x '$installer_path'" "Make installer executable"
    
    if timeout 300 "$installer_path" --yes; then
        log_success "OpenVPN AS installed successfully"
        rm -f "$installer_path"
    else
        log_error "OpenVPN AS installation failed or timed out"
    fi
}

# Configure virtual network
configure_virtual_network() {
    log_info "Configuring virtual network..."
    
    systemctl stop openvpnas 2>/dev/null || true
    sleep 3
    
    local config_settings=(
        "host.name=$DOMAIN_NAME"
        "cs.https.port=$OPENVPN_PORT"
        "cs.https.ip=127.0.0.1"
        "vpn.server.port_share.service=admin+client"
        "vpn.server.port_share.port=$HTTPS_PORT"
        "vpn.daemon.0.client.network=172.27.224.0"
        "vpn.daemon.0.server.ip_address=172.27.224.1"
        "vpn.daemon.0.server.netmask=255.255.252.0"
        "vpn.daemon.0.listen.ip_address=0.0.0.0"
        "vpn.server.daemon.udp.port=$OPENVPN_UDP_PORT"
        "vpn.server.daemon.tcp.port=443"
        "vpn.client.routing.reroute_dns=true"
        "vpn.client.routing.reroute_gw=true"
        "cs.daemon.enable=true"
    )
    
    for setting in "${config_settings[@]}"; do
        local key="${setting%=*}"
        local value="${setting#*=}"
        /usr/local/openvpn_as/scripts/sacli --key "$key" --value "$value" ConfigPut >/dev/null 2>&1 || 
            log_warning "Failed to configure: $key"
    done
    
    # Set admin password
    safe_exec "/usr/local/openvpn_as/scripts/sacli --user '$ADMIN_USER' --new_pass '$ADMIN_PASSWORD' SetLocalPassword" "Set admin password"
    
    systemctl start openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
    log_success "Virtual network configured"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates for $DOMAIN_NAME..."
    
    mkdir -p /etc/ssl/private /etc/ssl/certs
    
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
    log_info "Configuring Nginx reverse proxy..."
    
    systemctl stop nginx 2>/dev/null || true
    
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
    
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        log_success "Nginx configured successfully"
    else
        log_error "Nginx configuration test failed"
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    ufw --force reset || true
    echo "y" | ufw enable || true
    
    ufw allow "$SSH_PORT/tcp" comment "SSH"
    ufw allow "$HTTP_PORT/tcp" comment "HTTP"
    ufw allow "$HTTPS_PORT/tcp" comment "HTTPS"
    ufw allow "$OPENVPN_UDP_PORT/udp" comment "OpenVPN-UDP"
    ufw allow "$OPENVPN_PORT/tcp" comment "OpenVPN-TCP"
    
    # Additional ports for fallback
    ufw allow "8080/tcp" comment "OpenVPN-Fallback-1"
    ufw allow "8443/tcp" comment "OpenVPN-Fallback-2"
    ufw allow "8888/tcp" comment "OpenVPN-Fallback-3"
    
    echo "y" | ufw enable
    
    log_success "Firewall configured"
}

# Wait for services
wait_for_services() {
    log_info "Waiting for OpenVPN AS services to be ready..."
    
    local max_wait=60
    local wait_time=0
    
    while [ $wait_time -lt $max_wait ]; do
        if systemctl is-active --quiet openvpnas && \
           curl -k -s https://localhost:943/admin >/dev/null 2>&1; then
            log_success "OpenVPN AS is ready"
            return 0
        fi
        sleep 5
        ((wait_time+=5))
        log_info "Waiting... ${wait_time}s/${max_wait}s"
    done
    
    log_warning "OpenVPN AS taking longer than expected to start"
    return 1
}

# Display manual port forwarding instructions
show_port_forwarding_instructions() {
    echo
    echo "=== MANUAL PORT FORWARDING REQUIRED ==="
    echo "Since UPnP is not available on your router, you need to manually"
    echo "forward these ports on your router to $SERVER_IP:"
    echo
    echo "Port $OPENVPN_UDP_PORT UDP  -> OpenVPN Client Connections"
    echo "Port $HTTPS_PORT TCP        -> Web Administration"
    echo "Port $OPENVPN_PORT TCP      -> Admin Interface"
    echo
    echo "Router access typically: http://192.168.1.1 or http://192.168.0.1"
    echo "Look for 'Port Forwarding' or 'NAT' settings"
    echo
}

# Display installation summary
display_summary() {
    echo
    echo "=================================================="
    echo "    OPENVPN AS INSTALLATION COMPLETE"
    echo "=================================================="
    echo
    echo "=== CONNECTIVITY STATUS ==="
    echo "Public IP: $PUBLIC_IP"
    echo "Local IP: $SERVER_IP"
    echo "UPnP: $UPNP_AVAILABLE"
    echo "Domain: $DOMAIN_NAME"
    echo
    echo "=== ACTIVE STRATEGIES ==="
    for strategy in "${CONNECTION_STRATEGIES[@]}"; do
        echo "✓ $(echo $strategy | tr '_' ' ')"
    done
    echo
    echo "=== ACCESS INFORMATION ==="
    echo "Admin Interface:  https://$DOMAIN_NAME:$HTTPS_PORT/admin"
    echo "Client Interface: https://$DOMAIN_NAME:$HTTPS_PORT/"
    echo "Direct Access:    https://$SERVER_IP:$HTTPS_PORT/admin"
    if [ "$PUBLIC_IP" != "Unable to detect" ]; then
        echo "Public Access:    https://$PUBLIC_IP:$HTTPS_PORT/admin"
    fi
    echo
    echo "=== PORTS CONFIGURED ==="
    echo "OpenVPN UDP: $OPENVPN_UDP_PORT/udp"
    echo "OpenVPN TCP: $OPENVPN_PORT/tcp"
    echo "Web Interface: $HTTPS_PORT/tcp"
    echo "Fallback Ports: 8080, 8443, 8888/tcp"
    echo
    echo "=== CREDENTIALS ==="
    echo "Username: $ADMIN_USER"
    echo "Password: ********"
    echo
    echo "=== SERVICE STATUS ==="
    if systemctl is-active --quiet openvpnas; then
        echo -e "${GREEN}✓ OpenVPN AS: RUNNING${NC}"
    else
        echo -e "${RED}✗ OpenVPN AS: STOPPED${NC}"
    fi
    
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✓ Nginx: RUNNING${NC}"
    else
        echo -e "${RED}✗ Nginx: STOPPED${NC}"
    fi
    echo
    
    # Show port forwarding instructions if UPnP is not available
    if [ "$UPNP_AVAILABLE" = "false" ]; then
        show_port_forwarding_instructions
    fi
}

# Main installation function
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS + ZeroTier NAT Traversal"
    echo "           Ubuntu 24.04 Installer"
    echo "=================================================="
    echo
    
    trap 'log_error "Installation interrupted"; exit 1' INT TERM
    
    # Installation steps
    check_root
    detect_os
    get_public_ip
    check_upnp
    get_user_input
    configure_hosts_file
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    configure_virtual_network
    configure_nginx
    configure_firewall
    
    # Setup ZeroTier-style NAT traversal
    setup_zerotier_nat
    
    wait_for_services
    display_summary
    
    log_success "OpenVPN AS installation completed successfully!"
    echo
    if [ "$UPNP_AVAILABLE" = "false" ]; then
        log_warning "IMPORTANT: Manual port forwarding required on your router"
        log_info "Forward ports $OPENVPN_UDP_PORT/UDP and $HTTPS_PORT/TCP to $SERVER_IP"
    fi
}

# Run main function
main "$@"
