#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Enhanced version with UPnP, virtual network, and comprehensive error handling

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
MAX_RETRIES=3
RETRY_DELAY=5

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
    local retries=${3:-$MAX_RETRIES}
    
    for ((i=1; i<=retries; i++)); do
        log_info "$description (attempt $i/$retries)"
        if eval "$cmd"; then
            log_success "$description completed"
            return 0
        else
            log_warning "$description failed on attempt $i"
            if [ $i -lt $retries ]; then
                sleep $RETRY_DELAY
            fi
        fi
    done
    
    log_error "$description failed after $retries attempts"
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
    OS=$ID
    OS_VERSION=$VERSION_ID
    
    if [ "$OS" != "ubuntu" ]; then
        log_error "This script is designed for Ubuntu systems only. Detected: $OS"
    fi
    
    # Get network information
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' | head -1)
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    SERVER_IP=${SERVER_IP:-"127.0.0.1"}
    
    SERVER_HOSTNAME=$(hostname -s)
    
    log_info "Detected: $NAME $VERSION ($VERSION_CODENAME)"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
}

# Get public IP address
get_public_ip() {
    log_info "Detecting public IP address..."
    
    local services=(
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://icanhazip.com"
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

# Check UPnP availability
check_upnp() {
    log_info "Checking UPnP availability..."
    
    safe_exec "apt-get install -y miniupnpc" "Install UPnP client" 2
    
    if timeout 10 upnpc -s >/dev/null 2>&1; then
        UPNP_AVAILABLE=true
        log_success "UPnP is available on your router"
        return 0
    else
        UPNP_AVAILABLE=false
        log_warning "UPnP is not available on your router"
        return 1
    fi
}

# Enhanced UPnP port configuration
configure_upnp_ports() {
    if [ "$UPNP_AVAILABLE" != "true" ]; then
        return 1
    fi
    
    log_info "Configuring UPnP port forwarding..."
    
    # Clear existing mappings first
    upnpc -d $OPENVPN_UDP_PORT UDP >/dev/null 2>&1 || true
    upnpc -d $OPENVPN_PORT TCP >/dev/null 2>&1 || true
    upnpc -d $HTTPS_PORT TCP >/dev/null 2>&1 || true
    sleep 2
    
    local success_count=0
    local ports_to_forward=(
        "$OPENVPN_UDP_PORT UDP OpenVPN-Client"
        "$OPENVPN_PORT TCP OpenVPN-Admin" 
        "$HTTPS_PORT TCP OpenVPN-Web"
    )
    
    for port_config in "${ports_to_forward[@]}"; do
        local port=$(echo "$port_config" | awk '{print $1}')
        local protocol=$(echo "$port_config" | awk '{print $2}')
        local description=$(echo "$port_config" | awk '{print $3}')
        
        if upnpc -a "$SERVER_IP" "$port" "$port" "$protocol" "$description" >/dev/null 2>&1; then
            log_success "UPnP: Forwarded $protocol port $port ($description)"
            ((success_count++))
        else
            log_warning "UPnP: Failed to forward $protocol port $port"
        fi
    done
    
    if [ $success_count -gt 0 ]; then
        log_success "UPnP port forwarding configured for $success_count ports"
        return 0
    else
        log_warning "No UPnP port forwarding configured"
        return 1
    fi
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
    
    # Port configuration
    echo
    echo "Port Configuration:"
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
    
    echo
    read -p "Continue with these settings? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled."
        exit 0
    fi
}

# Configure hosts file
configure_hosts_file() {
    log_info "Configuring /etc/hosts file..."
    
    # Backup hosts file
    cp /etc/hosts /etc/hosts.bak.$(date +%Y%m%d_%H%M%S)
    
    # Remove existing entry and add new one
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
        netcat dnsutils
    )
    
    safe_exec "DEBIAN_FRONTEND=noninteractive apt-get install -y ${dependencies[*]}" "Install dependencies"
}

# Install OpenVPN AS
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    local installer_url="https://packages.openvpn.net/as/install.sh"
    local installer_path="/tmp/openvpn-as-install.sh"
    
    safe_exec "wget -q $installer_url -O $installer_path" "Download OpenVPN AS installer"
    safe_exec "chmod +x $installer_path" "Make installer executable"
    
    # Run installer with timeout
    if timeout 300 $installer_path --yes; then
        log_success "OpenVPN AS installed successfully"
        rm -f $installer_path
    else
        log_error "OpenVPN AS installation failed or timed out"
    fi
}

# Configure virtual network for client access
configure_virtual_network() {
    log_info "Configuring virtual network for client access..."
    
    # Stop service for configuration
    systemctl stop openvpnas 2>/dev/null || true
    sleep 3
    
    # Configure virtual network settings
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
        if /usr/local/openvpn_as/scripts/sacli --key "$key" --value "$value" ConfigPut >/dev/null 2>&1; then
            log_info "Configured: $key = $value"
        else
            log_warning "Failed to configure: $key"
        fi
    done
    
    # Set admin password
    safe_exec "/usr/local/openvpn_as/scripts/sacli --user '$ADMIN_USER' --new_pass '$ADMIN_PASSWORD' SetLocalPassword" "Set admin password"
    
    # Start service
    systemctl start openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
    log_success "Virtual network configuration completed"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    mkdir -p /etc/ssl/private /etc/ssl/certs
    
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME" 2>/dev/null
    
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    
    log_success "SSL certificates generated for $DOMAIN_NAME"
}

# Configure Nginx reverse proxy
configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
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
    
    # Test and start Nginx
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
    
    # Reset and configure UFW
    ufw --force reset || true
    echo "y" | ufw enable || true
    
    ufw allow "$SSH_PORT/tcp" comment "SSH"
    ufw allow "$HTTP_PORT/tcp" comment "HTTP"
    ufw allow "$HTTPS_PORT/tcp" comment "HTTPS"
    ufw allow "$OPENVPN_UDP_PORT/udp" comment "OpenVPN-UDP"
    ufw allow "$OPENVPN_PORT/tcp" comment "OpenVPN-Admin"
    
    echo "y" | ufw enable
    
    log_success "Firewall configured"
}

# Wait for services to be ready
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

# Display installation summary
display_summary() {
    echo
    echo "=================================================="
    echo "           OPENVPN AS INSTALLATION COMPLETE"
    echo "=================================================="
    echo
    echo "=== ACCESS INFORMATION ==="
    echo "Admin Interface:  https://$DOMAIN_NAME:$HTTPS_PORT/admin"
    echo "Client Interface: https://$DOMAIN_NAME:$HTTPS_PORT/"
    echo "Direct Access:    https://$SERVER_IP:$HTTPS_PORT/admin"
    if [ "$PUBLIC_IP" != "Unable to detect" ]; then
        echo "Public Access:    https://$PUBLIC_IP:$HTTPS_PORT/admin"
    fi
    echo
    echo "=== CREDENTIALS ==="
    echo "Username: $ADMIN_USER"
    echo "Password: ********"
    echo
    echo "=== NETWORK CONFIGURATION ==="
    echo "Virtual Network: 172.27.224.0/22"
    echo "Client IP Range: 172.27.224.2 - 172.27.227.254"
    echo "Server VPN IP:   172.27.224.1"
    echo
    echo "=== PORTS CONFIGURED ==="
    echo "OpenVPN UDP:     $OPENVPN_UDP_PORT/udp"
    echo "OpenVPN Admin:   $OPENVPN_PORT/tcp"
    echo "Web Interface:   $HTTPS_PORT/tcp"
    echo "UPnP Status:     $UPNP_AVAILABLE"
    echo
    echo "=== VERIFICATION ==="
    
    # Service status check
    if systemctl is-active --quiet openvpnas; then
        echo -e "${GREEN}✓ OpenVPN AS service: RUNNING${NC}"
    else
        echo -e "${RED}✗ OpenVPN AS service: STOPPED${NC}"
    fi
    
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✓ Nginx service: RUNNING${NC}"
    else
        echo -e "${RED}✗ Nginx service: STOPPED${NC}"
    fi
    
    # Port accessibility check
    if ss -tulpn | grep -q ":$HTTPS_PORT "; then
        echo -e "${GREEN}✓ HTTPS port $HTTPS_PORT: LISTENING${NC}"
    else
        echo -e "${RED}✗ HTTPS port $HTTPS_PORT: NOT LISTENING${NC}"
    fi
    
    echo
    echo "=== NEXT STEPS ==="
    echo "1. Access the admin interface to configure your VPN"
    echo "2. Create user profiles and download client configurations"
    echo "3. Configure client devices to connect to your VPN"
    echo "4. Monitor logs: journalctl -u openvpnas -f"
    echo
    echo "=== TROUBLESHOOTING ==="
    echo "If you cannot access the web interface:"
    echo "• Wait 2-3 minutes for full initialization"
    echo "• Check service: systemctl status openvpnas"
    echo "• View logs: journalctl -u openvpnas -n 50"
    echo "• Restart services: systemctl restart openvpnas nginx"
    echo
}

# Main installation function
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS Installer for Ubuntu 24.04"
    echo "    Enhanced with UPnP & Virtual Networking"
    echo "=================================================="
    echo
    
    # Set error trap
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
    configure_upnp_ports
    wait_for_services
    display_summary
    
    log_success "OpenVPN Access Server installation completed successfully!"
    echo
}

# Run main function
main "$@"
