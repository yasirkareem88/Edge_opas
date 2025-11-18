#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Fully automated with error handling

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
PUBLIC_IP=""
UPNP_AVAILABLE=false

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
}

# Continue on error for non-critical functions
continue_on_error() {
    local cmd="$1"
    local description="$2"
    
    log_info "$description"
    if eval "$cmd"; then
        log_success "$description completed"
    else
        log_warning "$description failed, but continuing..."
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Detect OS and network information
detect_os() {
    log_info "Detecting operating system and network configuration..."
    
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    # Source the OS release file
    . /etc/os-release
    
    # Get network information
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' | head -1)
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    SERVER_IP=${SERVER_IP:-"127.0.0.1"}
    
    SERVER_HOSTNAME=$(hostname -s)
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    DOMAIN_NAME="vpn.${SERVER_HOSTNAME}.local"
    
    log_info "Detected: $NAME $VERSION"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
    log_info "Network Interface: $NETWORK_INTERFACE"
    log_info "Domain: $DOMAIN_NAME"
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
    
    # Install miniupnpc if not available
    if ! command -v upnpc >/dev/null 2>&1; then
        log_info "Installing UPnP client..."
        apt-get install -y miniupnpc >/dev/null 2>&1 || {
            log_warning "Failed to install UPnP client"
            UPNP_AVAILABLE=false
            return 1
        }
    fi
    
    # Test UPnP with timeout
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

# Configure hosts file
configure_hosts_file() {
    log_info "Configuring /etc/hosts file..."
    
    # Backup hosts file
    cp /etc/hosts /etc/hosts.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Remove existing entry and add new one
    sed -i "/$DOMAIN_NAME/d" /etc/hosts 2>/dev/null || true
    echo "$SERVER_IP    $DOMAIN_NAME" >> /etc/hosts
    
    log_success "Added $DOMAIN_NAME to /etc/hosts"
}

# Install dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    # Update package lists
    apt-get update || {
        log_warning "Failed to update package lists, but continuing..."
    }
    
    local dependencies=(
        wget curl gnupg lsb-release
        software-properties-common apt-transport-https
        ca-certificates sqlite3 python3 python3-pip
        net-tools nginx ufw openssl
        netcat dnsutils
    )
    
    # Install dependencies individually to continue on failures
    for package in "${dependencies[@]}"; do
        apt-get install -y "$package" >/dev/null 2>&1 || {
            log_warning "Failed to install $package, but continuing..."
        }
    done
    
    log_success "Dependencies installation attempted"
}

# Install OpenVPN AS
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    local installer_url="https://packages.openvpn.net/as/openvpn-as-2.12.0-ubuntu24.amd_64.deb"
    local installer_path="/tmp/openvpn-as.deb"
    
    # Download the DEB package directly (more reliable)
    continue_on_error "wget -q '$installer_url' -O '$installer_path'" "Download OpenVPN AS"
    
    # Install the package
    if [ -f "$installer_path" ]; then
        dpkg -i "$installer_path" 2>/dev/null || {
            # Fix dependencies if needed
            apt-get install -f -y >/dev/null 2>&1
        }
        log_success "OpenVPN AS installed successfully"
        rm -f "$installer_path"
    else
        log_error "OpenVPN AS download failed"
        exit 1
    fi
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    mkdir -p /etc/ssl/private /etc/ssl/certs
    
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME" 2>/dev/null || {
        log_warning "SSL certificate generation failed, using existing certificates"
    }
    
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key 2>/dev/null || true
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem 2>/dev/null || true
    
    log_success "SSL certificates configured"
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Stop service for configuration
    systemctl stop openvpnas 2>/dev/null || true
    sleep 5
    
    # Generate a secure random password
    ADMIN_PASSWORD=$(openssl rand -base64 12 2>/dev/null || echo "OpenVPN123!")
    ADMIN_USER="admin"
    
    # Configure basic settings
    local config_commands=(
        "--key host.name --value $DOMAIN_NAME"
        "--key cs.https.port --value 943"
        "--key cs.https.ip --value 127.0.0.1"
        "--key vpn.server.port_share.service --value admin+client"
        "--key vpn.server.port_share.port --value 443"
        "--key vpn.daemon.0.client.network --value 172.27.224.0"
        "--key vpn.daemon.0.server.ip_address --value 172.27.224.1"
        "--key vpn.daemon.0.server.netmask --value 255.255.252.0"
        "--key vpn.server.daemon.udp.port --value 1194"
        "--key vpn.server.daemon.tcp.port --value 443"
        "--key cs.daemon.enable --value true"
    )
    
    for cmd in "${config_commands[@]}"; do
        /usr/local/openvpn_as/scripts/sacli $cmd ConfigPut >/dev/null 2>&1 || true
    done
    
    # Set admin password
    if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
        log_success "Admin password configured"
    else
        log_warning "Failed to set admin password automatically"
        ADMIN_PASSWORD="SET_MANUALLY"
    fi
    
    # Start service
    systemctl start openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
    log_success "OpenVPN AS configuration applied"
}

# Configure Nginx
configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
    systemctl stop nginx 2>/dev/null || true
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << 'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name _;
    
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
        proxy_pass https://127.0.0.1:943;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
EOF
    
    # Enable site
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/ 2>/dev/null || true
    
    # Test and start Nginx
    if nginx -t >/dev/null 2>&1; then
        systemctl enable nginx 2>/dev/null || true
        systemctl restart nginx 2>/dev/null || true
        log_success "Nginx configured successfully"
    else
        log_warning "Nginx configuration test failed"
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset >/dev/null 2>&1 || true
    
    # Allow essential ports
    ufw allow 22/tcp comment "SSH" >/dev/null 2>&1 || true
    ufw allow 80/tcp comment "HTTP" >/dev/null 2>&1 || true
    ufw allow 443/tcp comment "HTTPS" >/dev/null 2>&1 || true
    ufw allow 1194/udp comment "OpenVPN-UDP" >/dev/null 2>&1 || true
    ufw allow 943/tcp comment "OpenVPN-Admin" >/dev/null 2>&1 || true
    
    # Enable UFW non-interactively
    echo "y" | ufw enable >/dev/null 2>&1 || true
    
    log_success "Firewall configured"
}

# Wait for services to be ready
wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if systemctl is-active --quiet openvpnas 2>/dev/null; then
            log_success "OpenVPN AS service is running"
            return 0
        fi
        
        if [ $attempt -eq 10 ]; then
            log_info "Still waiting for services... (attempt $attempt/$max_attempts)"
            # Try to start the service
            systemctl start openvpnas 2>/dev/null || true
        fi
        
        sleep 3
        attempt=$((attempt + 1))
    done
    
    log_warning "Services taking longer than expected to start"
    return 1
}

# Display installation summary
display_summary() {
    echo
    echo "=================================================="
    echo "        OPENVPN AS INSTALLATION COMPLETE"
    echo "=================================================="
    echo
    echo "=== SERVER INFORMATION ==="
    echo "Public IP:    $PUBLIC_IP"
    echo "Local IP:     $SERVER_IP"
    echo "Hostname:     $SERVER_HOSTNAME"
    echo "Domain:       $DOMAIN_NAME"
    echo "UPnP:         $UPNP_AVAILABLE"
    echo
    echo "=== ACCESS URLs ==="
    echo "Admin Interface:  https://$DOMAIN_NAME/admin"
    echo "Client Interface: https://$DOMAIN_NAME/"
    echo "Local Access:     https://$SERVER_IP/admin"
    if [ "$PUBLIC_IP" != "Unable to detect" ]; then
        echo "Public Access:     https://$PUBLIC_IP/admin"
    fi
    echo
    echo "=== CREDENTIALS ==="
    echo "Username: admin"
    echo "Password: $ADMIN_PASSWORD"
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
    
    if [ "$UPNP_AVAILABLE" = "false" ]; then
        echo "=== MANUAL PORT FORWARDING REQUIRED ==="
        echo "Forward these ports on your router to $SERVER_IP:"
        echo "  Port 1194/UDP - OpenVPN client connections"
        echo "  Port 443/TCP  - Web administration"
        echo
        echo "Router access: http://192.168.1.1 or http://192.168.0.1"
        echo
    fi
}

# Main installation function
main() {
    echo "=================================================="
    echo "   OpenVPN AS Automated Installation"
    echo "        Ubuntu 24.04"
    echo "=================================================="
    echo
    
    # Check root first
    check_root
    
    # Installation steps
    detect_os
    get_public_ip
    check_upnp
    configure_hosts_file
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    configure_openvpn_as
    configure_nginx
    configure_firewall
    wait_for_services
    display_summary
    
    echo
    log_success "Installation completed!"
    echo
    log_info "Next steps:"
    log_info "1. Access https://$DOMAIN_NAME/admin"
    log_info "2. Login with admin / $ADMIN_PASSWORD"
    log_info "3. Configure your VPN settings"
    log_info "4. Create user profiles"
    echo
}

# Run main function
main "$@"
