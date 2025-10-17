#!/bin/bash

# OpenVPN Access Server Complete Installation with Nginx Reverse Proxy
# This script uses the official OpenVPN installer and adds Nginx configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Cleanup previous installations
cleanup_previous() {
    log "Cleaning up previous installations..."
    
    # Stop services
    systemctl stop nginx 2>/dev/null || true
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    
    # Remove OpenVPN AS
    dpkg -r openvpn-as 2>/dev/null || true
    dpkg -P openvpn-as 2>/dev/null || true
    rm -rf /usr/local/openvpn_as
    
    # Remove repositories
    rm -f /etc/apt/sources.list.d/openvpn-as.list
    rm -f /etc/apt/trusted.gpg.d/openvpn-as-repo.asc
    
    # Clean Nginx
    rm -f /etc/nginx/sites-available/openvpn-as
    rm -f /etc/nginx/sites-enabled/openvpn-as
    
    # Clean apt
    apt-get autoremove -y 2>/dev/null || true
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    
    success "Cleanup completed"
}

# Fix repository and download issues
fix_download_issues() {
    log "Fixing repository and download issues..."
    
    # Clean existing repos
    rm -f /etc/apt/sources.list.d/openvpn-as-repo.list
    rm -f /etc/apt/sources.list.d/openvpn-as.list
    rm -f /etc/apt/trusted.gpg.d/as-repository.asc
    
    # Update package list
    apt-get update
    
    # Install required tools
    apt-get install -y wget curl gnupg ca-certificates
    
    # Create keyrings directory
    mkdir -p /etc/apt/keyrings
    
    # Download and install the GPG key
    if ! wget -qO /etc/apt/keyrings/as-repository.asc https://packages.openvpn.net/as-repo-public.asc; then
        error "Failed to download GPG key"
        return 1
    fi
    
    # Detect Ubuntu version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        UBUNTU_CODENAME=$VERSION_CODENAME
    else
        UBUNTU_CODENAME="jammy"  # Default to Ubuntu 22.04
    fi
    
    # Add repository
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/as-repository.asc] http://packages.openvpn.net/as/debian $UBUNTU_CODENAME main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    
    # Update package list
    if ! apt-get update; then
        error "Failed to update package list"
        return 1
    fi
    
    success "Repository configuration fixed"
}

# Download and install OpenVPN AS using official method
install_openvpn_official() {
    log "Installing OpenVPN Access Server using official method..."
    
    # Method 1: Use the official install script
    if ! bash <(curl -fsSL https://packages.openvpn.net/as/install.sh) --yes; then
        warn "Official installer failed, trying alternative method..."
        
        # Method 2: Manual package installation
        install_openvpn_manual
    fi
}

# Manual installation as fallback
install_openvpn_manual() {
    log "Attempting manual installation..."
    
    cd /tmp
    
    # Try different package URLs
    local packages=(
        "https://swupdate.openvpn.net/scripts/openvpn-as-2.12.0-ubuntu20.amd_64.deb"
        "https://swupdate.openvpn.net/scripts/openvpn-as-2.11.0-ubuntu20.amd_64.deb"
        "https://swupdate.openvpn.net/scripts/openvpn-as-2.10.0-ubuntu20.amd_64.deb"
        "https://swupdate.openvpn.net/scripts/openvpn-as-latest-ubuntu20.amd_64.deb"
    )
    
    for package in "${packages[@]}"; do
        log "Trying to download: $package"
        if wget -O openvpn-as.deb "$package"; then
            if dpkg -i openvpn-as.deb || apt-get install -y -f; then
                success "OpenVPN AS installed manually"
                return 0
            fi
        fi
    done
    
    error "All manual installation attempts failed"
    return 1
}

# Get user configuration
get_user_config() {
    echo
    log "OpenVPN Access Server Configuration"
    echo "=================================="
    
    read -p "Enter server domain name or IP address: " SERVER_HOST
    SERVER_HOST=${SERVER_HOST:-$(hostname -I | awk '{print $1}')}
    
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        if [ -n "$ADMIN_PASS" ]; then
            read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
            echo
            if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ]; then
                break
            else
                error "Passwords do not match"
            fi
        else
            error "Password cannot be empty"
        fi
    done
    
    read -p "Enter Nginx external port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    read -p "Enter OpenVPN AS internal port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    
    # Display configuration
    echo
    log "Configuration Summary:"
    echo "---------------------"
    echo "Server Host: $SERVER_HOST"
    echo "Admin User: $ADMIN_USER"
    echo "Nginx Port: $NGINX_PORT"
    echo "OpenVPN AS Port: $OPENVPN_PORT"
    echo
    
    read -p "Continue with installation? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        error "Installation cancelled"
        exit 1
    fi
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log "Configuring OpenVPN Access Server..."
    
    # Wait for services to initialize
    sleep 10
    
    # Stop OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    sleep 3
    
    # Configure basic settings
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$SERVER_HOST" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    
    # Configure for Nginx reverse proxy
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut
    
    # Bind to localhost only
    /usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.ip_address" --value "127.0.0.1" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip_address" --value "127.0.0.1" ConfigPut
    
    # Set admin password
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASS" SetLocalPassword
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASS" ConfigPut
    
    # Start OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli start
    
    # Wait for service
    log "Waiting for OpenVPN AS to start..."
    for i in {1..30}; do
        if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "Service is running"; then
            success "OpenVPN AS is running"
            return 0
        fi
        sleep 2
    done
    
    error "OpenVPN AS failed to start properly"
    return 1
}

# Install and configure Nginx
install_nginx() {
    log "Installing and configuring Nginx..."
    
    # Install Nginx
    apt-get install -y nginx
    
    # Generate SSL certificates
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$SERVER_HOST" \
        -addext "subjectAltName=DNS:$SERVER_HOST" 2>/dev/null
    
    chmod 600 /etc/ssl/private/nginx-selfsigned.key
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
server {
    listen 80;
    server_name $SERVER_HOST;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $NGINX_PORT ssl http2;
    server_name $SERVER_HOST;
    
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 90s;
        proxy_send_timeout 90s;
        proxy_read_timeout 90s;
        proxy_buffering off;
    }
    
    client_max_body_size 100M;
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and restart Nginx
    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        success "Nginx configured"
    else
        error "Nginx configuration test failed"
        return 1
    fi
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Install UFW if not present
    if ! command -v ufw >/dev/null; then
        apt-get install -y ufw
    fi
    
    # Reset and enable UFW
    ufw --force reset
    echo "y" | ufw enable
    
    # Allow necessary ports
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 1194/udp
    
    if [ "$NGINX_PORT" != "443" ]; then
        ufw allow "$NGINX_PORT/tcp"
    fi
    
    success "Firewall configured"
}

# Test installation
test_installation() {
    log "Testing installation..."
    
    local tests_passed=0
    
    # Test OpenVPN AS
    if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "Service is running"; then
        success "✓ OpenVPN AS service is running"
        ((tests_passed++))
    else
        error "✗ OpenVPN AS service is not running"
    fi
    
    # Test local access
    if curl -k -s https://127.0.0.1:$OPENVPN_PORT >/dev/null; then
        success "✓ OpenVPN AS is accessible locally"
        ((tests_passed++))
    else
        error "✗ OpenVPN AS is not accessible locally"
    fi
    
    # Test Nginx
    if systemctl is-active --quiet nginx; then
        success "✓ Nginx service is running"
        ((tests_passed++))
    else
        error "✗ Nginx service is not running"
    fi
    
    # Test proxy
    if curl -k -s -H "Host: $SERVER_HOST" https://127.0.0.1:$NGINX_PORT >/dev/null; then
        success "✓ Nginx proxy is working"
        ((tests_passed++))
    else
        error "✗ Nginx proxy is not working"
    fi
    
    if [ $tests_passed -eq 4 ]; then
        success "All tests passed!"
        return 0
    else
        warn "Some tests failed ($tests_passed/4 passed)"
        return 1
    fi
}

# Display final information
show_final_info() {
    echo
    success "================================================"
    success "    OpenVPN Access Server Installation Complete"
    success "================================================"
    echo
    log "Access Information:"
    echo "=================="
    echo "Admin Interface: https://$SERVER_HOST:$NGINX_PORT/admin"
    echo "Client Interface: https://$SERVER_HOST:$NGINX_PORT/"
    echo "Admin Username: $ADMIN_USER"
    echo
    log "Next Steps:"
    echo "==========="
    echo "1. Access the admin interface above"
    echo "2. Complete the VPN configuration"
    echo "3. Create user profiles"
    echo "4. Download client configuration files"
    echo
    warn "Important Notes:"
    echo "================"
    echo "• Using self-signed certificates (replace for production)"
    echo "• Ensure DNS points to: $SERVER_HOST"
    echo
    log "Troubleshooting:"
    echo "================"
    echo "Check status: /usr/local/openvpn_as/scripts/sacli status"
    echo "Nginx logs: tail -f /var/log/nginx/error.log"
    echo "OpenVPN logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo
}

# Main installation function
main() {
    clear
    echo "================================================"
    echo "   OpenVPN AS + Nginx Complete Installation"
    echo "================================================"
    echo
    
    check_root
    
    # Ask for cleanup
    read -p "Cleanup previous installation? (y/n): " cleanup_confirm
    if [[ $cleanup_confirm =~ ^[Yy]$ ]]; then
        cleanup_previous
    fi
    
    get_user_config
    fix_download_issues
    install_openvpn_official
    configure_openvpn_as
    install_nginx
    configure_firewall
    
    if test_installation; then
        show_final_info
    else
        warn "Installation completed with some issues"
        show_final_info
    fi
}

# Run main function
main "$@"
