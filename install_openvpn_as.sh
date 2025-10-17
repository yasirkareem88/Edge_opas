#!/bin/bash

# OpenVPN Access Server with Nginx Reverse Proxy - Complete Installation Script
# Fully automated with error handling and user input

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command executed successfully
check_success() {
    if [ $? -eq 0 ]; then
        success "$1"
    else
        error "$2"
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Get user input with validation
get_user_input() {
    echo
    log "Please provide the following information:"
    echo "========================================"
    
    while true; do
        read -p "Enter your server's public IP address or domain name: " SERVER_HOST
        if [ -n "$SERVER_HOST" ]; then
            break
        else
            error "Server host cannot be empty"
        fi
    done
    
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        if [ -n "$ADMIN_PASS" ]; then
            break
        else
            error "Admin password cannot be empty"
        fi
    done
    
    read -p "Enter Nginx external port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    read -p "Enter OpenVPN AS internal port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    
    # Display configuration summary
    echo
    log "Configuration Summary:"
    echo "====================="
    echo "Server Host: $SERVER_HOST"
    echo "Admin Username: $ADMIN_USER"
    echo "Nginx Port: $NGINX_PORT"
    echo "OpenVPN AS Port: $OPENVPN_PORT"
    echo
    
    read -p "Continue with this configuration? (y/n): " CONFIRM
    if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
        error "Installation cancelled by user"
        exit 1
    fi
}

# Detect OS and install dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    # Update package list
    apt-get update
    check_success "Package list updated" "Failed to update package list"
    
    # Install required packages
    apt-get install -y wget curl nginx python3 net-tools ufw \
                       openssl sqlite3 pkg-config build-essential \
                       libssl-dev libpam0g-dev liblz4-dev liblzo2-dev \
                       libpcap-dev net-tools iproute2
    check_success "Dependencies installed" "Failed to install dependencies"
}

# Install OpenVPN Access Server
install_openvpn_as() {
    log "Installing OpenVPN Access Server..."
    
    cd /tmp
    
    # Download OpenVPN AS
    if wget -O openvpn-as.deb "https://swupdate.openvpn.net/scripts/openvpn-as-2.12.0-ubuntu20.amd_64.deb"; then
        success "OpenVPN AS package downloaded"
    else
        warn "Primary download failed, trying alternative..."
        wget -O openvpn-as.deb "https://swupdate.openvpn.net/scripts/openvpn-as-2.11.0-ubuntu20.amd_64.deb"
        check_success "OpenVPN AS package downloaded" "Failed to download OpenVPN AS"
    fi
    
    # Install the package
    dpkg -i openvpn-as.deb || true  # Allow it to fail for dependency resolution
    
    # Fix any dependency issues
    apt-get install -y -f
    check_success "OpenVPN AS installed" "Failed to install OpenVPN AS"
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log "Configuring OpenVPN Access Server..."
    
    # Wait for services to initialize
    sleep 10
    
    # Stop OpenVPN AS first
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    sleep 2
    
    # Configure basic settings
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$SERVER_HOST" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    
    # Configure for Nginx reverse proxy
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut
    
    # Bind to localhost only for security
    /usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.ip_address" --value "127.0.0.1" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip_address" --value "127.0.0.1" ConfigPut
    
    # Set admin password
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASS" SetLocalPassword
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASS" ConfigPut
    
    # Start OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli start
    check_success "OpenVPN AS configured and started" "Failed to configure OpenVPN AS"
    
    # Wait for service to fully start
    sleep 10
    
    # Verify OpenVPN AS is running
    if pgrep -f "openvpn-as" > /dev/null; then
        success "OpenVPN AS is running"
    else
        error "OpenVPN AS failed to start"
        exit 1
    fi
}

# Generate SSL certificates
generate_ssl_certificates() {
    log "Generating SSL certificates..."
    
    # Create certificate directory if it doesn't exist
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    # Generate self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$SERVER_HOST" \
        -addext "subjectAltName=DNS:$SERVER_HOST"
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/nginx-selfsigned.key
    chmod 644 /etc/ssl/certs/nginx-selfsigned.crt
    
    check_success "SSL certificates generated" "Failed to generate SSL certificates"
}

# Create Nginx configuration
configure_nginx() {
    log "Configuring Nginx reverse proxy..."
    
    # Create nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
# OpenVPN AS Reverse Proxy Configuration
server {
    listen 80;
    server_name $SERVER_HOST;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $NGINX_PORT ssl http2;
    server_name $SERVER_HOST;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # Proxy settings
    proxy_ssl_verify off;
    proxy_redirect off;
    
    # Main location - handle both admin and client interfaces
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 90s;
        proxy_send_timeout 90s;
        proxy_read_timeout 90s;
        
        # Buffer settings
        proxy_buffering off;
        proxy_request_buffering off;
    }
    
    # Specific WebSocket endpoints
    location ~* ^/(ws|api|jsonrpc) {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Increase file upload size
    client_max_body_size 100M;
    
    # Access and error logs
    access_log /var/log/nginx/openvpn-as-access.log;
    error_log /var/log/nginx/openvpn-as-error.log;
}
EOF
    
    # Enable the site
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Remove default nginx site
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx configuration
    if nginx -t; then
        success "Nginx configuration test passed"
    else
        error "Nginx configuration test failed"
        log "Check /etc/nginx/sites-available/openvpn-as for errors"
        exit 1
    fi
    
    # Restart nginx
    systemctl enable nginx
    systemctl restart nginx
    check_success "Nginx configured and started" "Failed to configure Nginx"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Enable UFW
    ufw --force enable
    
    # Allow SSH
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow OpenVPN port
    ufw allow 1194/udp
    
    # Allow custom Nginx port if not 443
    if [ "$NGINX_PORT" != "443" ]; then
        ufw allow "$NGINX_PORT/tcp"
    fi
    
    success "Firewall configured"
}

# Test the installation
test_installation() {
    log "Testing installation..."
    
    # Test 1: Check if OpenVPN AS is accessible locally
    log "Testing OpenVPN AS backend..."
    if curl -k -s --connect-timeout 10 https://127.0.0.1:$OPENVPN_PORT > /dev/null; then
        success "OpenVPN AS backend is accessible"
    else
        error "OpenVPN AS backend is not accessible"
        log "Checking OpenVPN AS status..."
        /usr/local/openvpn_as/scripts/sacli status
        return 1
    fi
    
    # Test 2: Check if Nginx is serving the proxy
    log "Testing Nginx reverse proxy..."
    if curl -k -s --connect-timeout 10 https://127.0.0.1:$NGINX_PORT > /dev/null; then
        success "Nginx reverse proxy is working"
    else
        error "Nginx reverse proxy is not working"
        log "Checking Nginx status..."
        systemctl status nginx
        log "Checking Nginx error logs..."
        tail -20 /var/log/nginx/error.log
        return 1
    fi
    
    # Test 3: Check if services are running
    if systemctl is-active --quiet nginx; then
        success "Nginx service is running"
    else
        error "Nginx service is not running"
    fi
    
    if pgrep -f "openvpn-as" > /dev/null; then
        success "OpenVPN AS service is running"
    else
        error "OpenVPN AS service is not running"
    fi
    
    success "All tests completed successfully!"
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
    echo "1. Access the admin interface using the URL above"
    echo "2. Log in with your admin credentials"
    echo "3. Configure your VPN settings"
    echo "4. Create user profiles"
    echo "5. Download client configuration files"
    echo
    warn "Important Notes:"
    echo "================"
    echo "• Self-signed certificates are used (for testing)"
    echo "• For production, replace with Let's Encrypt certificates"
    echo "• Ensure DNS is configured for $SERVER_HOST"
    echo
    log "Troubleshooting Commands:"
    echo "========================"
    echo "Check OpenVPN AS status: /usr/local/openvpn_as/scripts/sacli status"
    echo "Check Nginx status: systemctl status nginx"
    echo "View Nginx logs: tail -f /var/log/nginx/openvpn-as-error.log"
    echo "View OpenVPN AS logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo "Restart services: systemctl restart nginx && /usr/local/openvpn_as/scripts/sacli start"
    echo
}

# Main installation function
main() {
    clear
    echo "================================================"
    echo "   OpenVPN AS + Nginx Automated Installer"
    echo "================================================"
    echo
    
    # Check root privileges
    check_root
    
    # Get user input
    get_user_input
    
    # Installation steps
    install_dependencies
    install_openvpn_as
    generate_ssl_certificates
    configure_openvpn_as
    configure_nginx
    configure_firewall
    test_installation
    show_final_info
}

# Run main function
main "$@"
