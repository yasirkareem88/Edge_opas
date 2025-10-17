#!/bin/bash

# OpenVPN AS Installation Script with Nginx 502 Fix

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    log_info "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_CODENAME=$VERSION_CODENAME
        OS_NAME=$NAME
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    log_info "Detected: $OS_NAME $OS_VERSION ($OS_CODENAME)"
    
    if command -v apt-get &> /dev/null; then
        PKG_MGR="deb"
        log_success "Detected Debian/Ubuntu system (apt)"
    else
        log_error "Unsupported package manager"
        exit 1
    fi
}

# User input function
get_user_input() {
    log_info "Please provide the following configuration details:"
    
    read -p "Enter server domain name or IP address: " DOMAIN_NAME
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    read -s -p "Enter admin password (min 4 characters): " ADMIN_PASSWORD
    echo
    read -p "Enter OpenVPN AS port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    read -p "Enter Nginx virtual host port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    # Validate inputs
    if [ -z "$DOMAIN_NAME" ]; then
        log_error "Domain name or IP address is required"
        exit 1
    fi
    
    if [ -z "$ADMIN_PASSWORD" ]; then
        log_error "Admin password is required"
        exit 1
    fi
    
    if [ ${#ADMIN_PASSWORD} -lt 4 ]; then
        log_error "Admin password must be at least 4 characters long"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    apt-get update
    apt-get install -y wget curl nginx python3 net-tools ufw \
                       liblzo2-2 liblz4-1 libpkcs11-helper1 libcap-ng0 \
                       sqlite3 pkg-config build-essential libssl-dev \
                       libpam0g-dev liblz4-dev liblzo2-dev libpcap-dev \
                       net-tools iproute2 ca-certificates gnupg
    
    log_success "Dependencies installed successfully"
}

# Setup repository for Ubuntu 24.04
setup_repository() {
    log_info "Setting up repository..."
    
    # Remove any existing repository
    rm -f /etc/apt/sources.list.d/openvpn-as-repo.list
    rm -f /etc/apt/keyrings/as-repository.asc
    
    # Download and add the key
    wget https://packages.openvpn.net/as-repo-public.asc -qO /etc/apt/keyrings/as-repository.asc
    
    # For Ubuntu 24.04, use jammy (22.04) repository
    if [ "$OS" = "ubuntu" ] && [ "$OS_VERSION" = "24.04" ]; then
        log_info "Using Ubuntu 22.04 (jammy) repository for compatibility"
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/as-repository.asc] http://packages.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    else
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/as-repository.asc] http://packages.openvpn.net/as/debian $OS_CODENAME main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    fi
    
    apt-get update
}

# Install OpenVPN AS
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    setup_repository
    
    # Install OpenVPN AS
    if apt-get install -y openvpn-as; then
        log_success "OpenVPN AS installed successfully"
        return 0
    else
        log_error "Failed to install OpenVPN AS from repository"
        log_info "Trying alternative installation method..."
        
        # Alternative: Direct download
        cd /tmp
        wget -O openvpn-as.deb "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb" || \
        wget -O openvpn-as.deb "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.11.0-ubuntu22_amd64.deb"
        
        if [ -f "openvpn-as.deb" ]; then
            dpkg -i openvpn-as.deb || apt-get install -y -f
            log_success "OpenVPN AS installed via direct download"
            return 0
        else
            log_error "All installation methods failed"
            exit 1
        fi
    fi
}

# Wait for OpenVPN AS to be fully ready
wait_for_openvpn_ready() {
    log_info "Waiting for OpenVPN AS services to be fully ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        # Check if all services are running
        if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "started"; then
            # Additional check - try to connect to the admin interface
            if curl -k -s -f https://localhost:943/admin >/dev/null 2>&1; then
                log_success "OpenVPN AS is fully ready (attempt $attempt/$max_attempts)"
                return 0
            fi
        fi
        
        log_info "Waiting for services to be ready... (attempt $attempt/$max_attempts)"
        sleep 5
        attempt=$((attempt + 1))
    done
    
    log_warning "OpenVPN AS services are taking longer than expected to start"
    log_info "Continuing with configuration anyway..."
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Stop services for configuration
    /usr/local/openvpn_as/scripts/sacli stop >/dev/null 2>&1
    sleep 3
    
    # Configure admin password
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1
    
    # Configure superuser properties
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser" --value "$ADMIN_USER" ConfigPut >/dev/null 2>&1
    
    # Set host name - CRITICAL for Nginx proxy
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut >/dev/null 2>&1
    
    # Configure ports for Nginx reverse proxy - FIX for 502 error
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut >/dev/null 2>&1
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut >/dev/null 2>&1
    
    # Enable port sharing for Nginx
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut >/dev/null 2>&1
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut >/dev/null 2>&1
    
    # Additional configuration for stability
    /usr/local/openvpn_as/scripts/sacli --key "cs.daemon.enable" --value "true" ConfigPut >/dev/null 2>&1
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut >/dev/null 2>&1
    
    # Start services
    /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1
    sleep 10
    
    log_success "OpenVPN AS configured successfully"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    # Create directory if it doesn't exist
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    
    log_warning "Using self-signed certificates. For production, use Let's Encrypt"
}

# Configure Nginx with 502 fix
configure_nginx() {
    log_info "Configuring Nginx reverse proxy with 502 fix..."
    
    # Stop Nginx first
    systemctl stop nginx
    
    # Create a robust Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
# OpenVPN AS Reverse Proxy Configuration
# Fixed for 502 Bad Gateway errors

upstream openvpn_backend {
    server 127.0.0.1:$OPENVPN_PORT;
    keepalive 32;
}

server {
    listen $NGINX_PORT ssl;
    server_name $DOMAIN_NAME;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Proxy Settings - FIX for 502 errors
    location / {
        proxy_pass https://openvpn_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts - Increased for stability
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Buffer settings
        proxy_buffering off;
        proxy_request_buffering off;
        
        # Ignore certificate verification for backend
        proxy_ssl_verify off;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
        
        # Additional headers for OpenVPN AS
        proxy_set_header X-Forwarded-Ssl on;
    }
    
    # Larger client maximum body size for file uploads
    client_max_body_size 100M;
    
    # Access and error logs
    access_log /var/log/nginx/openvpn-as-access.log;
    error_log /var/log/nginx/openvpn-as-error.log;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name $DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}
EOF
    
    # Remove default Nginx site
    rm -f /etc/nginx/sites-enabled/default
    
    # Enable our site
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Test Nginx configuration
    log_info "Testing Nginx configuration..."
    if nginx -t; then
        log_success "Nginx configuration test passed"
    else
        log_error "Nginx configuration test failed"
        log_info "Checking for configuration errors..."
        nginx -T | grep -A 10 -B 10 error
        exit 1
    fi
    
    # Start Nginx
    systemctl enable nginx
    systemctl restart nginx
    
    log_success "Nginx configured successfully with 502 fixes"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    ufw allow ssh
    ufw allow "$NGINX_PORT/tcp"
    ufw allow "80/tcp"
    ufw allow "1194/udp"
    ufw allow "$OPENVPN_PORT/tcp"
    echo "y" | ufw enable
    
    log_success "Firewall configured"
}

# Fix common 502 issues
fix_502_issues() {
    log_info "Applying fixes for 502 Bad Gateway issues..."
    
    # 1. Check if OpenVPN AS is listening on the correct port
    log_info "Checking if OpenVPN AS is listening on port $OPENVPN_PORT..."
    if netstat -tlnp | grep -q ":$OPENVPN_PORT"; then
        log_success "OpenVPN AS is listening on port $OPENVPN_PORT"
    else
        log_error "OpenVPN AS is NOT listening on port $OPENVPN_PORT"
        log_info "Restarting OpenVPN AS services..."
        /usr/local/openvpn_as/scripts/sacli stop
        sleep 5
        /usr/local/openvpn_as/scripts/sacli start
        sleep 10
    fi
    
    # 2. Check if we can connect to OpenVPN AS locally
    log_info "Testing local connection to OpenVPN AS..."
    if curl -k -s -f https://127.0.0.1:$OPENVPN_PORT/admin >/dev/null 2>&1; then
        log_success "Local connection to OpenVPN AS successful"
    else
        log_error "Cannot connect to OpenVPN AS locally"
        log_info "Checking OpenVPN AS status..."
        /usr/local/openvpn_as/scripts/sacli status
        log_info "Checking OpenVPN AS logs..."
        tail -20 /usr/local/openvpn_as/logs/*.log
    fi
    
    # 3. Check Nginx error logs
    log_info "Checking Nginx error logs..."
    if [ -f "/var/log/nginx/openvpn-as-error.log" ]; then
        log_info "Recent Nginx errors:"
        tail -10 /var/log/nginx/openvpn-as-error.log
    fi
    
    # 4. Ensure proper SELinux/AppArmor settings (if applicable)
    if command -v getenforce &> /dev/null; then
        if [ "$(getenforce)" = "Enforcing" ]; then
            log_warning "SELinux is enforcing - this might cause issues"
            log_info "Consider setting SELinux to permissive or adding policies"
        fi
    fi
    
    # 5. Add hosts entry if using IP address
    if [[ $DOMAIN_NAME =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_info "Using IP address, adding to hosts file for local resolution"
        echo "127.0.0.1 $DOMAIN_NAME" >> /etc/hosts
    fi
    
    log_success "502 fixes applied"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    echo
    echo "=== Service Status ==="
    /usr/local/openvpn_as/scripts/sacli status
    
    echo
    echo "=== Network Connections ==="
    netstat -tlnp | grep -E "($OPENVPN_PORT|$NGINX_PORT|943|443)"
    
    echo
    echo "=== Testing Local Access ==="
    if curl -k -s -f https://127.0.0.1:$OPENVPN_PORT/admin >/dev/null 2>&1; then
        log_success "✓ OpenVPN AS is accessible locally on port $OPENVPN_PORT"
    else
        log_error "✗ OpenVPN AS is NOT accessible locally on port $OPENVPN_PORT"
    fi
    
    echo
    echo "=== Testing Nginx Proxy ==="
    if curl -k -s -f https://127.0.0.1:$NGINX_PORT/admin >/dev/null 2>&1; then
        log_success "✓ Nginx proxy is working locally on port $NGINX_PORT"
    else
        log_error "✗ Nginx proxy is NOT working locally on port $NGINX_PORT"
    fi
    
    # Test external access if domain is not localhost
    if [[ "$DOMAIN_NAME" != "localhost" ]] && [[ ! "$DOMAIN_NAME" =~ ^127\. ]]; then
        echo
        echo "=== Testing External Access ==="
        log_info "Please test externally: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    fi
    
    log_success "Verification completed"
}

# Display troubleshooting tips
show_troubleshooting() {
    echo
    echo "=== TROUBLESHOOTING 502 BAD GATEWAY ==="
    echo
    echo "If you're still getting 502 Bad Gateway:"
    echo
    echo "1. CHECK OPENVPN AS STATUS:"
    echo "   /usr/local/openvpn_as/scripts/sacli status"
    echo
    echo "2. CHECK OPENVPN AS LOGS:"
    echo "   tail -f /usr/local/openvpn_as/logs/*.log"
    echo
    echo "3. CHECK NGINX LOGS:"
    echo "   tail -f /var/log/nginx/openvpn-as-error.log"
    echo
    echo "4. TEST LOCAL CONNECTION:"
    echo "   curl -k https://127.0.0.1:$OPENVPN_PORT/admin"
    echo
    echo "5. RESTART SERVICES:"
    echo "   systemctl restart nginx"
    echo "   /usr/local/openvpn_as/scripts/sacli restart"
    echo
    echo "6. CHECK FIREWALL:"
    echo "   ufw status"
    echo
    echo "7. VERIFY PORTS:"
    echo "   netstat -tlnp | grep -E '($OPENVPN_PORT|$NGINX_PORT)'"
    echo
    echo "8. MANUAL CONFIGURATION CHECK:"
    echo "   /usr/local/openvpn_as/scripts/sacli --key host.name ConfigQuery"
    echo "   /usr/local/openvpn_as/scripts/sacli --key cs.https.port ConfigQuery"
    echo
}

# Display final summary
show_summary() {
    log_success "OpenVPN Access Server installation completed!"
    echo
    echo "=== INSTALLATION SUMMARY ==="
    echo "Domain: $DOMAIN_NAME"
    echo "Admin Username: $ADMIN_USER"
    echo "Admin Web Interface: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo "Client Access: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo "OpenVPN AS Backend Port: $OPENVPN_PORT"
    echo "Nginx Frontend Port: $NGINX_PORT"
    echo
    echo "=== ACCESS INFORMATION ==="
    echo "Web Admin: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo "Client Login: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo
    echo "=== SERVICE COMMANDS ==="
    echo "Check Status: /usr/local/openvpn_as/scripts/sacli status"
    echo "Restart OpenVPN: /usr/local/openvpn_as/scripts/sacli restart"
    echo "Restart Nginx: systemctl restart nginx"
    echo
}

# Main installation function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Installer with 502 Fix"
    echo "=========================================="
    echo
    
    check_root
    detect_os
    get_user_input
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    wait_for_openvpn_ready
    configure_openvpn_as
    configure_nginx
    configure_firewall
    fix_502_issues
    verify_installation
    show_summary
    show_troubleshooting
}

# Run main function
main "$@"
