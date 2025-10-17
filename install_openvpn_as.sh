#!/bin/bash

# OpenVPN Access Server Complete Installation Script
# Includes full cleanup, reinstall options, and error handling

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
SERVER_HOST=""
ADMIN_USER="admin"
ADMIN_PASS=""
NGINX_PORT="443"
OPENVPN_PORT="943"
CLEANUP_MODE=false
REINSTALL_MODE=false

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Display usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -c, --cleanup     Cleanup previous installation only"
    echo "  -r, --reinstall   Cleanup and reinstall everything"
    echo "  -h, --help        Show this help message"
    echo
    echo "Examples:"
    echo "  $0                 # Normal installation"
    echo "  $0 --cleanup       # Cleanup only"
    echo "  $0 --reinstall     # Cleanup and reinstall"
    exit 1
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--cleanup)
                CLEANUP_MODE=true
                shift
                ;;
            -r|--reinstall)
                REINSTALL_MODE=true
                shift
                ;;
            -h|--help)
                show_usage
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                ;;
        esac
    done
}

# Comprehensive cleanup function
cleanup_previous_installation() {
    log "Starting comprehensive cleanup of previous installation..."
    
    # Stop services
    log "Stopping services..."
    systemctl stop nginx 2>/dev/null || true
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    pkill -f openvpn-as 2>/dev/null || true
    sleep 3
    
    # Remove OpenVPN AS package and files
    log "Removing OpenVPN AS..."
    dpkg -r openvpn-as 2>/dev/null || true
    dpkg -P openvpn-as 2>/dev/null || true
    apt-get remove -y --purge openvpn-as 2>/dev/null || true
    
    # Remove all OpenVPN AS directories
    log "Removing OpenVPN AS directories..."
    rm -rf /usr/local/openvpn_as
    rm -rf /opt/openvpn-as
    rm -rf /var/log/openvpn-as
    rm -rf /tmp/ovpn_*
    
    # Remove OpenVPN AS user and group
    log "Removing OpenVPN AS user..."
    userdel openvpn_as 2>/dev/null || true
    groupdel openvpn_as 2>/dev/null || true
    
    # Remove repositories and GPG keys
    log "Cleaning up repositories..."
    rm -f /etc/apt/sources.list.d/openvpn*
    rm -f /etc/apt/sources.list.d/as-repository*
    rm -f /etc/apt/trusted.gpg.d/openvpn*
    rm -f /etc/apt/trusted.gpg.d/as-repository*
    
    # Clean Nginx configuration
    log "Cleaning Nginx configuration..."
    rm -f /etc/nginx/sites-available/openvpn-as
    rm -f /etc/nginx/sites-enabled/openvpn-as
    
    # Restore default nginx site if it exists
    if [ -f /etc/nginx/sites-available/default.bak ]; then
        mv /etc/nginx/sites-available/default.bak /etc/nginx/sites-available/default
    fi
    if [ ! -f /etc/nginx/sites-enabled/default ] && [ -f /etc/nginx/sites-available/default ]; then
        ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true
    fi
    
    # Remove SSL certificates
    log "Removing SSL certificates..."
    rm -f /etc/ssl/certs/nginx-selfsigned.crt
    rm -f /etc/ssl/private/nginx-selfsigned.key
    rm -f /etc/ssl/certs/ssl-cert-snakeoil.pem
    rm -f /etc/ssl/private/ssl-cert-snakeoil.key
    
    # Clean firewall rules
    log "Resetting firewall..."
    ufw --force reset 2>/dev/null || true
    ufw --force disable 2>/dev/null || true
    
    # Clean systemd services
    log "Cleaning systemd services..."
    systemctl daemon-reload
    systemctl reset-failed
    
    # Clean package cache
    log "Cleaning package cache..."
    apt-get autoremove -y 2>/dev/null || true
    apt-get clean 2>/dev/null || true
    rm -rf /var/lib/apt/lists/*
    
    # Remove temporary files
    log "Cleaning temporary files..."
    rm -f /tmp/openvpn-as*.deb
    rm -f /tmp/ovpn_*
    
    # Clean logs
    log "Cleaning logs..."
    rm -f /var/log/nginx/openvpn-as-*.log
    rm -f /var/log/openvpn-as*
    
    success "Cleanup completed successfully!"
    
    if [ "$CLEANUP_MODE" = true ] && [ "$REINSTALL_MODE" = false ]; then
        log "Cleanup-only mode completed. Exiting."
        exit 0
    fi
}

# Fix repository issues
fix_repositories() {
    log "Fixing repository issues..."
    
    # Remove any problematic OpenVPN repositories
    rm -f /etc/apt/sources.list.d/openvpn-as.list
    rm -f /etc/apt/sources.list.d/as-repository.list
    
    # Remove problematic GPG keys
    rm -f /etc/apt/trusted.gpg.d/openvpn-as-repo.asc
    rm -f /etc/apt/trusted.gpg.d/as-repository.asc
    
    # Clean apt cache
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    
    # Update package list
    apt-get update
    
    success "Repository issues fixed"
}

# Get user input with validation
get_user_input() {
    echo
    log "Please provide the following information:"
    echo "========================================"
    
    # Get server host
    while true; do
        read -p "Enter your server's public IP address or domain name: " SERVER_HOST
        if [ -n "$SERVER_HOST" ]; then
            # Basic validation for IP or domain
            if [[ $SERVER_HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $SERVER_HOST =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                break
            else
                warn "Please enter a valid IP address or domain name"
            fi
        else
            error "Server host cannot be empty"
        fi
    done
    
    # Get admin username
    read -p "Enter admin username [admin]: " input_user
    ADMIN_USER=${input_user:-admin}
    
    # Get admin password with confirmation
    while true; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        if [ -n "$ADMIN_PASS" ]; then
            if [ ${#ADMIN_PASS} -lt 8 ]; then
                warn "Password should be at least 8 characters long"
                continue
            fi
            read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
            echo
            if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ]; then
                break
            else
                error "Passwords do not match"
            fi
        else
            error "Admin password cannot be empty"
        fi
    done
    
    # Get ports
    read -p "Enter Nginx external port [443]: " input_nginx
    NGINX_PORT=${input_nginx:-443}
    
    read -p "Enter OpenVPN AS internal port [943]: " input_openvpn
    OPENVPN_PORT=${input_openvpn:-943}
    
    # Validate ports
    if ! [[ $NGINX_PORT =~ ^[0-9]+$ ]] || [ $NGINX_PORT -lt 1 ] || [ $NGINX_PORT -gt 65535 ]; then
        error "Invalid Nginx port: $NGINX_PORT"
        exit 1
    fi
    
    if ! [[ $OPENVPN_PORT =~ ^[0-9]+$ ]] || [ $OPENVPN_PORT -lt 1 ] || [ $OPENVPN_PORT -gt 65535 ]; then
        error "Invalid OpenVPN AS port: $OPENVPN_PORT"
        exit 1
    fi
    
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

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    # Update package list
    if ! apt-get update; then
        error "Failed to update package list"
        exit 1
    fi
    
    # Install required packages
    if ! apt-get install -y wget curl nginx python3 net-tools ufw \
                       openssl sqlite3 pkg-config build-essential \
                       libssl-dev libpam0g-dev liblz4-dev liblzo2-dev \
                       libpcap-dev net-tools iproute2; then
        error "Failed to install dependencies"
        exit 1
    fi
    
    success "Dependencies installed successfully"
}

# Download and install OpenVPN AS directly
install_openvpn_as_direct() {
    log "Downloading OpenVPN Access Server..."
    
    cd /tmp
    rm -f openvpn-as*.deb
    
    # Try multiple download URLs
    local download_urls=(
        "https://swupdate.openvpn.net/scripts/openvpn-as-2.12.0-ubuntu20.amd_64.deb"
        "https://swupdate.openvpn.net/scripts/openvpn-as-2.11.0-ubuntu20.amd_64.deb"
        "https://swupdate.openvpn.net/scripts/openvpn-as-2.10.0-ubuntu20.amd_64.deb"
        "https://swupdate.openvpn.net/scripts/openvpn-as-latest-ubuntu20.amd_64.deb"
    )
    
    local download_success=false
    for url in "${download_urls[@]}"; do
        log "Attempting download from: $url"
        if wget -O openvpn-as.deb "$url" 2>/dev/null; then
            if [ -s "openvpn-as.deb" ]; then
                download_success=true
                success "Successfully downloaded OpenVPN AS from $url"
                break
            else
                rm -f openvpn-as.deb
            fi
        fi
    done
    
    if [ "$download_success" = false ]; then
        error "All download attempts failed. Please check your internet connection."
        log "You can manually download OpenVPN AS from:"
        log "https://openvpn.net/vpn-software-packages/"
        exit 1
    fi
    
    # Install the package
    log "Installing OpenVPN AS package..."
    if ! dpkg -i openvpn-as.deb; then
        warn "First installation attempt failed, fixing dependencies..."
        if ! apt-get install -y -f; then
            error "Failed to install OpenVPN AS and fix dependencies"
            exit 1
        fi
    fi
    
    # Verify installation
    if [ -f "/usr/local/openvpn_as/scripts/sacli" ]; then
        success "OpenVPN AS installed successfully"
    else
        error "OpenVPN AS installation failed - sacli not found"
        exit 1
    fi
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log "Configuring OpenVPN Access Server..."
    
    # Stop OpenVPN AS if running
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    sleep 3
    
    # Wait for any existing processes to stop
    for i in {1..10}; do
        if ! pgrep -f "openvpn-as" > /dev/null; then
            break
        fi
        sleep 1
    done
    
    # Configure basic settings
    log "Setting host name and ports..."
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$SERVER_HOST" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    
    # Configure for Nginx reverse proxy
    log "Configuring for Nginx reverse proxy..."
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut
    
    # Bind to localhost only for security
    /usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.ip_address" --value "127.0.0.1" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip_address" --value "127.0.0.1" ConfigPut
    
    # Set admin password
    log "Setting admin password..."
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASS" SetLocalPassword
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASS" ConfigPut
    
    # Start OpenVPN AS
    log "Starting OpenVPN AS..."
    /usr/local/openvpn_as/scripts/sacli start
    
    # Wait for service to fully start
    log "Waiting for OpenVPN AS to start..."
    for i in {1..30}; do
        if curl -k -s https://127.0.0.1:$OPENVPN_PORT > /dev/null; then
            success "OpenVPN AS is running and accessible"
            break
        fi
        if [ $i -eq 30 ]; then
            error "OpenVPN AS failed to start within 30 seconds"
            log "Attempting to start manually..."
            /usr/local/openvpn_as/scripts/openvpnas -n
            sleep 5
        fi
        sleep 1
    done
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
        -addext "subjectAltName=DNS:$SERVER_HOST,IP:$SERVER_HOST" 2>/dev/null
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/nginx-selfsigned.key
    chmod 644 /etc/ssl/certs/nginx-selfsigned.crt
    
    success "SSL certificates generated"
}

# Create Nginx configuration
configure_nginx() {
    log "Configuring Nginx reverse proxy..."
    
    # Backup default nginx config if it exists
    if [ -f /etc/nginx/sites-available/default ]; then
        cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
    fi
    
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
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # Proxy settings
    proxy_ssl_verify off;
    proxy_redirect off;
    proxy_buffering off;
    
    # Main location
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
    
    success "Nginx configured and started"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Enable UFW
    echo "y" | ufw enable
    
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
    
    local tests_passed=0
    local total_tests=4
    
    # Test 1: Check if OpenVPN AS is accessible locally
    log "Test 1/$total_tests: Testing OpenVPN AS backend..."
    if curl -k -s --connect-timeout 10 https://127.0.0.1:$OPENVPN_PORT > /dev/null; then
        success "✓ OpenVPN AS backend is accessible"
        ((tests_passed++))
    else
        error "✗ OpenVPN AS backend is not accessible"
    fi
    
    # Test 2: Check if Nginx is serving the proxy
    log "Test 2/$total_tests: Testing Nginx reverse proxy..."
    if curl -k -s --connect-timeout 10 -H "Host: $SERVER_HOST" https://127.0.0.1:$NGINX_PORT > /dev/null; then
        success "✓ Nginx reverse proxy is working"
        ((tests_passed++))
    else
        error "✗ Nginx reverse proxy is not working"
    fi
    
    # Test 3: Check if services are running
    log "Test 3/$total_tests: Checking services..."
    if systemctl is-active --quiet nginx; then
        success "✓ Nginx service is running"
        ((tests_passed++))
    else
        error "✗ Nginx service is not running"
    fi
    
    if pgrep -f "openvpn-as" > /dev/null; then
        success "✓ OpenVPN AS service is running"
        ((tests_passed++))
    else
        error "✗ OpenVPN AS service is not running"
    fi
    
    # Final test result
    if [ $tests_passed -eq $total_tests ]; then
        success "All tests passed ($tests_passed/$total_tests)"
        return 0
    else
        warn "Some tests failed ($tests_passed/$total_tests passed)"
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
    echo "Check OpenVPN AS: /usr/local/openvpn_as/scripts/sacli status"
    echo "Check Nginx: systemctl status nginx"
    echo "View Nginx logs: tail -f /var/log/nginx/openvpn-as-error.log"
    echo "View OpenVPN AS logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo "Restart all: systemctl restart nginx && /usr/local/openvpn_as/scripts/sacli start"
    echo
}

# Main installation function
main() {
    clear
    echo "================================================"
    echo "   OpenVPN AS + Nginx Complete Installer"
    echo "   with Cleanup & Reinstall Options"
    echo "================================================"
    echo
    
    # Check root privileges
    check_root
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Handle cleanup modes
    if [ "$CLEANUP_MODE" = true ] || [ "$REINSTALL_MODE" = true ]; then
        cleanup_previous_installation
    fi
    
    if [ "$CLEANUP_MODE" = true ] && [ "$REINSTALL_MODE" = false ]; then
        exit 0
    fi
    
    # Fix repository issues
    fix_repositories
    
    # Get user input
    get_user_input
    
    # Installation steps
    install_dependencies
    install_openvpn_as_direct
    generate_ssl_certificates
    configure_openvpn_as
    configure_nginx
    configure_firewall
    
    # Test installation
    if test_installation; then
        show_final_info
    else
        warn "Installation completed with some test failures."
        warn "Please check the services and logs above."
        show_final_info
    fi
}

# Run main function with all arguments
main "$@"
