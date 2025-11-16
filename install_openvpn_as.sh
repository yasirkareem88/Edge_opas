#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Complete fix for missing pyovpn.zip issue

set -e  # Exit on any error

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
    exit 1
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

# Validate domain name
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]] || [[ "$domain" =~ \.\. ]] || [[ "$domain" =~ ^- ]] || [[ "$domain" =~ -$ ]]; then
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
                log_warning "Invalid domain name. Please enter a valid domain."
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
        read -s -p "Enter admin password (min 6 characters): " ADMIN_PASSWORD
        echo
        if [ ${#ADMIN_PASSWORD} -ge 6 ]; then
            read -s -p "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
            echo
            if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
                break
            else
                log_warning "Passwords do not match. Please try again."
            fi
        else
            log_warning "Password must be at least 6 characters long."
        fi
    done
    
    read -p "Enter OpenVPN AS port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    
    read -p "Enter Nginx virtual host port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    # Display configuration summary
    echo
    log_info "Configuration Summary:"
    echo "  Domain: $DOMAIN_NAME"
    echo "  Admin User: $ADMIN_USER"
    echo "  OpenVPN Port: $OPENVPN_PORT"
    echo "  Nginx Port: $NGINX_PORT"
    echo "  Server IP: $SERVER_IP"
    echo
    
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
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

# Install dependencies optimized for Ubuntu 24.04
install_dependencies() {
    log_info "Installing dependencies for Ubuntu 24.04..."
    
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
    )
    
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${essential_deps[@]}"; then
        log_error "Failed to install essential dependencies"
    fi
    
    # Install OpenVPN specific dependencies
    log_info "Installing OpenVPN specific dependencies..."
    local openvpn_deps=(
        liblzo2-2
        liblz4-1
        libpkcs11-helper1
        libcap-ng0
        libssl-dev
        libpam0g-dev
        liblz4-dev
        liblzo2-dev
        libpcap-dev
    )
    
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${openvpn_deps[@]}"; then
        log_error "Failed to install OpenVPN dependencies"
    fi
    
    log_success "All dependencies installed successfully"
}

# Setup repository optimized for Ubuntu 24.04
setup_repository() {
    log_info "Setting up OpenVPN AS repository for Ubuntu 24.04..."
    
    # Remove any existing repository
    rm -f /etc/apt/sources.list.d/openvpn-as-repo.list
    rm -f /etc/apt/trusted.gpg.d/as-repository.asc
    
    # Create directories if they don't exist
    mkdir -p /etc/apt/keyrings
    mkdir -p /etc/apt/sources.list.d
    
    # Download and add the key
    log_info "Downloading OpenVPN repository key..."
    if ! wget -qO /etc/apt/trusted.gpg.d/as-repository.asc https://packages.openvpn.net/as-repo-public.asc; then
        log_error "Failed to download OpenVPN repository key"
    fi
    
    # For Ubuntu 24.04, use jammy (22.04) repository
    log_info "Using Ubuntu 22.04 (jammy) repository for Ubuntu 24.04 compatibility"
    
    # Add repository
    echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/as-repository.asc] https://packages.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    
    # Update package list
    if ! apt-get update; then
        log_error "Failed to update package lists after adding repository"
    fi
    
    log_success "OpenVPN AS repository configured successfully"
}

# Download and extract pyovpn.zip from OpenVPN AS package
download_and_extract_pyovpn() {
    log_info "Downloading OpenVPN AS package to extract pyovpn.zip..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Use Ubuntu 22.04 package for 24.04 compatibility
    local package_url="https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb"
    
    log_info "Downloading package from: $package_url"
    
    # Download the package
    if ! wget -O openvpn-as.deb "$package_url"; then
        log_error "Failed to download OpenVPN AS package"
        return 1
    fi
    
    # Extract the package
    log_info "Extracting package contents..."
    ar x openvpn-as.deb
    
    # Extract data archive
    if [ -f "data.tar.xz" ]; then
        tar -xf data.tar.xz
    elif [ -f "data.tar.gz" ]; then
        tar -xzf data.tar.gz
    else
        log_error "Could not find data archive in package"
        return 1
    fi
    
    # Find and copy pyovpn.zip
    local pyovpn_path=$(find . -name "pyovpn.zip" -type f | head -1)
    if [ -n "$pyovpn_path" ] && [ -f "$pyovpn_path" ]; then
        log_info "Found pyovpn.zip, installing to OpenVPN AS directory..."
        
        # Create directory if it doesn't exist
        mkdir -p /usr/local/openvpn_as/lib/python/
        
        # Copy pyovpn.zip
        cp "$pyovpn_path" "/usr/local/openvpn_as/lib/python/pyovpn.zip"
        chmod 644 "/usr/local/openvpn_as/lib/python/pyovpn.zip"
        
        # Verify the file
        if [ -f "/usr/local/openvpn_as/lib/python/pyovpn.zip" ]; then
            log_success "pyovpn.zip successfully installed"
            
            # Test if the zip file is valid
            if unzip -t "/usr/local/openvpn_as/lib/python/pyovpn.zip" >/dev/null 2>&1; then
                log_success "pyovpn.zip is valid and not corrupted"
            else
                log_error "Downloaded pyovpn.zip is corrupted"
                return 1
            fi
        else
            log_error "Failed to copy pyovpn.zip"
            return 1
        fi
    else
        log_error "Could not find pyovpn.zip in the package"
        return 1
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    return 0
}

# Install OpenVPN AS with pre-downloaded pyovpn.zip
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    setup_repository
    
    # First, download and install pyovpn.zip to prevent missing file issues
    log_info "Pre-installing pyovpn.zip to prevent installation failures..."
    if ! download_and_extract_pyovpn; then
        log_error "Failed to pre-install pyovpn.zip"
    fi
    
    # Now install OpenVPN AS package
    log_info "Installing openvpn-as package..."
    if apt-get install -y openvpn-as; then
        log_success "OpenVPN AS installed successfully"
        
        # Verify pyovpn.zip still exists after installation
        if [ -f "/usr/local/openvpn_as/lib/python/pyovpn.zip" ]; then
            log_success "pyovpn.zip verified after installation"
        else
            log_warning "pyovpn.zip missing after installation, re-installing..."
            if ! download_and_extract_pyovpn; then
                log_error "Failed to re-install pyovpn.zip after package installation"
            fi
        fi
        return 0
    else
        log_error "Failed to install OpenVPN AS from repository"
    fi
}

# Verify OpenVPN AS installation and fix any issues
verify_openvpn_installation() {
    log_info "Verifying OpenVPN AS installation..."
    
    local pyovpn_zip="/usr/local/openvpn_as/lib/python/pyovpn.zip"
    local issues_found=0
    
    # Check if pyovpn.zip exists
    if [ ! -f "$pyovpn_zip" ]; then
        log_warning "pyovpn.zip is missing, downloading..."
        if ! download_and_extract_pyovpn; then
            log_error "Failed to install missing pyovpn.zip"
        fi
        issues_found=1
    fi
    
    # Check if pyovpn.zip is valid
    if [ -f "$pyovpn_zip" ]; then
        if ! unzip -t "$pyovpn_zip" >/dev/null 2>&1; then
            log_warning "pyovpn.zip is corrupted, re-downloading..."
            if ! download_and_extract_pyovpn; then
                log_error "Failed to replace corrupted pyovpn.zip"
            fi
            issues_found=1
        fi
    fi
    
    # Check if OpenVPN AS directory structure is complete
    local required_dirs=(
        "/usr/local/openvpn_as"
        "/usr/local/openvpn_as/bin"
        "/usr/local/openvpn_as/scripts"
        "/usr/local/openvpn_as/lib/python"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            log_warning "Missing directory: $dir"
            issues_found=1
        fi
    done
    
    if [ $issues_found -eq 0 ]; then
        log_success "OpenVPN AS installation verified successfully"
    else
        log_warning "Some issues were found and fixed during verification"
    fi
}

# Wait for OpenVPN AS to be fully ready
wait_for_openvpn_ready() {
    log_info "Waiting for OpenVPN AS services to be fully ready..."
    
    local max_attempts=50
    local attempt=1
    
    # Ensure services are started
    systemctl enable openvpnas 2>/dev/null || true
    systemctl start openvpnas 2>/dev/null || true
    
    while [ $attempt -le $max_attempts ]; do
        # Check if services are running
        if systemctl is-active --quiet openvpnas 2>/dev/null; then
            # Additional check - try to connect to the admin interface
            if curl -k -s -f https://localhost:943/admin >/dev/null 2>&1; then
                log_success "OpenVPN AS is fully ready (attempt $attempt/$max_attempts)"
                return 0
            fi
        fi
        
        # Progress indicators
        if [ $((attempt % 10)) -eq 0 ]; then
            log_info "Still waiting for services... (attempt $attempt/$max_attempts)"
        fi
        
        sleep 3
        attempt=$((attempt + 1))
    done
    
    log_warning "OpenVPN AS services are taking longer than expected to start"
    log_info "Checking service status for debugging..."
    systemctl status openvpnas --no-pager -l 2>/dev/null || true
    
    log_info "Continuing with configuration..."
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Stop services for configuration
    systemctl stop openvpnas 2>/dev/null || true
    sleep 5
    
    # Configure admin password with retry
    local password_set=0
    for i in {1..5}; do
        if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
            log_success "Admin password configured successfully"
            password_set=1
            break
        else
            log_warning "Failed to set admin password (attempt $i/5), retrying..."
            sleep 5
        fi
    done
    
    if [ $password_set -eq 0 ]; then
        log_warning "Failed to set admin password after multiple attempts"
    fi
    
    # Configure other settings
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser" --value "$ADMIN_USER" ConfigPut >/dev/null 2>&1 || true
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut >/dev/null 2>&1 || true
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut >/dev/null 2>&1 || true
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut >/dev/null 2>&1 || true
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut >/dev/null 2>&1 || true
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut >/dev/null 2>&1 || true
    /usr/local/openvpn_as/scripts/sacli --key "cs.daemon.enable" --value "true" ConfigPut >/dev/null 2>&1 || true
    
    # Start services
    systemctl start openvpnas 2>/dev/null || true
    
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
    listen 80;
    server_name $DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $NGINX_PORT ssl;
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
    ufw allow ssh
    ufw allow "$NGINX_PORT/tcp"
    ufw allow "80/tcp"
    ufw allow "1194/udp"
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
    systemctl status openvpnas --no-pager -l 2>/dev/null || echo "OpenVPN AS service status unavailable"
    
    echo
    echo "=== ACCESS INFORMATION ==="
    log_success "Admin Interface: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    log_success "Client Interface: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo
    echo "=== CREDENTIALS ==="
    echo "Username: $ADMIN_USER"
    echo "Password: [The password you set during installation]"
    echo
    echo "=== VERIFICATION ==="
    
    # Test pyovpn import
    if python3 -c "import sys; sys.path.insert(0, '/usr/local/openvpn_as/lib/python'); import pyovpn; print('✓ pyovpn module imports successfully')" 2>/dev/null; then
        log_success "✓ pyovpn module is working correctly"
    else
        log_error "✗ pyovpn module is not working"
    fi
    
    echo
    echo "=== TROUBLESHOOTING ==="
    echo "If you encounter issues:"
    echo "1. Check service status: systemctl status openvpnas"
    echo "2. View logs: journalctl -u openvpnas -f"
    echo "3. Test pyovpn: python3 -c \"import sys; sys.path.insert(0, '/usr/local/openvpn_as/lib/python'); import pyovpn; print('SUCCESS')\""
    echo "4. Check Nginx: systemctl status nginx"
    echo
    echo "For network access, add to hosts file on other machines:"
    echo "$SERVER_IP $DOMAIN_NAME"
}

# Main installation function
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS Installer for Ubuntu 24.04"
    echo "    Complete Fix for Missing pyovpn.zip"
    echo "=================================================="
    echo
    
    # Trap to handle script interruption
    trap 'log_error "Script interrupted by user"; exit 1' INT TERM
    
    check_root
    detect_os
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
    verify_installation
    
    log_success "OpenVPN Access Server installation completed successfully!"
    echo
    log_info "Important: It may take 1-2 minutes for all services to be fully operational"
    log_info "Access your VPN administration at: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo
}

# Run main function
main "$@"
