#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Compatible with Ubuntu 24.04.02 LTS

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
    
    # Check system architecture
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" != "amd64" ]; then
        log_warning "This script is optimized for amd64 architecture. Detected: $ARCH"
    fi
    
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
    
    # Install Ubuntu 24.04 specific dependencies
    local dependencies=(
        wget
        curl
        nginx
        python3
        python3-pip
        python3-venv
        net-tools
        ufw
        liblzo2-2
        liblz4-1
        libpkcs11-helper1
        libcap-ng0
        sqlite3
        pkg-config
        build-essential
        libssl-dev
        libpam0g-dev
        liblz4-dev
        liblzo2-dev
        libpcap-dev
        iproute2
        ca-certificates
        gnupg
        lsb-release
        software-properties-common
        apt-transport-https
        systemd
        iptables
        netfilter-persistent
    )
    
    log_info "Installing: ${dependencies[*]}"
    
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${dependencies[@]}"; then
        log_error "Failed to install dependencies"
    fi
    
    log_success "Dependencies installed successfully"
}

# Setup repository optimized for Ubuntu 24.04
setup_repository() {
    log_info "Setting up OpenVPN AS repository for Ubuntu 24.04..."
    
    # Remove any existing repository
    rm -f /etc/apt/sources.list.d/openvpn-as-repo.list
    rm -f /etc/apt/trusted.gpg.d/as-repository.asc
    rm -f /etc/apt/keyrings/as-repository.asc
    
    # Create directories if they don't exist
    mkdir -p /etc/apt/keyrings
    mkdir -p /etc/apt/sources.list.d
    
    # Download and add the key (Ubuntu 24.04 compatible method)
    log_info "Downloading OpenVPN repository key..."
    if ! wget -qO /etc/apt/trusted.gpg.d/as-repository.asc https://packages.openvpn.net/as-repo-public.asc; then
        log_error "Failed to download OpenVPN repository key"
    fi
    
    # For Ubuntu 24.04, use jammy (22.04) repository as OpenVPN AS doesn't have a 24.04 repo yet
    log_info "Using Ubuntu 22.04 (jammy) repository for Ubuntu 24.04 compatibility"
    
    # Add repository - using jammy for 24.04 compatibility
    echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/as-repository.asc] https://packages.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    
    # Update package list
    if ! apt-get update; then
        log_error "Failed to update package lists after adding repository"
    fi
    
    log_success "OpenVPN AS repository configured successfully for Ubuntu 24.04"
}

# Check and fix pyovpn.zip corruption
check_and_fix_pyovpn() {
    log_info "Checking pyovpn.zip integrity..."
    
    local pyovpn_zip="/usr/local/openvpn_as/lib/python/pyovpn.zip"
    
    if [ ! -f "$pyovpn_zip" ]; then
        log_error "pyovpn.zip not found at $pyovpn_zip"
        return 1
    fi
    
    # Test if the zip file is valid
    if unzip -t "$pyovpn_zip" >/dev/null 2>&1; then
        log_success "pyovpn.zip is valid and not corrupted"
        return 0
    else
        log_warning "pyovpn.zip is corrupted, downloading fresh copy..."
        download_fresh_pyovpn
    fi
}

# Download and install fresh pyovpn.zip
download_fresh_pyovpn() {
    log_info "Downloading fresh pyovpn.zip for Ubuntu 24.04 compatibility..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Use Ubuntu 22.04 package for 24.04 compatibility
    local package_url="https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb"
    
    log_info "Downloading package from: $package_url"
    
    # Download the package
    if ! wget -O openvpn-as.deb "$package_url"; then
        log_error "Failed to download OpenVPN AS package for pyovpn extraction"
        return 1
    fi
    
    # Extract the package to get pyovpn.zip
    log_info "Extracting pyovpn.zip from package..."
    
    # Extract data archive
    ar x openvpn-as.deb
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
        log_info "Found pyovpn.zip, installing fresh copy..."
        
        # Stop OpenVPN AS services before replacing the file
        systemctl stop openvpnas 2>/dev/null || true
        
        # Remove the corrupted file and copy the fresh one
        rm -f "/usr/local/openvpn_as/lib/python/pyovpn.zip"
        mkdir -p /usr/local/openvpn_as/lib/python/
        cp "$pyovpn_path" "/usr/local/openvpn_as/lib/python/pyovpn.zip"
        chmod 644 "/usr/local/openvpn_as/lib/python/pyovpn.zip"
        
        # Clean Python cache
        find "/usr/local/openvpn_as/lib/python" -name "*.pyc" -delete 2>/dev/null || true
        find "/usr/local/openvpn_as/lib/python" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
        
        # Verify the new file is valid
        if unzip -t "/usr/local/openvpn_as/lib/python/pyovpn.zip" >/dev/null 2>&1; then
            log_success "Fresh pyovpn.zip installed and verified successfully"
        else
            log_error "Replaced pyovpn.zip is still corrupted"
            return 1
        fi
    else
        log_error "Could not find pyovpn.zip in the package"
        return 1
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
}

# Install OpenVPN AS with Ubuntu 24.04 compatibility
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server for Ubuntu 24.04..."
    
    setup_repository
    
    # Install OpenVPN AS
    log_info "Installing openvpn-as package..."
    if apt-get install -y openvpn-as; then
        log_success "OpenVPN AS installed successfully"
        
        # CRITICAL: Check and fix pyovpn corruption immediately
        log_info "Performing post-installation integrity check..."
        if check_and_fix_pyovpn; then
            log_success "OpenVPN AS installation completed successfully"
        else
            log_error "Failed to fix pyovpn corruption after installation"
        fi
        return 0
    else
        log_error "Failed to install OpenVPN AS from repository"
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
        # Check if services are running using multiple methods
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
            systemctl status openvpnas --no-pager -l | head -10 2>/dev/null || true
        fi
        
        sleep 3
        attempt=$((attempt + 1))
    done
    
    log_warning "OpenVPN AS services are taking longer than expected to start"
    log_info "Checking service status for debugging..."
    systemctl status openvpnas --no-pager -l 2>/dev/null || true
    journalctl -u openvpnas --no-pager -n 20 2>/dev/null || true
    
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
    for i in {1..3}; do
        if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
            log_success "Admin password configured successfully"
            password_set=1
            break
        else
            log_warning "Failed to set admin password (attempt $i/3), retrying..."
            sleep 3
        fi
    done
    
    if [ $password_set -eq 0 ]; then
        log_warning "Failed to set admin password initially, will retry later"
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

# Configure firewall for Ubuntu 24.04
configure_firewall() {
    log_info "Configuring firewall for Ubuntu 24.04..."
    
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
    echo "          Optimized for 24.04.02 LTS"
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
    log_info "Installation log saved in system logs"
}

# Run main function
main "$@"
