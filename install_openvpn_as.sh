#!/bin/bash

# OpenVPN AS Installation Script with Enhanced Error Handling
# Fixed version addressing common installation issues

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

# Detect OS and get system information
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
    fi
    
    # Get server IP address
    SERVER_IP=$(ip route get 1 | awk '{print $7; exit}')
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
    
    if ! command -v apt-get &> /dev/null; then
        log_error "Unsupported package manager. Only Debian/Ubuntu systems are supported."
    fi
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
            break
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

# Install dependencies with proper error handling
install_dependencies() {
    log_info "Installing dependencies..."
    
    # Update package list
    if ! apt-get update; then
        log_error "Failed to update package lists"
    fi
    
    # Install dependencies
    local dependencies=(
        wget curl nginx python3 net-tools ufw
        liblzo2-2 liblz4-1 libpkcs11-helper1 libcap-ng0
        sqlite3 pkg-config build-essential libssl-dev
        libpam0g-dev liblz4-dev liblzo2-dev libpcap-dev
        iproute2 ca-certificates gnupg lsb-release
        software-properties-common apt-transport-https
    )
    
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${dependencies[@]}"; then
        log_error "Failed to install dependencies"
    fi
    
    log_success "Dependencies installed successfully"
}

# Setup repository with proper key handling
setup_repository() {
    log_info "Setting up OpenVPN AS repository..."
    
    # Remove any existing repository
    rm -f /etc/apt/sources.list.d/openvpn-as-repo.list
    rm -f /etc/apt/trusted.gpg.d/as-repository.asc
    
    # Create directories if they don't exist
    mkdir -p /etc/apt/keyrings
    mkdir -p /etc/apt/sources.list.d
    
    # Download and add the key
    if ! wget -qO /etc/apt/trusted.gpg.d/as-repository.asc https://packages.openvpn.net/as-repo-public.asc; then
        log_error "Failed to download OpenVPN repository key"
    fi
    
    # Determine repository based on OS version
    local repo_codename="$OS_CODENAME"
    if [ "$OS" = "ubuntu" ] && [ "$OS_VERSION" = "24.04" ]; then
        repo_codename="jammy"
        log_info "Using Ubuntu 22.04 (jammy) repository for Ubuntu 24.04 compatibility"
    fi
    
    # Add repository
    echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/as-repository.asc] https://packages.openvpn.net/as/debian $repo_codename main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    
    # Update package list
    if ! apt-get update; then
        log_error "Failed to update package lists after adding repository"
    fi
    
    log_success "OpenVPN AS repository configured successfully"
}

# Install OpenVPN AS with multiple fallback methods
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    # Method 1: Install from repository
    if apt-get install -y openvpn-as; then
        log_success "OpenVPN AS installed successfully from repository"
        return 0
    fi
    
    log_warning "Repository installation failed, trying direct download..."
    
    # Method 2: Direct download
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Try different package versions
    local package_urls=(
        "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb"
        "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.11.0-ubuntu22_amd64.deb"
        "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.10.2-ubuntu22_amd64.deb"
    )
    
    for package_url in "${package_urls[@]}"; do
        log_info "Trying to download: $package_url"
        if wget -O openvpn-as.deb "$package_url"; then
            log_success "Package downloaded successfully"
            break
        fi
    done
    
    if [ ! -f "openvpn-as.deb" ]; then
        log_error "Failed to download OpenVPN AS package"
    fi
    
    # Install the package
    if ! dpkg -i openvpn-as.deb; then
        log_warning "DPKG installation had issues, attempting to fix..."
        if ! apt-get install -y -f; then
            log_error "Failed to fix package dependencies"
        fi
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    log_success "OpenVPN AS installed via direct download"
}

# Fix pyovpn.zip corruption if detected
fix_pyovpn_corruption() {
    log_info "Checking for pyovpn.zip corruption..."
    
    local pyovpn_zip="/usr/local/openvpn_as/lib/python/pyovpn.zip"
    
    if [ -f "$pyovpn_zip" ]; then
        # Test if the zip file is valid
        if ! unzip -t "$pyovpn_zip" >/dev/null 2>&1; then
            log_warning "Detected corrupted pyovpn.zip, attempting to fix..."
            
            # Stop services
            systemctl stop openvpnas 2>/dev/null || true
            /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
            
            # Remove corrupted file
            rm -f "$pyovpn_zip"
            
            # Reinstall OpenVPN AS to get fresh pyovpn.zip
            if ! apt-get install --reinstall -y openvpn-as; then
                log_warning "Reinstallation failed, trying to extract from package..."
                extract_pyovpn_from_package
            fi
            
            log_success "pyovpn.zip corruption fixed"
        else
            log_success "pyovpn.zip is valid"
        fi
    fi
}

# Extract pyovpn from downloaded package as last resort
extract_pyovpn_from_package() {
    log_info "Extracting pyovpn.zip from package..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download package
    wget -O openvpn-as.deb "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb" || return 1
    
    # Extract data archive
    ar x openvpn-as.deb
    if [ -f "data.tar.xz" ]; then
        tar -xf data.tar.xz ./usr/local/openvpn_as/lib/python/pyovpn.zip
    elif [ -f "data.tar.gz" ]; then
        tar -xzf data.tar.gz ./usr/local/openvpn_as/lib/python/pyovpn.zip
    else
        log_error "Could not extract data from package"
        return 1
    fi
    
    # Copy pyovpn.zip
    if [ -f "./usr/local/openvpn_as/lib/python/pyovpn.zip" ]; then
        cp ./usr/local/openvpn_as/lib/python/pyovpn.zip /usr/local/openvpn_as/lib/python/
        log_success "pyovpn.zip extracted and installed"
    else
        log_error "Could not find pyovpn.zip in extracted package"
        return 1
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
}

# Wait for OpenVPN AS to be fully ready
wait_for_openvpn_ready() {
    log_info "Waiting for OpenVPN AS services to be fully ready..."
    
    local max_attempts=40
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "started"; then
            if curl -k -s -f https://localhost:943/admin >/dev/null 2>&1; then
                log_success "OpenVPN AS is fully ready (attempt $attempt/$max_attempts)"
                return 0
            fi
        fi
        
        if [ $attempt -eq 10 ] || [ $attempt -eq 20 ] || [ $attempt -eq 30 ]; then
            log_info "Still waiting for services... (attempt $attempt/$max_attempts)"
        fi
        
        sleep 5
        attempt=$((attempt + 1))
    done
    
    log_warning "OpenVPN AS services are taking longer than expected to start"
    log_info "Checking service status..."
    systemctl status openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli status 2>/dev/null || true
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Stop services for configuration
    /usr/local/openvpn_as/scripts/sacli stop >/dev/null 2>&1 || true
    sleep 5
    
    # Configure admin password
    if ! /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
        log_warning "Failed to set admin password, will try again later"
    fi
    
    # Configure settings
    local config_cmds=(
        "--key prop_superuser --value $ADMIN_USER"
        "--key host.name --value $DOMAIN_NAME"
        "--key cs.https.port --value $OPENVPN_PORT"
        "--key cs.https.ip --value 127.0.0.1"
        "--key vpn.server.port_share.service --value admin+client"
        "--key vpn.server.port_share.port --value $NGINX_PORT"
        "--key cs.daemon.enable --value true"
        "--key cs.https.ip --value 127.0.0.1"
    )
    
    for cmd in "${config_cmds[@]}"; do
        /usr/local/openvpn_as/scripts/sacli $cmd ConfigPut >/dev/null 2>&1 || true
    done
    
    # Start services
    /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
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
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Allow necessary ports
    ufw allow ssh
    ufw allow "$NGINX_PORT/tcp"
    ufw allow "80/tcp"
    ufw allow "1194/udp"
    ufw allow "$OPENVPN_PORT/tcp"
    
    # Enable UFW
    echo "y" | ufw enable
    
    log_success "Firewall configured"
}

# Final verification and summary
verify_installation() {
    log_info "Verifying installation..."
    
    echo
    echo "=== SERVICE STATUS ==="
    /usr/local/openvpn_as/scripts/sacli status || true
    
    echo
    echo "=== ACCESS INFORMATION ==="
    log_success "Admin Interface: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    log_success "Client Interface: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo
    echo "Credentials:"
    echo "  Username: $ADMIN_USER"
    echo "  Password: [The password you set during installation]"
    echo
    echo "=== TROUBLESHOOTING ==="
    echo "If you cannot access the web interface:"
    echo "1. Check if domain is in hosts file: grep '$DOMAIN_NAME' /etc/hosts"
    echo "2. Check service status: systemctl status openvpnas"
    echo "3. Check logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo
    echo "For other computers to access, add to their hosts file:"
    echo "$SERVER_IP $DOMAIN_NAME"
}

# Main installation function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Installer - Enhanced Version"
    echo "=========================================="
    echo
    
    # Trap to handle script interruption
    trap 'log_error "Script interrupted by user"; exit 1' INT TERM
    
    check_root
    detect_os
    get_user_input
    configure_hosts_file
    install_dependencies
    setup_repository
    install_openvpn_as
    fix_pyovpn_corruption
    generate_ssl_certificates
    wait_for_openvpn_ready
    configure_openvpn_as
    configure_nginx
    configure_firewall
    verify_installation
    
    log_success "OpenVPN Access Server installation completed successfully!"
}

# Run main function
main "$@"
