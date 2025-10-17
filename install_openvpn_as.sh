#!/bin/bash

# OpenVPN AS Installation Script with Local Domain & Hosts Auto-Configuration

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
        exit 1
    fi
    
    # Get server IP address
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi
    
    # Get hostname
    SERVER_HOSTNAME=$(hostname)
    
    log_info "Detected: $OS_NAME $OS_VERSION ($OS_CODENAME)"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
    
    if command -v apt-get &> /dev/null; then
        PKG_MGR="deb"
        log_success "Detected Debian/Ubuntu system (apt)"
    else
        log_error "Unsupported package manager"
        exit 1
    fi
}

# Generate suggested local domains
generate_domain_suggestions() {
    local suggestions=()
    
    # Option 1: Use hostname with .local domain
    suggestions+=("$SERVER_HOSTNAME.local")
    
    # Option 2: Use hostname with .test domain
    suggestions+=("$SERVER_HOSTNAME.test")
    
    # Option 3: Use hostname with .lan domain
    suggestions+=("$SERVER_HOSTNAME.lan")
    
    # Option 4: Use vpn prefix with hostname
    suggestions+=("vpn.$SERVER_HOSTNAME.local")
    
    # Option 5: Use openvpn prefix
    suggestions+=("openvpn.$SERVER_HOSTNAME.local")
    
    # Option 6: Simple vpn domain
    suggestions+=("vpn.local")
    
    # Option 7: Simple openvpn domain
    suggestions+=("openvpn.local")
    
    echo "${suggestions[@]}"
}

# User input function with domain suggestions
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
    
    read -p "Choose a domain (1-${#DOMAIN_SUGGESTIONS[@]}) or enter custom domain: " domain_choice
    
    if [[ "$domain_choice" =~ ^[0-9]+$ ]] && [ "$domain_choice" -ge 1 ] && [ "$domain_choice" -le "${#DOMAIN_SUGGESTIONS[@]}" ]; then
        DOMAIN_NAME="${DOMAIN_SUGGESTIONS[$((domain_choice-1))]}"
        log_success "Selected domain: $DOMAIN_NAME"
    else
        DOMAIN_NAME="$domain_choice"
        # Validate custom domain
        if [[ -z "$DOMAIN_NAME" ]]; then
            DOMAIN_NAME="${DOMAIN_SUGGESTIONS[0]}"
            log_info "Using default domain: $DOMAIN_NAME"
        elif [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            log_error "Invalid domain name. Using default."
            DOMAIN_NAME="${DOMAIN_SUGGESTIONS[0]}"
        fi
    fi
    
    echo
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    read -s -p "Enter admin password (min 4 characters): " ADMIN_PASSWORD
    echo
    read -p "Enter OpenVPN AS port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    read -p "Enter Nginx virtual host port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    # Validate inputs
    if [ -z "$ADMIN_PASSWORD" ]; then
        log_error "Admin password is required"
        exit 1
    fi
    
    if [ ${#ADMIN_PASSWORD} -lt 4 ]; then
        log_error "Admin password must be at least 4 characters long"
        exit 1
    fi
    
    # Display configuration summary
    echo
    log_info "Configuration Summary:"
    echo "  Domain: $DOMAIN_NAME"
    echo "  Admin User: $ADMIN_USER"
    echo "  OpenVPN Port: $OPENVPN_PORT"
    echo "  Nginx Port: $NGINX_PORT"
    echo "  Server IP: $SERVER_IP"
    echo
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
    
    # Also add localhost entry for redundancy
    if [[ "$SERVER_IP" != "127.0.0.1" ]]; then
        echo "127.0.0.1    $DOMAIN_NAME" >> /etc/hosts
    fi
    
    # Add IPv6 entry as well
    echo "::1          $DOMAIN_NAME" >> /etc/hosts
    
    log_success "Added $DOMAIN_NAME to /etc/hosts pointing to $SERVER_IP"
    
    # Display the added entries
    log_info "Current hosts entries for $DOMAIN_NAME:"
    grep "$DOMAIN_NAME" /etc/hosts
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
    log_info "Setting up OpenVPN AS repository..."
    
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
    
    # Set host name - CRITICAL for virtual hosts
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut >/dev/null 2>&1
    
    # Configure ports for Nginx reverse proxy
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut >/dev/null 2>&1
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut >/dev/null 2>&1
    
    # Enable port sharing for Nginx
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut >/dev/null 2>&1
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut >/dev/null 2>&1
    
    # Additional configuration for stability
    /usr/local/openvpn_as/scripts/sacli --key "cs.daemon.enable" --value "true" ConfigPut >/dev/null 2>&1
    
    # Start services
    /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1
    sleep 10
    
    log_success "OpenVPN AS configured successfully"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates for $DOMAIN_NAME..."
    
    # Create directory if it doesn't exist
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    # Generate certificate with the domain name
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    
    log_warning "Using self-signed certificates for $DOMAIN_NAME"
}

# Configure Nginx with virtual host
configure_nginx() {
    log_info "Configuring Nginx virtual host for $DOMAIN_NAME..."
    
    # Stop Nginx first
    systemctl stop nginx
    
    # Create Nginx configuration with virtual host
    cat > /etc/nginx/sites-available/openvpn-as << EOF
# OpenVPN AS Virtual Host Configuration for $DOMAIN_NAME
# Auto-generated by installation script

upstream openvpn_backend {
    server 127.0.0.1:$OPENVPN_PORT;
    keepalive 32;
}

# HTTPS Server for $DOMAIN_NAME
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
    
    # Proxy Settings
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
        
        # Timeouts
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

# HTTP to HTTPS redirect for $DOMAIN_NAME
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
        exit 1
    fi
    
    # Start Nginx
    systemctl enable nginx
    systemctl restart nginx
    
    log_success "Nginx virtual host configured for $DOMAIN_NAME"
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

# Test domain resolution
test_domain_resolution() {
    log_info "Testing domain resolution for $DOMAIN_NAME..."
    
    echo
    echo "=== DOMAIN RESOLUTION TEST ==="
    
    # Test using getent
    if getent hosts "$DOMAIN_NAME" > /dev/null; then
        log_success "✓ Domain $DOMAIN_NAME resolves correctly"
        getent hosts "$DOMAIN_NAME"
    else
        log_error "✗ Domain $DOMAIN_NAME does not resolve"
    fi
    
    # Test using ping (will only work if domain points to reachable IP)
    if ping -c 1 -W 1 "$DOMAIN_NAME" &> /dev/null; then
        log_success "✓ Domain $DOMAIN_NAME is reachable via ping"
    else
        log_warning "⚠ Domain $DOMAIN_NAME is not reachable via ping (may be normal for local domains)"
    fi
    
    # Test using curl locally
    if curl -k -s -f "https://$DOMAIN_NAME:$NGINX_PORT" > /dev/null; then
        log_success "✓ Domain $DOMAIN_NAME is accessible via HTTPS"
    else
        log_error "✗ Domain $DOMAIN_NAME is not accessible via HTTPS"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    echo
    echo "=== SERVICE STATUS ==="
    /usr/local/openvpn_as/scripts/sacli status
    
    echo
    echo "=== NETWORK CONNECTIONS ==="
    netstat -tlnp | grep -E "($OPENVPN_PORT|$NGINX_PORT|943|443)"
    
    echo
    echo "=== LOCAL ACCESS TESTS ==="
    if curl -k -s -f "https://127.0.0.1:$OPENVPN_PORT/admin" > /dev/null; then
        log_success "✓ OpenVPN AS backend accessible locally"
    else
        log_error "✗ OpenVPN AS backend not accessible locally"
    fi
    
    if curl -k -s -f "https://127.0.0.1:$NGINX_PORT/admin" > /dev/null; then
        log_success "✓ Nginx proxy accessible locally"
    else
        log_error "✗ Nginx proxy not accessible locally"
    fi
    
    echo
    echo "=== DOMAIN ACCESS TESTS ==="
    if curl -k -s -f "https://$DOMAIN_NAME:$NGINX_PORT/admin" > /dev/null; then
        log_success "✓ Domain $DOMAIN_NAME accessible via Nginx"
    else
        log_error "✗ Domain $DOMAIN_NAME not accessible via Nginx"
    fi
}

# Display final summary
show_summary() {
    log_success "OpenVPN Access Server installation completed!"
    echo
    echo "=== INSTALLATION SUMMARY ==="
    echo "Local Domain: $DOMAIN_NAME"
    echo "Server IP: $SERVER_IP"
    echo "Admin Username: $ADMIN_USER"
    echo "Admin Interface: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo "Client Interface: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo
    echo "=== HOSTS CONFIGURATION ==="
    echo "The domain $DOMAIN_NAME has been added to /etc/hosts"
    echo "pointing to $SERVER_IP"
    echo
    echo "=== ACCESS INSTRUCTIONS ==="
    echo "1. On this server: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo "2. On local network: https://$SERVER_IP:$NGINX_PORT/admin"
    echo "3. Add $DOMAIN_NAME to hosts file on other machines to access via domain"
    echo
    echo "=== QUICK COMMANDS ==="
    echo "Check status: /usr/local/openvpn_as/scripts/sacli status"
    echo "Restart OpenVPN: /usr/local/openvpn_as/scripts/sacli restart"
    echo "Restart Nginx: systemctl restart nginx"
    echo "View logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo
    echo "=== FOR OTHER COMPUTERS ==="
    echo "To access from other computers, add this line to their hosts file:"
    echo "$SERVER_IP    $DOMAIN_NAME"
    echo
    echo "Windows: C:\\Windows\\System32\\drivers\\etc\\hosts"
    echo "Linux/Mac: /etc/hosts"
    echo
}

# Main installation function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Installer with Local Domain"
    echo "=========================================="
    echo
    
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
    test_domain_resolution
    verify_installation
    show_summary
}

# Run main function
main "$@"
