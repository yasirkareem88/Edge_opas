#!/bin/bash

# Fixed OpenVPN Access Server Installation Script for Ubuntu 24.04
# Enhanced version that handles repository issues and provides fallbacks

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

# Detect OS and handle Ubuntu 24.04 specifically
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
    
    # Detect package manager
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
    read -s -p "Enter admin password: " ADMIN_PASSWORD
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

# Fix for Ubuntu 24.04 - Use Ubuntu 22.04 repositories
setup_ubuntu_24_repository() {
    log_info "Setting up repository for Ubuntu 24.04..."
    
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

# Alternative installation method - direct package download
download_and_install_direct() {
    log_info "Attempting direct package download..."
    
    cd /tmp
    rm -f openvpn-as*.deb
    
    # Try multiple URL patterns
    BASE_URL="https://packages.openvpn.net/as"
    
    # Pattern 1: Latest stable for Ubuntu 22.04
    wget -O openvpn-as.deb "$BASE_URL/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb" ||
    wget -O openvpn-as.deb "$BASE_URL/pool/main/o/openvpn-as/openvpn-as_2.11.0-ubuntu22_amd64.deb" ||
    wget -O openvpn-as.deb "$BASE_URL/pool/main/o/openvpn-as/openvpn-as_2.10.0-ubuntu22_amd64.deb"
    
    if [ -f "openvpn-as.deb" ] && [ -s "openvpn-as.deb" ]; then
        log_success "Package downloaded successfully"
        
        # Install with dependency resolution
        dpkg -i openvpn-as.deb || {
            log_info "Resolving dependencies..."
            apt-get install -y -f
        }
        return 0
    else
        log_error "Failed to download package"
        return 1
    fi
}

# Manual installation with dependency override
manual_install_with_override() {
    log_info "Attempting manual installation with dependency override..."
    
    cd /tmp
    
    # Download the package
    wget -O openvpn-as.deb "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb"
    
    if [ ! -f "openvpn-as.deb" ]; then
        log_error "Could not download package"
        return 1
    fi
    
    # Create a temporary directory for package modification
    mkdir -p /tmp/openvpn-pkg
    cd /tmp/openvpn-pkg
    
    # Extract the package
    dpkg-deb -x ../openvpn-as.deb .
    dpkg-deb -e ../openvpn-as.deb DEBIAN
    
    # Modify control file to be less strict about dependencies
    if [ -f DEBIAN/control ]; then
        sed -i 's/Depends:.*/Depends: libc6, libssl3, liblzo2-2, liblz4-1, libcap-ng0, libpkcs11-helper1, python3, sqlite3/g' DEBIAN/control
    fi
    
    # Repackage
    dpkg-deb -b . /tmp/openvpn-as-modified.deb
    
    # Install the modified package
    cd /tmp
    dpkg -i openvpn-as-modified.deb || apt-get install -y -f
    
    if systemctl is-active --quiet openvpnas; then
        log_success "Manual installation successful"
        return 0
    else
        log_error "Manual installation failed"
        return 1
    fi
}

# Docker installation as fallback
install_openvpn_as_docker() {
    log_info "Setting up OpenVPN AS using Docker..."
    
    if ! command -v docker &> /dev/null; then
        log_info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        usermod -aG docker $SUDO_USER
    fi
    
    # Stop any existing container
    docker stop openvpn-as 2>/dev/null || true
    docker rm openvpn-as 2>/dev/null || true
    
    # Create Docker compose file
    cat > /tmp/docker-compose.yml << EOF
version: '3.8'
services:
  openvpn-as:
    image: linuxserver/openvpn-as:latest
    container_name: openvpn-as
    cap_add:
      - NET_ADMIN
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
      - INTERFACE=eth0
    volumes:
      - /opt/openvpn-as/config:/config
    ports:
      - $NGINX_PORT:943
      - 1194:1194/udp
    restart: unless-stopped
EOF
    
    # Run Docker container
    docker compose -f /tmp/docker-compose.yml up -d
    
    if [ $? -eq 0 ]; then
        log_success "OpenVPN AS Docker container started successfully"
        DOCKER_MODE=1
        return 0
    else
        log_error "Failed to start OpenVPN AS Docker container"
        return 1
    fi
}

# Main installation function
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    # Method 1: Try standard repository installation
    log_info "Method 1: Standard repository installation..."
    setup_ubuntu_24_repository
    
    if apt-get install -y openvpn-as; then
        log_success "Repository installation successful"
        return 0
    fi
    
    # Method 2: Direct package download
    log_info "Method 2: Direct package download..."
    if download_and_install_direct; then
        return 0
    fi
    
    # Method 3: Manual installation with dependency override
    log_info "Method 3: Manual installation with dependency override..."
    if manual_install_with_override; then
        return 0
    fi
    
    # Method 4: Docker installation
    log_info "Method 4: Docker installation..."
    if install_openvpn_as_docker; then
        return 0
    fi
    
    # Final fallback
    log_error "All installation methods failed"
    log_info ""
    log_info "Manual installation instructions:"
    log_info "1. Visit: https://openvpn.net/vpn-software-packages/"
    log_info "2. Download Ubuntu 22.04 package manually"
    log_info "3. Install with: dpkg -i openvpn-as_2.12.0-ubuntu22_amd64.deb"
    log_info "4. Fix dependencies: apt-get install -y -f"
    exit 1
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    if [ "$DOCKER_MODE" = "1" ]; then
        log_info "Docker mode detected - configuration will be handled via Docker volumes"
        log_info "Access the web interface at: https://$DOMAIN_NAME:$NGINX_PORT"
        log_info "Default credentials: admin / password"
        return 0
    fi
    
    # Wait for services to start
    sleep 10
    
    # Set admin password
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASSWORD" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut
    
    # Configure for Nginx reverse proxy
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "web+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut
    
    # Additional configuration
    /usr/local/openvpn_as/scripts/sacli --key "cs.daemon.enable" --value "true" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut
    
    # Restart OpenVPN AS to apply changes
    /usr/local/openvpn_as/scripts/sacli start
    
    # Wait for service to fully start
    sleep 5
    
    log_success "OpenVPN AS configured successfully"
}

# Configure Nginx as reverse proxy
configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
    if [ "$DOCKER_MODE" = "1" ]; then
        log_info "Docker mode - Nginx configuration skipped (using Docker port mapping)"
        return 0
    fi
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
server {
    listen $NGINX_PORT ssl;
    server_name $DOMAIN_NAME;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy settings
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 90s;
        proxy_send_timeout 90s;
        proxy_read_timeout 90s;
    }
    
    client_max_body_size 100M;
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Disable default site
    if [ -f /etc/nginx/sites-enabled/default ]; then
        rm /etc/nginx/sites-enabled/default
    fi
    
    # Test Nginx configuration
    nginx -t
    if [ $? -eq 0 ]; then
        log_success "Nginx configuration test passed"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
    
    # Start and enable Nginx
    systemctl enable nginx
    systemctl restart nginx
    
    log_success "Nginx configured successfully"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
    
    log_warning "Using self-signed certificates. For production, use Let's Encrypt or a proper CA"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    ufw allow ssh
    ufw allow "$NGINX_PORT/tcp"
    ufw allow "1194/udp"
    ufw allow "$OPENVPN_PORT/tcp"
    echo "y" | ufw enable
    
    log_success "Firewall configured"
}

# Wait for service to be ready
wait_for_service() {
    log_info "Waiting for OpenVPN AS service to be ready..."
    
    if [ "$DOCKER_MODE" = "1" ]; then
        log_info "Docker mode - waiting for container to start..."
        sleep 30
        return 0
    fi
    
    local counter=12
    while [ $counter -gt 0 ]; do
        if /usr/local/openvpn_as/scripts/sacli status 2>&1 | grep -q -i "error:"; then
            sleep 5
            counter=$((counter - 1))
            log_info "Waiting for service... ($counter attempts left)"
        else
            log_success "Service is ready"
            return 0
        fi
    done
    
    log_warning "Service taking longer than expected to start"
    log_info "You can check status manually with: /usr/local/openvpn_as/scripts/sacli status"
}

# Display installation summary
show_summary() {
    log_success "Installation completed!"
    echo
    echo "=== Installation Summary ==="
    echo "Domain: $DOMAIN_NAME"
    echo "Admin Username: $ADMIN_USER"
    
    if [ "$DOCKER_MODE" = "1" ]; then
        echo "Installation Mode: Docker"
        echo "Admin Web Interface: https://$DOMAIN_NAME:$NGINX_PORT"
        echo "Default credentials: admin / password"
    else
        echo "Installation Mode: Native"
        echo "Admin Web Interface: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    fi
    
    echo "OpenVPN Port: 1194/udp"
    echo
    echo "=== Next Steps ==="
    echo "1. Configure DNS for $DOMAIN_NAME"
    echo "2. Access the web interface and complete setup"
    echo "3. Replace self-signed certificates"
    echo "4. Create client profiles"
    
    if [ "$DOCKER_MODE" = "1" ]; then
        echo
        echo "=== Docker Commands ==="
        echo "View logs: docker logs openvpn-as"
        echo "Restart: docker restart openvpn-as"
        echo "Stop: docker stop openvpn-as"
    fi
}

# Main installation function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Fixed Installer"
    echo "  for Ubuntu 24.04 Compatibility"
    echo "=========================================="
    echo
    
    # Initialize variables
    DOCKER_MODE=0
    
    # Execute installation steps
    check_root
    detect_os
    get_user_input
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    configure_openvpn_as
    configure_nginx
    configure_firewall
    wait_for_service
    show_summary
}

# Run main function
main "$@"
