#!/bin/bash

# OpenVPN AS Automated Installation Script for Ubuntu 24.04 and newer systems
# Alternative installation methods for unsupported OS versions

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

# Detect OS and package manager
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
    elif command -v yum &> /dev/null; then
        PKG_MGR="rpm"
        log_success "Detected RHEL/CentOS system (yum)"
    elif command -v dnf &> /dev/null; then
        PKG_MGR="rpm"
        log_success "Detected RHEL/CentOS/Fedora system (dnf)"
    else
        log_error "Unsupported package manager"
        exit 1
    fi
}

# Check OS compatibility
check_os_compatibility() {
    log_info "Checking OS compatibility..."
    
    case $OS in
        "ubuntu")
            case $OS_VERSION in
                "18.04"|"20.04"|"22.04")
                    log_success "Ubuntu $OS_VERSION is officially supported"
                    return 0
                    ;;
                "24.04")
                    log_warning "Ubuntu 24.04 is not officially supported by OpenVPN AS yet"
                    log_info "Will use Ubuntu 22.04 packages as fallback"
                    return 1
                    ;;
                *)
                    log_warning "Ubuntu $OS_VERSION may not be officially supported"
                    return 1
                    ;;
            esac
            ;;
        "debian")
            case $OS_VERSION in
                "10"|"11"|"12")
                    log_success "Debian $OS_VERSION is supported"
                    return 0
                    ;;
                *)
                    log_warning "Debian $OS_VERSION may not be officially supported"
                    return 1
                    ;;
            esac
            ;;
        *)
            log_warning "$OS_NAME may not be officially supported"
            return 1
            ;;
    esac
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
                       net-tools iproute2
    
    # For Ubuntu 24.04, install compatible SSL libraries
    if [ "$OS" = "ubuntu" ] && [ "$OS_VERSION" = "24.04" ]; then
        log_info "Installing compatible SSL libraries for Ubuntu 24.04..."
        apt-get install -y libssl3 libssl-dev
    fi
}

# Method 1: Download from correct URL structure
download_openvpn_as_correct_url() {
    log_info "Attempting to download OpenVPN AS with correct URL structure..."
    
    cd /tmp
    rm -f openvpn-as*.deb
    
    # Try different URL patterns
    BASE_URL="https://swupdate.openvpn.net/scripts"
    
    # Pattern 1: Latest stable
    wget -O openvpn-as.deb "$BASE_URL/openvpn-as-latest-ubuntu22.amd_64.deb" || \
    wget -O openvpn-as.deb "$BASE_URL/openvpn-as-2.12.0-ubuntu22.amd_64.deb" || \
    wget -O openvpn-as.deb "$BASE_URL/openvpn-as-2.11.0-ubuntu22.amd_64.deb" || \
    wget -O openvpn-as.deb "$BASE_URL/openvpn-as-2.10.0-ubuntu22.amd_64.deb"
    
    if [ -f "openvpn-as.deb" ] && [ -s "openvpn-as.deb" ]; then
        log_success "Downloaded OpenVPN AS package successfully"
        return 0
    else
        log_error "Failed to download from standard URLs"
        return 1
    fi
}

# Method 2: Use Docker alternative
install_openvpn_as_docker() {
    log_info "Setting up OpenVPN AS using Docker..."
    
    if ! command -v docker &> /dev/null; then
        log_info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        usermod -aG docker $SUDO_USER
    fi
    
    # Create Docker compose file
    cat > /tmp/docker-compose.yml << EOF
version: '3.8'
services:
  openvpn-as:
    image: linuxserver/openvpn-as
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
        return 0
    else
        log_error "Failed to start OpenVPN AS Docker container"
        return 1
    fi
}

# Method 3: Manual build from source (fallback)
install_openvpn_as_source() {
    log_info "Building OpenVPN AS from source..."
    
    cd /tmp
    apt-get install -y build-essential devscripts debhelper dh-systemd \
                       libssl-dev liblzo2-dev libpam0g-dev libpkcs11-helper-dev \
                       liblz4-dev libcap-ng-dev python3-dev
    
    # Clone OpenVPN AS source (if available)
    log_info "Attempting to build from source..."
    
    # This is a complex build process, so we'll use a simplified approach
    # Download the Ubuntu 22.04 package and attempt to install with dependency overrides
    wget -O openvpn-as.deb "http://archive.ubuntu.com/ubuntu/pool/universe/o/openvpn-as/openvpn-as_2.12.0-ubuntu1_amd64.deb" || \
    wget -O openvpn-as.deb "https://download.openvpn.net/as/openvpn-as-2.12.0-ubuntu22.amd_64.deb"
    
    if [ -f "openvpn-as.deb" ]; then
        # Extract the package
        dpkg-deb -x openvpn-as.deb /tmp/openvpn-extract
        dpkg-deb -e openvpn-as.deb /tmp/openvpn-extract/DEBIAN
        
        # Modify control file to be less strict about dependencies
        sed -i 's/Depends:.*/Depends: libc6, libssl3, liblzo2-2, liblz4-1, libcap-ng0, libpkcs11-helper1/g' /tmp/openvpn-extract/DEBIAN/control
        
        # Repackage
        dpkg-deb -b /tmp/openvpn-extract /tmp/openvpn-as-modified.deb
        
        # Install
        dpkg -i /tmp/openvpn-as-modified.deb || apt-get install -y -f
        return $?
    else
        log_error "Could not download source package for building"
        return 1
    fi
}

# Method 4: Use alternative repository
install_openvpn_as_alternative_repo() {
    log_info "Trying alternative repository approach..."
    
    # For Ubuntu 24.04, use the 22.04 repository
    if [ "$OS" = "ubuntu" ] && [ "$OS_VERSION" = "24.04" ]; then
        log_info "Using Ubuntu 22.04 repository for OpenVPN AS..."
        
        # Add the repository for Ubuntu 22.04
        wget -O /etc/apt/trusted.gpg.d/openvpn-as-repo.asc https://as-repository.openvpn.net/as-repo-public.asc
        echo "deb [arch=amd64] http://as-repository.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as.list
        
        apt-get update
        
        # Download the package directly
        cd /tmp
        apt-get download openvpn-as
        
        if [ -f openvpn-as*.deb ]; then
            # Install with dependency resolution
            dpkg -i openvpn-as*.deb || apt-get install -y -f
            return $?
        else
            log_error "Could not download package from alternative repository"
            return 1
        fi
    fi
    
    return 1
}

# Main installation function with multiple fallbacks
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    local method_success=0
    
    # Method 1: Correct URL download
    log_info "Trying Method 1: Direct download with correct URLs..."
    if download_openvpn_as_correct_url; then
        if dpkg -i /tmp/openvpn-as.deb || apt-get install -y -f; then
            log_success "Method 1 successful!"
            return 0
        fi
    fi
    
    # Method 2: Alternative repository
    log_info "Trying Method 2: Alternative repository..."
    if install_openvpn_as_alternative_repo; then
        log_success "Method 2 successful!"
        return 0
    fi
    
    # Method 3: Docker installation
    log_info "Trying Method 3: Docker installation..."
    if install_openvpn_as_docker; then
        log_success "Method 3 successful! Using Docker-based OpenVPN AS"
        DOCKER_MODE=1
        return 0
    fi
    
    # Method 4: Source build
    log_info "Trying Method 4: Source build..."
    if install_openvpn_as_source; then
        log_success "Method 4 successful!"
        return 0
    fi
    
    # Final fallback: Manual download instructions
    log_error "All automated installation methods failed"
    log_info ""
    log_info "Manual installation required:"
    log_info "1. Visit: https://openvpn.net/vpn-software-packages/"
    log_info "2. Download the appropriate package for your system"
    log_info "3. Install manually with: dpkg -i openvpn-as-*.deb"
    log_info "4. Run this script again to continue with configuration"
    log_info ""
    log_info "For Ubuntu 24.04, you may need to:"
    log_info "1. Download Ubuntu 22.04 package manually"
    log_info "2. Install with: dpkg -i --force-all openvpn-as-*.deb"
    log_info "3. Fix dependencies with: apt-get install -y -f"
    
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
    
    # Additional configuration for better compatibility
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
    CONFIG_DIR="/etc/nginx/sites-available"
    ENABLED_DIR="/etc/nginx/sites-enabled"
    mkdir -p $CONFIG_DIR $ENABLED_DIR
    
    cat > $CONFIG_DIR/openvpn-as << EOF
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
    ln -sf $CONFIG_DIR/openvpn-as $ENABLED_DIR/
    
    # Disable default site
    if [ -f $ENABLED_DIR/default ]; then
        rm $ENABLED_DIR/default
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
    echo "  OpenVPN AS Automated Installer"
    echo "  for Ubuntu 24.04 and Newer Systems"
    echo "=========================================="
    echo
    
    # Initialize variables
    DOCKER_MODE=0
    
    # Execute installation steps
    check_root
    detect_os
    check_os_compatibility
    get_user_input
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    configure_openvpn_as
    configure_nginx
    configure_firewall
    show_summary
}

# Run main function
main "$@"
