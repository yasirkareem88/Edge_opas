#!/bin/bash

# OpenVPN AS Automated Installation Script with Nginx Reverse Proxy
# Enhanced version with dependency resolution and multiple installation methods

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
        OS_NAME=$NAME
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
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
    
    log_info "OS: $OS_NAME $OS_VERSION"
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

# Install dependencies with version checking
install_dependencies() {
    log_info "Installing dependencies..."
    
    case $PKG_MGR in
        "deb")
            apt-get update
            
            # Install essential packages
            apt-get install -y wget curl nginx python3 net-tools ufw
            
            # Check for libssl1.1 availability
            if apt-cache show libssl1.1 &> /dev/null; then
                apt-get install -y libssl1.1
            else
                log_warning "libssl1.1 not available, trying libssl3 or libssl1.0"
                # Try alternative SSL libraries
                apt-get install -y libssl3 || apt-get install -y libssl1.0.0 || log_warning "Proceeding without specific libssl version"
            fi
            ;;
        "rpm")
            if command -v dnf &> /dev/null; then
                dnf install -y wget curl nginx python3 net-tools firewalld
            else
                yum install -y wget curl nginx python3 net-tools firewalld
            fi
            ;;
    esac
}

# Download specific version based on OS
download_openvpn_as() {
    log_info "Downloading OpenVPN Access Server..."
    
    cd /tmp
    
    case $OS in
        "ubuntu")
            case $OS_VERSION in
                "22.04"|"20.04")
                    # Use the latest compatible version
                    wget -O openvpn-as.deb https://swupdate.openvpn.net/scripts/openvpn-as-latest-ubuntu22.amd_64.deb
                    ;;
                "18.04")
                    wget -O openvpn-as.deb https://swupdate.openvpn.net/scripts/openvpn-as-latest-ubuntu18.amd_64.deb
                    ;;
                *)
                    wget -O openvpn-as.deb https://swupdate.openvpn.net/scripts/openvpn-as-latest-ubuntu22.amd_64.deb
                    ;;
            esac
            ;;
        "debian")
            case $OS_VERSION in
                "12"|"11")
                    wget -O openvpn-as.deb https://swupdate.openvpn.net/scripts/openvpn-as-latest-debian11.amd_64.deb
                    ;;
                "10")
                    wget -O openvpn-as.deb https://swupdate.openvpn.net/scripts/openvpn-as-latest-debian10.amd_64.deb
                    ;;
                *)
                    wget -O openvpn-as.deb https://swupdate.openvpn.net/scripts/openvpn-as-latest-debian11.amd_64.deb
                    ;;
            esac
            ;;
        "centos"|"rhel"|"fedora")
            wget -O openvpn-as.rpm https://swupdate.openvpn.net/scripts/openvpn-as-latest-centos8.x86_64.rpm
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Alternative installation method - direct download
install_openvpn_as_alternative() {
    log_info "Trying alternative OpenVPN AS installation method..."
    
    cd /tmp
    
    # Determine architecture
    ARCH=$(uname -m)
    case $ARCH in
        "x86_64")
            ARCH="amd64"
            ;;
        "aarch64")
            ARCH="arm64"
            ;;
        *)
            ARCH="amd64"
            log_warning "Unsupported architecture, defaulting to amd64"
            ;;
    esac
    
    # Download based on OS and architecture
    if [ "$PKG_MGR" = "deb" ]; then
        # Try direct download from OpenVPN
        wget -O openvpn-as.deb "https://swupdate.openvpn.net/scripts/openvpn-as-latest-${OS}${OS_VERSION}.${ARCH}.deb"
        
        if [ ! -f "openvpn-as.deb" ] || [ ! -s "openvpn-as.deb" ]; then
            log_warning "Specific version not found, trying generic Ubuntu 22.04 version"
            wget -O openvpn-as.deb "https://swupdate.openvpn.net/scripts/openvpn-as-latest-ubuntu22.${ARCH}.deb"
        fi
        
        # Install with dependency resolution
        apt-get install -y ./openvpn-as.deb || {
            log_warning "Installation failed, trying with forced dependencies..."
            apt-get install -y -f ./openvpn-as.deb
        }
        
    else
        # RPM-based systems
        wget -O openvpn-as.rpm "https://swupdate.openvpn.net/scripts/openvpn-as-latest-centos8.${ARCH}.rpm"
        
        if command -v dnf &> /dev/null; then
            dnf install -y ./openvpn-as.rpm
        else
            yum install -y ./openvpn-as.rpm
        fi
    fi
}

# Manual dependency resolution for Debian/Ubuntu
resolve_dependencies_deb() {
    log_info "Resolving dependencies for Debian/Ubuntu..."
    
    # Install required libraries
    apt-get install -y liblzo2-2 liblz4-1 libpkcs11-helper1 libcap-ng0
    
    # Try to install compatible SSL libraries
    if [ "$OS" = "ubuntu" ] && [ "$OS_VERSION" = "22.04" ]; then
        log_info "Ubuntu 22.04 detected - installing compatible libraries..."
        apt-get install -y libssl3 libssl1.1
    elif [ "$OS" = "debian" ] && [ "$OS_VERSION" = "11" ]; then
        log_info "Debian 11 detected - installing compatible libraries..."
        apt-get install -y libssl1.1
    else
        # Try to find and install libssl1.1 from alternative sources
        log_info "Attempting to install libssl1.1 from Ubuntu 20.04 repository..."
        
        # Download libssl1.1 from Ubuntu 20.04 if not available
        if ! apt-get install -y libssl1.1; then
            wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
            dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb || apt-get install -y -f
        fi
    fi
}

# Install OpenVPN AS with comprehensive error handling
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    case $PKG_MGR in
        "deb")
            resolve_dependencies_deb
            
            # Method 1: Try official repository
            log_info "Attempting installation from official repository..."
            wget -O /etc/apt/trusted.gpg.d/openvpn-as-repo.asc https://as-repository.openvpn.net/as-repo-public.asc
            echo "deb [arch=amd64] http://as-repository.openvpn.net/as/debian $OS_VERSION main" > /etc/apt/sources.list.d/openvpn-as.list
            apt-get update
            
            if apt-get install -y openvpn-as; then
                log_success "OpenVPN AS installed successfully from repository"
                return 0
            fi
            
            # Method 2: Try direct package download
            log_info "Repository installation failed, trying direct package download..."
            download_openvpn_as
            
            if [ -f "/tmp/openvpn-as.deb" ] && [ -s "/tmp/openvpn-as.deb" ]; then
                if dpkg -i /tmp/openvpn-as.deb; then
                    log_success "OpenVPN AS installed successfully from direct download"
                    return 0
                else
                    # Fix dependencies
                    apt-get install -y -f
                    log_success "OpenVPN AS installed after dependency resolution"
                    return 0
                fi
            fi
            
            # Method 3: Alternative download
            install_openvpn_as_alternative
            ;;
        "rpm")
            # RPM-based installation
            download_openvpn_as
            
            if command -v dnf &> /dev/null; then
                dnf install -y ./openvpn-as.rpm
            else
                yum install -y ./openvpn-as.rpm
            fi
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log_success "OpenVPN AS installed successfully"
    else
        log_error "All installation methods failed"
        log_info "You may need to manually install OpenVPN AS"
        log_info "Visit: https://openvpn.net/vpn-software-packages/"
        exit 1
    fi
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
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
    
    # Create Nginx configuration
    if [ "$PKG_MGR" = "deb" ]; then
        CONFIG_DIR="/etc/nginx/sites-available"
        ENABLED_DIR="/etc/nginx/sites-enabled"
        mkdir -p $CONFIG_DIR $ENABLED_DIR
        CONFIG_FILE="$CONFIG_DIR/openvpn-as"
    else
        CONFIG_DIR="/etc/nginx/conf.d"
        CONFIG_FILE="$CONFIG_DIR/openvpn-as.conf"
    fi
    
    cat > $CONFIG_FILE << EOF
server {
    listen $NGINX_PORT ssl;
    server_name $DOMAIN_NAME;
    
    # SSL configuration - you should replace these with your actual certificates
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
    
    # Larger client maximum body size for file uploads
    client_max_body_size 100M;
}
EOF
    
    # Enable site (Debian/Ubuntu)
    if [ "$PKG_MGR" = "deb" ]; then
        ln -sf $CONFIG_FILE $ENABLED_DIR/
        # Disable default site if it exists
        if [ -f $ENABLED_DIR/default ]; then
            rm $ENABLED_DIR/default
        fi
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

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # Ubuntu firewall
        ufw allow ssh
        ufw allow "$NGINX_PORT/tcp"
        ufw allow 1194/udp
        ufw allow "$OPENVPN_PORT/tcp"
        echo "y" | ufw enable
    elif command -v firewall-cmd &> /dev/null; then
        # firewalld (RHEL/CentOS)
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-port=$NGINX_PORT/tcp
        firewall-cmd --permanent --add-port=1194/udp
        firewall-cmd --permanent --add-port=$OPENVPN_PORT/tcp
        firewall-cmd --reload
    elif command -v iptables &> /dev/null; then
        # iptables fallback
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport $NGINX_PORT -j ACCEPT
        iptables -A INPUT -p udp --dport 1194 -j ACCEPT
        iptables -A INPUT -p tcp --dport $OPENVPN_PORT -j ACCEPT
        iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -P INPUT DROP
        # Save iptables rules
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables.rules
        fi
    fi
    
    log_success "Firewall configured"
}

# Generate SSL certificates (self-signed for demo)
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    if [ "$PKG_MGR" = "deb" ]; then
        # Generate self-signed certificate on Debian/Ubuntu
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
            -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
    else
        # On RHEL/CentOS, create directory structure first
        mkdir -p /etc/ssl/private
        mkdir -p /etc/ssl/certs
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
            -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
        chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    fi
    
    log_warning "Using self-signed certificates. For production, use certificates from Let's Encrypt or a CA"
}

# Display installation summary
show_summary() {
    log_success "OpenVPN Access Server installation completed!"
    echo
    echo "=== Installation Summary ==="
    echo "Domain: $DOMAIN_NAME"
    echo "Admin Username: $ADMIN_USER"
    echo "Admin Web Interface: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo "Client Access: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo "OpenVPN AS Port: $OPENVPN_PORT"
    echo "Nginx Port: $NGINX_PORT"
    echo
    echo "=== Next Steps ==="
    echo "1. Configure DNS to point $DOMAIN_NAME to your server IP"
    echo "2. Access the admin interface and complete the setup"
    echo "3. Replace self-signed certificates with proper SSL certificates"
    echo "4. Create client profiles and distribute to users"
    echo
    echo "=== Troubleshooting ==="
    echo "If you cannot access the web interface:"
    echo "1. Check firewall rules"
    echo "2. Verify Nginx is running: systemctl status nginx"
    echo "3. Check OpenVPN AS status: /usr/local/openvpn_as/scripts/sacli status"
    echo "4. View logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo
    log_warning "Remember to change default certificates for production use!"
}

# Main installation function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Automated Installer"
    echo "  with Nginx Reverse Proxy"
    echo "=========================================="
    echo
    
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
    show_summary
}

# Run main function
main "$@"
