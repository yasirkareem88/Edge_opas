#!/bin/bash

# OpenVPN AS Automated Installation Script with Nginx Reverse Proxy
# Supports Debian/Ubuntu (deb) and RHEL/CentOS (rpm) systems

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
        OS=$NAME
        OS_VERSION=$VERSION_ID
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
}

# User input function
get_user_input() {
    log_info "Please provide the following configuration details:"
    
    read -p "Enter server domain name (e.g., vpn.example.com): " DOMAIN_NAME
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
        log_error "Domain name is required"
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
    
    case $PKG_MGR in
        "deb")
            apt-get update
            apt-get install -y wget curl nginx python3 net-tools
            ;;
        "rpm")
            if command -v dnf &> /dev/null; then
                dnf install -y wget curl nginx python3 net-tools
            else
                yum install -y wget curl nginx python3 net-tools
            fi
            ;;
    esac
}

# Download and install OpenVPN AS
install_openvpn_as() {
    log_info "Downloading and installing OpenVPN Access Server..."
    
    cd /tmp
    
    case $PKG_MGR in
        "deb")
            wget -O openvpn-as.deb https://as-repository.openvpn.net/as-repo-public.asc
            wget -O /etc/apt/trusted.gpg.d/openvpn-as-repo.asc https://as-repository.openvpn.net/as-repo-public.asc
            echo "deb http://as-repository.openvpn.net/as/debian bullseye main" > /etc/apt/sources.list.d/openvpn-as.list
            apt-get update
            apt-get install -y openvpn-as
            ;;
        "rpm")
            wget -O openvpn-as.rpm https://as-repository.openvpn.net/as-repo-public.asc
            if command -v dnf &> /dev/null; then
                dnf install -y openvpn-as.rpm
            else
                yum install -y openvpn-as.rpm
            fi
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log_success "OpenVPN AS installed successfully"
    else
        log_error "Failed to install OpenVPN AS"
        exit 1
    fi
}

# Configure OpenVPN AS
configure_openvpn_as() {
    log_info "Configuring OpenVPN Access Server..."
    
    # Set admin password
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASSWORD" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut
    
    # Configure for Nginx reverse proxy
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut
    
    # Restart OpenVPN AS to apply changes
    /usr/local/openvpn_as/scripts/sacli start
    
    log_success "OpenVPN AS configured successfully"
}

# Configure Nginx as reverse proxy
configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
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
        ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
        # Disable default site if it exists
        if [ -f /etc/nginx/sites-enabled/default ]; then
            rm /etc/nginx/sites-enabled/default
        fi
    else
        # For RHEL/CentOS, configuration goes in conf.d
        mv /etc/nginx/sites-available/openvpn-as /etc/nginx/conf.d/openvpn-as.conf
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
        echo "y" | ufw enable
    elif command -v firewall-cmd &> /dev/null; then
        # firewalld (RHEL/CentOS)
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-port=$NGINX_PORT/tcp
        firewall-cmd --permanent --add-port=1194/udp
        firewall-cmd --reload
    elif command -v iptables &> /dev/null; then
        # iptables fallback
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport $NGINX_PORT -j ACCEPT
        iptables -A INPUT -p udp --dport 1194 -j ACCEPT
        iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -P INPUT DROP
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
    install_openvpn_as
    generate_ssl_certificates
    configure_openvpn_as
    configure_nginx
    configure_firewall
    show_summary
}

# Run main function
main "$@"