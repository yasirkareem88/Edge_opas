#!/bin/bash

# OpenVPN Access Server Automated Installation with Virtual Host
# Complete standalone script extracted from GitHub Actions workflow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_detail() { echo -e "${BLUE}[DETAIL]${NC} $1"; }

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --admin-password    OpenVPN Admin Password (required)"
    echo "  --domain-name       Domain Name (e.g., vpn.yourcompany.com) (required)"
    echo "  --nginx-port        Nginx Port (default: 8080)"
    echo "  --enable-ssl        Enable SSL (true/false) (default: false)"
    echo "  --ssl-email         SSL Email (for Let's Encrypt)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --admin-password 'securepassword' --domain-name 'vpn.company.com' --enable-ssl true --ssl-email 'admin@company.com'"
}

# Parse command line arguments
ADMIN_PASSWORD=""
DOMAIN_NAME=""
NGINX_PORT="8080"
ENABLE_SSL="false"
SSL_EMAIL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --admin-password)
            ADMIN_PASSWORD="$2"
            shift 2
            ;;
        --domain-name)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --nginx-port)
            NGINX_PORT="$2"
            shift 2
            ;;
        --enable-ssl)
            ENABLE_SSL="$2"
            shift 2
            ;;
        --ssl-email)
            SSL_EMAIL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$ADMIN_PASSWORD" || -z "$DOMAIN_NAME" ]]; then
    log_error "Missing required parameters"
    usage
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root"
    exit 1
fi

log_info "Starting OpenVPN AS installation with virtual host..."
log_info "Domain: $DOMAIN_NAME"
log_info "Admin password: [HIDDEN]"
log_info "Nginx port: $NGINX_PORT"
log_info "SSL Enabled: $ENABLE_SSL"
if [ "$ENABLE_SSL" = "true" ]; then
    log_info "SSL Email: $SSL_EMAIL"
fi

# Main installation function
install_openvpn_as() {
    # Comprehensive system update
    log_info "Performing comprehensive system update..."
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists and upgrade all packages
    apt update
    apt full-upgrade -y
    apt dist-upgrade -y
    apt autoremove -y --purge
    apt autoclean
    
    # Update firmware if available
    [ -x "$(command -v fwupd)" ] && fwupd refresh && fwupd update -y
    
    # Install prerequisites with latest versions
    log_info "Installing latest prerequisites..."
    apt install -y \
        curl wget gnupg2 software-properties-common \
        ufw nginx certbot python3-certbot-nginx \
        htop net-tools dnsutils jq \
        apt-transport-https ca-certificates \
        systemd timesyncd
        
    # Ensure time synchronization
    systemctl enable systemd-timesyncd
    systemctl start systemd-timesyncd
    
    # Configure firewall
    log_info "Configuring firewall..."
    ufw --force reset
    ufw allow ssh
    ufw allow $NGINX_PORT/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 943/tcp
    ufw allow 945/tcp
    ufw allow 1194/udp
    ufw --force enable
    
    # Install OpenVPN Access Server
    log_info "Installing OpenVPN Access Server..."
    cd /tmp
    wget -q https://as-repository.openvpn.net/as-repo-public.asc -O /etc/apt/trusted.gpg.d/as-repository.asc
    echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/as-repository.asc] http://as-repository.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y openvpn-as
    
    log_info "OpenVPN AS installation completed successfully!"
}

# Virtual host setup function
setup_virtual_host() {
    log_info "Configuring OpenVPN Access Server and setting up virtual host..."
    
    # Set admin password
    echo "openvpn:$ADMIN_PASSWORD" | chpasswd
    
    # Configure OpenVPN AS for external access
    /usr/local/openvpn_as/scripts/confdba -mk "admin_ui.https.ip_address" -v "all"
    /usr/local/openvpn_as/scripts/confdba -mk "admin_ui.https.port" -v "943"
    /usr/local/openvpn_as/scripts/confdba -mk "cs.https.ip_address" -v "all"
    /usr/local/openvpn_as/scripts/confdba -mk "cs.https.port" -v "943"
    /usr/local/openvpn_as/scripts/confdba -mk "vpn.server.port_share.enable" -v "false"
    /usr/local/openvpn_as/scripts/confdba -mk "vpn.server.daemon.enable" -v "true"
    
    # Create Nginx virtual host configuration
    log_info "Creating Nginx virtual host for $DOMAIN_NAME..."
    
    if [ "$ENABLE_SSL" = "true" ]; then
        # SSL Virtual Host Configuration
        cat > /etc/nginx/sites-available/openvpn-$DOMAIN_NAME << NGINX_EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # OpenVPN AS web interface proxy
    location / {
        proxy_pass https://localhost:943;
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
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Client connection service
    location /vpn/ {
        proxy_pass https://localhost:943;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
    
    # Block sensitive paths
    location ~* /\\.(?!well-known) {
        deny all;
        return 404;
    }
}
NGINX_EOF
    else
        # Non-SSL Virtual Host Configuration
        cat > /etc/nginx/sites-available/openvpn-$DOMAIN_NAME << NGINX_EOF
server {
    listen $NGINX_PORT;
    server_name $DOMAIN_NAME;
    
    # Security headers
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # OpenVPN AS web interface proxy
    location / {
        proxy_pass https://localhost:943;
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
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Client connection service
    location /vpn/ {
        proxy_pass https://localhost:943;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
}
NGINX_EOF
    fi
    
    # Enable the virtual host
    ln -sf /etc/nginx/sites-available/openvpn-$DOMAIN_NAME /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test Nginx configuration
    nginx -t
    
    # Setup SSL if enabled
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$SSL_EMAIL" ]; then
        log_info "Setting up SSL certificate with Let's Encrypt..."
        certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos -m $SSL_EMAIL
        systemctl enable certbot.timer
    fi
    
    # Restart services
    log_info "Restarting services..."
    systemctl reload nginx
    systemctl restart openvpnas
    
    # Wait for services to stabilize
    sleep 10
    
    log_info "Virtual host configuration completed!"
}

# Post-installation configuration function
post_install_config() {
    log_info "Performing post-installation configuration..."
    
    # Generate client configuration
    log_info "Generating client configuration and optimizing settings..."
    cd /usr/local/openvpn_as/scripts/
    
    # Configure user settings
    ./sacli --user "openvpn" --key "prop_autologin" --value "true" ConfigPut
    ./sacli --user "openvpn" --key "prop_superuser" --value "true" ConfigPut
    ./sacli --user "openvpn" --key "prop_force_interval" --value "0" ConfigPut
    
    # Start the configuration service
    ./sacli start
    
    # Create client profiles
    log_info "Creating client profiles..."
    ./sacli --user "openvpn" GetAutologin > /tmp/openvpn-client-profile.ovpn
    ./sacli --user "openvpn" GetUserlogin > /tmp/openvpn-user-profile.ovpn
    
    # Set proper permissions
    chmod 600 /tmp/openvpn-*.ovpn
    
    # Create startup optimization
    log_info "Optimizing startup configuration..."
    cat > /etc/systemd/system/openvpnas-optimized.service << 'SERVICE_EOF'
[Unit]
Description=OpenVPN Access Server Optimized
After=network.target nginx.service

[Service]
Type=forking
PIDFile=/usr/local/openvpn_as/tmp/pids/server.pid
ExecStart=/usr/local/openvpn_as/scripts/openvpnas --log --conf=/usr/local/openvpn_as/etc/as.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable openvpnas-optimized
    
    # Create maintenance script
    cat > /usr/local/bin/openvpn-maintenance << 'MAINT_EOF'
#!/bin/bash
# OpenVPN AS Maintenance Script

case "\$1" in
    status)
        systemctl status openvpnas-optimized
        systemctl status nginx
        ;;
    restart)
        systemctl restart openvpnas-optimized
        systemctl restart nginx
        ;;
    update)
        apt update && apt upgrade -y openvpn-as
        ;;
    logs)
        journalctl -u openvpnas-optimized -f
        ;;
    *)
        echo "Usage: \$0 {status|restart|update|logs}"
        exit 1
        ;;
esac
MAINT_EOF
    
    chmod +x /usr/local/bin/openvpn-maintenance
    
    log_info "Post-installation configuration completed!"
    log_detail "Client profiles created in /tmp/"
    log_detail "Use 'openvpn-maintenance' for service management"
}

# Verification function
verify_installation() {
    log_info "Verifying installation..."
    
    # Check services
    if systemctl is-active openvpnas-optimized >/dev/null 2>&1 && systemctl is-active nginx >/dev/null 2>&1; then
        log_info "All services are running successfully!"
    else
        log_error "Some services are not running properly"
        exit 1
    fi
    
    # Display access information
    log_info "=== OPENVPN AS DEPLOYMENT COMPLETE ==="
    if [ "$ENABLE_SSL" = "true" ]; then
        log_info "Web interface: https://$DOMAIN_NAME"
    else
        log_info "Web interface: http://$DOMAIN_NAME:$NGINX_PORT"
    fi
    log_info "Username: openvpn"
    log_info "Password: [configured]"
    log_info "Management: Use 'openvpn-maintenance' command for service management"
    log_info "Client profiles: /tmp/openvpn-client-profile.ovpn"
    log_info "User profiles: /tmp/openvpn-user-profile.ovpn"
}

# Main execution
main() {
    log_info "Starting OpenVPN AS automated installation..."
    
    # Execute all installation steps
    install_openvpn_as
    setup_virtual_host
    post_install_config
    verify_installation
    
    log_info "OpenVPN AS installation completed successfully!"
}

# Run main function
main "$@"