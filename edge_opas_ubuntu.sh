#!/bin/bash

# OpenVPN Access Server Automated Installation with Virtual Host
# Interactive installation script with menu options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_detail() { echo -e "${BLUE}[DETAIL]${NC} $1"; }
log_input() { echo -e "${CYAN}[INPUT]${NC} $1"; }

# Function to display banner
show_banner() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           OpenVPN Access Server Automated Installer          ║"
    echo "║                 with Virtual Host Configuration              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Function to display menu
show_menu() {
    echo "Please choose installation type:"
    echo
    echo "1) Basic Installation (HTTP)"
    echo "   - OpenVPN AS with Nginx reverse proxy"
    echo "   - HTTP access on custom port"
    echo "   - Basic security configuration"
    echo
    echo "2) SSL Installation (HTTPS)"
    echo "   - OpenVPN AS with Nginx reverse proxy"
    echo "   - SSL encryption with Let's Encrypt"
    echo "   - Enhanced security headers"
    echo "   - Automatic SSL renewal"
    echo
    echo "3) Advanced Custom Installation"
    echo "   - Customize all parameters manually"
    echo
    echo "4) Exit"
    echo
}

# Function to get user input with validation
get_input() {
    local prompt="$1"
    local default="$2"
    local validation="$3"
    local input=""
    
    while true; do
        if [ -n "$default" ]; then
            log_input "$prompt [$default]: "
        else
            log_input "$prompt: "
        fi
        
        read input
        input=${input:-$default}
        
        if [ -z "$input" ]; then
            log_error "This field cannot be empty. Please try again."
            continue
        fi
        
        case "$validation" in
            "domain")
                if [[ "$input" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    break
                else
                    log_error "Invalid domain format. Please enter a valid domain (e.g., vpn.company.com)"
                fi
                ;;
            "port")
                if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le 65535 ]; then
                    break
                else
                    log_error "Invalid port number. Please enter a number between 1 and 65535"
                fi
                ;;
            "email")
                if [[ "$input" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    break
                else
                    log_error "Invalid email format. Please enter a valid email address"
                fi
                ;;
            "password")
                if [ ${#input} -ge 8 ]; then
                    break
                else
                    log_error "Password must be at least 8 characters long"
                fi
                ;;
            *)
                break
                ;;
        esac
    done
    
    echo "$input"
}

# Function to confirm installation
confirm_installation() {
    local installation_type="$1"
    local admin_password="$2"
    local domain_name="$3"
    local nginx_port="$4"
    local enable_ssl="$5"
    local ssl_email="$6"
    
    echo
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                  Installation Summary                        ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "Installation Type: ${CYAN}$installation_type${NC}"
    echo -e "Domain Name: ${CYAN}$domain_name${NC}"
    echo -e "Admin Password: ${CYAN}********${NC}"
    
    if [ "$enable_ssl" = "true" ]; then
        echo -e "SSL Enabled: ${GREEN}Yes${NC}"
        echo -e "SSL Email: ${CYAN}$ssl_email${NC}"
        echo -e "Access URL: ${GREEN}https://$domain_name${NC}"
    else
        echo -e "SSL Enabled: ${YELLOW}No${NC}"
        echo -e "Nginx Port: ${CYAN}$nginx_port${NC}"
        echo -e "Access URL: ${YELLOW}http://$domain_name:$nginx_port${NC}"
    fi
    
    echo
    log_input "Do you want to proceed with the installation? (y/N): "
    read -r confirmation
    
    if [[ "$confirmation" =~ ^[Yy]$ ]]; then
        return 0
    else
        log_info "Installation cancelled."
        exit 0
    fi
}

# Basic installation function
basic_installation() {
    show_banner
    log_info "Starting Basic Installation Setup..."
    echo
    
    # Get inputs for basic installation
    ADMIN_PASSWORD=$(get_input "Enter OpenVPN Admin Password" "" "password")
    DOMAIN_NAME=$(get_input "Enter Domain Name (e.g., vpn.yourcompany.com)" "" "domain")
    NGINX_PORT=$(get_input "Enter Nginx Port" "8080" "port")
    ENABLE_SSL="false"
    SSL_EMAIL=""
    
    # Confirm installation
    confirm_installation "Basic Installation (HTTP)" "$ADMIN_PASSWORD" "$DOMAIN_NAME" "$NGINX_PORT" "$ENABLE_SSL" "$SSL_EMAIL"
    
    # Execute installation
    execute_installation
}

# SSL installation function
ssl_installation() {
    show_banner
    log_info "Starting SSL Installation Setup..."
    echo
    
    # Get inputs for SSL installation
    ADMIN_PASSWORD=$(get_input "Enter OpenVPN Admin Password" "" "password")
    DOMAIN_NAME=$(get_input "Enter Domain Name (e.g., vpn.yourcompany.com)" "" "domain")
    SSL_EMAIL=$(get_input "Enter SSL Email (for Let's Encrypt)" "" "email")
    ENABLE_SSL="true"
    NGINX_PORT="443"  # SSL uses port 443
    
    # Confirm installation
    confirm_installation "SSL Installation (HTTPS)" "$ADMIN_PASSWORD" "$DOMAIN_NAME" "$NGINX_PORT" "$ENABLE_SSL" "$SSL_EMAIL"
    
    # Execute installation
    execute_installation
}

# Advanced installation function
advanced_installation() {
    show_banner
    log_info "Starting Advanced Installation Setup..."
    echo
    
    # Get all inputs
    ADMIN_PASSWORD=$(get_input "Enter OpenVPN Admin Password" "" "password")
    DOMAIN_NAME=$(get_input "Enter Domain Name (e.g., vpn.yourcompany.com)" "" "domain")
    
    log_input "Enable SSL? (y/N): "
    read -r ssl_choice
    if [[ "$ssl_choice" =~ ^[Yy]$ ]]; then
        ENABLE_SSL="true"
        SSL_EMAIL=$(get_input "Enter SSL Email (for Let's Encrypt)" "" "email")
        NGINX_PORT="443"
    else
        ENABLE_SSL="false"
        SSL_EMAIL=""
        NGINX_PORT=$(get_input "Enter Nginx Port" "8080" "port")
    fi
    
    # Confirm installation
    confirm_installation "Advanced Custom Installation" "$ADMIN_PASSWORD" "$DOMAIN_NAME" "$NGINX_PORT" "$ENABLE_SSL" "$SSL_EMAIL"
    
    # Execute installation
    execute_installation
}

# Main installation execution function
execute_installation() {
    log_info "Starting installation process..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi
    
    # Execute installation steps
    install_openvpn_as
    setup_virtual_host
    post_install_config
    verify_installation
    
    log_info "OpenVPN AS installation completed successfully!"
}

# Installation functions (same as before but now as functions)
install_openvpn_as() {
    log_info "Performing comprehensive system update..."
    export DEBIAN_FRONTEND=noninteractive
    
    apt update
    apt full-upgrade -y
    apt dist-upgrade -y
    apt autoremove -y --purge
    apt autoclean
    
    [ -x "$(command -v fwupd)" ] && fwupd refresh && fwupd update -y
    
    log_info "Installing latest prerequisites..."
    apt install -y \
        curl wget gnupg2 software-properties-common \
        ufw nginx certbot python3-certbot-nginx \
        htop net-tools dnsutils jq \
        apt-transport-https ca-certificates \
        systemd timesyncd
        
    systemctl enable systemd-timesyncd
    systemctl start systemd-timesyncd
    
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
    
    log_info "Installing OpenVPN Access Server..."
    cd /tmp
    wget -q https://as-repository.openvpn.net/as-repo-public.asc -O /etc/apt/trusted.gpg.d/as-repository.asc
    echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/as-repository.asc] http://as-repository.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as-repo.list
    
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y openvpn-as
    
    log_info "OpenVPN AS installation completed successfully!"
}

setup_virtual_host() {
    log_info "Configuring OpenVPN Access Server and setting up virtual host..."
    
    echo "openvpn:$ADMIN_PASSWORD" | chpasswd
    
    /usr/local/openvpn_as/scripts/confdba -mk "admin_ui.https.ip_address" -v "all"
    /usr/local/openvpn_as/scripts/confdba -mk "admin_ui.https.port" -v "943"
    /usr/local/openvpn_as/scripts/confdba -mk "cs.https.ip_address" -v "all"
    /usr/local/openvpn_as/scripts/confdba -mk "cs.https.port" -v "943"
    /usr/local/openvpn_as/scripts/confdba -mk "vpn.server.port_share.enable" -v "false"
    /usr/local/openvpn_as/scripts/confdba -mk "vpn.server.daemon.enable" -v "true"
    
    log_info "Creating Nginx virtual host for $DOMAIN_NAME..."
    
    if [ "$ENABLE_SSL" = "true" ]; then
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
    
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    location / {
        proxy_pass https://localhost:943;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    location /vpn/ {
        proxy_pass https://localhost:943;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
    
    location ~* /\\.(?!well-known) {
        deny all;
        return 404;
    }
}
NGINX_EOF
    else
        cat > /etc/nginx/sites-available/openvpn-$DOMAIN_NAME << NGINX_EOF
server {
    listen $NGINX_PORT;
    server_name $DOMAIN_NAME;
    
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    location / {
        proxy_pass https://localhost:943;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    location /vpn/ {
        proxy_pass https://localhost:943;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
}
NGINX_EOF
    fi
    
    ln -sf /etc/nginx/sites-available/openvpn-$DOMAIN_NAME /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    nginx -t
    
    if [ "$ENABLE_SSL" = "true" ] && [ -n "$SSL_EMAIL" ]; then
        log_info "Setting up SSL certificate with Let's Encrypt..."
        certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos -m $SSL_EMAIL
        systemctl enable certbot.timer
    fi
    
    log_info "Restarting services..."
    systemctl reload nginx
    systemctl restart openvpnas
    
    sleep 10
    log_info "Virtual host configuration completed!"
}

post_install_config() {
    log_info "Performing post-installation configuration..."
    cd /usr/local/openvpn_as/scripts/
    
    ./sacli --user "openvpn" --key "prop_autologin" --value "true" ConfigPut
    ./sacli --user "openvpn" --key "prop_superuser" --value "true" ConfigPut
    ./sacli --user "openvpn" --key "prop_force_interval" --value "0" ConfigPut
    
    ./sacli start
    
    log_info "Creating client profiles..."
    ./sacli --user "openvpn" GetAutologin > /tmp/openvpn-client-profile.ovpn
    ./sacli --user "openvpn" GetUserlogin > /tmp/openvpn-user-profile.ovpn
    
    chmod 600 /tmp/openvpn-*.ovpn
    
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
    
    cat > /usr/local/bin/openvpn-maintenance << 'MAINT_EOF'
#!/bin/bash
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
}

verify_installation() {
    log_info "Verifying installation..."
    
    if systemctl is-active openvpnas-optimized >/dev/null 2>&1 && systemctl is-active nginx >/dev/null 2>&1; then
        log_info "All services are running successfully!"
    else
        log_error "Some services are not running properly"
        exit 1
    fi
    
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               INSTALLATION COMPLETE!                         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    log_info "=== ACCESS INFORMATION ==="
    if [ "$ENABLE_SSL" = "true" ]; then
        log_info "Web Admin Interface: ${GREEN}https://$DOMAIN_NAME${NC}"
    else
        log_info "Web Admin Interface: ${YELLOW}http://$DOMAIN_NAME:$NGINX_PORT${NC}"
    fi
    log_info "Username: ${CYAN}openvpn${NC}"
    log_info "Password: ${CYAN}********${NC}"
    echo
    log_info "=== MANAGEMENT ==="
    log_info "Use '${CYAN}openvpn-maintenance${NC}' command for service management:"
    log_info "  openvpn-maintenance status  - Check service status"
    log_info "  openvpn-maintenance restart - Restart services"
    log_info "  openvpn-maintenance update  - Update OpenVPN AS"
    log_info "  openvpn-maintenance logs    - View service logs"
    echo
    log_info "=== FILES ==="
    log_info "Client profiles created in: ${CYAN}/tmp/${NC}"
    log_info "  - /tmp/openvpn-client-profile.ovpn"
    log_info "  - /tmp/openvpn-user-profile.ovpn"
    echo
    log_warn "Please download and secure the client profiles immediately!"
}

# Main menu loop
main() {
    while true; do
        show_banner
        show_menu
        
        log_input "Enter your choice (1-4): "
        read -r choice
        
        case $choice in
            1)
                basic_installation
                break
                ;;
            2)
                ssl_installation
                break
                ;;
            3)
                advanced_installation
                break
                ;;
            4)
                log_info "Goodbye!"
                exit 0
                ;;
            *)
                log_error "Invalid choice. Please enter 1, 2, 3, or 4."
                sleep 2
                ;;
        esac
    done
}

# Check if script is run with arguments for non-interactive mode
if [ $# -gt 0 ]; then
    # Non-interactive mode (for backward compatibility)
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
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --admin-password    OpenVPN Admin Password"
                echo "  --domain-name       Domain Name"
                echo "  --nginx-port        Nginx Port (default: 8080)"
                echo "  --enable-ssl        Enable SSL (true/false)"
                echo "  --ssl-email         SSL Email"
                echo ""
                echo "Interactive mode will start if no arguments are provided."
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate non-interactive mode parameters
    if [[ -z "$ADMIN_PASSWORD" || -z "$DOMAIN_NAME" ]]; then
        log_error "Missing required parameters for non-interactive mode"
        exit 1
    fi
    
    # Set defaults for non-interactive mode
    NGINX_PORT=${NGINX_PORT:-"8080"}
    ENABLE_SSL=${ENABLE_SSL:-"false"}
    
    execute_installation
else
    # Interactive mode
    main
fi
