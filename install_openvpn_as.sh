#!/bin/bash

# OpenVPN AS Complete Fix Script with Port Configuration and UPnP
# Fixes pyovpn.zip issues and adds advanced features

set -e

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
        log_error "This script must be run as root. Use: sudo $0"
    fi
}

# Get system information
get_system_info() {
    SERVER_IP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')
    [ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I | awk '{print $1}')
    [ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"
    
    SERVER_HOSTNAME=$(hostname -s)
    PUBLIC_IP=$(curl -s -4 ifconfig.co || curl -s -4 icanhazip.com || echo "Unable to determine")
    
    log_info "Local IP: $SERVER_IP"
    log_info "Public IP: $PUBLIC_IP"
    log_info "Hostname: $SERVER_HOSTNAME"
}

# Fix pyovpn.zip missing issue
fix_pyovpn_missing() {
    log_info "Fixing missing pyovpn.zip issue..."
    
    local pyovpn_path="/usr/local/openvpn_as/lib/python/pyovpn.zip"
    
    # Stop services first
    systemctl stop openvpnas 2>/dev/null || true
    sleep 3
    
    # Check if pyovpn directory exists but zip is missing
    if [ -d "/usr/local/openvpn_as/lib/python" ] && [ ! -f "$pyovpn_path" ]; then
        log_info "pyovpn.zip is missing, downloading from official source..."
        
        # Try to extract from installed package
        if [ -f "/var/cache/apt/archives/openvpn-as"*".deb" ]; then
            log_info "Extracting from cached package..."
            local deb_file=$(ls -t /var/cache/apt/archives/openvpn-as*deb 2>/dev/null | head -1)
            if [ -f "$deb_file" ]; then
                local temp_dir=$(mktemp -d)
                cd "$temp_dir"
                ar x "$deb_file"
                if [ -f "data.tar.xz" ]; then
                    tar -xf data.tar.xz --strip-components=4 ./usr/local/openvpn_as/lib/python/pyovpn.zip 2>/dev/null
                elif [ -f "data.tar.gz" ]; then
                    tar -xzf data.tar.gz --strip-components=4 ./usr/local/openvpn_as/lib/python/pyovpn.zip 2>/dev/null
                fi
                
                if [ -f "pyovpn.zip" ]; then
                    cp pyovpn.zip "$pyovpn_path"
                    chmod 644 "$pyovpn_path"
                    log_success "pyovpn.zip extracted from cached package"
                fi
                cd /
                rm -rf "$temp_dir"
            fi
        fi
        
        # If still missing, download fresh
        if [ ! -f "$pyovpn_path" ]; then
            log_info "Downloading fresh pyovpn.zip..."
            local temp_dir=$(mktemp -d)
            cd "$temp_dir"
            
            # Download the official package
            wget -O openvpn-as.deb "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.12.0-ubuntu22_amd64.deb" || \
            wget -O openvpn-as.deb "https://packages.openvpn.net/as/pool/main/o/openvpn-as/openvpn-as_2.11.0-ubuntu22_amd64.deb" || {
                log_error "Failed to download OpenVPN AS package"
                return 1
            }
            
            # Extract pyovpn.zip
            ar x openvpn-as.deb
            if [ -f "data.tar.xz" ]; then
                tar -xf data.tar.xz --strip-components=4 ./usr/local/openvpn_as/lib/python/pyovpn.zip 2>/dev/null || \
                tar -xf data.tar.xz 2>/dev/null
            elif [ -f "data.tar.gz" ]; then
                tar -xzf data.tar.gz --strip-components=4 ./usr/local/openvpn_as/lib/python/pyovpn.zip 2>/dev/null || \
                tar -xzf data.tar.gz 2>/dev/null
            fi
            
            # Find and copy pyovpn.zip
            local found_pyovpn=$(find . -name "pyovpn.zip" -type f | head -1)
            if [ -n "$found_pyovpn" ] && [ -f "$found_pyovpn" ]; then
                mkdir -p /usr/local/openvpn_as/lib/python/
                cp "$found_pyovpn" "$pyovpn_path"
                chmod 644 "$pyovpn_path"
                log_success "pyovpn.zip installed successfully"
            else
                log_error "Could not find pyovpn.zip in downloaded package"
                return 1
            fi
            
            cd /
            rm -rf "$temp_dir"
        fi
    fi
    
    # Verify pyovpn.zip
    if [ -f "$pyovpn_path" ]; then
        if unzip -t "$pyovpn_path" >/dev/null 2>&1; then
            log_success "pyovpn.zip is valid and working"
            return 0
        else
            log_error "pyovpn.zip is corrupted"
            return 1
        fi
    else
        log_error "pyovpn.zip still missing after repair attempt"
        return 1
    fi
}

# Fix OpenVPN AS configuration
fix_openvpn_configuration() {
    log_info "Fixing OpenVPN AS configuration..."
    
    # Stop services
    systemctl stop openvpnas 2>/dev/null || true
    sleep 5
    
    # Get user input for configuration
    echo
    log_info "Please provide configuration details:"
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
    
    read -p "Enter domain name [vpn.$SERVER_HOSTNAME.local]: " DOMAIN_NAME
    DOMAIN_NAME=${DOMAIN_NAME:-vpn.$SERVER_HOSTNAME.local}
    
    read -p "Enter OpenVPN AS admin port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    
    read -p "Enter Nginx proxy port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    read -p "Enter OpenVPN server port [1194]: " VPN_SERVER_PORT
    VPN_SERVER_PORT=${VPN_SERVER_PORT:-1194}
    
    # Update hosts file
    log_info "Updating hosts file..."
    sed -i "/$DOMAIN_NAME/d" /etc/hosts
    echo "$SERVER_IP    $DOMAIN_NAME" >> /etc/hosts
    
    # Configure using ovpn-init for initial setup
    log_info "Running OpenVPN AS initial configuration..."
    /usr/local/openvpn_as/bin/ovpn-init --batch --force --no-start || true
    
    # Start services to apply configuration
    systemctl start openvpnas 2>/dev/null || true
    sleep 10
    
    # Wait for services to be ready
    local attempt=1
    while [ $attempt -le 30 ]; do
        if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "started"; then
            break
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    
    # Configure settings using sacli
    log_info "Applying configuration settings..."
    
    # Set admin password
    if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
        log_success "Admin password set successfully"
    else
        log_warning "Failed to set admin password via sacli"
    fi
    
    # Configure other settings
    local config_settings=(
        "prop_superuser=$ADMIN_USER"
        "host.name=$DOMAIN_NAME"
        "cs.https.port=$OPENVPN_PORT"
        "cs.https.ip=127.0.0.1"
        "vpn.server.port_share.service=admin+client"
        "vpn.server.port_share.port=$NGINX_PORT"
        "vpn.server.port=$VPN_SERVER_PORT"
        "vpn.server.routing.private_access=true"
        "vpn.daemon.0.client.network=$SERVER_IP/24"
        "vpn.daemon.0.server.network=172.27.224.0/20"
        "cs.daemon.enable=true"
    )
    
    for setting in "${config_settings[@]}"; do
        local key="${setting%=*}"
        local value="${setting#*=}"
        if /usr/local/openvpn_as/scripts/sacli --key "$key" --value "$value" ConfigPut >/dev/null 2>&1; then
            log_success "Set $key = $value"
        else
            log_warning "Failed to set $key"
        fi
    done
    
    # Restart services to apply changes
    systemctl restart openvpnas 2>/dev/null || true
    log_success "OpenVPN AS configuration applied"
}

# Configure Nginx with updated settings
configure_nginx_proxy() {
    log_info "Configuring Nginx reverse proxy..."
    
    # Get configuration from user or use defaults
    read -p "Enter domain name for Nginx [vpn.$SERVER_HOSTNAME.local]: " NGINX_DOMAIN
    NGINX_DOMAIN=${NGINX_DOMAIN:-vpn.$SERVER_HOSTNAME.local}
    
    read -p "Enter Nginx port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    read -p "Enter OpenVPN AS backend port [943]: " OPENVPN_BACKEND_PORT
    OPENVPN_BACKEND_PORT=${OPENVPN_BACKEND_PORT:-943}
    
    # Stop Nginx
    systemctl stop nginx 2>/dev/null || true
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
# OpenVPN AS Reverse Proxy Configuration
server {
    listen 80;
    server_name $NGINX_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $NGINX_PORT ssl;
    server_name $NGINX_DOMAIN;
    
    # SSL Configuration (using self-signed for now)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    # Proxy settings
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_BACKEND_PORT;
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
        
        # Disable buffering
        proxy_buffering off;
        proxy_request_buffering off;
        
        # SSL verification for backend
        proxy_ssl_verify off;
    }
    
    # Larger file uploads
    client_max_body_size 100M;
    
    # Logging
    access_log /var/log/nginx/openvpn-as-access.log;
    error_log /var/log/nginx/openvpn-as-error.log;
}
EOF
    
    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Test and start Nginx
    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        log_success "Nginx reverse proxy configured"
    else
        log_error "Nginx configuration test failed"
    fi
}

# Configure firewall with port options
configure_firewall_ports() {
    log_info "Configuring firewall with custom ports..."
    
    echo
    log_info "Current firewall status:"
    ufw status numbered
    
    echo
    log_info "Port Configuration:"
    read -p "Enter SSH port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    read -p "Enter HTTP port [80]: " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-80}
    
    read -p "Enter HTTPS port [443]: " HTTPS_PORT
    HTTPS_PORT=${HTTPS_PORT:-443}
    
    read -p "Enter OpenVPN UDP port [1194]: " OPENVPN_UDP_PORT
    OPENVPN_UDP_PORT=${OPENVPN_UDP_PORT:-1194}
    
    read -p "Enter OpenVPN AS admin port [943]: " OPENVPN_ADMIN_PORT
    OPENVPN_ADMIN_PORT=${OPENVPN_ADMIN_PORT:-943}
    
    # Reset and configure UFW
    ufw --force reset
    ufw --force enable
    
    # Allow configured ports
    ufw allow "$SSH_PORT/tcp"
    ufw allow "$HTTP_PORT/tcp"
    ufw allow "$HTTPS_PORT/tcp"
    ufw allow "$OPENVPN_UDP_PORT/udp"
    ufw allow "$OPENVPN_ADMIN_PORT/tcp"
    
    # Enable UFW
    echo "y" | ufw enable
    
    log_success "Firewall configured with custom ports"
    echo
    ufw status
}

# UPnP Port Forwarding setup
setup_upnp_port_forwarding() {
    log_info "Setting up UPnP port forwarding..."
    
    # Check if upnpc is available
    if ! command -v upnpc >/dev/null 2>&1; then
        log_info "Installing miniupnpc tools..."
        apt-get update
        apt-get install -y miniupnpc
    fi
    
    # Get public IP
    PUBLIC_IP=$(curl -s -4 ifconfig.co || curl -s -4 icanhazip.com || echo "Unknown")
    log_info "Public IP: $PUBLIC_IP"
    
    # Get ports from user
    echo
    log_info "UPnP Port Forwarding Configuration:"
    read -p "Enter external HTTP port [80]: " EXTERNAL_HTTP
    EXTERNAL_HTTP=${EXTERNAL_HTTP:-80}
    read -p "Enter external HTTPS port [443]: " EXTERNAL_HTTPS
    EXTERNAL_HTTPS=${EXTERNAL_HTTPS:-443}
    read -p "Enter external OpenVPN UDP port [1194]: " EXTERNAL_VPN
    EXTERNAL_VPN=${EXTERNAL_VPN:-1194}
    
    # Attempt UPnP port forwarding
    log_info "Attempting UPnP port forwarding..."
    
    local success_count=0
    
    # HTTP port
    if upnpc -a "$SERVER_IP" 80 "$EXTERNAL_HTTP" TCP >/dev/null 2>&1; then
        log_success "HTTP port $EXTERNAL_HTTP forwarded to $SERVER_IP:80"
        success_count=$((success_count + 1))
    else
        log_warning "Failed to forward HTTP port $EXTERNAL_HTTP"
    fi
    
    # HTTPS port
    if upnpc -a "$SERVER_IP" 443 "$EXTERNAL_HTTPS" TCP >/dev/null 2>&1; then
        log_success "HTTPS port $EXTERNAL_HTTPS forwarded to $SERVER_IP:443"
        success_count=$((success_count + 1))
    else
        log_warning "Failed to forward HTTPS port $EXTERNAL_HTTPS"
    fi
    
    # OpenVPN port
    if upnpc -a "$SERVER_IP" 1194 "$EXTERNAL_VPN" UDP >/dev/null 2>&1; then
        log_success "OpenVPN port $EXTERNAL_VPN forwarded to $SERVER_IP:1194"
        success_count=$((success_count + 1))
    else
        log_warning "Failed to forward OpenVPN port $EXTERNAL_VPN"
    fi
    
    if [ $success_count -gt 0 ]; then
        log_success "UPnP port forwarding completed ($success_count ports forwarded)"
        log_info "External access: https://$PUBLIC_IP:$EXTERNAL_HTTPS"
    else
        log_warning "UPnP port forwarding failed. You may need to manually configure port forwarding on your router."
        log_info "Manual port forwarding required for:"
        log_info "  - TCP $EXTERNAL_HTTP -> $SERVER_IP:80 (HTTP)"
        log_info "  - TCP $EXTERNAL_HTTPS -> $SERVER_IP:443 (HTTPS)"
        log_info "  - UDP $EXTERNAL_VPN -> $SERVER_IP:1194 (OpenVPN)"
    fi
}

# Display network information
show_network_info() {
    echo
    log_info "=== NETWORK INFORMATION ==="
    log_info "Local IP Address: $SERVER_IP"
    log_info "Public IP Address: $PUBLIC_IP"
    log_info "Hostname: $SERVER_HOSTNAME"
    
    # Show listening ports
    echo
    log_info "=== LISTENING PORTS ==="
    netstat -tlnp | grep -E ":(943|443|80|1194)" | while read line; do
        log_info "$line"
    done
    
    # Show firewall status
    echo
    log_info "=== FIREWALL STATUS ==="
    ufw status
    
    # Show access URLs
    echo
    log_info "=== ACCESS URLs ==="
    log_success "Local Admin: https://$SERVER_IP:943/admin"
    log_success "Domain Admin: https://$DOMAIN_NAME:443/admin"
    log_success "Public Admin: https://$PUBLIC_IP:443/admin"
    log_success "OpenVPN Port: UDP $PUBLIC_IP:1194"
}

# Test OpenVPN AS functionality
test_openvpn_functionality() {
    log_info "Testing OpenVPN AS functionality..."
    
    echo
    log_info "=== SERVICE STATUS ==="
    systemctl status openvpnas --no-pager -l
    
    echo
    log_info "=== CONNECTION TESTS ==="
    
    # Test local access
    if curl -k -s -f https://localhost:943/admin >/dev/null 2>&1; then
        log_success "✓ OpenVPN AS backend accessible locally"
    else
        log_warning "✗ OpenVPN AS backend not accessible locally"
    fi
    
    # Test Nginx proxy
    if curl -k -s -f https://localhost/admin >/dev/null 2>&1; then
        log_success "✓ Nginx proxy accessible locally"
    else
        log_warning "✗ Nginx proxy not accessible locally"
    fi
    
    # Test pyovpn
    if python3 -c "import sys; sys.path.insert(0, '/usr/local/openvpn_as/lib/python'); import pyovpn; print('✓ pyovpn module working')" 2>/dev/null; then
        log_success "✓ pyovpn module is working"
    else
        log_error "✗ pyovpn module is not working"
    fi
    
    echo
    log_info "=== FINAL CONFIGURATION ==="
    /usr/local/openvpn_as/scripts/sacli status || true
}

# Main fix function
main() {
    clear
    echo "=================================================="
    echo "    OpenVPN AS Complete Fix & Configuration"
    echo "        with Port Management & UPnP"
    echo "=================================================="
    echo
    
    check_root
    get_system_info
    
    # Present options to user
    echo "Available Operations:"
    echo "1) Fix pyovpn.zip missing issue"
    echo "2) Reconfigure OpenVPN AS settings"
    echo "3) Configure Nginx reverse proxy"
    echo "4) Configure firewall ports"
    echo "5) Setup UPnP port forwarding"
    echo "6) Full repair (all of the above)"
    echo "7) Show network information"
    echo
    
    read -p "Choose operation (1-7): " choice
    
    case $choice in
        1)
            fix_pyovpn_missing
            ;;
        2)
            fix_openvpn_configuration
            ;;
        3)
            configure_nginx_proxy
            ;;
        4)
            configure_firewall_ports
            ;;
        5)
            setup_upnp_port_forwarding
            ;;
        6)
            fix_pyovpn_missing
            fix_openvpn_configuration
            configure_nginx_proxy
            configure_firewall_ports
            setup_upnp_port_forwarding
            ;;
        7)
            show_network_info
            ;;
        *)
            log_error "Invalid choice"
            exit 1
            ;;
    esac
    
    # Always show final status
    test_openvpn_functionality
    show_network_info
    
    log_success "Operation completed successfully!"
}

# Run main function
main "$@"
