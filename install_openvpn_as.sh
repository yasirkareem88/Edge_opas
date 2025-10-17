#!/bin/bash

# OpenVPN Access Server Complete Installation with Nginx Fix
# Fixes virtual host and admin login issues

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Get user configuration
get_user_config() {
    echo
    log "OpenVPN Access Server Configuration"
    echo "=================================="
    
    read -p "Enter server domain name or IP address: " SERVER_HOST
    SERVER_HOST=${SERVER_HOST:-$(curl -s ifconfig.me)}
    
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        if [ -n "$ADMIN_PASS" ]; then
            read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
            echo
            if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ]; then
                break
            else
                error "Passwords do not match"
            fi
        else
            error "Password cannot be empty"
        fi
    done
    
    read -p "Enter Nginx external port [443]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-443}
    
    read -p "Enter OpenVPN AS internal port [943]: " OPENVPN_PORT
    OPENVPN_PORT=${OPENVPN_PORT:-943}
    
    # Display configuration
    echo
    log "Configuration Summary:"
    echo "---------------------"
    echo "Server Host: $SERVER_HOST"
    echo "Admin User: $ADMIN_USER"
    echo "Nginx Port: $NGINX_PORT"
    echo "OpenVPN AS Port: $OPENVPN_PORT"
    echo
    
    read -p "Continue with installation? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        error "Installation cancelled"
        exit 1
    fi
}

# Fix OpenVPN AS admin login issue
fix_admin_login() {
    log "Fixing admin login configuration..."
    
    # Stop OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    sleep 3
    
    # Remove any existing admin user and recreate
    log "Setting up admin user: $ADMIN_USER"
    
    # Create the admin user with proper permissions
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --key "type" --value "user_connect" UserPropPut
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --key "prop_superuser" --value "true" UserPropPut
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --key "prop_deny" --value "false" UserPropPut
    
    # Set the password
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASS" SetLocalPassword
    
    # Also set in global config as backup
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASS" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_name" --value "$ADMIN_USER" ConfigPut
    
    # Configure authentication
    /usr/local/openvpn_as/scripts/sacli --key "auth.module.type" --value "local" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.enable" --value "true" ConfigPut
    
    # Start OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli start
    
    # Wait for service to start
    log "Waiting for OpenVPN AS to start..."
    for i in {1..30}; do
        if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "Service is running"; then
            success "OpenVPN AS is running"
            break
        fi
        sleep 2
    done
    
    # Verify admin user was created
    if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" ListUserProps 2>/dev/null | grep -q "prop_superuser"; then
        success "Admin user '$ADMIN_USER' configured successfully"
    else
        error "Failed to configure admin user"
        return 1
    fi
}

# Create proper Nginx virtual host configuration
create_nginx_virtual_host() {
    log "Creating Nginx virtual host configuration..."
    
    # Create sites-available and sites-enabled directories if they don't exist
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    
    # Remove any existing configuration
    rm -f /etc/nginx/sites-available/openvpn-as
    rm -f /etc/nginx/sites-enabled/openvpn-as
    
    # Create comprehensive Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << EOF
# OpenVPN Access Server Virtual Host Configuration
# Server: $SERVER_HOST

server {
    listen 80;
    server_name $SERVER_HOST;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $NGINX_PORT ssl http2;
    server_name $SERVER_HOST;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Proxy settings
    proxy_ssl_verify off;
    proxy_redirect off;
    proxy_buffering off;
    proxy_request_buffering off;
    
    # Increase timeouts
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;
    
    # Main location block
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        
        # WebSocket support for admin interface
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Buffer settings
        proxy_buffers 16 16k;
        proxy_buffer_size 16k;
    }
    
    # Specific handling for admin interface
    location /admin/ {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT/admin/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
    
    # Specific handling for client interface
    location /client/ {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT/client/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
    }
    
    # API endpoints
    location /api/ {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # WebSocket endpoints
    location ~* ^/(websocket|ws|socket) {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Static files
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_hide_header X-Frame-Options;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Increase file upload size
    client_max_body_size 100M;
    
    # Access and error logs
    access_log /var/log/nginx/openvpn-as-access.log;
    error_log /var/log/nginx/openvpn-as-error.log;
}
EOF

    # Enable the virtual host
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    # Remove default site if it exists and causes conflicts
    if [ -f /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    
    # Test Nginx configuration
    if nginx -t; then
        success "Nginx virtual host configuration created successfully"
    else
        error "Nginx configuration test failed"
        log "Check /etc/nginx/sites-available/openvpn-as for errors"
        return 1
    fi
    
    # Restart Nginx
    systemctl restart nginx
    success "Nginx virtual host activated"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log "Generating SSL certificates for virtual host..."
    
    # Create directories
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    # Generate self-signed certificate with proper SAN
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$SERVER_HOST" \
        -addext "subjectAltName=DNS:$SERVER_HOST,DNS:*.$SERVER_HOST,IP:127.0.0.1" 2>/dev/null
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/nginx-selfsigned.key
    chmod 644 /etc/ssl/certs/nginx-selfsigned.crt
    
    success "SSL certificates generated for $SERVER_HOST"
}

# Configure OpenVPN AS for virtual host
configure_openvpn_for_virtual_host() {
    log "Configuring OpenVPN AS for virtual host..."
    
    # Stop OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli stop 2>/dev/null || true
    sleep 3
    
    # Configure OpenVPN AS to work with Nginx virtual host
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$SERVER_HOST" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut
    
    # Configure port sharing for Nginx
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut
    
    # Bind to localhost only
    /usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.ip_address" --value "127.0.0.1" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip_address" --value "127.0.0.1" ConfigPut
    
    # Disable public access to backend
    /usr/local/openvpn_as/scripts/sacli --key "vpn.client.routing.inter_client" --value "false" ConfigPut
    
    # Start OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli start
    
    # Wait for service
    sleep 5
    
    success "OpenVPN AS configured for virtual host"
}

# Test the installation
test_installation() {
    log "Testing installation..."
    
    local tests_passed=0
    local total_tests=5
    
    # Test 1: OpenVPN AS service
    if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "Service is running"; then
        success "✓ OpenVPN AS service is running"
        ((tests_passed++))
    else
        error "✗ OpenVPN AS service is not running"
    fi
    
    # Test 2: Local access to OpenVPN AS
    if curl -k -s https://127.0.0.1:$OPENVPN_PORT >/dev/null; then
        success "✓ OpenVPN AS backend accessible locally"
        ((tests_passed++))
    else
        error "✗ OpenVPN AS backend not accessible locally"
    fi
    
    # Test 3: Nginx service
    if systemctl is-active --quiet nginx; then
        success "✓ Nginx service is running"
        ((tests_passed++))
    else
        error "✗ Nginx service is not running"
    fi
    
    # Test 4: Virtual host access
    if curl -k -s -H "Host: $SERVER_HOST" https://127.0.0.1:$NGINX_PORT >/dev/null; then
        success "✓ Virtual host is accessible"
        ((tests_passed++))
    else
        error "✗ Virtual host is not accessible"
    fi
    
    # Test 5: Admin user exists
    if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" ListUserProps 2>/dev/null | grep -q "prop_superuser"; then
        success "✓ Admin user '$ADMIN_USER' exists"
        ((tests_passed++))
    else
        error "✗ Admin user '$ADMIN_USER' does not exist"
    fi
    
    # Final result
    if [ $tests_passed -eq $total_tests ]; then
        success "All tests passed ($tests_passed/$total_tests)"
        return 0
    else
        warn "Some tests failed ($tests_passed/$total_tests passed)"
        return 1
    fi
}

# Display final information
show_final_info() {
    echo
    success "================================================"
    success "    OpenVPN AS Installation Complete"
    success "================================================"
    echo
    log "Virtual Host Access URLs:"
    echo "========================"
    echo "Admin Interface:  https://$SERVER_HOST:$NGINX_PORT/admin"
    echo "Client Interface: https://$SERVER_HOST:$NGINX_PORT/"
    echo
    log "Login Credentials:"
    echo "================="
    echo "Username: $ADMIN_USER"
    echo "Password: [the password you set]"
    echo
    log "Configuration Details:"
    echo "====================="
    echo "Server Host: $SERVER_HOST"
    echo "Nginx Port: $NGINX_PORT"
    echo "OpenVPN AS Backend Port: $OPENVPN_PORT"
    echo
    warn "Important Notes:"
    echo "================"
    echo "• Using self-signed certificates (replace for production)"
    echo "• Ensure DNS/hosts file points $SERVER_HOST to this server"
    echo "• Admin interface is at /admin path"
    echo
    log "Troubleshooting Commands:"
    echo "========================"
    echo "Check OpenVPN AS: /usr/local/openvpn_as/scripts/sacli status"
    echo "Check Nginx: systemctl status nginx"
    echo "View Nginx logs: tail -f /var/log/nginx/openvpn-as-error.log"
    echo "View OpenVPN logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo "Test admin login: /usr/local/openvpn_as/scripts/sacli --user $ADMIN_USER ListUserProps"
    echo
}

# Main installation function
main() {
    clear
    echo "================================================"
    echo "   OpenVPN AS Virtual Host & Admin Login Fix"
    echo "================================================"
    echo
    
    check_root
    get_user_config
    
    log "Starting installation and configuration..."
    
    # Generate SSL certificates first
    generate_ssl_certificates
    
    # Fix admin login
    if ! fix_admin_login; then
        error "Failed to configure admin login"
        exit 1
    fi
    
    # Create virtual host configuration
    if ! create_nginx_virtual_host; then
        error "Failed to create virtual host configuration"
        exit 1
    fi
    
    # Configure OpenVPN for virtual host
    configure_openvpn_for_virtual_host
    
    # Test everything
    if test_installation; then
        show_final_info
    else
        warn "Installation completed with some test failures"
        show_final_info
        echo
        log "Please check the errors above and run the troubleshooting commands."
    fi
}

# Run main function
main "$@"
