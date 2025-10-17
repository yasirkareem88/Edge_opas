#!/bin/bash

# OpenVPN AS Nginx Bad Gateway Fix Script
# This script fixes common Nginx reverse proxy issues with OpenVPN AS

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

# Get current configuration
get_current_config() {
    log_info "Gathering current configuration..."
    
    # Get OpenVPN AS configuration
    if [ -f "/usr/local/openvpn_as/etc/as.conf" ]; then
        OPENVPN_AS_PORT=$(grep "admin_ui.https.port" /usr/local/openvpn_as/etc/as.conf | cut -d'=' -f2 | tr -d ' ')
        OPENVPN_AS_IP=$(grep "admin_ui.https.ip_address" /usr/local/openvpn_as/etc/as.conf | cut -d'=' -f2 | tr -d ' ')
    else
        OPENVPN_AS_PORT="943"
        OPENVPN_AS_IP="127.0.0.1"
    fi
    
    # Get domain from previous configuration
    if [ -f "/usr/local/openvpn_as/etc/config.json" ]; then
        DOMAIN_NAME=$(grep -A5 "host.name" /usr/local/openvpn_as/etc/config.json | grep "value" | cut -d'"' -f4)
    fi
    
    # If domain not found, ask user
    if [ -z "$DOMAIN_NAME" ]; then
        read -p "Enter your server domain name or IP address: " DOMAIN_NAME
    fi
    
    log_info "Detected OpenVPN AS running on: $OPENVPN_AS_IP:$OPENVPN_AS_PORT"
}

# Check if services are running
check_services() {
    log_info "Checking service status..."
    
    # Check OpenVPN AS
    if pgrep -f "openvpn-as" > /dev/null; then
        log_success "OpenVPN AS is running"
    else
        log_error "OpenVPN AS is not running"
        log_info "Starting OpenVPN AS..."
        /usr/local/openvpn_as/scripts/openvpnas -n
        sleep 5
    fi
    
    # Check Nginx
    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx is not running"
        log_info "Starting Nginx..."
        systemctl start nginx
    fi
    
    # Check if OpenVPN AS is listening on the expected port
    if netstat -tlnp | grep ":$OPENVPN_AS_PORT" | grep "openvpn-as" > /dev/null; then
        log_success "OpenVPN AS is listening on port $OPENVPN_AS_PORT"
    else
        log_error "OpenVPN AS is not listening on port $OPENVPN_AS_PORT"
        log_info "Current listening ports:"
        netstat -tlnp | grep "openvpn-as" || log_info "No OpenVPN AS ports found"
    fi
}

# Fix OpenVPN AS configuration
fix_openvpn_config() {
    log_info "Reconfiguring OpenVPN AS for Nginx reverse proxy..."
    
    # Stop OpenVPN AS first
    /usr/local/openvpn_as/scripts/ovpn-init --stop
    
    # Configure OpenVPN AS to work with Nginx reverse proxy
    /usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.ip_address" --value "127.0.0.1" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.port" --value "943" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "943" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "443" ConfigPut
    /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut
    
    # Restart OpenVPN AS
    /usr/local/openvpn_as/scripts/ovpn-init --start
    /usr/local/openvpn_as/scripts/sacli start
    
    log_success "OpenVPN AS reconfigured for reverse proxy"
}

# Create proper Nginx configuration
create_nginx_config() {
    log_info "Creating proper Nginx configuration..."
    
    # Backup existing config
    if [ -f "/etc/nginx/sites-available/openvpn-as" ]; then
        cp /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-available/openvpn-as.backup
    fi
    
    # Create optimized Nginx configuration
    cat > /etc/nginx/sites-available/openvpn-as << 'EOF'
# OpenVPN AS Reverse Proxy Configuration
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;
    
    # SSL Configuration - Using self-signed for now
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin";
    
    # Proxy settings
    proxy_ssl_server_name on;
    proxy_redirect off;
    
    # Main location block
    location / {
        proxy_pass https://127.0.0.1:943;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 90s;
        proxy_send_timeout 90s;
        proxy_read_timeout 90s;
        proxy_buffering off;
    }
    
    # Specific handling for different paths
    location ~ ^/(admin|client) {
        proxy_pass https://127.0.0.1:943;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 90s;
        proxy_send_timeout 90s;
        proxy_read_timeout 90s;
        proxy_buffering off;
    }
    
    # Increase file upload size
    client_max_body_size 100M;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;
}
EOF
    
    # Replace domain placeholder
    sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /etc/nginx/sites-available/openvpn-as
    
    # Enable site
    if [ ! -f "/etc/nginx/sites-enabled/openvpn-as" ]; then
        ln -s /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    fi
    
    # Remove default site if it exists
    if [ -f "/etc/nginx/sites-enabled/default" ]; then
        rm /etc/nginx/sites-enabled/default
    fi
    
    log_success "Nginx configuration created"
}

# Test connectivity to OpenVPN AS
test_openvpn_connectivity() {
    log_info "Testing connectivity to OpenVPN AS backend..."
    
    # Test if we can reach OpenVPN AS locally
    if curl -k -s --connect-timeout 10 https://127.0.0.1:943 > /dev/null; then
        log_success "OpenVPN AS is accessible locally on port 943"
        return 0
    else
        log_error "Cannot reach OpenVPN AS on 127.0.0.1:943"
        log_info "Checking what's running on port 943..."
        netstat -tlnp | grep ":943"
        
        log_info "Checking OpenVPN AS process..."
        ps aux | grep openvpn-as
        
        log_info "Checking OpenVPN AS logs..."
        tail -20 /usr/local/openvpn_as/logs/*.log 2>/dev/null || log_info "No log files found"
        return 1
    fi
}

# Fix SSL certificates
fix_ssl_certificates() {
    log_info "Ensuring SSL certificates are properly configured..."
    
    # Check if certificates exist
    if [ ! -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" ] || [ ! -f "/etc/ssl/private/ssl-cert-snakeoil.key" ]; then
        log_info "Generating new SSL certificates..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
            -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
    fi
    
    # Set proper permissions
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    chmod 640 /etc/ssl/private/ssl-cert-snakeoil.key
    
    log_success "SSL certificates configured"
}

# Test Nginx configuration
test_nginx_config() {
    log_info "Testing Nginx configuration..."
    
    if nginx -t; then
        log_success "Nginx configuration test passed"
        return 0
    else
        log_error "Nginx configuration test failed"
        log_info "Checking Nginx error log..."
        tail -20 /var/log/nginx/error.log
        return 1
    fi
}

# Restart services
restart_services() {
    log_info "Restarting services..."
    
    # Restart OpenVPN AS
    /usr/local/openvpn_as/scripts/sacli stop
    sleep 2
    /usr/local/openvpn_as/scripts/sacli start
    sleep 5
    
    # Restart Nginx
    systemctl reload nginx
    
    log_success "Services restarted"
}

# Final verification
verify_fix() {
    log_info "Verifying the fix..."
    
    # Wait a moment for services to fully start
    sleep 5
    
    # Test local connectivity
    if test_openvpn_connectivity; then
        log_success "✓ OpenVPN AS backend is accessible"
    else
        log_error "✗ OpenVPN AS backend is not accessible"
        return 1
    fi
    
    # Test through Nginx
    log_info "Testing through Nginx reverse proxy..."
    if curl -k -s --connect-timeout 10 https://localhost/ > /dev/null; then
        log_success "✓ Nginx reverse proxy is working"
    else
        log_error "✗ Nginx reverse proxy is not working"
        log_info "Checking Nginx access logs..."
        tail -10 /var/log/nginx/access.log 2>/dev/null || log_info "No access logs found"
        return 1
    fi
    
    log_success "All checks passed! The Bad Gateway issue should be resolved."
}

# Display access information
show_access_info() {
    log_success "=== Access Information ==="
    echo "Admin Interface: https://$DOMAIN_NAME/admin"
    echo "Client Interface: https://$DOMAIN_NAME/"
    echo ""
    echo "If you're still having issues:"
    echo "1. Check firewall: ufw status"
    echo "2. Check services: systemctl status nginx"
    echo "3. Check OpenVPN AS: /usr/local/openvpn_as/scripts/sacli status"
    echo "4. View logs: tail -f /var/log/nginx/error.log"
}

# Main fix function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Nginx Bad Gateway Fix"
    echo "=========================================="
    echo
    
    check_root
    get_current_config
    check_services
    fix_openvpn_config
    fix_ssl_certificates
    create_nginx_config
    
    if test_nginx_config; then
        restart_services
        verify_fix
        show_access_info
    else
        log_error "Nginx configuration test failed. Please check the errors above."
    fi
}

# Run main function
main "$@"
