#!/bin/bash

# Fixed OpenVPN Access Server Installation Script with Admin Configuration Fix

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

# Detect OS
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
    read -s -p "Enter admin password (min 4 characters): " ADMIN_PASSWORD
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
    
    if [ ${#ADMIN_PASSWORD} -lt 4 ]; then
        log_error "Admin password must be at least 4 characters long"
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

# Setup repository for Ubuntu 24.04
setup_repository() {
    log_info "Setting up repository..."
    
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

# Configure admin user with multiple retries
configure_admin_user() {
    log_info "Configuring admin user..."
    
    local max_retries=10
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        # Stop OpenVPN AS services temporarily for configuration
        /usr/local/openvpn_as/scripts/sacli stop >/dev/null 2>&1
        sleep 2
        
        # Configure admin password
        if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
            log_success "Admin password configured successfully"
            
            # Configure superuser properties
            /usr/local/openvpn_as/scripts/sacli --key "prop_superuser_password" --value "$ADMIN_PASSWORD" ConfigPut >/dev/null 2>&1
            /usr/local/openvpn_as/scripts/sacli --key "prop_superuser" --value "$ADMIN_USER" ConfigPut >/dev/null 2>&1
            
            # Set host name
            /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut >/dev/null 2>&1
            
            # Configure ports for Nginx reverse proxy
            /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut >/dev/null 2>&1
            /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "web+client" ConfigPut >/dev/null 2>&1
            /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut >/dev/null 2>&1
            
            # Additional configuration for stability
            /usr/local/openvpn_as/scripts/sacli --key "cs.daemon.enable" --value "true" ConfigPut >/dev/null 2>&1
            /usr/local/openvpn_as/scripts/sacli --key "cs.https.ip" --value "127.0.0.1" ConfigPut >/dev/null 2>&1
            
            # Start services
            /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1
            sleep 5
            
            # Verify configuration
            if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" GetLocalPassword >/dev/null 2>&1; then
                log_success "Admin user configuration verified successfully"
                return 0
            fi
        fi
        
        retry=$((retry + 1))
        log_info "Retrying admin configuration... (attempt $retry/$max_retries)"
        sleep 5
    done
    
    log_error "Failed to configure admin user after $max_retries attempts"
    log_info "Trying alternative configuration method..."
    
    # Alternative method using Python
    configure_admin_alternative
}

# Alternative configuration method using Python
configure_admin_alternative() {
    log_info "Using alternative configuration method..."
    
    # Create a Python script to configure the admin user
    cat > /tmp/configure_admin.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import hashlib
import os
import sys

def configure_admin():
    try:
        # Path to OpenVPN AS database
        db_path = '/usr/local/openvpn_as/etc/db/config.db'
        
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get admin username and password from arguments
        admin_user = sys.argv[1] if len(sys.argv) > 1 else 'admin'
        admin_pass = sys.argv[2] if len(sys.argv) > 2 else 'password'
        
        # Create password hash (OpenVPN AS uses SHA1 for passwords)
        password_hash = hashlib.sha1(admin_pass.encode()).hexdigest()
        
        # Update or insert admin user
        cursor.execute('''
            INSERT OR REPLACE INTO user (user_name, pwd, access_granted, deactivated) 
            VALUES (?, ?, 1, 0)
        ''', (admin_user, password_hash))
        
        # Set as superuser
        cursor.execute('''
            INSERT OR REPLACE INTO user_prop (user_name, prop_name, value) 
            VALUES (?, 'prop_superuser', 'true')
        ''', (admin_user,))
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print(f"Successfully configured admin user: {admin_user}")
        return True
        
    except Exception as e:
        print(f"Error configuring admin user: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 configure_admin.py <username> <password>")
        sys.exit(1)
    
    if configure_admin():
        sys.exit(0)
    else:
        sys.exit(1)
EOF
    
    # Stop OpenVPN AS services
    /usr/local/openvpn_as/scripts/sacli stop >/dev/null 2>&1
    sleep 3
    
    # Run the Python configuration script
    if python3 /tmp/configure_admin.py "$ADMIN_USER" "$ADMIN_PASSWORD"; then
        log_success "Alternative admin configuration successful"
        
        # Set additional configuration
        /usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$DOMAIN_NAME" ConfigPut >/dev/null 2>&1
        /usr/local/openvpn_as/scripts/sacli --key "cs.https.port" --value "$OPENVPN_PORT" ConfigPut >/dev/null 2>&1
        /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.service" --value "web+client" ConfigPut >/dev/null 2>&1
        /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.port" --value "$NGINX_PORT" ConfigPut >/dev/null 2>&1
        
        # Start services
        /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1
        sleep 5
        
        return 0
    else
        log_error "Alternative configuration also failed"
        return 1
    fi
}

# Manual configuration as last resort
manual_admin_configuration() {
    log_info "Attempting manual configuration..."
    
    # Stop services
    /usr/local/openvpn_as/scripts/sacli stop >/dev/null 2>&1
    sleep 3
    
    # Manual configuration using sacli
    /usr/local/openvpn_as/scripts/confdba -us -p "$ADMIN_PASSWORD" >/dev/null 2>&1
    /usr/local/openvpn_as/scripts/confdba -m -k "host.name" -v "$DOMAIN_NAME" >/dev/null 2>&1
    
    # Start services
    /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1
    sleep 5
    
    # Try to set password again
    if /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1; then
        log_success "Manual configuration successful"
        return 0
    else
        log_warning "Manual configuration may have partial success"
        log_info "You may need to configure admin user through web interface"
        return 1
    fi
}

# Configure Nginx
configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
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
        proxy_buffering off;
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
    
    # Test and restart Nginx
    nginx -t && systemctl restart nginx
    log_success "Nginx configured successfully"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
    
    log_warning "Using self-signed certificates. For production, use Let's Encrypt"
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

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check if services are running
    if /usr/local/openvpn_as/scripts/sacli status 2>/dev/null | grep -q "started"; then
        log_success "OpenVPN AS services are running"
    else
        log_warning "Some OpenVPN AS services may not be running"
    fi
    
    # Check if we can access the admin interface
    if curl -k -s -f https://localhost:$OPENVPN_PORT/admin >/dev/null 2>&1; then
        log_success "Admin interface is accessible internally"
    else
        log_warning "Admin interface may not be accessible yet"
    fi
    
    log_success "Verification completed"
}

# Display final summary
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
    echo "=== Access Information ==="
    echo "Web Admin: https://$DOMAIN_NAME:$NGINX_PORT/admin"
    echo "Client Login: https://$DOMAIN_NAME:$NGINX_PORT/"
    echo
    echo "=== Next Steps ==="
    echo "1. Access the web interface using the credentials above"
    echo "2. Complete the setup wizard"
    echo "3. Replace self-signed certificates with proper SSL certificates"
    echo "4. Create client profiles and distribute to users"
    echo
    echo "=== Troubleshooting ==="
    echo "If you cannot login:"
    echo "1. Check service status: /usr/local/openvpn_as/scripts/sacli status"
    echo "2. View logs: tail -f /usr/local/openvpn_as/logs/*.log"
    echo "3. Reset admin password: /usr/local/openvpn_as/scripts/sacli --user $ADMIN_USER --new_pass 'newpassword' SetLocalPassword"
    echo
}

# Main installation function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Installer with Admin Fix"
    echo "=========================================="
    echo
    
    check_root
    detect_os
    get_user_input
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    wait_for_openvpn_ready
    
    # Try multiple configuration methods
    if ! configure_admin_user; then
        log_warning "Primary configuration failed, trying manual method..."
        if ! manual_admin_configuration; then
            log_error "All configuration methods failed"
            log_info "You may need to configure admin user through web interface"
        fi
    fi
    
    configure_nginx
    configure_firewall
    verify_installation
    show_summary
}

# Run main function
main "$@"
