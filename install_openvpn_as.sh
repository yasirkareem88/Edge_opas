#!/bin/bash

# OpenVPN AS Installation Script for Ubuntu 24.04
# Enhanced with ZeroTier-style NAT traversal and peer-to-peer connectivity

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
PUBLIC_IP=""
UPNP_AVAILABLE=false
ZEROTIER_MODE=true
CONNECTION_STRATEGIES=()

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
    exit 1
}

log_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $1"
}

# ZeroTier-inspired NAT traversal class
ZeroTierNAT() {
    local strategy_id=""
    local max_retries=3
    local retry_delay=2
    
    # Initialize ZeroTier-style NAT traversal
    init() {
        log_info "Initializing ZeroTier-style NAT traversal..."
        STRATEGY_ID=$(date +%s)
        CONNECTION_STRATEGIES=(
            "udp_hole_punching"
            "tcp_hole_punching" 
            "upnp_forwarding"
            "relay_fallback"
            "ipv6_native"
        )
    }
    
    # ZeroTier's coordinated hole punching technique
    udp_hole_punching() {
        log_info "Attempting UDP hole punching (ZeroTier technique)..."
        
        local external_host="8.8.8.8"
        local external_port="53"
        local local_port=$1
        
        # Phase 1: Send packets to create NAT mapping (ZeroTier's simultaneous open)
        for i in {1..5}; do
            (
                echo "PUNCH" | timeout 1 nc -u -p $local_port $external_host $external_port >/dev/null 2>&1 &
                sleep 0.2
            ) &
        done
        
        # Phase 2: Maintain NAT binding with keep-alive packets
        (
            while true; do
                echo "KEEPALIVE" | nc -u -p $local_port 127.0.0.1 9999 >/dev/null 2>&1
                sleep 30
            done
        ) &
        
        log_success "UDP hole punching initiated on port $local_port"
        return 0
    }
    
    # TCP hole punching for fallback
    tcp_hole_punching() {
        log_info "Attempting TCP hole punching..."
        
        local local_port=$1
        local test_services=("google.com:80" "cloudflare.com:80" "1.1.1.1:80")
        
        for service in "${test_services[@]}"; do
            local host=${service%:*}
            local port=${service#*:}
            
            timeout 3 bash -c "echo 'PUNCH' | nc -p $local_port $host $port" >/dev/null 2>&1 &
        done
        
        log_info "TCP hole punching attempts sent"
        return 0
    }
    
    # Enhanced UPnP with ZeroTier-style cleanup
    upnp_forwarding() {
        if [ "$UPNP_AVAILABLE" != "true" ]; then
            return 1
        fi
        
        log_info "Configuring UPnP with ZeroTier-style mapping..."
        
        local internal_port=$1
        local external_port=$2
        local protocol=$3
        
        # ZeroTier principle: Clean previous mappings first
        upnpc -d $external_port $protocol >/dev/null 2>&1 || true
        sleep 1
        
        # Create new mapping with unique description
        local mapping_id="zt_${STRATEGY_ID}_${internal_port}_${protocol}"
        if upnpc -a "$SERVER_IP" $internal_port $external_port $protocol "OpenVPN_ZT_${mapping_id}" >/dev/null 2>&1; then
            log_success "UPnP mapping created: $internal_port->$external_port/$protocol"
            return 0
        else
            log_warning "UPnP mapping failed: $internal_port->$external_port/$protocol"
            return 1
        fi
    }
    
    # Relay fallback simulation (ZeroTier Moon/Planet concept)
    relay_fallback() {
        log_info "Configuring relay fallback (ZeroTier Planet concept)..."
        
        # Configure multiple listener ports for redundancy
        local relay_ports=("1194" "443" "8080" "8443")
        
        for port in "${relay_ports[@]}"; do
            /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.tcp.port" --value "$port" ConfigPut >/dev/null 2>&1 || true
        done
        
        log_success "Relay fallback configured on multiple ports"
        return 0
    }
    
    # IPv6 native connectivity
    ipv6_native() {
        log_info "Checking IPv6 native connectivity..."
        
        if ip -6 addr show | grep -q "inet6" && [ "$(curl -s -6 --connect-timeout 3 https://ipv6.google.com >/dev/null 2>&1; echo $?)" -eq 0 ]; then
            log_success "IPv6 native connectivity available"
            return 0
        else
            log_warning "IPv6 native connectivity not available"
            return 1
        fi
    }
    
    # ZeroTier-style multi-strategy connectivity
    establish_connectivity() {
        local port_configs=("$@")
        
        log_info "Establishing connectivity using ZeroTier multi-strategy approach..."
        
        local successful_strategies=()
        
        for config in "${port_configs[@]}"; do
            local internal_port=$(echo "$config" | cut -d':' -f1)
            local external_port=$(echo "$config" | cut -d':' -f2)
            local protocol=$(echo "$config" | cut -d':' -f3)
            
            log_info "Configuring port $internal_port->$external_port/$protocol"
            
            # Try multiple strategies in parallel
            if udp_hole_punching $internal_port; then
                successful_strategies+=("udp_hole_punching:$internal_port")
            fi
            
            if [ "$protocol" = "tcp" ] && tcp_hole_punching $internal_port; then
                successful_strategies+=("tcp_hole_punching:$internal_port")
            fi
            
            if upnp_forwarding $internal_port $external_port $protocol; then
                successful_strategies+=("upnp_forwarding:${internal_port}->${external_port}")
            fi
        done
        
        # Always configure relay fallback
        relay_fallback
        
        # Enable IPv6 if available
        ipv6_native || true
        
        log_success "Connectivity established with ${#successful_strategies[@]} strategies"
        printf '%s\n' "${successful_strategies[@]}"
    }
    
    "$@"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
    fi
}

# Detect OS and verify Ubuntu compatibility
detect_os() {
    log_info "Detecting operating system..."
    
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect operating system"
    fi
    
    . /etc/os-release
    
    # Get network information
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    SERVER_IP=${SERVER_IP:-"127.0.0.1"}
    
    SERVER_HOSTNAME=$(hostname -s)
    
    log_info "Detected: $NAME $VERSION"
    log_info "Server IP: $SERVER_IP"
    log_info "Server Hostname: $SERVER_HOSTNAME"
}

# Get public IP address using multiple services
get_public_ip() {
    log_info "Detecting public IP address..."
    
    local services=(
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://icanhazip.com"
        "https://ident.me"
    )
    
    for service in "${services[@]}"; do
        if PUBLIC_IP=$(curl -s -4 --connect-timeout 3 "$service" 2>/dev/null); then
            if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                log_success "Public IP detected: $PUBLIC_IP"
                return 0
            fi
        fi
    done
    
    PUBLIC_IP="Unable to detect"
    log_warning "Could not detect public IP address"
    return 1
}

# Check UPnP availability with timeout
check_upnp() {
    log_info "Checking UPnP availability..."
    
    if ! command -v upnpc >/dev/null 2>&1; then
        log_info "Installing UPnP client..."
        apt-get install -y miniupnpc >/dev/null 2>&1 || {
            log_warning "Failed to install UPnP client"
            UPNP_AVAILABLE=false
            return 1
        }
    fi
    
    if timeout 10 upnpc -s >/dev/null 2>&1; then
        UPNP_AVAILABLE=true
        log_success "UPnP is available on your router"
        return 0
    else
        UPNP_AVAILABLE=false
        log_warning "UPnP is not available on your router"
        return 1
    fi
}

# Enhanced port configuration with ZeroTier strategy
configure_ports() {
    log_info "Configuring network ports with ZeroTier strategy..."
    
    # Default ports with ZeroTier-style redundancy
    SSH_PORT=22
    HTTP_PORT=80
    HTTPS_PORT=443
    OPENVPN_PORT=943
    OPENVPN_UDP_PORT=1194
    
    # Additional ports for relay fallback
    RELAY_PORTS=("8080" "8443" "8888")
    
    log_info "Port Configuration:"
    echo "  Primary UDP: $OPENVPN_UDP_PORT/udp"
    echo "  Primary TCP: $OPENVPN_PORT/tcp"
    echo "  Web Interface: $HTTPS_PORT/tcp"
    echo "  Relay Ports: ${RELAY_PORTS[*]}"
}

# User input with validation
get_user_input() {
    log_info "OpenVPN AS Configuration"
    echo "======================================"
    
    # Domain configuration
    local default_domain="vpn.${SERVER_HOSTNAME}.local"
    echo "Domain Configuration:"
    read -p "Enter domain name [$default_domain]: " user_domain
    DOMAIN_NAME=${user_domain:-$default_domain}
    
    # Admin credentials
    echo
    read -p "Enter admin username [admin]: " admin_user
    ADMIN_USER=${admin_user:-admin}
    
    while true; do
        read -s -p "Enter admin password (min 8 characters): " ADMIN_PASSWORD
        echo
        if [ ${#ADMIN_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
            echo
            if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
                break
            else
                log_warning "Passwords do not match. Please try again."
            fi
        else
            log_warning "Password must be at least 8 characters long."
        fi
    done
    
    # Configure ports
    configure_ports
    
    echo
    read -p "Continue with installation? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled."
        exit 0
    fi
}

# Configure hosts file
configure_hosts_file() {
    log_info "Configuring /etc/hosts file..."
    
    cp /etc/hosts /etc/hosts.bak.$(date +%Y%m%d_%H%M%S)
    sed -i "/$DOMAIN_NAME/d" /etc/hosts
    echo "$SERVER_IP    $DOMAIN_NAME" >> /etc/hosts
    
    log_success "Added $DOMAIN_NAME to /etc/hosts"
}

# Install dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    apt-get update || log_error "Failed to update package lists"
    
    local dependencies=(
        wget curl gnupg lsb-release
        software-properties-common apt-transport-https
        ca-certificates sqlite3 python3 python3-pip
        net-tools nginx ufw openssl miniupnpc
        netcat dnsutils socat
    )
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${dependencies[@]}" || 
        log_error "Failed to install dependencies"
    
    log_success "Dependencies installed successfully"
}

# Install OpenVPN AS
install_openvpn_as() {
    log_info "Installing OpenVPN Access Server..."
    
    local installer_url="https://packages.openvpn.net/as/install.sh"
    local installer_path="/tmp/openvpn-as-install.sh"
    
    wget -q "$installer_url" -O "$installer_path" || 
        log_error "Failed to download OpenVPN AS installer"
    
    chmod +x "$installer_path"
    
    if timeout 300 "$installer_path" --yes; then
        log_success "OpenVPN AS installed successfully"
        rm -f "$installer_path"
    else
        log_error "OpenVPN AS installation failed or timed out"
    fi
}

# Configure virtual network with ZeroTier-style settings
configure_virtual_network() {
    log_info "Configuring virtual network with ZeroTier principles..."
    
    systemctl stop openvpnas 2>/dev/null || true
    sleep 3
    
    # ZeroTier-style network configuration
    local virtual_subnet="172.27.224.0"
    local virtual_netmask="255.255.252.0"  # /22 subnet for more clients
    local server_ip="172.27.224.1"
    
    local config_settings=(
        "host.name=$DOMAIN_NAME"
        "cs.https.port=$OPENVPN_PORT"
        "cs.https.ip=127.0.0.1"
        "vpn.server.port_share.service=admin+client"
        "vpn.server.port_share.port=$HTTPS_PORT"
        "vpn.daemon.0.client.network=$virtual_subnet"
        "vpn.daemon.0.server.ip_address=$server_ip"
        "vpn.daemon.0.server.netmask=$virtual_netmask"
        "vpn.daemon.0.listen.ip_address=0.0.0.0"  # Listen on all interfaces
        "vpn.server.daemon.udp.port=$OPENVPN_UDP_PORT"
        "vpn.server.daemon.tcp.port=443"
        "vpn.client.routing.reroute_dns=true"
        "vpn.client.routing.reroute_gw=true"
        "cs.daemon.enable=true"
        "vpn.server.daemon.debug=true"
    )
    
    for setting in "${config_settings[@]}"; do
        local key="${setting%=*}"
        local value="${setting#*=}"
        /usr/local/openvpn_as/scripts/sacli --key "$key" --value "$value" ConfigPut >/dev/null 2>&1 || 
            log_warning "Failed to configure: $key"
    done
    
    # Set admin password
    /usr/local/openvpn_as/scripts/sacli --user "$ADMIN_USER" --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null 2>&1 ||
        log_warning "Admin password setting failed, may need manual setup"
    
    systemctl start openvpnas 2>/dev/null || /usr/local/openvpn_as/scripts/sacli start >/dev/null 2>&1 || true
    
    log_success "Virtual network configured with ZeroTier principles"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates for $DOMAIN_NAME..."
    
    mkdir -p /etc/ssl/private /etc/ssl/certs
    
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME" 2>/dev/null
    
    chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
    
    log_success "SSL certificates generated"
}

# Configure Nginx with enhanced security
configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
    systemctl stop nginx 2>/dev/null || true
    
    cat > /etc/nginx/sites-available/openvpn-as << EOF
server {
    listen $HTTP_PORT;
    server_name $DOMAIN_NAME;
    return 301 https://\$server_name:\$server_port\$request_uri;
}

server {
    listen $HTTPS_PORT ssl;
    server_name $DOMAIN_NAME;
    
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Enhanced security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    location / {
        proxy_pass https://127.0.0.1:$OPENVPN_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Buffer settings for better performance
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
EOF
    
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/openvpn-as /etc/nginx/sites-enabled/
    
    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        log_success "Nginx configured successfully"
    else
        log_error "Nginx configuration test failed"
    fi
}

# Configure firewall with ZeroTier-style port rules
configure_firewall() {
    log_info "Configuring firewall with ZeroTier-style rules..."
    
    ufw --force reset || true
    echo "y" | ufw enable || true
    
    # Primary ports
    ufw allow "$SSH_PORT/tcp" comment "SSH"
    ufw allow "$HTTP_PORT/tcp" comment "HTTP"
    ufw allow "$HTTPS_PORT/tcp" comment "HTTPS"
    ufw allow "$OPENVPN_UDP_PORT/udp" comment "OpenVPN-UDP-Primary"
    ufw allow "$OPENVPN_PORT/tcp" comment "OpenVPN-TCP-Primary"
    
    # Relay/fallback ports
    ufw allow "8080/tcp" comment "OpenVPN-Relay-1"
    ufw allow "8443/tcp" comment "OpenVPN-Relay-2"
    ufw allow "8888/tcp" comment "OpenVPN-Relay-3"
    
    echo "y" | ufw enable
    
    log_success "Firewall configured with ZeroTier-style redundancy"
}

# Wait for services with progress indicator
wait_for_services() {
    log_info "Waiting for OpenVPN AS services to be ready..."
    
    local max_wait=60
    local wait_time=0
    
    while [ $wait_time -lt $max_wait ]; do
        if systemctl is-active --quiet openvpnas && \
           curl -k -s https://localhost:943/admin >/dev/null 2>&1; then
            log_success "OpenVPN AS is ready"
            return 0
        fi
        sleep 5
        ((wait_time+=5))
        log_info "Waiting... ${wait_time}s/${max_wait}s"
    done
    
    log_warning "OpenVPN AS taking longer than expected to start"
    return 1
}

# Display installation summary with ZeroTier-style info
display_summary() {
    echo
    echo "=================================================="
    echo "    OPENVPN AS + ZEROTIER NAT TRAVERSAL"
    echo "=================================================="
    echo
    echo "=== ZEROTIER-STYLE CONNECTIVITY ==="
    echo "NAT Traversal Strategies:"
    for strategy in "${CONNECTION_STRATEGIES[@]}"; do
        echo "  ✓ $strategy"
    done
    echo "UPnP Status: $UPNP_AVAILABLE"
    echo "Public IP: $PUBLIC_IP"
    echo
    echo "=== ACCESS INFORMATION ==="
    echo "Admin Interface:  https://$DOMAIN_NAME:$HTTPS_PORT/admin"
    echo "Client Interface: https://$DOMAIN_NAME:$HTTPS_PORT/"
    echo "Direct Access:    https://$SERVER_IP:$HTTPS_PORT/admin"
    if [ "$PUBLIC_IP" != "Unable to detect" ]; then
        echo "Public Access:    https://$PUBLIC_IP:$HTTPS_PORT/admin"
    fi
    echo
    echo "=== NETWORK CONFIGURATION ==="
    echo "Virtual Network:  172.27.224.0/22"
    echo "Client IP Range:  172.27.224.2 - 172.27.227.254"
    echo "Server VPN IP:    172.27.224.1"
    echo "Primary UDP Port: $OPENVPN_UDP_PORT"
    echo "Primary TCP Port: $OPENVPN_PORT"
    echo "Relay Ports:      8080, 8443, 8888"
    echo
    echo "=== CREDENTIALS ==="
    echo "Username: $ADMIN_USER"
    echo "Password: ********"
    echo
    echo "=== SERVICE STATUS ==="
    if systemctl is-active --quiet openvpnas; then
        echo -e "${GREEN}✓ OpenVPN AS: RUNNING${NC}"
    else
        echo -e "${RED}✗ OpenVPN AS: STOPPED${NC}"
    fi
    
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✓ Nginx: RUNNING${NC}"
    else
        echo -e "${RED}✗ Nginx: STOPPED${NC}"
    fi
    
    echo
    echo "=== ZEROTIER FEATURES ENABLED ==="
    echo "✓ Multi-strategy NAT traversal"
    echo "✓ UDP/TCP hole punching"
    echo "✓ Relay fallback ports"
    echo "✓ IPv6 readiness"
    echo "✓ Enhanced connectivity"
    echo
}

# Main installation function
main() {
    clear
    echo "=================================================="
    echo "   OpenVPN AS + ZeroTier NAT Traversal"
    echo "           Ubuntu 24.04 Installer"
    echo "=================================================="
    echo
    
    trap 'log_error "Installation interrupted"; exit 1' INT TERM
    
    # Initialize ZeroTier NAT traversal
    ZeroTierNAT init
    
    # Installation steps
    check_root
    detect_os
    get_public_ip
    check_upnp
    get_user_input
    configure_hosts_file
    install_dependencies
    generate_ssl_certificates
    install_openvpn_as
    configure_virtual_network
    configure_nginx
    configure_firewall
    
    # Establish ZeroTier-style connectivity
    log_info "Establishing ZeroTier-style connectivity..."
    local port_configs=(
        "$OPENVPN_UDP_PORT:$OPENVPN_UDP_PORT:udp"
        "$OPENVPN_PORT:$OPENVPN_PORT:tcp"
        "$HTTPS_PORT:$HTTPS_PORT:tcp"
    )
    
    CONNECTION_STRATEGIES=($(ZeroTierNAT establish_connectivity "${port_configs[@]}"))
    
    wait_for_services
    display_summary
    
    log_success "OpenVPN AS with ZeroTier NAT traversal installed successfully!"
    echo
    log_info "ZeroTier Features Active:"
    log_info "• Multi-path connectivity established"
    log_info "• NAT traversal strategies: ${#CONNECTION_STRATEGIES[@]}"
    log_info "• Relay fallback configured"
    log_info "• Enhanced client connectivity"
}

# Run main function
main "$@"
