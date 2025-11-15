#!/bin/bash

# OpenVPN AS Complete Uninstall Script
# Removes everything installed by the installation script

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

# Get domain name from current configuration
get_domain_name() {
    if [ -f /usr/local/openvpn_as/etc/config.json ]; then
        DOMAIN_NAME=$(grep -o '"host.name": *"[^"]*"' /usr/local/openvpn_as/etc/config.json | cut -d'"' -f4)
    fi
    
    if [ -z "$DOMAIN_NAME" ]; then
        # Try to get from hosts file (most recent entry)
        DOMAIN_NAME=$(grep -v "^#" /etc/hosts | grep -v "localhost" | tail -1 | awk '{print $2}')
    fi
    
    if [ -z "$DOMAIN_NAME" ]; then
        DOMAIN_NAME="edge-srv.local"
        log_warning "Could not detect domain name, using default: $DOMAIN_NAME"
    fi
    
    echo "$DOMAIN_NAME"
}

# Stop all services
stop_services() {
    log_info "Stopping all related services..."
    
    # Stop OpenVPN AS
    if systemctl is-active --quiet openvpnas; then
        systemctl stop openvpnas
        log_success "Stopped OpenVPN AS service"
    fi
    
    # Stop Nginx
    if systemctl is-active --quiet nginx; then
        systemctl stop nginx
        log_success "Stopped Nginx service"
    fi
    
    # Kill any remaining OpenVPN processes
    pkill -f openvpn 2>/dev/null && log_info "Killed remaining OpenVPN processes"
    
    # Wait a moment for services to stop
    sleep 3
}

# Remove OpenVPN AS completely
remove_openvpn_as() {
    log_info "Removing OpenVPN Access Server completely..."
    
    # Remove via apt if installed
    if dpkg -l | grep -q "openvpn-as"; then
        apt-get remove --purge -y openvpn-as
        log_success "Removed OpenVPN AS package"
    fi
    
    # Remove any residual configuration
    apt-get autoremove -y
    apt-get autoclean
    
    # Completely remove OpenVPN AS directories
    if [ -d "/usr/local/openvpn_as" ]; then
        rm -rf /usr/local/openvpn_as
        log_success "Removed /usr/local/openvpn_as directory"
    fi
    
    if [ -d "/var/log/openvpn_as" ]; then
        rm -rf /var/log/openvpn_as
        log_success "Removed /var/log/openvpn_as directory"
    fi
    
    # Remove systemd service
    if [ -f "/usr/lib/systemd/system/openvpnas.service" ]; then
        rm -f /usr/lib/systemd/system/openvpnas.service
        systemctl daemon-reload
        log_success "Removed OpenVPN AS systemd service"
    fi
    
    # Remove any leftover files
    find /var/log -name "*openvpn*" -type f -delete 2>/dev/null
    find /tmp -name "*openvpn*" -type f -delete 2>/dev/null
    find /var/tmp -name "*openvpn*" -type f -delete 2>/dev/null
}

# Remove Nginx configuration
remove_nginx_config() {
    log_info "Removing Nginx configuration..."
    
    local domain_name="$1"
    
    # Remove our specific configuration
    if [ -f "/etc/nginx/sites-available/openvpn-as" ]; then
        rm -f /etc/nginx/sites-available/openvpn-as
        log_success "Removed Nginx site configuration"
    fi
    
    if [ -L "/etc/nginx/sites-enabled/openvpn-as" ]; then
        rm -f /etc/nginx/sites-enabled/openvpn-as
        log_success "Removed Nginx enabled site link"
    fi
    
    # Restore default site if it exists
    if [ -f "/etc/nginx/sites-available/default" ] && [ ! -L "/etc/nginx/sites-enabled/default" ]; then
        ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/
        log_info "Restored default Nginx site"
    fi
    
    # Remove our SSL certificates
    if [ -f "/etc/ssl/private/ssl-cert-snakeoil.key" ]; then
        rm -f /etc/ssl/private/ssl-cert-snakeoil.key
        log_success "Removed SSL private key"
    fi
    
    if [ -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" ]; then
        rm -f /etc/ssl/certs/ssl-cert-snakeoil.pem
        log_success "Removed SSL certificate"
    fi
    
    # Remove our log files
    if [ -f "/var/log/nginx/openvpn-as-access.log" ]; then
        rm -f /var/log/nginx/openvpn-as-access.log*
    fi
    
    if [ -f "/var/log/nginx/openvpn-as-error.log" ]; then
        rm -f /var/log/nginx/openvpn-as-error.log*
    fi
    
    # Restart Nginx with clean config
    if systemctl is-active --quiet nginx; then
        systemctl restart nginx
        log_success "Restarted Nginx with clean configuration"
    fi
}

# Remove repository configuration
remove_repository() {
    log_info "Removing OpenVPN AS repository..."
    
    if [ -f "/etc/apt/sources.list.d/openvpn-as-repo.list" ]; then
        rm -f /etc/apt/sources.list.d/openvpn-as-repo.list
        log_success "Removed OpenVPN AS repository"
    fi
    
    if [ -f "/etc/apt/keyrings/as-repository.asc" ]; then
        rm -f /etc/apt/keyrings/as-repository.asc
        log_success "Removed OpenVPN AS repository key"
    fi
    
    # Update package list
    apt-get update
}

# Clean up firewall rules
cleanup_firewall() {
    log_info "Cleaning up firewall rules..."
    
    if command -v ufw >/dev/null 2>&1; then
        # Remove specific OpenVPN rules
        ufw delete allow 943/tcp 2>/dev/null || true
        ufw delete allow 443/tcp 2>/dev/null || true
        ufw delete allow 1194/udp 2>/dev/null || true
        ufw delete allow 80/tcp 2>/dev/null || true
        
        log_success "Removed OpenVPN firewall rules"
        
        # Reload firewall
        ufw reload
    fi
}

# Remove domain from hosts file
remove_hosts_entry() {
    log_info "Removing domain from /etc/hosts file..."
    
    local domain_name="$1"
    
    if [ -n "$domain_name" ]; then
        # Create backup before modification
        cp /etc/hosts /etc/hosts.backup.uninstall.$(date +%Y%m%d_%H%M%S)
        
        # Remove all entries for the domain
        sed -i "/$domain_name/d" /etc/hosts
        
        log_success "Removed $domain_name from /etc/hosts"
    else
        log_warning "No domain name specified for hosts file cleanup"
    fi
}

# Remove user data and configurations
remove_user_data() {
    log_info "Removing user data and configurations..."
    
    # Remove any OpenVPN AS databases
    if [ -d "/usr/local/openvpn_as/etc/db" ]; then
        rm -rf /usr/local/openvpn_as/etc/db
        log_success "Removed OpenVPN AS databases"
    fi
    
    # Remove configuration directory
    if [ -d "/usr/local/openvpn_as/etc" ]; then
        rm -rf /usr/local/openvpn_as/etc
        log_success "Removed OpenVPN AS configuration directory"
    fi
    
    # Remove log directory
    if [ -d "/usr/local/openvpn_as/logs" ]; then
        rm -rf /usr/local/openvpn_as/logs
        log_success "Removed OpenVPN AS log directory"
    fi
    
    # Remove temporary files
    if [ -d "/usr/local/openvpn_as/tmp" ]; then
        rm -rf /usr/local/openvpn_as/tmp
        log_success "Removed OpenVPN AS temporary files"
    fi
}

# Remove installed dependencies (optional)
remove_dependencies() {
    log_info "Removing installed dependencies..."
    
    read -p "Remove installed dependencies? (y/N): " remove_deps
    
    if [[ "$remove_deps" =~ ^[Yy]$ ]]; then
        apt-get remove --purge -y \
            nginx \
            python3 \
            net-tools \
            ufw \
            liblzo2-2 \
            liblz4-1 \
            libpkcs11-helper1 \
            libcap-ng0 \
            sqlite3 \
            pkg-config \
            build-essential \
            libssl-dev \
            libpam0g-dev \
            liblz4-dev \
            liblzo2-dev \
            libpcap-dev \
            net-tools \
            iproute2 \
            ca-certificates \
            gnupg
            
        apt-get autoremove -y
        apt-get autoclean
        
        log_success "Removed installed dependencies"
    else
        log_info "Keeping dependencies installed"
    fi
}

# Clean up Python cache and temporary files
cleanup_python_cache() {
    log_info "Cleaning up Python cache and temporary files..."
    
    # Remove any Python cache files that might be left
    find /usr/local -name "*openvpn*" -type d -exec rm -rf {} + 2>/dev/null || true
    find /tmp -name "*openvpn*" -type f -delete 2>/dev/null
    find /var/tmp -name "*openvpn*" -type f -delete 2>/dev/null
    
    # Clean Python cache system-wide
    find /usr/lib/python* -name "*openvpn*" -type f -delete 2>/dev/null || true
    find /usr/local/lib/python* -name "*openvpn*" -type f -delete 2>/dev/null || true
    
    log_success "Cleaned up Python cache and temporary files"
}

# Verify complete removal
verify_removal() {
    log_info "Verifying complete removal..."
    
    echo
    echo "=== REMOVAL VERIFICATION ==="
    
    local errors=0
    
    # Check if OpenVPN AS directory is gone
    if [ -d "/usr/local/openvpn_as" ]; then
        log_error "✗ OpenVPN AS directory still exists: /usr/local/openvpn_as"
        ((errors++))
    else
        log_success "✓ OpenVPN AS directory removed"
    fi
    
    # Check if service is gone
    if systemctl list-unit-files | grep -q "openvpnas"; then
        log_error "✗ OpenVPN AS service still exists"
        ((errors++))
    else
        log_success "✓ OpenVPN AS service removed"
    fi
    
    # Check if processes are running
    if pgrep -f openvpn >/dev/null; then
        log_error "✗ OpenVPN processes still running"
        ((errors++))
    else
        log_success "✓ No OpenVPN processes running"
    fi
    
    # Check if Nginx configuration is clean
    if [ -f "/etc/nginx/sites-available/openvpn-as" ] || [ -L "/etc/nginx/sites-enabled/openvpn-as" ]; then
        log_error "✗ Nginx configuration still exists"
        ((errors++))
    else
        log_success "✓ Nginx configuration cleaned"
    fi
    
    if [ $errors -eq 0 ]; then
        log_success "✓ Complete removal verified successfully"
    else
        log_warning "⚠ Some components may not have been fully removed"
    fi
}

# Display final summary
show_summary() {
    log_success "OpenVPN AS uninstallation completed!"
    echo
    echo "=== UNINSTALLATION SUMMARY ==="
    echo "✓ Stopped all services"
    echo "✓ Removed OpenVPN AS software"
    echo "✓ Cleaned Nginx configuration"
    echo "✓ Removed firewall rules"
    echo "✓ Removed hosts entries"
    echo "✓ Cleaned up configuration files"
    echo "✓ Removed temporary files and cache"
    echo
    echo "=== NEXT STEPS ==="
    echo "1. If you want to reinstall, run the installation script again"
    echo "2. Reboot recommended: sudo reboot"
    echo "3. Check if any manual cleanup is needed in /etc/hosts"
    echo
}

# Main uninstall function
main() {
    clear
    echo "=========================================="
    echo "  OpenVPN AS Complete Uninstaller"
    echo "=========================================="
    echo
    echo "This script will COMPLETELY remove OpenVPN Access Server"
    echo "and all associated configurations from your system."
    echo
    echo "WARNING: This action cannot be undone!"
    echo "All OpenVPN AS data and configurations will be lost."
    echo
    
    read -p "Are you sure you want to continue? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
    
    check_root
    
    # Get domain name for cleanup
    DOMAIN_NAME=$(get_domain_name)
    log_info "Detected domain: $DOMAIN_NAME"
    
    # Perform uninstallation steps
    stop_services
    remove_openvpn_as
    remove_nginx_config "$DOMAIN_NAME"
    remove_repository
    cleanup_firewall
    remove_hosts_entry "$DOMAIN_NAME"
    remove_user_data
    cleanup_python_cache
    
    # Optional: Remove dependencies
    remove_dependencies
    
    # Verify removal
    verify_removal
    
    # Show summary
    show_summary
    
    log_info "Recommendation: Reboot your system to ensure complete cleanup"
    echo
    read -p "Reboot now? (y/N): " reboot_now
    if [[ "$reboot_now" =~ ^[Yy]$ ]]; then
        log_info "Rebooting system..."
        reboot
    fi
}

# Run main function
main "$@"