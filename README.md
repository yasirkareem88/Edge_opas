# OpenVPN AS with Virtual Host - Automated Deployment

Complete automated deployment of OpenVPN Access Server with virtual host configuration, SSL support, and comprehensive system optimization.

## Features

- ✅ **Full System Updates**: Comprehensive package and security updates
- ✅ **Virtual Host Configuration**: Professional domain-based setup
- ✅ **SSL/TLS Support**: Automatic Let's Encrypt integration
- ✅ **Nginx Reverse Proxy**: Optimized with security headers
- ✅ **Service Optimization**: Custom systemd service for better performance
- ✅ **Maintenance Tools**: Built-in management scripts
- ✅ **Health Monitoring**: Built-in health check endpoints

## Deployment Methods

### GitHub Actions (Recommended)
1. Go to **Actions** → **"Deploy OpenVPN AS with Virtual Host"**
2. Click **"Run workflow"**
3. Provide required inputs:
   - Target Server IP/Hostname
   - SSH Credentials
   - Domain Name
   - Admin Password
   - SSL Configuration

### Manual Deployment
```bash
# Clone and setup
git clone <your-repo>
cd <your-repo>

# Run deployment
chmod +x scripts/deploy-with-virtualhost.sh
./scripts/deploy-with-virtualhost.sh domain.com admin_password
