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
cd $HOME
sudo apt install git -y (Ubuntu)
sudo yum install git -y  (Alma,centos,Redhat)
git clone https://github.com/yasirkareem88/Edge_opas.git
cd edge_opas

# Run deployment
chmod +x edge_opas.sh
sudo ./edge_opas.sh
