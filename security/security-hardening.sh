#!/bin/bash

# SmellPin Security Hardening Script
# Comprehensive security setup for production environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Update system packages
update_system() {
    log "Updating system packages..."
    
    # Detect OS
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get upgrade -y
        apt-get install -y curl wget gnupg2 software-properties-common \
            ufw fail2ban logrotate htop iotop nethogs \
            ssl-cert ca-certificates
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y curl wget gnupg2 epel-release \
            firewalld fail2ban logrotate htop iotop
    else
        error "Unsupported operating system"
    fi
}

# Configure firewall
setup_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian firewall setup
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        # SSH access
        ufw allow 22/tcp
        
        # HTTP/HTTPS
        ufw allow 80/tcp
        ufw allow 443/tcp
        
        # Monitoring (restrict to internal network)
        ufw allow from 10.0.0.0/8 to any port 3000
        ufw allow from 172.16.0.0/12 to any port 3000
        ufw allow from 192.168.0.0/16 to any port 3000
        ufw allow from 10.0.0.0/8 to any port 9090
        ufw allow from 172.16.0.0/12 to any port 9090
        ufw allow from 192.168.0.0/16 to any port 9090
        
        # Application ports (internal only)
        ufw allow from 10.0.0.0/8 to any port 3000
        ufw allow from 172.16.0.0/12 to any port 3000
        ufw allow from 192.168.0.0/16 to any port 3000
        
        # Docker subnet (if using Docker)
        ufw allow from 172.17.0.0/16
        ufw allow from 172.20.0.0/16
        
        ufw --force enable
        
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL firewall setup
        systemctl enable firewalld
        systemctl start firewalld
        
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    fi
    
    info "Firewall configured successfully"
}

# Install and configure Fail2Ban
setup_fail2ban() {
    log "Configuring Fail2Ban..."
    
    # Create jail.local configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban for 1 hour
bantime = 3600
# Check for attacks in 10 minutes
findtime = 600
# Allow 3 attempts before banning
maxretry = 3

# Email notifications
destemail = security@smellpin.com
sender = fail2ban@smellpin.com
mta = sendmail

# Enable notifications
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-nohome]
enabled = true
port = http,https
filter = nginx-nohome
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-nophp]
enabled = true
port = http,https
filter = nginx-nophp
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
EOF

    # Create custom filters for SmellPin
    cat > /etc/fail2ban/filter.d/nginx-limit-req.conf << 'EOF'
[Definition]
failregex = limiting requests, excess: [.\d]+ by zone ".*", client: <HOST>
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/nginx-badbots.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" (404|403|200) .*".*bot.*".*
ignoreregex = (googlebot|bingbot|slurp|DuckDuckBot)
EOF

    cat > /etc/fail2ban/filter.d/nginx-nophp.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*\.php.*" (404|403|200).*
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/nginx-nohome.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*"GET .*/~.*".*
ignoreregex =
EOF

    # Start and enable Fail2Ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    info "Fail2Ban configured successfully"
}

# Generate SSL certificates using Let's Encrypt
setup_ssl() {
    log "Setting up SSL certificates..."
    
    # Install Certbot
    if command -v apt-get &> /dev/null; then
        snap install --classic certbot
        ln -sf /snap/bin/certbot /usr/bin/certbot
    elif command -v yum &> /dev/null; then
        yum install -y certbot python3-certbot-nginx
    fi
    
    # Create directories for SSL
    mkdir -p /etc/nginx/ssl
    
    # Generate DH parameters
    if [[ ! -f /etc/nginx/ssl/dhparam.pem ]]; then
        info "Generating DH parameters (this may take a while)..."
        openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
    fi
    
    # Generate self-signed certificates for testing
    if [[ ! -f /etc/nginx/ssl/smellpin.com.crt ]]; then
        warn "Generating self-signed certificates for testing"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/smellpin.com.key \
            -out /etc/nginx/ssl/smellpin.com.crt \
            -subj "/C=US/ST=CA/L=SF/O=SmellPin/OU=IT/CN=smellpin.com"
        
        cp /etc/nginx/ssl/smellpin.com.crt /etc/nginx/ssl/smellpin.com.chain.crt
        cp /etc/nginx/ssl/smellpin.com.key /etc/nginx/ssl/api.smellpin.com.key
        cp /etc/nginx/ssl/smellpin.com.crt /etc/nginx/ssl/api.smellpin.com.crt
        cp /etc/nginx/ssl/smellpin.com.crt /etc/nginx/ssl/api.smellpin.com.chain.crt
        cp /etc/nginx/ssl/smellpin.com.key /etc/nginx/ssl/monitoring.smellpin.com.key
        cp /etc/nginx/ssl/smellpin.com.crt /etc/nginx/ssl/monitoring.smellpin.com.crt
    fi
    
    # Set proper permissions
    chmod 644 /etc/nginx/ssl/*.crt
    chmod 600 /etc/nginx/ssl/*.key
    chown -R root:root /etc/nginx/ssl/
    
    info "SSL certificates configured"
    warn "Replace self-signed certificates with Let's Encrypt in production"
    info "Run: certbot --nginx -d smellpin.com -d www.smellpin.com -d api.smellpin.com"
}

# Configure system security settings
harden_system() {
    log "Applying system security hardening..."
    
    # Kernel parameters for security
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0

# TCP SYN Cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# TCP connection settings
net.ipv4.tcp_keepalive_time = 7200
net.ipv4.tcp_keepalive_probes = 9
net.ipv4.tcp_keepalive_intvl = 75
net.ipv4.tcp_fin_timeout = 30

# Network security
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864

# File system security
fs.file-max = 2097152
fs.suid_dumpable = 0

# Process security
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
EOF

    # Apply kernel parameters
    sysctl -p /etc/sysctl.d/99-security.conf
    
    # Set file permissions for security
    chmod 700 /root
    chmod 755 /etc/crontab
    chmod 600 /etc/ssh/sshd_config
    
    # Remove unnecessary packages
    if command -v apt-get &> /dev/null; then
        apt-get autoremove -y
        apt-get autoclean
    fi
    
    info "System hardening completed"
}

# Configure SSH security
harden_ssh() {
    log "Hardening SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    cat > /etc/ssh/sshd_config << 'EOF'
# SmellPin SSH Security Configuration

# Basic Settings
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 4
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Kerberos and GSSAPI
KerberosAuthentication no
GSSAPIAuthentication no

# Security
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
UsePrivilegeSeparation sandbox
PermitUserEnvironment no
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server -l INFO

# Allow only specific users/groups
AllowUsers smellpin deploy
DenyUsers root

# Banner
Banner /etc/issue.net
EOF

    # Create security banner
    cat > /etc/issue.net << 'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for the use of authorized users only. Individuals using
this computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored
and recorded by system personnel.

Anyone using this system expressly consents to such monitoring and is
advised that if such monitoring reveals possible evidence of criminal
activity, system personnel may provide the evidence from such monitoring
to law enforcement officials.

Unauthorized access is prohibited and may be subject to criminal and/or
civil prosecution.
***************************************************************************
EOF

    # Test SSH configuration
    sshd -t || error "SSH configuration is invalid"
    
    # Restart SSH service
    systemctl restart sshd
    
    info "SSH hardening completed"
}

# Create monitoring user and directories
setup_monitoring_user() {
    log "Setting up monitoring user and directories..."
    
    # Create smellpin user if it doesn't exist
    if ! id "smellpin" &>/dev/null; then
        useradd -r -m -s /bin/bash -d /opt/smellpin smellpin
        usermod -aG docker smellpin 2>/dev/null || true
    fi
    
    # Create directory structure
    mkdir -p /opt/smellpin/{monitoring,logs,backups,ssl}
    mkdir -p /opt/smellpin/monitoring/{data,configs}
    mkdir -p /opt/smellpin/monitoring/data/{prometheus,grafana,alertmanager,loki}
    
    # Set permissions
    chown -R smellpin:smellpin /opt/smellpin
    chmod -R 755 /opt/smellpin
    chmod -R 700 /opt/smellpin/ssl
    
    info "Monitoring user and directories created"
}

# Setup log rotation
setup_logrotate() {
    log "Configuring log rotation..."
    
    cat > /etc/logrotate.d/smellpin << 'EOF'
/opt/smellpin/logs/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 smellpin smellpin
    postrotate
        systemctl reload nginx > /dev/null 2>&1 || true
    endscript
}

/var/log/nginx/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload nginx > /dev/null 2>&1 || true
    endscript
}
EOF

    # Test logrotate
    logrotate -d /etc/logrotate.d/smellpin
    
    info "Log rotation configured"
}

# Create system monitoring script
create_monitoring_script() {
    log "Creating system monitoring script..."
    
    cat > /opt/smellpin/monitor-system.sh << 'EOF'
#!/bin/bash

# SmellPin System Monitoring Script

LOGFILE="/opt/smellpin/logs/system-monitor.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Create log directory if it doesn't exist
mkdir -p /opt/smellpin/logs

# Function to log messages
log_message() {
    echo "[$TIMESTAMP] $1" >> $LOGFILE
}

# Check disk space
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 85 ]; then
    log_message "WARNING: Disk usage is ${DISK_USAGE}%"
    echo "WARNING: Disk usage is ${DISK_USAGE}%" | mail -s "Disk Space Alert - SmellPin" admin@smellpin.com
fi

# Check memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
if [ $MEMORY_USAGE -gt 85 ]; then
    log_message "WARNING: Memory usage is ${MEMORY_USAGE}%"
fi

# Check CPU load
CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | xargs)
if (( $(echo "$CPU_LOAD > 4" | bc -l) )); then
    log_message "WARNING: High CPU load: $CPU_LOAD"
fi

# Check if services are running
SERVICES=("nginx" "fail2ban" "docker")
for SERVICE in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet $SERVICE; then
        log_message "ERROR: $SERVICE is not running"
        echo "ERROR: $SERVICE is not running" | mail -s "Service Down Alert - SmellPin" admin@smellpin.com
    fi
done

# Check SSL certificate expiry
if command -v openssl &> /dev/null; then
    CERT_EXPIRY=$(echo | openssl s_client -servername smellpin.com -connect smellpin.com:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s)
    CURRENT_EPOCH=$(date +%s)
    DAYS_UNTIL_EXPIRY=$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
    
    if [ $DAYS_UNTIL_EXPIRY -lt 30 ]; then
        log_message "WARNING: SSL certificate expires in $DAYS_UNTIL_EXPIRY days"
        echo "WARNING: SSL certificate expires in $DAYS_UNTIL_EXPIRY days" | mail -s "SSL Certificate Expiry Alert - SmellPin" admin@smellpin.com
    fi
fi

# Log successful completion
log_message "System monitoring completed successfully"
EOF

    chmod +x /opt/smellpin/monitor-system.sh
    chown smellpin:smellpin /opt/smellpin/monitor-system.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/15 * * * * /opt/smellpin/monitor-system.sh") | crontab -
    
    info "System monitoring script created and scheduled"
}

# Setup intrusion detection
setup_intrusion_detection() {
    log "Setting up intrusion detection..."
    
    # Install AIDE (Advanced Intrusion Detection Environment)
    if command -v apt-get &> /dev/null; then
        apt-get install -y aide
        
        # Initialize AIDE database
        aideinit
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        
        # Schedule daily integrity checks
        echo "0 2 * * * /usr/bin/aide --check && /usr/bin/aide --update" >> /var/spool/cron/crontabs/root
        
    elif command -v yum &> /dev/null; then
        yum install -y aide
        aide --init
        mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
    
    info "Intrusion detection configured"
}

# Main execution
main() {
    log "Starting SmellPin security hardening..."
    
    check_root
    update_system
    setup_firewall
    setup_fail2ban
    setup_ssl
    harden_system
    harden_ssh
    setup_monitoring_user
    setup_logrotate
    create_monitoring_script
    setup_intrusion_detection
    
    log "Security hardening completed successfully!"
    info "Please review the following:"
    info "1. Update /etc/hosts with proper domain mappings"
    info "2. Replace self-signed SSL certificates with Let's Encrypt"
    info "3. Configure email settings for alerts"
    info "4. Review firewall rules for your specific environment"
    info "5. Test SSH access with key-based authentication"
    info "6. Setup proper DNS records for domains"
    
    warn "Reboot the system to ensure all changes take effect"
}

# Run main function
main "$@"