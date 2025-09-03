#!/bin/bash

# SSL证书配置和HTTPS设置脚本
# 支持Let's Encrypt自动证书和自签名证书

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
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

# 检查是否为root用户
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root user"
    fi
}

# 检查系统依赖
check_dependencies() {
    log_info "Checking system dependencies..."
    
    # 检查操作系统
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macOS"
    else
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    log_info "Detected OS: $OS ($DISTRO)"
    
    # 检查必要工具
    local tools=("curl" "openssl")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    log_success "All dependencies satisfied"
}

# 安装Certbot (Let's Encrypt客户端)
install_certbot() {
    log_info "Installing Certbot..."
    
    if [[ "$OS" == "linux" ]]; then
        if [[ "$DISTRO" == "Ubuntu" ]] || [[ "$DISTRO" == "Debian" ]]; then
            sudo apt-get update
            sudo apt-get install -y certbot python3-certbot-nginx
        elif [[ "$DISTRO" == "CentOS" ]] || [[ "$DISTRO" == "RHEL" ]]; then
            sudo yum install -y epel-release
            sudo yum install -y certbot python3-certbot-nginx
        else
            log_warning "Unknown Linux distribution, trying snap installation"
            sudo snap install --classic certbot
            sudo ln -sf /snap/bin/certbot /usr/bin/certbot
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew install certbot
        else
            log_error "Homebrew not found. Please install Homebrew first."
            exit 1
        fi
    fi
    
    log_success "Certbot installed successfully"
}

# 生成自签名证书
generate_self_signed_cert() {
    local domain="$1"
    local cert_dir="$2"
    
    log_info "Generating self-signed certificate for $domain..."
    
    # 创建证书目录
    mkdir -p "$cert_dir"
    
    # 生成私钥
    openssl genrsa -out "$cert_dir/privkey.pem" 2048
    
    # 生成证书签名请求配置
    cat > "$cert_dir/cert.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = CN
ST = Beijing
L = Beijing
O = SmellPin
OU = IT Department
CN = $domain

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = *.$domain
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    
    # 生成证书
    openssl req -new -x509 -key "$cert_dir/privkey.pem" \
        -out "$cert_dir/fullchain.pem" \
        -days 365 \
        -config "$cert_dir/cert.conf" \
        -extensions v3_req
    
    # 复制证书文件
    cp "$cert_dir/fullchain.pem" "$cert_dir/cert.pem"
    
    # 设置权限
    chmod 600 "$cert_dir/privkey.pem"
    chmod 644 "$cert_dir/fullchain.pem" "$cert_dir/cert.pem"
    
    # 清理临时文件
    rm -f "$cert_dir/cert.conf"
    
    log_success "Self-signed certificate generated: $cert_dir"
}

# 获取Let's Encrypt证书
get_letsencrypt_cert() {
    local domain="$1"
    local email="$2"
    local webroot="$3"
    
    log_info "Obtaining Let's Encrypt certificate for $domain..."
    
    if [[ -z "$email" ]]; then
        log_error "Email address is required for Let's Encrypt"
        exit 1
    fi
    
    # 检查域名是否可访问
    if ! curl -s --connect-timeout 10 "http://$domain" > /dev/null; then
        log_warning "Domain $domain may not be accessible from the internet"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Certificate generation cancelled"
            exit 0
        fi
    fi
    
    # 使用webroot方式获取证书
    if [[ -n "$webroot" ]] && [[ -d "$webroot" ]]; then
        certbot certonly \
            --webroot \
            --webroot-path="$webroot" \
            --email="$email" \
            --agree-tos \
            --no-eff-email \
            --domains="$domain"
    else
        # 使用standalone方式（需要停止web服务器）
        log_warning "Using standalone mode - web server will be temporarily stopped"
        certbot certonly \
            --standalone \
            --email="$email" \
            --agree-tos \
            --no-eff-email \
            --domains="$domain"
    fi
    
    if [[ $? -eq 0 ]]; then
        log_success "Let's Encrypt certificate obtained successfully"
        log_info "Certificate location: /etc/letsencrypt/live/$domain/"
    else
        log_error "Failed to obtain Let's Encrypt certificate"
        exit 1
    fi
}

# 设置证书自动续期
setup_auto_renewal() {
    log_info "Setting up automatic certificate renewal..."
    
    # 创建续期脚本
    cat > "/usr/local/bin/certbot-renew.sh" << 'EOF'
#!/bin/bash

# 证书自动续期脚本
LOG_FILE="/var/log/certbot-renew.log"

echo "[$(date)] Starting certificate renewal check" >> "$LOG_FILE"

# 尝试续期证书
certbot renew --quiet --no-self-upgrade >> "$LOG_FILE" 2>&1

if [[ $? -eq 0 ]]; then
    echo "[$(date)] Certificate renewal check completed successfully" >> "$LOG_FILE"
    
    # 重启相关服务
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        echo "[$(date)] Nginx reloaded" >> "$LOG_FILE"
    fi
    
    if systemctl is-active --quiet apache2; then
        systemctl reload apache2
        echo "[$(date)] Apache reloaded" >> "$LOG_FILE"
    fi
else
    echo "[$(date)] Certificate renewal failed" >> "$LOG_FILE"
fi
EOF
    
    chmod +x "/usr/local/bin/certbot-renew.sh"
    
    # 添加到crontab
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/certbot-renew.sh") | crontab -
    
    log_success "Automatic renewal configured (runs daily at 2 AM)"
}

# 生成Nginx SSL配置
generate_nginx_ssl_config() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"
    local config_file="$4"
    
    log_info "Generating Nginx SSL configuration..."
    
    cat > "$config_file" << EOF
# SSL配置 for $domain
server {
    listen 80;
    server_name $domain;
    
    # 重定向HTTP到HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;
    
    # SSL证书配置
    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;
    
    # SSL安全配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # 其他安全头
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # 应用配置
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    # 静态文件缓存
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        proxy_pass http://localhost:3000;
    }
    
    # 健康检查
    location /health {
        proxy_pass http://localhost:3000/health;
        access_log off;
    }
}
EOF
    
    log_success "Nginx SSL configuration generated: $config_file"
}

# 验证SSL证书
validate_ssl_cert() {
    local domain="$1"
    local cert_path="$2"
    
    log_info "Validating SSL certificate..."
    
    # 检查证书文件是否存在
    if [[ ! -f "$cert_path" ]]; then
        log_error "Certificate file not found: $cert_path"
        return 1
    fi
    
    # 检查证书有效期
    local expiry_date=$(openssl x509 -in "$cert_path" -noout -enddate | cut -d= -f2)
    local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s)
    local current_timestamp=$(date +%s)
    local days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
    
    if [[ $days_until_expiry -lt 0 ]]; then
        log_error "Certificate has expired!"
        return 1
    elif [[ $days_until_expiry -lt 30 ]]; then
        log_warning "Certificate expires in $days_until_expiry days"
    else
        log_success "Certificate is valid for $days_until_expiry days"
    fi
    
    # 检查证书域名
    local cert_domains=$(openssl x509 -in "$cert_path" -noout -text | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/DNS://g' | sed 's/,//g')
    log_info "Certificate domains: $cert_domains"
    
    # 测试SSL连接
    if command -v curl &> /dev/null; then
        if curl -s --connect-timeout 10 "https://$domain" > /dev/null; then
            log_success "SSL connection test passed"
        else
            log_warning "SSL connection test failed (domain may not be accessible)"
        fi
    fi
    
    return 0
}

# 主函数
main() {
    local action="$1"
    local domain="$2"
    local email="$3"
    local cert_type="$4"
    
    echo "SmellPin SSL Setup Script"
    echo "========================"
    
    check_root
    check_dependencies
    
    case "$action" in
        "install")
            if [[ -z "$domain" ]]; then
                log_error "Domain name is required"
                echo "Usage: $0 install <domain> [email] [letsencrypt|self-signed]"
                exit 1
            fi
            
            cert_type=${cert_type:-"self-signed"}
            
            if [[ "$cert_type" == "letsencrypt" ]]; then
                if [[ -z "$email" ]]; then
                    log_error "Email is required for Let's Encrypt certificates"
                    exit 1
                fi
                install_certbot
                get_letsencrypt_cert "$domain" "$email"
                setup_auto_renewal
                
                # 生成Nginx配置
                generate_nginx_ssl_config "$domain" \
                    "/etc/letsencrypt/live/$domain/fullchain.pem" \
                    "/etc/letsencrypt/live/$domain/privkey.pem" \
                    "/etc/nginx/sites-available/$domain-ssl"
                    
                validate_ssl_cert "$domain" "/etc/letsencrypt/live/$domain/fullchain.pem"
            else
                # 自签名证书
                local cert_dir="./ssl/$domain"
                generate_self_signed_cert "$domain" "$cert_dir"
                
                # 生成Nginx配置
                generate_nginx_ssl_config "$domain" \
                    "$cert_dir/fullchain.pem" \
                    "$cert_dir/privkey.pem" \
                    "./nginx-$domain-ssl.conf"
                    
                validate_ssl_cert "$domain" "$cert_dir/fullchain.pem"
            fi
            ;;
        "renew")
            if command -v certbot &> /dev/null; then
                log_info "Renewing certificates..."
                certbot renew
            else
                log_error "Certbot not installed"
                exit 1
            fi
            ;;
        "validate")
            if [[ -z "$domain" ]]; then
                log_error "Domain name is required"
                exit 1
            fi
            
            local cert_path="$email" # 复用email参数作为证书路径
            if [[ -z "$cert_path" ]]; then
                cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
            fi
            
            validate_ssl_cert "$domain" "$cert_path"
            ;;
        *)
            echo "Usage: $0 <action> [options]"
            echo ""
            echo "Actions:"
            echo "  install <domain> [email] [letsencrypt|self-signed]  - Install SSL certificate"
            echo "  renew                                               - Renew Let's Encrypt certificates"
            echo "  validate <domain> [cert_path]                      - Validate SSL certificate"
            echo ""
            echo "Examples:"
            echo "  $0 install example.com admin@example.com letsencrypt"
            echo "  $0 install localhost self-signed"
            echo "  $0 renew"
            echo "  $0 validate example.com"
            exit 1
            ;;
    esac
    
    log_success "SSL setup completed successfully!"
}

# 执行主函数
main "$@"