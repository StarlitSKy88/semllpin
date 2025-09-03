#!/bin/bash

# SSL证书设置脚本
# 支持Let's Encrypt自动证书和自签名证书

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# 配置变量
DOMAIN=${1:-localhost}
EMAIL=${2:-admin@example.com}
SSL_DIR="./ssl"
CERT_TYPE=${3:-letsencrypt}  # letsencrypt 或 selfsigned

log_info "开始设置SSL证书"
log_info "域名: $DOMAIN"
log_info "邮箱: $EMAIL"
log_info "证书类型: $CERT_TYPE"

# 创建SSL目录
mkdir -p "$SSL_DIR"

# Let's Encrypt证书
setup_letsencrypt() {
    log_info "设置Let's Encrypt证书..."
    
    # 检查certbot是否安装
    if ! command -v certbot &> /dev/null; then
        log_info "安装certbot..."
        
        # 根据系统安装certbot
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update
                sudo apt-get install -y certbot
            elif command -v yum &> /dev/null; then
                sudo yum install -y certbot
            else
                log_error "不支持的Linux发行版"
                exit 1
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            if command -v brew &> /dev/null; then
                brew install certbot
            else
                log_error "请先安装Homebrew"
                exit 1
            fi
        else
            log_error "不支持的操作系统"
            exit 1
        fi
    fi
    
    # 停止nginx以释放80端口
    log_info "临时停止nginx服务..."
    docker-compose -f docker-compose.prod.yml stop nginx || true
    
    # 获取证书
    log_info "获取Let's Encrypt证书..."
    certbot certonly \
        --standalone \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --domains "$DOMAIN" \
        --non-interactive
    
    # 复制证书到项目目录
    sudo cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/cert.pem"
    sudo cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/key.pem"
    sudo chown $(whoami):$(whoami) "$SSL_DIR/cert.pem" "$SSL_DIR/key.pem"
    
    # 设置自动续期
    setup_auto_renewal
    
    log_success "Let's Encrypt证书设置完成"
}

# 自签名证书
setup_selfsigned() {
    log_info "生成自签名证书..."
    
    # 生成私钥
    openssl genrsa -out "$SSL_DIR/key.pem" 2048
    
    # 生成证书签名请求
    openssl req -new -key "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.csr" -subj "/C=CN/ST=Beijing/L=Beijing/O=SmellPin/OU=IT/CN=$DOMAIN"
    
    # 生成自签名证书
    openssl x509 -req -days 365 -in "$SSL_DIR/cert.csr" -signkey "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem"
    
    # 删除临时文件
    rm "$SSL_DIR/cert.csr"
    
    log_warning "使用自签名证书，浏览器会显示安全警告"
    log_success "自签名证书生成完成"
}

# 设置证书自动续期
setup_auto_renewal() {
    log_info "设置证书自动续期..."
    
    # 创建续期脚本
    cat > "$SSL_DIR/renew-cert.sh" << 'EOF'
#!/bin/bash

# Let's Encrypt证书续期脚本

DOMAIN=$1
SSL_DIR=$2

# 续期证书
certbot renew --quiet

# 检查证书是否更新
if [ $? -eq 0 ]; then
    # 复制新证书
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/cert.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/key.pem"
    
    # 重启nginx
    docker-compose -f docker-compose.prod.yml restart nginx
    
    echo "证书续期成功: $(date)"
else
    echo "证书续期失败: $(date)"
fi
EOF
    
    chmod +x "$SSL_DIR/renew-cert.sh"
    
    # 添加到crontab（每月1号凌晨2点执行）
    (crontab -l 2>/dev/null; echo "0 2 1 * * $PWD/$SSL_DIR/renew-cert.sh $DOMAIN $SSL_DIR >> $PWD/logs/ssl-renewal.log 2>&1") | crontab -
    
    log_success "自动续期设置完成"
}

# 验证证书
validate_certificate() {
    log_info "验证SSL证书..."
    
    if [ ! -f "$SSL_DIR/cert.pem" ] || [ ! -f "$SSL_DIR/key.pem" ]; then
        log_error "证书文件不存在"
        exit 1
    fi
    
    # 检查证书有效性
    if openssl x509 -in "$SSL_DIR/cert.pem" -text -noout > /dev/null 2>&1; then
        log_success "证书格式有效"
    else
        log_error "证书格式无效"
        exit 1
    fi
    
    # 检查私钥
    if openssl rsa -in "$SSL_DIR/key.pem" -check > /dev/null 2>&1; then
        log_success "私钥格式有效"
    else
        log_error "私钥格式无效"
        exit 1
    fi
    
    # 检查证书和私钥是否匹配
    cert_hash=$(openssl x509 -noout -modulus -in "$SSL_DIR/cert.pem" | openssl md5)
    key_hash=$(openssl rsa -noout -modulus -in "$SSL_DIR/key.pem" | openssl md5)
    
    if [ "$cert_hash" = "$key_hash" ]; then
        log_success "证书和私钥匹配"
    else
        log_error "证书和私钥不匹配"
        exit 1
    fi
    
    # 显示证书信息
    log_info "证书信息:"
    openssl x509 -in "$SSL_DIR/cert.pem" -text -noout | grep -E "Subject:|Not Before:|Not After:|DNS:"
}

# 创建nginx SSL配置
create_nginx_ssl_config() {
    log_info "创建nginx SSL配置..."
    
    mkdir -p nginx/conf.d
    
    cat > nginx/conf.d/ssl.conf << 'EOF'
# SSL配置
ssl_session_timeout 1d;
ssl_session_cache shared:MozTLS:10m;
ssl_session_tickets off;

# 现代SSL配置
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
EOF
    
    log_success "nginx SSL配置创建完成"
}

# 主函数
main() {
    case "$CERT_TYPE" in
        "letsencrypt")
            setup_letsencrypt
            ;;
        "selfsigned")
            setup_selfsigned
            ;;
        *)
            log_error "不支持的证书类型: $CERT_TYPE"
            log_info "支持的类型: letsencrypt, selfsigned"
            exit 1
            ;;
    esac
    
    validate_certificate
    create_nginx_ssl_config
    
    log_success "🔒 SSL证书设置完成！"
    log_info "证书位置: $SSL_DIR/"
    log_info "请重启nginx服务以应用新证书"
}

# 显示帮助信息
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "SSL证书设置脚本"
    echo ""
    echo "使用方法:"
    echo "  $0 <域名> <邮箱> [证书类型]"
    echo ""
    echo "参数:"
    echo "  域名        - 要申请证书的域名"
    echo "  邮箱        - Let's Encrypt通知邮箱"
    echo "  证书类型    - letsencrypt 或 selfsigned (默认: letsencrypt)"
    echo ""
    echo "示例:"
    echo "  $0 example.com admin@example.com letsencrypt"
    echo "  $0 localhost admin@localhost selfsigned"
    exit 0
fi

# 检查参数
if [ -z "$1" ]; then
    log_error "请提供域名参数"
    log_info "使用 $0 --help 查看帮助信息"
    exit 1
fi

# 执行主函数
main