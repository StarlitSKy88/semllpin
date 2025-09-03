# SmellPin 生产环境部署指南

本文档详细介绍了如何将 SmellPin 应用部署到生产环境。

## 📋 部署前准备

### 系统要求

- **操作系统**: Ubuntu 20.04+ / CentOS 8+ / macOS 10.15+
- **内存**: 最低 4GB，推荐 8GB+
- **存储**: 最低 50GB，推荐 100GB+
- **CPU**: 最低 2核，推荐 4核+
- **网络**: 公网IP和域名

### 必需软件

```bash
# Docker & Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Git
sudo apt update && sudo apt install -y git

# 其他工具
sudo apt install -y curl wget unzip
```

## 🚀 快速部署

### 1. 克隆项目

```bash
git clone https://github.com/your-org/smellpin.git
cd smellpin
```

### 2. 配置环境变量

```bash
# 复制环境变量模板
cp .env.production .env.prod

# 编辑配置文件
nano .env.prod
```

**重要配置项**:

```bash
# 数据库密码（必须修改）
DB_PASSWORD=your_secure_db_password_here

# JWT密钥（必须修改，至少32字符）
JWT_SECRET=your_very_secure_jwt_secret_key_at_least_32_characters_long

# Stripe支付配置
STRIPE_SECRET_KEY=sk_live_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_stripe_webhook_secret

# 域名配置
APP_URL=https://your-domain.com
CORS_ORIGIN=https://your-domain.com
```

### 3. 设置SSL证书

#### 选项A: Let's Encrypt（推荐）

```bash
./scripts/setup-ssl.sh your-domain.com admin@your-domain.com letsencrypt
```

#### 选项B: 自签名证书（仅测试）

```bash
./scripts/setup-ssl.sh localhost admin@localhost selfsigned
```

### 4. 执行部署

```bash
./scripts/deploy.sh production v1.0.0
```

## 📊 监控和日志

### 访问监控面板

- **Grafana**: https://your-domain.com:3001
  - 用户名: admin
  - 密码: 在 `.env.prod` 中的 `GRAFANA_PASSWORD`

- **Prometheus**: https://your-domain.com:9090

### 查看日志

```bash
# 查看所有服务日志
docker-compose -f docker-compose.prod.yml logs -f

# 查看特定服务日志
docker-compose -f docker-compose.prod.yml logs -f backend
docker-compose -f docker-compose.prod.yml logs -f frontend
docker-compose -f docker-compose.prod.yml logs -f postgres
```

## 🔧 高级配置

### 负载均衡配置

如果需要多实例部署，可以修改 `docker-compose.prod.yml`：

```yaml
backend:
  deploy:
    replicas: 3
    resources:
      limits:
        cpus: '1.0'
        memory: 1G
      reservations:
        cpus: '0.5'
        memory: 512M
```

### 数据库集群

对于高可用部署，建议使用外部数据库服务：

```bash
# 修改 .env.prod
DATABASE_URL=postgresql://user:pass@your-db-cluster:5432/smellpin_prod
```

### CDN配置

配置CDN以提升静态资源加载速度：

```bash
# 在 .env.prod 中配置
CDN_BASE_URL=https://cdn.your-domain.com
CDN_ACCESS_KEY=your_cdn_access_key
CDN_SECRET_KEY=your_cdn_secret_key
```

## 🔒 安全配置

### 防火墙设置

```bash
# Ubuntu/Debian
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# CentOS/RHEL
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 定期安全更新

```bash
# 创建自动更新脚本
echo '#!/bin/bash
apt update && apt upgrade -y
docker system prune -f
' | sudo tee /etc/cron.weekly/security-updates
sudo chmod +x /etc/cron.weekly/security-updates
```

## 💾 备份策略

### 自动备份设置

```bash
# 设置每日自动备份
echo "0 2 * * * cd /path/to/smellpin && ./scripts/backup.sh backup full" | crontab -
```

### 手动备份

```bash
# 完整备份
./scripts/backup.sh backup full

# 仅数据库备份
./scripts/backup.sh backup database

# 查看备份列表
./scripts/backup.sh list
```

### 恢复数据

```bash
# 恢复数据库
./scripts/backup.sh restore database backups/database_20240101_120000.sql.gz

# 恢复文件
./scripts/backup.sh restore files backups/files_20240101_120000.tar.gz
```

## 🔄 更新和维护

### 应用更新

```bash
# 拉取最新代码
git pull origin main

# 部署新版本
./scripts/deploy.sh production v1.1.0
```

### 回滚部署

```bash
# 回滚到上一个版本
./scripts/deploy.sh rollback
```

### 健康检查

```bash
# 检查服务状态
docker-compose -f docker-compose.prod.yml ps

# 检查应用健康状态
curl -f https://your-domain.com/health
curl -f https://your-domain.com/api/health
```

## 📈 性能优化

### 数据库优化

```sql
-- 创建必要的索引
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_annotations_location ON annotations USING GIST (ST_Point(longitude, latitude));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_annotations_created_at ON annotations (created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users (email);

-- 更新统计信息
ANALYZE;
```

### 缓存配置

```bash
# 在 .env.prod 中调整缓存TTL
CACHE_TTL_DEFAULT=3600    # 1小时
CACHE_TTL_STATIC=86400    # 24小时
CACHE_TTL_API=300         # 5分钟
```

### Nginx优化

编辑 `frontend/nginx.conf`：

```nginx
# 增加worker进程数
worker_processes auto;

# 优化连接数
events {
    worker_connections 2048;
    use epoll;
    multi_accept on;
}

# 启用HTTP/2
listen 443 ssl http2;
```

## 🚨 故障排除

### 常见问题

#### 1. 数据库连接失败

```bash
# 检查数据库容器状态
docker-compose -f docker-compose.prod.yml logs postgres

# 检查网络连接
docker-compose -f docker-compose.prod.yml exec backend ping postgres
```

#### 2. SSL证书问题

```bash
# 检查证书有效性
openssl x509 -in ssl/cert.pem -text -noout

# 重新生成证书
./scripts/setup-ssl.sh your-domain.com admin@your-domain.com letsencrypt
```

#### 3. 内存不足

```bash
# 检查内存使用
docker stats

# 增加swap空间
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### 4. 磁盘空间不足

```bash
# 清理Docker资源
docker system prune -a

# 清理旧日志
sudo journalctl --vacuum-time=7d

# 清理旧备份
./scripts/backup.sh cleanup
```

### 日志分析

```bash
# 查看错误日志
docker-compose -f docker-compose.prod.yml logs backend | grep ERROR

# 查看访问日志
docker-compose -f docker-compose.prod.yml logs nginx | grep -E "4[0-9]{2}|5[0-9]{2}"

# 实时监控日志
tail -f logs/app.log | grep ERROR
```

## 📞 支持和联系

如果在部署过程中遇到问题，请：

1. 查看本文档的故障排除部分
2. 检查 [GitHub Issues](https://github.com/your-org/smellpin/issues)
3. 联系技术支持: support@your-domain.com

## 📝 部署检查清单

- [ ] 服务器环境准备完成
- [ ] Docker和Docker Compose已安装
- [ ] 项目代码已克隆
- [ ] 环境变量已正确配置
- [ ] SSL证书已设置
- [ ] 防火墙规则已配置
- [ ] 域名DNS已解析
- [ ] 数据库备份策略已设置
- [ ] 监控系统已配置
- [ ] 健康检查通过
- [ ] 性能测试完成

---

**注意**: 请确保在生产环境部署前，先在测试环境验证所有配置和功能。