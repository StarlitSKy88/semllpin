# SmellPin 生产环境部署指南

## 目录
- [1. 环境准备](#1-环境准备)
- [2. 服务器配置](#2-服务器配置)
- [3. 代码部署](#3-代码部署)
- [4. 环境变量配置](#4-环境变量配置)
- [5. 部署执行](#5-部署执行)
- [6. 服务管理](#6-服务管理)
- [7. 监控与日志](#7-监控与日志)
- [8. 故障排查](#8-故障排查)
- [9. 备份与恢复](#9-备份与恢复)
- [10. 性能优化](#10-性能优化)

## 1. 环境准备

### 1.1 服务器要求

**最低配置**
- CPU: 2核心
- 内存: 4GB RAM
- 存储: 50GB SSD
- 网络: 10 Mbps 带宽

**推荐配置**
- CPU: 4核心
- 内存: 8GB RAM
- 存储: 100GB SSD
- 网络: 20 Mbps 带宽

**高负载配置**
- CPU: 8核心
- 内存: 16GB RAM
- 存储: 200GB SSD
- 网络: 50 Mbps 带宽

### 1.2 操作系统

支持的操作系统：
- Ubuntu 20.04 LTS / 22.04 LTS（推荐）
- CentOS 8 / Rocky Linux 8
- Debian 11

### 1.3 域名与 SSL

1. **域名解析**
   ```
   A    api.yourdomain.com     -> 服务器IP
   A    www.yourdomain.com     -> 服务器IP
   CNAME cdn.yourdomain.com    -> CDN服务商地址
   ```

2. **SSL 证书**
   - 推荐使用 Let's Encrypt 免费证书
   - 或使用 Cloudflare SSL
   - 证书路径：`/etc/ssl/certs/`

## 2. 服务器配置

### 2.1 基础软件安装

**Ubuntu/Debian**
```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装基础工具
sudo apt install -y curl wget git unzip ufw fail2ban

# 安装 Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# 安装 Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

**CentOS/Rocky Linux**
```bash
# 更新系统
sudo yum update -y

# 安装基础工具
sudo yum install -y curl wget git unzip firewalld

# 安装 Docker
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# 安装 Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2.2 防火墙配置

**Ubuntu/Debian (UFW)**
```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3000/tcp  # 后端API（可选，通过Nginx代理）
sudo ufw allow 5432/tcp  # PostgreSQL（仅内网）
sudo ufw allow 6379/tcp  # Redis（仅内网）
```

**CentOS/Rocky Linux (firewalld)**
```bash
sudo systemctl start firewalld
sudo systemctl enable firewalld
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=3000/tcp
sudo firewall-cmd --reload
```

### 2.3 系统优化

```bash
# 增加文件描述符限制
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# 优化内核参数
echo "net.core.somaxconn = 65535" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65535" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 3. 代码部署

### 3.1 获取代码

```bash
# 创建部署目录
sudo mkdir -p /opt/smellpin
sudo chown $USER:$USER /opt/smellpin
cd /opt/smellpin

# 克隆代码
git clone https://github.com/your-org/smellpin.git .

# 切换到稳定分支
git checkout main
```

### 3.2 目录结构

```
/opt/smellpin/
├── backend/                 # 后端代码
├── frontend/               # 前端代码
├── docs/                   # 文档
├── scripts/                # 部署脚本
├── monitoring/             # 监控配置
├── ssl/                    # SSL证书
├── uploads/                # 上传文件
├── logs/                   # 日志文件
├── docker-compose.prod.yml # 生产环境配置
└── .env.production         # 环境变量
```

## 4. 环境变量配置

### 4.1 创建环境变量文件

```bash
cp .env.production.example .env.production
nano .env.production
```

### 4.2 必填配置项

```bash
# 应用配置
NODE_ENV=production
APP_NAME=SmellPin
APP_URL=https://www.yourdomain.com
API_URL=https://api.yourdomain.com
PORT=3000

# 数据库配置
DB_TYPE=postgresql
DB_HOST=postgres
DB_PORT=5432
DB_NAME=smellpin_prod
DB_USER=smellpin
DB_PASSWORD=your_secure_password_here

# Redis 配置
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password_here
REDIS_DB=0

# JWT 配置
JWT_SECRET=your_jwt_secret_key_here_minimum_32_characters
JWT_EXPIRES_IN=7d

# Stripe 支付配置
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# CDN 配置
CDN_BASE_URL=https://cdn.yourdomain.com
CDN_ACCESS_KEY=your_cdn_access_key
CDN_SECRET_KEY=your_cdn_secret_key
CDN_BUCKET=smellpin-uploads

# 邮件配置
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=your_email_password
SMTP_FROM=SmellPin <noreply@yourdomain.com>

# 监控配置
SENTRY_DSN=https://your-sentry-dsn
PROMETHEUS_ENABLED=true
LOG_LEVEL=info

# SSL 证书路径
SSL_CERT_PATH=/etc/ssl/certs/yourdomain.com.crt
SSL_KEY_PATH=/etc/ssl/private/yourdomain.com.key
```

### 4.3 安全密钥生成

```bash
# 生成 JWT Secret
openssl rand -base64 32

# 生成数据库密码
openssl rand -base64 24

# 生成 Redis 密码
openssl rand -base64 16
```

## 5. 部署执行

### 5.1 使用部署脚本

```bash
# 赋予执行权限
chmod +x scripts/deploy.sh

# 执行部署
./scripts/deploy.sh prod
```

### 5.2 手动部署步骤

如果自动部署失败，可以手动执行：

```bash
# 1. 构建镜像
docker-compose -f docker-compose.prod.yml build

# 2. 启动数据库
docker-compose -f docker-compose.prod.yml up -d postgres redis

# 3. 等待数据库启动
sleep 30

# 4. 运行数据库迁移
docker-compose -f docker-compose.prod.yml exec backend npm run migrate

# 5. 启动所有服务
docker-compose -f docker-compose.prod.yml up -d
```

### 5.3 验证部署

```bash
# 检查容器状态
docker-compose -f docker-compose.prod.yml ps

# 检查日志
docker-compose -f docker-compose.prod.yml logs -f --tail=100

# 健康检查
curl -f http://localhost:3000/health
curl -f https://www.yourdomain.com
```

## 6. 服务管理

### 6.1 常用命令

| 操作 | 命令 |
|------|------|
| 启动服务 | `docker-compose -f docker-compose.prod.yml up -d` |
| 停止服务 | `docker-compose -f docker-compose.prod.yml down` |
| 重启服务 | `docker-compose -f docker-compose.prod.yml restart` |
| 查看状态 | `docker-compose -f docker-compose.prod.yml ps` |
| 查看日志 | `docker-compose -f docker-compose.prod.yml logs -f` |
| 进入容器 | `docker-compose -f docker-compose.prod.yml exec backend bash` |

### 6.2 单独管理服务

```bash
# 重启后端
docker-compose -f docker-compose.prod.yml restart backend

# 重启前端
docker-compose -f docker-compose.prod.yml restart frontend

# 重启 Nginx
docker-compose -f docker-compose.prod.yml restart nginx

# 重启数据库
docker-compose -f docker-compose.prod.yml restart postgres
```

### 6.3 数据库管理

```bash
# 连接数据库
docker-compose -f docker-compose.prod.yml exec postgres psql -U smellpin -d smellpin_prod

# 备份数据库
docker-compose -f docker-compose.prod.yml exec postgres pg_dump -U smellpin smellpin_prod > backup_$(date +%Y%m%d_%H%M%S).sql

# 恢复数据库
docker-compose -f docker-compose.prod.yml exec -T postgres psql -U smellpin -d smellpin_prod < backup.sql
```

## 7. 监控与日志

### 7.1 启动监控服务

```bash
# 启动 Prometheus + Grafana
docker-compose -f docker-compose.prod.yml up -d prometheus grafana

# 访问监控面板
# Grafana: http://your-server:3001 (admin/admin)
# Prometheus: http://your-server:9090
```

### 7.2 日志管理

```bash
# 查看应用日志
tail -f logs/app.log
tail -f logs/error.log

# 查看 Docker 日志
docker logs smellpin_backend_1
docker logs smellpin_frontend_1
docker logs smellpin_nginx_1

# 日志轮转配置
sudo nano /etc/logrotate.d/smellpin
```

### 7.3 性能监控

```bash
# 系统资源监控
htop
iotop
netstat -tulpn

# Docker 资源使用
docker stats

# 磁盘使用
df -h
du -sh /opt/smellpin/*
```

## 8. 故障排查

### 8.1 常见问题

**问题：容器无法启动**
```bash
# 检查容器状态
docker ps -a

# 查看容器日志
docker logs <container_id>

# 检查端口占用
sudo netstat -tulpn | grep :3000
```

**问题：502 Bad Gateway**
```bash
# 检查后端服务
curl http://localhost:3000/health

# 检查 Nginx 配置
docker-compose -f docker-compose.prod.yml exec nginx nginx -t

# 查看 Nginx 日志
docker logs smellpin_nginx_1
```

**问题：数据库连接失败**
```bash
# 检查数据库状态
docker-compose -f docker-compose.prod.yml exec postgres pg_isready

# 测试连接
docker-compose -f docker-compose.prod.yml exec postgres psql -U smellpin -d smellpin_prod -c "SELECT 1;"

# 检查环境变量
docker-compose -f docker-compose.prod.yml exec backend env | grep DB_
```

**问题：支付回调失败**
```bash
# 检查 Stripe Webhook
curl -X POST https://api.yourdomain.com/payments/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": true}'

# 查看支付日志
docker-compose -f docker-compose.prod.yml logs backend | grep payment
```

### 8.2 性能问题

**高 CPU 使用率**
```bash
# 查看进程
top -p $(docker inspect --format='{{.State.Pid}}' smellpin_backend_1)

# 分析慢查询
docker-compose -f docker-compose.prod.yml exec postgres psql -U smellpin -d smellpin_prod -c "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

**高内存使用率**
```bash
# 检查内存使用
free -h
docker stats --no-stream

# 重启服务释放内存
docker-compose -f docker-compose.prod.yml restart backend
```

**磁盘空间不足**
```bash
# 清理 Docker 镜像
docker system prune -a

# 清理日志文件
sudo truncate -s 0 /var/lib/docker/containers/*/*-json.log

# 清理上传文件（谨慎操作）
find uploads/ -type f -mtime +30 -delete
```

## 9. 备份与恢复

### 9.1 自动备份脚本

```bash
# 创建备份脚本
sudo nano /opt/smellpin/scripts/backup.sh

#!/bin/bash
BACKUP_DIR="/opt/backups/smellpin"
DATE=$(date +%Y%m%d_%H%M%S)

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
docker-compose -f /opt/smellpin/docker-compose.prod.yml exec -T postgres pg_dump -U smellpin smellpin_prod > $BACKUP_DIR/db_$DATE.sql

# 备份上传文件
tar -czf $BACKUP_DIR/uploads_$DATE.tar.gz -C /opt/smellpin uploads/

# 备份配置文件
cp /opt/smellpin/.env.production $BACKUP_DIR/env_$DATE.backup

# 删除7天前的备份
find $BACKUP_DIR -type f -mtime +7 -delete

echo "Backup completed: $DATE"
```

### 9.2 设置定时备份

```bash
# 添加到 crontab
crontab -e

# 每天凌晨2点备份
0 2 * * * /opt/smellpin/scripts/backup.sh >> /var/log/smellpin_backup.log 2>&1
```

### 9.3 恢复数据

```bash
# 恢复数据库
docker-compose -f docker-compose.prod.yml exec -T postgres psql -U smellpin -d smellpin_prod < backup_20240101_020000.sql

# 恢复上传文件
tar -xzf uploads_20240101_020000.tar.gz -C /opt/smellpin/

# 恢复配置文件
cp env_20240101_020000.backup /opt/smellpin/.env.production
```

## 10. 性能优化

### 10.1 数据库优化

```sql
-- 创建索引
CREATE INDEX CONCURRENTLY idx_annotations_location ON annotations USING GIST (location);
CREATE INDEX CONCURRENTLY idx_annotations_created_at ON annotations (created_at);
CREATE INDEX CONCURRENTLY idx_users_email ON users (email);

-- 分析表统计信息
ANALYZE;

-- 清理无用数据
VACUUM ANALYZE;
```

### 10.2 Redis 优化

```bash
# Redis 配置优化
docker-compose -f docker-compose.prod.yml exec redis redis-cli CONFIG SET maxmemory 1gb
docker-compose -f docker-compose.prod.yml exec redis redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### 10.3 Nginx 优化

```nginx
# 在 frontend/nginx/default.conf 中添加
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

# 启用缓存
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

### 10.4 应用优化

```bash
# 启用 PM2 集群模式（在 Dockerfile 中）
CMD ["pm2-runtime", "start", "ecosystem.config.js"]

# 配置连接池
# 在 backend/config/database.ts 中
pool: {
  min: 2,
  max: 10,
  acquireTimeoutMillis: 30000,
  idleTimeoutMillis: 30000
}
```

## 11. 安全加固

### 11.1 系统安全

```bash
# 禁用 root SSH 登录
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no

# 安装 fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

### 11.2 应用安全

```bash
# 定期更新依赖
npm audit fix

# 使用安全头
# 在 Nginx 配置中添加
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
```

## 12. 更新部署

### 12.1 滚动更新

```bash
# 拉取最新代码
git pull origin main

# 重新构建并部署
./scripts/deploy.sh prod
```

### 12.2 回滚部署

```bash
# 回滚到上一个版本
./scripts/deploy.sh rollback

# 或手动回滚
git checkout <previous_commit>
./scripts/deploy.sh prod
```

---

## 联系支持

如遇到部署问题，请联系：
- 技术支持：devops@yourcompany.com
- 文档更新：docs@yourcompany.com
- 紧急联系：+86-xxx-xxxx-xxxx

---

**最后更新时间：** 2024年1月
**文档版本：** v1.0
**适用版本：** SmellPin v1.0+