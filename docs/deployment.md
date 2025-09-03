# SmellPin 部署指南

## 目录
- [部署概览](#部署概览)
- [环境准备](#环境准备)
- [数据库配置](#数据库配置)
- [应用部署](#应用部署)
- [监控配置](#监控配置)
- [安全配置](#安全配置)
- [故障排除](#故障排除)

## 部署概览

### 架构图
```
用户 → CloudFlare CDN → Nginx → Node.js 应用 → Neon PostgreSQL
                                    ↓
                                Redis 缓存
```

### 部署环境
- **前端**: Vercel/Netlify
- **后端**: Cloudflare Workers / VPS
- **数据库**: Neon PostgreSQL (严格禁止使用Supabase)
- **缓存**: Redis Cloud / 自建Redis
- **CDN**: CloudFlare
- **监控**: Prometheus + Grafana

## 环境准备

### 1. 服务器要求
- **CPU**: 2核心以上
- **内存**: 4GB以上
- **存储**: 50GB SSD
- **网络**: 100Mbps带宽
- **操作系统**: Ubuntu 20.04 LTS 或 CentOS 8

### 2. 软件依赖
```bash
# 安装 Node.js 20+
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# 安装 Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# 安装 Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 安装 Nginx
sudo apt update
sudo apt install nginx
```

### 3. 域名和SSL证书
```bash
# 使用 Let's Encrypt 获取SSL证书
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.smellpin.com
```

## 数据库配置

### 1. Neon PostgreSQL 设置

**重要**: 必须使用Neon PostgreSQL，严格禁止使用Supabase

1. 访问 [Neon Console](https://console.neon.tech/)
2. 创建新项目 "SmellPin"
3. 选择区域（推荐 us-east-1）
4. 获取连接字符串

```bash
# 连接字符串格式
DATABASE_URL="postgresql://username:password@ep-xxx.us-east-1.aws.neon.tech/smellpin?sslmode=require"
```

### 2. 数据库初始化
```bash
# 运行数据库迁移
npm run migrate:prod

# 初始化基础数据
npm run seed:prod
```

### 3. 数据库优化
```sql
-- 创建索引
CREATE INDEX CONCURRENTLY idx_annotations_location ON annotations USING GIST (location);
CREATE INDEX CONCURRENTLY idx_annotations_created_at ON annotations (created_at);
CREATE INDEX CONCURRENTLY idx_users_phone ON users (phone);
CREATE INDEX CONCURRENTLY idx_transactions_user_id ON transactions (user_id);

-- 设置连接池
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
```

## 应用部署

### 1. 环境变量配置
```bash
# 复制环境变量模板
cp .env.template .env.production

# 编辑生产环境配置
vim .env.production
```

### 2. 构建应用
```bash
# 安装依赖
npm ci --production

# 构建应用
npm run build

# 运行测试
npm run test:prod
```

### 3. Docker 部署
```bash
# 构建镜像
docker build -t smellpin:latest .

# 启动服务
docker-compose -f docker-compose.prod.yml up -d

# 查看日志
docker-compose logs -f app
```

### 4. PM2 部署（可选）
```bash
# 安装 PM2
npm install -g pm2

# 启动应用
pm2 start ecosystem.config.js --env production

# 设置开机自启
pm2 startup
pm2 save
```

### 5. Nginx 配置
```nginx
# /etc/nginx/sites-available/smellpin
server {
    listen 80;
    server_name api.smellpin.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.smellpin.com;
    
    ssl_certificate /etc/letsencrypt/live/api.smellpin.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.smellpin.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    location /health {
        access_log off;
        proxy_pass http://localhost:3000/health;
    }
}
```

## 前端部署

### 1. Vercel 部署
```bash
# 安装 Vercel CLI
npm i -g vercel

# 登录 Vercel
vercel login

# 部署
vercel --prod
```

### 2. 环境变量设置
在 Vercel Dashboard 中设置：
```
NEXT_PUBLIC_API_URL=https://api.smellpin.com
NEXT_PUBLIC_WS_URL=wss://api.smellpin.com
NEXT_PUBLIC_CDN_URL=https://cdn.smellpin.com
```

## 监控配置

### 1. Prometheus 配置
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'smellpin-api'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

### 2. Grafana 仪表板
```bash
# 启动 Grafana
docker run -d -p 3001:3000 grafana/grafana

# 导入仪表板
curl -X POST \
  http://admin:admin@localhost:3001/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @config/grafana/dashboards/smellpin-overview.json
```

### 3. 日志收集
```bash
# 配置 Filebeat
sudo apt install filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

## 安全配置

### 1. 防火墙设置
```bash
# UFW 防火墙
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 3000/tcp
```

### 2. 安全头配置
```nginx
# 在 Nginx 配置中添加
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
```

### 3. 限流配置
```nginx
# 限制请求频率
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

location /api/ {
    limit_req zone=api burst=20 nodelay;
}

location /api/auth/login {
    limit_req zone=login burst=5 nodelay;
}
```

## 备份策略

### 1. 数据库备份
```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/database"

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
pg_dump $DATABASE_URL > $BACKUP_DIR/smellpin_$DATE.sql

# 压缩备份文件
gzip $BACKUP_DIR/smellpin_$DATE.sql

# 删除7天前的备份
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete

# 上传到云存储（可选）
# aws s3 cp $BACKUP_DIR/smellpin_$DATE.sql.gz s3://smellpin-backups/
```

### 2. 定时备份
```bash
# 添加到 crontab
crontab -e

# 每天凌晨2点备份
0 2 * * * /path/to/backup.sh
```

## 性能优化

### 1. Redis 缓存配置
```redis
# redis.conf
maxmemory 1gb
maxmemory-policy allkeys-lru
tcp-keepalive 60
timeout 300
```

### 2. Node.js 优化
```bash
# 设置环境变量
export NODE_ENV=production
export NODE_OPTIONS="--max-old-space-size=2048"
export UV_THREADPOOL_SIZE=16
```

### 3. 数据库连接池
```javascript
// 数据库配置
const pool = {
  min: 2,
  max: 10,
  acquireTimeoutMillis: 60000,
  idleTimeoutMillis: 30000,
  reapIntervalMillis: 1000,
  createRetryIntervalMillis: 200
};
```

## 故障排除

### 1. 常见问题

#### 数据库连接失败
```bash
# 检查数据库连接
psql $DATABASE_URL -c "SELECT 1;"

# 检查网络连接
telnet ep-xxx.us-east-1.aws.neon.tech 5432
```

#### 应用启动失败
```bash
# 查看应用日志
docker logs smellpin-app

# 检查端口占用
netstat -tulpn | grep :3000

# 检查环境变量
env | grep DATABASE_URL
```

#### 内存不足
```bash
# 查看内存使用
free -h

# 查看进程内存
ps aux --sort=-%mem | head

# 重启应用
docker-compose restart app
```

### 2. 监控告警

#### 设置告警规则
```yaml
# alert_rules.yml
groups:
  - name: smellpin.rules
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High error rate detected"
```

#### 通知配置
```yaml
# alertmanager.yml
route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'https://hooks.slack.com/services/xxx'
```

### 3. 性能调优

#### 慢查询优化
```sql
-- 启用慢查询日志
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- 查看慢查询
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

#### 缓存优化
```javascript
// 缓存策略
const cacheConfig = {
  user: { ttl: 1800 },      // 30分钟
  annotation: { ttl: 3600 }, // 1小时
  lbs: { ttl: 300 }         // 5分钟
};
```

## 回滚策略

### 1. 应用回滚
```bash
# Docker 回滚
docker tag smellpin:latest smellpin:backup
docker pull smellpin:previous
docker-compose up -d

# PM2 回滚
pm2 stop all
git checkout previous-version
npm install
pm2 start ecosystem.config.js
```

### 2. 数据库回滚
```bash
# 恢复数据库备份
psql $DATABASE_URL < /backup/database/smellpin_backup.sql

# 运行回滚迁移
npm run migrate:rollback
```

## 维护计划

### 1. 定期维护
- **每日**: 检查系统状态、备份验证
- **每周**: 更新安全补丁、性能分析
- **每月**: 容量规划、成本优化
- **每季度**: 灾备演练、架构评估

### 2. 升级计划
- **依赖更新**: 每月检查并更新依赖包
- **系统升级**: 每季度升级操作系统
- **数据库升级**: 每半年评估数据库版本
- **架构优化**: 每年进行架构评估和优化

---

**文档版本**: v1.0  
**最后更新**: 2024年12月  
**维护责任人**: DevOps团队  
**紧急联系**: ops@smellpin.com