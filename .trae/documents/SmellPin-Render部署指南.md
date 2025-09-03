# SmellPin 项目 Render 部署指南

## 1. 部署前准备

### 1.1 确认项目状态
- ✅ 项目已推送到 GitHub 仓库：`https://github.com/StarlitSKy88/semllpin`
- ✅ 项目包含完整的 Node.js 后端代码
- ✅ 项目包含必要的配置文件（package.json、tsconfig.json 等）

### 1.2 准备环境变量
在部署前，请确保您已准备好以下环境变量的值：

| 环境变量 | 说明 | 示例值 |
|---------|------|--------|
| `DATABASE_URL` | Neon PostgreSQL 连接字符串 | `postgresql://username:password@host/database` |
| `REDIS_URL` | Upstash Redis 连接字符串 | `redis://username:password@host:port` |
| `JWT_SECRET` | JWT 密钥 | `your-super-secret-jwt-key` |
| `PAYPAL_CLIENT_ID` | PayPal 客户端 ID | `your-paypal-client-id` |
| `PAYPAL_CLIENT_SECRET` | PayPal 客户端密钥 | `your-paypal-client-secret` |
| `STRIPE_SECRET_KEY` | Stripe 密钥 | `sk_test_...` |
| `NODE_ENV` | 环境标识 | `production` |

## 2. Render 平台注册和登录

### 2.1 注册 Render 账号
1. 访问 [Render 官网](https://render.com)
2. 点击右上角 "Sign Up" 按钮
3. 选择使用 GitHub 账号登录（推荐）或邮箱注册
4. 完成邮箱验证（如果使用邮箱注册）

### 2.2 连接 GitHub 账号
1. 登录 Render 后，进入 Dashboard
2. 如果未连接 GitHub，系统会提示连接
3. 授权 Render 访问您的 GitHub 仓库

## 3. 创建 Web Service

### 3.1 开始创建服务
1. 在 Render Dashboard 中，点击 "New +" 按钮
2. 选择 "Web Service"
3. 选择 "Build and deploy from a Git repository"

### 3.2 连接 GitHub 仓库
1. 在仓库列表中找到 `semllpin` 仓库
2. 点击 "Connect" 按钮
3. 如果看不到仓库，点击 "Configure GitHub App" 重新授权

### 3.3 基础配置
填写以下基础信息：

| 配置项 | 值 | 说明 |
|--------|----|----- |
| **Name** | `smellpin-backend` | 服务名称（可自定义） |
| **Region** | `Oregon (US West)` | 选择离用户最近的区域 |
| **Branch** | `main` | 部署分支 |
| **Root Directory** | 留空 | 项目根目录 |
| **Runtime** | `Node` | 运行时环境 |

### 3.4 构建和启动配置

| 配置项 | 值 | 说明 |
|--------|----|----- |
| **Build Command** | `npm install && npm run build` | 构建命令 |
| **Start Command** | `npm start` | 启动命令 |

### 3.5 选择计划
- 对于测试：选择 "Free" 计划
- 对于生产：建议选择 "Starter" 或更高级计划

## 4. 环境变量配置

### 4.1 添加环境变量
在服务配置页面的 "Environment" 部分：

1. 点击 "Add Environment Variable" 按钮
2. 逐一添加以下环境变量：

```bash
# 数据库配置
DATABASE_URL=postgresql://username:password@host/database
DB_HOST=your-neon-host
DB_PORT=5432
DB_NAME=your-database-name
DB_USER=your-username
DB_PASSWORD=your-password
DB_SSL=true

# Redis 配置
REDIS_URL=redis://username:password@host:port
REDIS_HOST=your-upstash-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# JWT 配置
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters
JWT_EXPIRES_IN=7d

# PayPal 配置
PAYPAL_CLIENT_ID=your-paypal-client-id
PAYPAL_CLIENT_SECRET=your-paypal-client-secret
PAYPAL_MODE=sandbox

# Stripe 配置
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_PUBLISHABLE_KEY=pk_test_your_stripe_publishable_key

# 应用配置
NODE_ENV=production
PORT=10000
API_VERSION=v1

# CORS 配置
CORS_ORIGIN=*

# 日志配置
LOG_LEVEL=info
```

### 4.2 环境变量安全提示
- ⚠️ 确保所有密钥和密码都是生产环境专用的
- ⚠️ 不要在代码中硬编码任何敏感信息
- ⚠️ 定期轮换密钥和密码

## 5. 高级配置

### 5.1 健康检查配置
在 "Settings" 部分配置健康检查：

| 配置项 | 值 | 说明 |
|--------|----|----- |
| **Health Check Path** | `/health` | 健康检查端点 |
| **Health Check Grace Period** | `300` | 启动宽限期（秒） |

### 5.2 自动部署配置
- ✅ 启用 "Auto-Deploy" 功能
- 当 `main` 分支有新提交时，Render 会自动重新部署

### 5.3 域名配置（可选）
1. 在 "Settings" 中找到 "Custom Domains"
2. 添加您的自定义域名
3. 配置 DNS 记录指向 Render 提供的地址

## 6. 开始部署

### 6.1 启动部署
1. 确认所有配置无误后，点击 "Create Web Service"
2. Render 开始自动部署流程
3. 可以在 "Logs" 标签页实时查看部署日志

### 6.2 部署过程监控
部署过程包括以下步骤：
1. **Clone Repository** - 克隆 GitHub 仓库
2. **Install Dependencies** - 安装 npm 依赖
3. **Build Application** - 编译 TypeScript 代码
4. **Start Application** - 启动服务
5. **Health Check** - 健康检查

## 7. 部署验证

### 7.1 检查部署状态
1. 在 Render Dashboard 中查看服务状态
2. 状态应显示为 "Live" 且为绿色
3. 记录服务的 URL 地址（格式：`https://your-service-name.onrender.com`）

### 7.2 测试 API 端点
使用以下命令测试主要端点：

```bash
# 健康检查
curl https://your-service-name.onrender.com/health

# API 版本信息
curl https://your-service-name.onrender.com/api/v1/health

# 测试响应格式
curl -H "Content-Type: application/json" https://your-service-name.onrender.com/api/v1/health
```

预期响应示例：
```json
{
  "status": "healthy",
  "timestamp": "2024-01-20T10:30:00.000Z",
  "uptime": 3600,
  "version": "1.0.0",
  "environment": "production"
}
```

### 7.3 验证数据库连接
```bash
# 测试数据库连接（如果有相关端点）
curl https://your-service-name.onrender.com/api/v1/status
```

## 8. 常见部署问题排查

### 8.1 构建失败问题

**问题："Build failed with exit code 1"**

**排查步骤：**
1. 检查 `package.json` 中的 scripts 配置
2. 确认 Node.js 版本兼容性
3. 检查 TypeScript 编译错误
4. 查看详细构建日志

**解决方案：**
```json
// package.json 确保包含正确的脚本
{
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js",
    "dev": "ts-node src/server.ts"
  }
}
```

### 8.2 启动失败问题

**问题："Application failed to start"**

**排查步骤：**
1. 检查环境变量是否正确设置
2. 确认端口配置（Render 使用 PORT 环境变量）
3. 检查数据库连接字符串
4. 查看应用启动日志

**解决方案：**
```typescript
// 确保服务器监听正确的端口
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
```

### 8.3 数据库连接问题

**问题："Database connection failed"**

**排查步骤：**
1. 验证 `DATABASE_URL` 格式
2. 检查 Neon 数据库状态
3. 确认网络连接权限
4. 测试 SSL 连接配置

**解决方案：**
```bash
# 正确的 DATABASE_URL 格式
DATABASE_URL=postgresql://username:password@ep-xxx.us-east-1.aws.neon.tech/dbname?sslmode=require
```

### 8.4 内存不足问题

**问题："Out of memory" 或应用频繁重启**

**解决方案：**
1. 升级到更高的 Render 计划
2. 优化应用内存使用
3. 添加内存监控

### 8.5 健康检查失败

**问题："Health check failed"**

**排查步骤：**
1. 确认 `/health` 端点正常工作
2. 检查健康检查超时设置
3. 验证应用启动时间

**解决方案：**
```typescript
// 确保健康检查端点简单可靠
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});
```

## 9. 部署后优化

### 9.1 性能监控
1. 在 Render Dashboard 查看性能指标
2. 监控 CPU 和内存使用情况
3. 设置告警通知

### 9.2 日志管理
1. 使用结构化日志格式
2. 设置合适的日志级别
3. 定期清理旧日志

### 9.3 安全配置
1. 启用 HTTPS（Render 自动提供）
2. 配置 CORS 策略
3. 设置速率限制
4. 定期更新依赖包

## 10. 维护和更新

### 10.1 代码更新流程
1. 在本地开发和测试新功能
2. 提交代码到 GitHub `main` 分支
3. Render 自动检测更改并重新部署
4. 监控部署状态和应用健康

### 10.2 环境变量更新
1. 在 Render Dashboard 中更新环境变量
2. 重启服务使更改生效
3. 验证更新后的功能

### 10.3 备份和恢复
1. 定期备份数据库
2. 保存重要的配置信息
3. 制定灾难恢复计划

## 11. 成本优化建议

### 11.1 免费计划限制
- 每月 750 小时免费使用时间
- 服务在无活动时会自动休眠
- 冷启动可能需要几秒钟时间

### 11.2 付费计划优势
- 无休眠限制
- 更好的性能保证
- 更多的计算资源
- 优先技术支持

### 11.3 成本控制
1. 合理选择服务计划
2. 监控资源使用情况
3. 优化应用性能
4. 定期评估需求变化

---

## 快速部署检查清单

- [ ] GitHub 仓库已准备就绪
- [ ] Render 账号已注册并连接 GitHub
- [ ] 所有环境变量已准备
- [ ] 创建 Web Service 并配置基础信息
- [ ] 设置构建和启动命令
- [ ] 添加所有必要的环境变量
- [ ] 配置健康检查路径
- [ ] 启动部署并监控日志
- [ ] 验证部署成功
- [ ] 测试主要 API 端点
- [ ] 设置监控和告警

**部署完成后，您的 SmellPin 后端服务将在以下地址可用：**
`https://your-service-name.onrender.com`

如遇到问题，请参考故障排查部分或联系技术支持。