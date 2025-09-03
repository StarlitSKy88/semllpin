# SmellPin项目Render部署完整指南

## 📋 部署概述

本指南将详细介绍如何将SmellPin后端服务部署到Render平台。Render提供免费750小时/月的服务，非常适合中小型项目的部署需求。

### 🎯 部署目标
- 在Render平台部署SmellPin后端服务
- 配置生产环境所需的所有环境变量
- 设置健康检查和自动部署
- 获取可访问的生产域名

## 🚀 第一步：创建Render账号和服务

### 1.1 注册Render账号
1. 访问 [https://render.com/](https://render.com/)
2. 点击 **"Get Started for Free"** 按钮
3. 选择 **"Sign up with GitHub"** 使用GitHub账号登录
4. 授权Render访问您的GitHub仓库

### 1.2 创建Web Service
1. 登录后，点击右上角的 **"New +"** 按钮
2. 选择 **"Web Service"**
3. 在仓库列表中找到并选择您的 **SmellPin GitHub仓库**
4. 如果没有看到仓库，点击 **"Connect account"** 重新授权

## ⚙️ 第二步：基础配置

在服务配置页面，按照以下参数进行设置：

| 配置项 | 值 | 说明 |
|--------|----|---------|
| **Name** | `smellpin-backend` | 服务名称，将用于生成域名 |
| **Region** | `Oregon (US West)` | 推荐选择美国西部，延迟较低 |
| **Branch** | `main` | 部署分支，确保是您的主分支 |
| **Root Directory** | `/` | 项目根目录 |
| **Runtime** | `Node` | 自动检测，确保选择Node.js |
| **Build Command** | `npm install && npm run build` | 构建命令 |
| **Start Command** | `npm run start:prod` | 启动命令 |
| **Plan** | `Free` | 选择免费计划 |

### 📝 重要说明
- **Build Command**: 会先安装依赖，然后编译TypeScript代码到`dist`目录
- **Start Command**: 使用生产环境启动脚本，设置`NODE_ENV=production`
- **Free Plan**: 提供750小时/月免费使用时间，足够个人项目使用

## 🔐 第三步：环境变量配置

在 **Environment** 部分，添加以下环境变量：

### 3.1 核心环境变量

| 变量名 | 值 | 说明 |
|--------|----|---------|
| `NODE_ENV` | `production` | 设置为生产环境 |
| `PORT` | `10000` | Render默认端口（可选，系统会自动设置） |

### 3.2 数据库配置

| 变量名 | 值 |
|--------|---------|
| `DATABASE_URL` | `postgresql://neondb_owner:npg_e3mCxo2VtySa@ep-shy-frost-aehftle9-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require` |

### 3.3 Redis缓存配置

| 变量名 | 值 |
|--------|---------|
| `REDIS_URL` | `rediss://default:AfFQAAIncDE5M2NkZTFjOGE3ZTk0NGVjYTIxZDI5ZmE2NTFiZDE0OXAxNjE3NzY@special-lionfish-61776.upstash.io:6379` |

### 3.4 PayPal支付配置

| 变量名 | 值 |
|--------|---------|
| `PAYPAL_CLIENT_ID` | `AR3lanKZLAf8blcwdG3mlJOyLvUxjM7gn2QsFTLIwWDlf1sALN7vnQJQwa-J0krqIxwgu6Oruj3gqETQ` |
| `PAYPAL_CLIENT_SECRET` | `EER7aD7W-cypjMSSXdQK4LhOOKPIKZS77PODN2TLFSZn3g0k6fx3q-XjyQsOSvyAmTr2AJS3KgGq0iGs` |
| `PAYPAL_MODE` | `live` |

### 3.5 安全配置

| 变量名 | 值 |
|--------|---------|
| `JWT_SECRET` | `3ef5278e751aab6ba6fedf2d8382777022323b906b4ae76e32fbff3bfce01a82` |

### 3.6 可选配置（根据需要添加）

| 变量名 | 示例值 | 说明 |
|--------|--------|---------|
| `CORS_ORIGIN` | `https://your-frontend-domain.com` | 前端域名 |
| `LOG_LEVEL` | `info` | 日志级别 |
| `RATE_LIMIT_MAX` | `1000` | API速率限制 |

## 🏥 第四步：健康检查配置

在 **Advanced** 部分进行健康检查配置：

| 配置项 | 值 | 说明 |
|--------|----|---------|
| **Health Check Path** | `/health` | 健康检查端点 |
| **Auto-Deploy** | `Yes` | 启用自动部署 |

### 健康检查说明
- SmellPin项目在 `/health` 端点提供健康检查
- 返回服务状态、数据库连接、Redis连接等信息
- Render会定期检查此端点，确保服务正常运行

## 🚀 第五步：部署并获取域名

### 5.1 开始部署
1. 确认所有配置无误后，点击 **"Create Web Service"**
2. Render开始自动部署流程：
   - 克隆GitHub仓库
   - 安装npm依赖
   - 执行构建命令
   - 启动服务

### 5.2 监控部署过程
- 在部署页面可以实时查看构建日志
- 正常情况下部署需要3-5分钟
- 如果出现错误，查看日志进行排查

### 5.3 获取服务域名
部署成功后，您将获得类似以下格式的域名：
```
https://smellpin-backend-xxxx.onrender.com
```

## ✅ 第六步：部署后验证

### 6.1 健康检查验证
访问健康检查端点：
```bash
curl https://your-render-domain.onrender.com/health
```

期望返回：
```json
{
  "success": true,
  "data": {
    "status": "ok",
    "timestamp": "2024-01-01T00:00:00.000Z",
    "uptime": 123.45,
    "environment": "production",
    "version": "1.0.0"
  },
  "message": "服务运行正常"
}
```

### 6.2 API端点验证
测试主要API端点：
```bash
# 测试用户注册
curl -X POST https://your-render-domain.onrender.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"phone": "1234567890", "password": "test123"}'

# 测试标注列表
curl https://your-render-domain.onrender.com/api/v1/annotations
```

### 6.3 数据库连接验证
访问数据库健康检查：
```bash
curl https://your-render-domain.onrender.com/api/health/database
```

## 🔧 常见问题排查

### 问题1：构建失败
**症状**: 部署过程中构建命令执行失败

**可能原因**:
- Node.js版本不兼容
- 依赖安装失败
- TypeScript编译错误

**解决方案**:
1. 检查`package.json`中的`engines`字段
2. 确保所有依赖都在`dependencies`中
3. 本地运行`npm run build`确保无编译错误

### 问题2：启动失败
**症状**: 构建成功但服务无法启动

**可能原因**:
- 环境变量配置错误
- 数据库连接失败
- 端口配置问题

**解决方案**:
1. 检查所有环境变量是否正确设置
2. 验证数据库URL格式和连接权限
3. 确保启动命令正确：`npm run start:prod`

### 问题3：健康检查失败
**症状**: 服务启动但健康检查返回错误

**可能原因**:
- 数据库连接问题
- Redis连接问题
- 健康检查路径错误

**解决方案**:
1. 检查数据库和Redis连接配置
2. 确认健康检查路径为`/health`
3. 查看服务日志排查具体错误

### 问题4：CORS错误
**症状**: 前端无法访问API

**解决方案**:
1. 设置`CORS_ORIGIN`环境变量为前端域名
2. 确保前端使用正确的API域名
3. 检查API路径是否正确（包含`/api/v1`前缀）

### 问题5：PayPal支付失败
**症状**: 支付功能无法正常工作

**解决方案**:
1. 确认PayPal配置使用的是`live`模式
2. 验证Client ID和Secret是否正确
3. 检查PayPal账户是否已激活商家功能

## 📊 监控和维护

### 日志查看
在Render控制台可以查看：
- 实时日志流
- 历史日志记录
- 错误日志过滤

### 性能监控
Render提供基础监控指标：
- CPU使用率
- 内存使用率
- 响应时间
- 错误率

### 自动重启
- 服务异常时Render会自动重启
- 可以手动重启服务
- 支持零停机部署

## 🔄 更新部署

### 自动部署
- 推送代码到`main`分支会自动触发部署
- 可以在设置中关闭自动部署

### 手动部署
- 在Render控制台点击"Manual Deploy"
- 选择特定的commit进行部署
- 支持回滚到之前的版本

## 📞 技术支持

如果遇到部署问题，可以：
1. 查看Render官方文档：[https://render.com/docs](https://render.com/docs)
2. 联系Render技术支持
3. 在项目GitHub仓库提交Issue

---

**部署完成后，您的SmellPin后端服务将在Render平台稳定运行，支持自动扩展和零停机部署！**