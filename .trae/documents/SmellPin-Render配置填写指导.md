# SmellPin Render 部署配置填写指导

## 📋 配置概览

根据您提供的 Render 配置界面截图，我将为您详细指导如何正确填写每个配置项，确保 SmellPin 项目能够成功部署。

## 🔧 基本设置 (Basic Settings)

### 1. Name 名称

```
填写值：semllpin
说明：保持当前设置，这是您的 Web 服务唯一标识符
```

### 2. Project 项目 (可选)

```
填写值：可以保持空白或选择一个项目
说明：用于组织管理多个服务，对部署功能无影响
```

### 3. Language 语言

```
填写值：Node.js
说明：SmellPin 是基于 Node.js + TypeScript 的项目
注意：不要选择 Docker，我们使用 Node.js 原生部署
```

### 4. Branch 分支

```
填写值：main
说明：使用主分支进行部署，确保代码是最新稳定版本
```

### 5. Region 区域

```
填写值：Oregon (US West) 俄勒冈州（美国西部）
说明：当前设置合适，提供良好的全球访问性能
```

### 6. Root Directory 根目录 (可选)

```
填写值：保持空白
说明：SmellPin 项目根目录就是仓库根目录，无需特殊设置
```

## 🌍 环境变量配置 (Environment Variables)

### 必需环境变量清单

点击 "Add Environment Variable" 按钮，逐一添加以下环境变量：

#### 1. 数据库配置

```
NAME_OF_VARIABLE: DATABASE_URL
VALUE: postgresql://username:password@host:port/database
说明：您的 Neon PostgreSQL 连接字符串
```

#### 2. Redis 配置

```
NAME_OF_VARIABLE: REDIS_URL
VALUE: redis://username:password@host:port
说明：Redis 缓存服务连接字符串
```

#### 3. JWT 配置

```
NAME_OF_VARIABLE: JWT_SECRET
VALUE: your-super-secret-jwt-key-here
说明：用于 JWT 令牌签名的密钥，建议使用 32 位随机字符串
```

#### 4. 应用配置

```
NAME_OF_VARIABLE: NODE_ENV
VALUE: production
说明：设置为生产环境模式
```

```
NAME_OF_VARIABLE: PORT
VALUE: 10000
说明：Render 默认端口，必须设置
```

#### 5. PayPal 配置

```
NAME_OF_VARIABLE: PAYPAL_CLIENT_ID
VALUE: your-paypal-client-id
说明：PayPal 支付集成客户端 ID
```

```
NAME_OF_VARIABLE: PAYPAL_CLIENT_SECRET
VALUE: your-paypal-client-secret
说明：PayPal 支付集成客户端密钥
```

#### 6. Stripe 配置

```
NAME_OF_VARIABLE: STRIPE_SECRET_KEY
VALUE: sk_live_your-stripe-secret-key
说明：Stripe 支付集成密钥
```

#### 7. 其他可选配置

```
NAME_OF_VARIABLE: API_BASE_URL
VALUE: https://semllpin.onrender.com
说明：API 基础 URL
```

```
NAME_OF_VARIABLE: CORS_ORIGIN
VALUE: https://your-frontend-domain.com
说明：前端域名，用于 CORS 配置
```

## ⚙️ 高级设置 (Advanced Settings)

### 1. Health Check Path 健康检查路径

```
填写值：/health
说明：SmellPin 项目已实现 /health 端点用于健康检查
```

### 2. Pre-Deploy Command 部署前命令

```
填写值：npm run migrate
说明：部署前运行数据库迁移，确保数据库结构最新
```

### 3. Build Command 构建命令

```
填写值：npm install && npm run build
说明：安装依赖并构建 TypeScript 项目
```

### 4. Start Command 启动命令

```
填写值：npm start
说明：启动生产环境服务器
```

### 5. Auto-Deploy 自动部署

```
设置：On Commit (保持启用)
说明：代码提交时自动触发部署
```

## 🐳 Docker 相关配置

**重要提示**：由于我们选择了 Node.js 语言而非 Docker，以下 Docker 相关配置将被忽略：

* Dockerfile Path

* Docker Build Context Directory

* Docker Command

* Registry Credential

这些字段可以保持空白或默认值。

## 📁 构建过滤器 (Build Filters)

### Included Paths 包含路径

```
建议设置：
- src/**
- package.json
- package-lock.json
- tsconfig.json
说明：只有这些路径的更改才会触发重新部署
```

### Ignored Paths 忽略路径

```
建议设置：
- README.md
- docs/**
- tests/**
- .github/**
说明：这些路径的更改不会触发部署
```

## ✅ 配置验证清单

在点击 "Deploy Web Service" 之前，请确认：

* [ ] **Language** 设置为 **Node.js**

* [ ] **Branch** 设置为 **main**

* [ ] **所有必需环境变量** 已正确添加

* [ ] **Health Check Path** 设置为 **/health**

* [ ] **Pre-Deploy Command** 设置为 **npm run migrate**

* [ ] **数据库连接字符串** 格式正确

* [ ] **JWT\_SECRET** 使用强密码

* [ ] **PORT** 设置为 **10000**

## 🚀 部署步骤

1. **填写基本设置**：按照上述指导填写所有基本配置
2. **添加环境变量**：逐一添加所有必需的环境变量
3. **配置高级设置**：设置健康检查和部署命令
4. **验证配置**：使用上述清单检查所有配置
5. **开始部署**：点击 "Deploy Web Service" 按钮
6. **监控部署**：观察部署日

