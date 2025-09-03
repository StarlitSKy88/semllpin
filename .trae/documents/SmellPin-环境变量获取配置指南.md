# SmellPin 环境变量获取和配置指南

## 概述

本指南详细说明如何获取和配置 SmellPin 项目部署所需的三个关键环境变量：
- `DATABASE_URL`: Neon PostgreSQL 连接字符串
- `REDIS_URL`: Redis 缓存连接字符串  
- `JWT_SECRET`: JWT 签名密钥

## 1. DATABASE_URL - Neon PostgreSQL 配置

### 1.1 注册 Neon 账号

1. **访问 Neon 官网**
   - 打开 [https://neon.tech](https://neon.tech)
   - 点击 "Sign Up" 注册账号

2. **选择注册方式**
   - GitHub 账号登录（推荐）
   - Google 账号登录
   - 邮箱注册

### 1.2 创建数据库项目

1. **创建新项目**
   ```
   项目名称: smellpin-production
   数据库名称: smellpin_db
   区域: 选择离用户最近的区域（如 Asia Pacific）
   ```

2. **等待项目创建**
   - 创建过程通常需要 1-2 分钟
   - 创建完成后会自动跳转到项目仪表板

### 1.3 获取连接字符串

1. **进入项目仪表板**
   - 点击项目名称进入详情页
   - 找到 "Connection Details" 部分

2. **复制连接字符串**
   ```
   格式示例：
   postgresql://username:password@ep-xxx-xxx.us-east-1.aws.neon.tech/smellpin_db?sslmode=require
   ```

3. **连接字符串说明**
   ```
   postgresql://[用户名]:[密码]@[主机地址]/[数据库名]?sslmode=require
   ```

### 1.4 配置示例

```bash
# 在 Render 环境变量中设置
DATABASE_URL=postgresql://neondb_owner:AbCd1234@ep-cool-lab-123456.us-east-1.aws.neon.tech/neondb?sslmode=require
```

### 1.5 安全注意事项

- ✅ **必须使用 SSL 连接** (`sslmode=require`)
- ✅ **定期轮换密码**
- ✅ **限制数据库访问 IP**（如果可能）
- ❌ **不要在代码中硬编码连接字符串**
- ❌ **不要将连接字符串提交到 Git 仓库**

## 2. REDIS_URL - Redis 缓存配置

### 2.1 推荐服务：Upstash Redis

#### 注册 Upstash 账号

1. **访问 Upstash 官网**
   - 打开 [https://upstash.com](https://upstash.com)
   - 点击 "Sign Up" 注册账号

2. **选择注册方式**
   - GitHub 账号登录（推荐）
   - Google 账号登录
   - 邮箱注册

#### 创建 Redis 数据库

1. **创建新数据库**
   ```
   数据库名称: smellpin-cache
   区域: 选择离应用服务器最近的区域
   类型: Global（全球分布）或 Regional（区域性）
   ```

2. **选择计划**
   - **Free Plan**: 10,000 命令/天，适合开发测试
   - **Pay as you Scale**: 按使用量付费，适合生产环境

#### 获取连接信息

1. **进入数据库详情**
   - 点击创建的数据库名称
   - 查看 "Details" 标签页

2. **复制连接字符串**
   ```
   格式示例：
   redis://default:AbCd1234@us1-xxx-xxx.upstash.io:6379
   ```

### 2.2 替代方案：Redis Cloud

#### 注册 Redis Cloud

1. **访问 Redis Cloud**
   - 打开 [https://redis.com/try-free](https://redis.com/try-free)
   - 注册免费账号

2. **创建数据库**
   ```
   数据库名称: smellpin-cache
   云提供商: AWS/GCP/Azure
   区域: 选择合适区域
   ```

#### 获取连接信息

```bash
# Redis Cloud 连接字符串格式
redis://default:password@redis-12345.c1.us-east-1-1.ec2.cloud.redislabs.com:12345
```

### 2.3 配置示例

```bash
# 在 Render 环境变量中设置
REDIS_URL=redis://default:AbCd1234@us1-xxx-xxx.upstash.io:6379
```

### 2.4 安全注意事项

- ✅ **使用强密码**
- ✅ **启用 TLS/SSL**（如果支持）
- ✅ **限制访问 IP**（如果可能）
- ✅ **定期监控使用量**
- ❌ **不要使用默认密码**
- ❌ **不要在公网暴露 Redis 端口**

## 3. JWT_SECRET - JWT 签名密钥配置

### 3.1 生成安全的 JWT 密钥

#### 方法一：使用 Node.js 生成

```javascript
// 在本地终端运行
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

#### 方法二：使用 OpenSSL 生成

```bash
# 在终端运行
openssl rand -hex 64
```

#### 方法三：在线生成器

1. **访问在线生成器**
   - [https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx](https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx)
   - 选择 "512-bit" 或 "256-bit"
   - 点击 "Generate" 生成密钥

2. **推荐设置**
   ```
   长度: 64 字符（256-bit）或 128 字符（512-bit）
   格式: 十六进制字符串
   ```

### 3.2 密钥示例格式

```bash
# 256-bit JWT 密钥示例（64 字符）
JWT_SECRET=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

# 512-bit JWT 密钥示例（128 字符）
JWT_SECRET=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456789012345678901234567890abcdef1234567890abcdef1234567890abcdef
```

### 3.3 配置示例

```bash
# 在 Render 环境变量中设置
JWT_SECRET=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

### 3.4 安全注意事项

- ✅ **使用足够长的密钥**（至少 256-bit）
- ✅ **使用加密安全的随机数生成器**
- ✅ **定期轮换 JWT 密钥**
- ✅ **不同环境使用不同密钥**
- ❌ **不要使用简单的字符串**
- ❌ **不要在代码中硬编码密钥**
- ❌ **不要将密钥提交到版本控制**

## 4. 完整配置清单

### 4.1 Render 环境变量配置

在 Render 部署配置中，添加以下环境变量：

```bash
# 数据库配置
DATABASE_URL=postgresql://neondb_owner:your_password@ep-xxx-xxx.us-east-1.aws.neon.tech/neondb?sslmode=require

# Redis 缓存配置
REDIS_URL=redis://default:your_password@us1-xxx-xxx.upstash.io:6379

# JWT 密钥配置
JWT_SECRET=your_generated_jwt_secret_key_here

# 其他必要配置
NODE_ENV=production
PORT=10000
```

### 4.2 本地开发配置

创建 `.env` 文件（不要提交到 Git）：

```bash
# .env 文件内容
DATABASE_URL=postgresql://localhost:5432/smellpin_dev
REDIS_URL=redis://localhost:6379
JWT_SECRET=your_development_jwt_secret
NODE_ENV=development
PORT=3000
```

## 5. 常见问题和解决方案

### 5.1 数据库连接问题

**问题**: `connection refused` 或 `timeout`

**解决方案**:
1. 检查连接字符串格式是否正确
2. 确认数据库服务是否正常运行
3. 检查网络防火墙设置
4. 验证 SSL 配置 (`sslmode=require`)

### 5.2 Redis 连接问题

**问题**: `Redis connection failed`

**解决方案**:
1. 验证 Redis URL 格式
2. 检查 Redis 服务状态
3. 确认密码和端口正确
4. 检查网络连接

### 5.3 JWT 验证失败

**问题**: `JsonWebTokenError: invalid signature`

**解决方案**:
1. 确认 JWT_SECRET 在所有服务实例中一致
2. 检查密钥长度和格式
3. 验证 token 生成和验证逻辑

### 5.4 环境变量未生效

**问题**: 应用无法读取环境变量

**解决方案**:
1. 重新部署应用
2. 检查变量名拼写
3. 确认变量值没有多余空格
4. 验证 Render 配置页面设置

## 6. 安全最佳实践

### 6.1 密钥管理

- 🔐 **使用密钥管理服务**（如 AWS Secrets Manager）
- 🔐 **定期轮换密钥**
- 🔐 **最小权限原则**
- 🔐 **审计日志记录**

### 6.2 网络安全

- 🌐 **使用 HTTPS/TLS**
- 🌐 **IP 白名单**
- 🌐 **VPC 网络隔离**
- 🌐 **DDoS 防护**

### 6.3 监控告警

- 📊 **连接数监控**
- 📊 **性能指标监控**
- 📊 **错误率告警**
- 📊 **资源使用监控**

---

## 总结

按照本指南完成环境变量配置后，你的 SmellPin 项目将具备：

✅ **安全的数据库连接**（Neon PostgreSQL）  
✅ **高性能缓存服务**（Upstash Redis）  
✅ **安全的身份验证**（JWT 签名）  
✅ **生产级别的安全配置**  

如果在配置过程中遇到问题，请参考常见问题部分或联系技术支持。