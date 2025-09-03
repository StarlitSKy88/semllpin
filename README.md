# SmellPin - 全球臭味标注平台

一个基于地图的全球臭味标注和分享平台，用户可以在地图上标记和分享各种气味信息。

## 🌟 功能特性

- 🗺️ **地图标注**: 在全球地图上标记臭味位置
- 📊 **强度评级**: 1-10级臭味强度评分系统
- 📸 **媒体上传**: 支持图片、视频、音频文件上传
- 💬 **评论系统**: 用户可以对标注进行评论和讨论
- 👍 **点赞功能**: 对有用的标注进行点赞
- 📈 **数据统计**: 丰富的数据分析和可视化
- 🔐 **用户系统**: 完整的用户注册、登录、权限管理
- 💳 **支付系统**: 支持多种支付方式的标注费用
- 🛡️ **内容审核**: 管理员和版主审核系统
- 🌍 **多语言**: 支持中文、英文等多种语言

## 🏗️ 技术架构

### 后端技术栈
- **Node.js** + **TypeScript** - 服务端运行时和类型安全
- **Express.js** - Web框架
- **PostgreSQL** + **PostGIS** - 主数据库和地理信息扩展
- **Redis** - 缓存和会话存储
- **JWT** - 身份认证
- **Joi** - 数据验证
- **Winston** - 日志系统
- **Jest** - 测试框架

### 前端技术栈
- **React 18** + **TypeScript**
- **Tailwind CSS** - 样式框架
- **Google Maps API** - 地图服务
- **Chart.js** - 数据可视化
- **Ant Design** - UI组件库

### 基础设施
- **Docker** + **Docker Compose** - 容器化部署
- **AWS S3** - 文件存储
- **Stripe/PayPal** - 支付处理
- **GitHub Actions** - CI/CD

## 📚 项目文档

核心项目文档已整理到 [`docs/`](./docs/) 目录中：

- **[PRD.md](./docs/PRD.md)** - 产品需求文档
- **[PROJECT_PLAN.md](./docs/PROJECT_PLAN.md)** - 项目开发计划
- **[TECH_ARCHITECTURE.md](./docs/TECH_ARCHITECTURE.md)** - 技术架构设计
- **[PAYMENT_SETUP.md](./docs/PAYMENT_SETUP.md)** - 支付系统配置指南

详细信息请查看 [docs/README.md](./docs/README.md)

## 🚀 快速开始

### 环境要求

- Node.js 18+
- npm 或 yarn
- Docker & Docker Compose (生产环境)
- PostgreSQL 15+ (生产环境)
- Redis 7+ (生产环境)

### 方式一：开发模式（推荐新手）

**无需Docker，使用SQLite数据库**

```bash
# 克隆项目
git clone <repository-url>
cd 臭味

# 一键启动开发环境
./start-dev.sh

# 或者使用部署脚本
./scripts/deploy.sh dev
```

访问地址：
- 前端: http://localhost:5173
- 后端: http://localhost:3000

### 方式二：Docker部署

**适合生产环境或完整功能测试**

#### Docker安装

如果遇到"Docker 未安装"错误，请选择以下方式之一：

1. **Docker Desktop（推荐）**
   ```bash
   # 访问 https://www.docker.com/products/docker-desktop
   # 下载并安装 Docker Desktop
   ```

2. **Colima（轻量级）**
   ```bash
   brew install colima docker docker-compose
   colima start
   ```

3. **查看详细安装指南**
   ```bash
   # 查看完整的Docker安装指南
   cat docs/DOCKER_SETUP.md
   ```

#### 启动服务

```bash
# 生产环境部署
./scripts/deploy.sh production v1.0.0

# 或使用docker-compose
docker-compose up -d
```

访问地址：
- API服务: http://localhost:3000
- API文档: http://localhost:3000/api/v1/docs
- 数据库管理: http://localhost:5050 (pgAdmin)
- Redis管理: http://localhost:8081 (Redis Commander)

### 手动安装

1. **安装依赖**
```bash
npm install
```

2. **配置环境变量**
```bash
cp .env.example .env
# 编辑 .env 文件，填入正确的配置
```

3. **启动数据库服务**
```bash
# PostgreSQL
sudo service postgresql start

# Redis
sudo service redis start
```

4. **运行数据库迁移**
```bash
npm run migrate
```

5. **填充示例数据**
```bash
npm run seed
```

6. **启动开发服务器**
```bash
npm run dev
```

## 📚 API文档

### 认证

大部分API需要JWT令牌认证：

```bash
Authorization: Bearer <your-jwt-token>
```

### 主要端点

#### 用户管理
- `POST /api/v1/users/register` - 用户注册
- `POST /api/v1/users/login` - 用户登录
- `GET /api/v1/users/profile/me` - 获取当前用户信息
- `PUT /api/v1/users/profile` - 更新用户资料

#### 标注管理
- `GET /api/v1/annotations/list` - 获取标注列表
- `GET /api/v1/annotations/map` - 获取地图数据
- `POST /api/v1/annotations` - 创建新标注
- `GET /api/v1/annotations/:id` - 获取标注详情
- `PUT /api/v1/annotations/:id` - 更新标注

#### 示例请求

**创建标注**
```bash
curl -X POST http://localhost:3000/api/v1/annotations \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "latitude": 39.9042,
    "longitude": 116.4074,
    "smellIntensity": 8,
    "description": "强烈的汽车尾气味道"
  }'
```

**获取地图数据**
```bash
curl "http://localhost:3000/api/v1/annotations/map?north=40&south=39&east=117&west=116"
```

## 🧪 测试

```bash
# 运行所有测试
npm test

# 运行单元测试
npm run test:unit

# 运行集成测试
npm run test:integration

# 生成测试覆盖率报告
npm run test:coverage
```

## 📦 部署

### 生产环境部署

1. **构建应用**
```bash
npm run build
```

2. **设置生产环境变量**
```bash
cp .env.example .env.production
# 编辑生产环境配置
```

3. **启动生产服务**
```bash
npm start
```

### Docker生产部署

```bash
# 构建生产镜像
docker build -t smellpin-api .

# 运行生产容器
docker run -d \
  --name smellpin-api \
  -p 3000:3000 \
  --env-file .env.production \
  smellpin-api
```

## 🔧 开发指南

### 项目结构

```
src/
├── config/          # 配置文件
├── controllers/     # 控制器
├── middleware/      # 中间件
├── models/          # 数据模型
├── routes/          # 路由定义
├── services/        # 业务逻辑服务
├── utils/           # 工具函数
└── types/           # TypeScript类型定义

migrations/          # 数据库迁移文件
seeds/              # 数据库种子数据
tests/              # 测试文件
scripts/            # 脚本文件
```

### 代码规范

- 使用ESLint和Prettier进行代码格式化
- 遵循TypeScript严格模式
- 编写单元测试和集成测试
- 使用语义化的Git提交信息

### 数据库迁移

```bash
# 创建新迁移
npm run migrate:create <migration_name>

# 运行迁移
npm run migrate

# 回滚迁移
npm run migrate:rollback
```

## 🤝 贡献指南

1. Fork项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

## 📄 许可证

本项目采用MIT许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🆘 支持

如果您遇到问题或有疑问，请：

1. 查看[常见问题](docs/FAQ.md)
2. 搜索[已有Issues](../../issues)
3. 创建新的[Issue](../../issues/new)

## 🙏 致谢

感谢所有为这个项目做出贡献的开发者和用户！

---

**SmellPin** - 让世界的气味信息更透明 🌍👃