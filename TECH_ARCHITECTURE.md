# SmellPin 搞笑恶搞平台技术架构设计文档

## 1. 系统架构概览

### 1.1 整体架构
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   前端应用层     │    │   移动端应用     │    │   管理后台       │
│   (React PWA)   │    │   (React Native)│    │   (React Admin) │
│   搞笑UI设计     │    │   校园社交版     │    │   内容审核管理   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
┌─────────────────────────────────┼─────────────────────────────────┐
│                        API网关 + CDN                             │
│                    (Kong/Nginx + CloudFlare)                    │
└─────────────────────────────────┼─────────────────────────────────┘
                                 │
┌─────────────────────────────────┼─────────────────────────────────┐
│                          微服务层                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │  用户服务    │ │ 恶搞标注服务 │ │ 透明支付服务 │ │  通知服务    │  │
│  │ (Node.js)   │ │ (Node.js)   │ │ (Node.js)   │ │ (Node.js)   │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │ LBS奖励服务 │ │ 搞笑分析服务 │ │ 媒体文件服务 │ │ 社交分享服务 │  │
│  │ (Node.js)   │ │ (Python)    │ │ (Node.js)   │ │ (Node.js)   │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │ 国际化服务   │ │ 内容审核服务 │ │ 实时动画服务 │ │ 校园推广服务 │  │
│  │ (Node.js)   │ │ (Python)    │ │ (Node.js)   │ │ (Node.js)   │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │
└─────────────────────────────────┼─────────────────────────────────┘
                                 │
┌─────────────────────────────────┼─────────────────────────────────┐
│                           数据层                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │ PostgreSQL  │ │    Redis    │ │ Elasticsearch│ │   MongoDB   │  │
│  │ (主数据库+   │ │ (缓存+实时   │ │ (搞笑内容    │ │ (日志+分析   │  │
│  │  PostGIS)   │ │  动画数据)   │ │  搜索引擎)   │ │  数据存储)   │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 技术栈选择

#### 前端技术栈
- **框架**：React 18 + TypeScript
- **状态管理**：Redux Toolkit + RTK Query
- **UI组件库**：Ant Design + Tailwind CSS + Framer Motion（动画）
- **地图组件**：React Google Maps API + Mapbox GL JS
- **图表库**：Chart.js + D3.js + React Spring（动画图表）
- **动画库**：Framer Motion + Lottie React（搞笑动画）
- **社交分享**：React Share + Web Share API
- **国际化**：React i18next
- **PWA支持**：Workbox + React PWA
- **构建工具**：Vite + PWA Plugin
- **测试框架**：Jest + React Testing Library + Playwright（E2E）
- **性能监控**：Web Vitals + Sentry

#### 后端技术栈
- **运行时**：Node.js 18+ (主要服务) + Python 3.11 (内容分析服务)
- **框架**：Express.js + FastAPI + Socket.io（实时功能）
- **数据库**：PostgreSQL 15 + PostGIS (地理数据)
- **缓存**：Redis 7 + Redis Streams（实时动画数据）
- **搜索引擎**：Elasticsearch 8（搞笑内容搜索）
- **消息队列**：Redis + Bull Queue + WebSocket
- **支付集成**：Stripe + PayPal + Apple Pay/Google Pay
- **社交分享**：Twitter API + Instagram Basic Display API
- **文件存储**：AWS S3 / CloudFlare R2（媒体文件CDN）
- **国际化**：i18next + ICU MessageFormat
- **内容审核**：OpenAI Moderation API + 自定义规则引擎
- **监控**：Prometheus + Grafana + Sentry

#### DevOps技术栈
- **容器化**：Docker + Docker Compose
- **编排**：Kubernetes
- **CI/CD**：GitHub Actions
- **云服务**：AWS / 阿里云
- **CDN**：CloudFlare
- **日志**：ELK Stack (Elasticsearch + Logstash + Kibana)

## 2. 数据库设计

### 2.1 PostgreSQL 主数据库

#### 用户表 (users)
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    avatar_url TEXT,
    bio TEXT,
    balance DECIMAL(10,2) DEFAULT 0.00, -- 用户余额
    total_earned DECIMAL(10,2) DEFAULT 0.00, -- 总收入（LBS奖励）
    total_spent DECIMAL(10,2) DEFAULT 0.00, -- 总支出（恶搞标注）
    points INTEGER DEFAULT 0, -- 积分系统
    level INTEGER DEFAULT 1, -- 用户等级
    prank_count INTEGER DEFAULT 0, -- 恶搞次数
    discovery_count INTEGER DEFAULT 0, -- 发现恶搞次数
    social_shares INTEGER DEFAULT 0, -- 社交分享次数
    preferred_language VARCHAR(10) DEFAULT 'en', -- 首选语言
    university VARCHAR(100), -- 所在大学
    graduation_year INTEGER, -- 毕业年份
    status VARCHAR(20) DEFAULT 'active', -- active, suspended, deleted
    email_verified BOOLEAN DEFAULT false,
    phone_verified BOOLEAN DEFAULT false,
    is_premium BOOLEAN DEFAULT false, -- 高级用户
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_university ON users(university);
CREATE INDEX idx_users_level ON users(level);
```

#### 恶搞标注表 (annotations)
```sql
CREATE TABLE annotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    location GEOGRAPHY(POINT, 4326) NOT NULL, -- PostGIS地理位置
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    smell_intensity INTEGER NOT NULL CHECK (smell_intensity >= 1 AND smell_intensity <= 10),
    paid_amount DECIMAL(10,2) NOT NULL CHECK (paid_amount >= 1.00 AND paid_amount <= 100.00), -- 付费金额
    description TEXT,
    funny_title VARCHAR(200), -- 搞笑标题
    prank_type VARCHAR(50), -- 恶搞类型：toilet, garbage, food, mystery等
    emoji_reaction VARCHAR(10), -- 表情反应
    weather_condition JSONB, -- 天气信息
    address TEXT,
    country VARCHAR(2), -- ISO国家代码
    region VARCHAR(100),
    city VARCHAR(100),
    university VARCHAR(100), -- 所在大学
    campus_area VARCHAR(100), -- 校园区域
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected, hidden
    is_verified BOOLEAN DEFAULT false,
    verification_count INTEGER DEFAULT 0,
    like_count INTEGER DEFAULT 0,
    laugh_count INTEGER DEFAULT 0, -- 搞笑点赞数
    share_count INTEGER DEFAULT 0, -- 分享次数
    comment_count INTEGER DEFAULT 0,
    discovery_reward DECIMAL(10,2) DEFAULT 0.00, -- 发现奖励
    viral_bonus DECIMAL(10,2) DEFAULT 0.00, -- 病毒传播奖励
    moderation_flags INTEGER DEFAULT 0, -- 举报次数
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE -- 标注过期时间
);

CREATE INDEX idx_annotations_location ON annotations USING GIST(location);
CREATE INDEX idx_annotations_user_id ON annotations(user_id);
CREATE INDEX idx_annotations_intensity ON annotations(smell_intensity);
CREATE INDEX idx_annotations_paid_amount ON annotations(paid_amount);
CREATE INDEX idx_annotations_status ON annotations(status);
CREATE INDEX idx_annotations_university ON annotations(university);
CREATE INDEX idx_annotations_prank_type ON annotations(prank_type);
CREATE INDEX idx_annotations_created_at ON annotations(created_at);
CREATE INDEX idx_annotations_expires_at ON annotations(expires_at);
```

#### 媒体文件表 (media_files)
```sql
CREATE TABLE media_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    file_type VARCHAR(20) NOT NULL, -- image, video, audio
    file_url TEXT NOT NULL,
    file_size INTEGER,
    mime_type VARCHAR(100),
    width INTEGER, -- 图片/视频宽度
    height INTEGER, -- 图片/视频高度
    duration INTEGER, -- 视频/音频时长(秒)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_media_files_annotation_id ON media_files(annotation_id);
```

#### 评论表 (comments)
```sql
CREATE TABLE comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    parent_id UUID REFERENCES comments(id), -- 回复评论
    content TEXT NOT NULL,
    like_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active', -- active, deleted, hidden
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_comments_annotation_id ON comments(annotation_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);
CREATE INDEX idx_comments_parent_id ON comments(parent_id);
```

#### 透明支付记录表 (payments)
```sql
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    annotation_id UUID REFERENCES annotations(id),
    transaction_type VARCHAR(20) NOT NULL, -- prank_payment, lbs_reward, discovery_bonus, viral_bonus
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    payment_method VARCHAR(50), -- stripe, paypal, apple_pay, google_pay
    payment_id TEXT, -- 第三方支付ID
    platform_fee DECIMAL(10,2) DEFAULT 0.00, -- 平台手续费
    tax_amount DECIMAL(10,2) DEFAULT 0.00, -- 税费
    net_amount DECIMAL(10,2) NOT NULL, -- 净金额
    status VARCHAR(20) DEFAULT 'pending', -- pending, completed, failed, refunded
    description TEXT,
    metadata JSONB, -- 额外信息（地理位置、奖励类型等）
    tax_year INTEGER, -- 税务年度
    is_taxable BOOLEAN DEFAULT true, -- 是否需要纳税
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    refunded_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_transaction_type ON payments(transaction_type);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_tax_year ON payments(tax_year);
CREATE INDEX idx_payments_created_at ON payments(created_at);
```

### 2.2 Redis 缓存设计

#### 缓存策略
```javascript
// 用户会话缓存
`session:${sessionId}` -> { userId, expiresAt, language, ... }

// 用户信息缓存
`user:${userId}` -> { id, username, avatar, university, level, ... }

// 搞笑标注缓存
`hot_pranks:${region}` -> [annotationId1, annotationId2, ...]
`trending_pranks:${university}` -> [annotationId1, annotationId2, ...]
`viral_pranks:global` -> [annotationId1, annotationId2, ...]

// 地图区域标注缓存
`map_annotations:${lat}:${lng}:${zoom}` -> [annotation1, annotation2, ...]
`campus_pranks:${university}:${area}` -> [annotation1, annotation2, ...]

// LBS奖励缓存
`lbs_rewards:${userId}:${date}` -> { totalRewards, locations, ... }
`nearby_users:${lat}:${lng}` -> [userId1, userId2, ...]

// 实时动画数据缓存
`live_animations:${region}` -> [animationData1, animationData2, ...]
`smell_heatmap:${lat}:${lng}:${zoom}` -> heatmapData

// 统计数据缓存
`stats:global` -> { totalPranks, activeUsers, totalRewards, ... }
`stats:daily:${date}` -> { newPranks, newUsers, rewardsGiven, ... }
`stats:university:${university}` -> { campusPranks, activeStudents, ... }

// 社交分享缓存
`share_count:${annotationId}` -> shareCount
`viral_tracking:${annotationId}` -> { platforms, shares, clicks, ... }

// 国际化缓存
`i18n:${language}:${version}` -> translationData

// 限流缓存
`rate_limit:${userId}:${action}` -> count
`rate_limit:${ip}:${action}` -> count
```

## 3. API设计

### 3.1 RESTful API规范

#### 基础URL结构
```
https://api.smellpin.com/v1/{resource}
```

#### 认证方式
```javascript
// JWT Token认证
Authorization: Bearer <jwt_token>

// API Key认证（企业用户）
X-API-Key: <api_key>
```

#### 响应格式
```javascript
// 成功响应
{
  "success": true,
  "data": {...},
  "message": "操作成功",
  "timestamp": "2024-12-19T10:30:00Z"
}

// 错误响应
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "请求参数验证失败",
    "details": {
      "field": "email",
      "reason": "邮箱格式不正确"
    }
  },
  "timestamp": "2024-12-19T10:30:00Z"
}
```

### 3.2 核心API接口

#### 用户相关API
```javascript
// 用户注册
POST /v1/auth/register
{
  "email": "user@example.com",
  "password": "password123",
  "username": "username",
  "university": "Stanford University",
  "graduation_year": 2025,
  "preferred_language": "en"
}

// 用户登录
POST /v1/auth/login
{
  "email": "user@example.com",
  "password": "password123"
}

// 获取用户信息
GET /v1/users/me

// 更新用户信息
PUT /v1/users/me
{
  "display_name": "搞笑大师",
  "bio": "专业恶搞，快乐至上",
  "university": "Harvard University",
  "preferred_language": "zh"
}

// 获取用户统计
GET /v1/users/me/stats
// 返回：{ prank_count, discovery_count, total_earned, level, ... }

// 获取用户钱包
GET /v1/users/me/wallet
// 返回：{ balance, total_earned, total_spent, recent_transactions, ... }
PUT /v1/users/me
{
  "display_name": "新昵称",
  "bio": "个人简介"
}
```

#### 恶搞标注相关API
```javascript
// 创建付费恶搞标注
POST /v1/pranks
{
  "latitude": 37.4419,
  "longitude": -122.1430,
  "smell_intensity": 9,
  "paid_amount": 25.00,
  "funny_title": "食堂神秘料理现场",
  "description": "今天的特色菜闻起来像...",
  "prank_type": "food",
  "emoji_reaction": "🤢",
  "university": "Stanford University",
  "campus_area": "Main Dining Hall",
  "media_files": ["funny_pic.jpg", "reaction_video.mp4"]
}

// 获取恶搞标注列表
GET /v1/pranks?lat=37.4419&lng=-122.1430&radius=1000&intensity_min=5&university=Stanford

// 获取热门恶搞
GET /v1/pranks/trending?university=Stanford&timeframe=week

// 获取病毒传播恶搞
GET /v1/pranks/viral?limit=20

// 获取恶搞详情
GET /v1/pranks/:id

// 点赞恶搞
POST /v1/pranks/:id/laugh

// 分享恶搞
POST /v1/pranks/:id/share
{
  "platform": "twitter", // twitter, instagram, tiktok
  "message": "这个太搞笑了！"
}

// 举报恶搞
POST /v1/pranks/:id/report
{
  "reason": "inappropriate",
  "details": "内容不当"
}

// 发现恶搞（获得奖励）
POST /v1/pranks/:id/discover
```

#### 搞笑地图相关API
```javascript
// 获取地图恶搞标注（支持聚合）
GET /v1/map/pranks?bounds=37.4,122.1,37.5,122.2&zoom=12&university=Stanford

// 获取搞笑热力图数据
GET /v1/map/heatmap?bounds=37.4,122.1,37.5,122.2&type=smell_intensity

// 获取实时动画数据
GET /v1/map/animations?bounds=37.4,122.1,37.5,122.2

// 获取校园统计
GET /v1/map/stats?university=Stanford&timeframe=week
// 返回：{ total_pranks, avg_intensity, most_active_area, ... }

// 获取排行榜
GET /v1/map/leaderboard?type=smelliest_spots&university=Stanford&limit=10
```

#### LBS奖励相关API
```javascript
// 签到获取奖励
POST /v1/lbs/checkin
{
  "latitude": 37.4419,
  "longitude": -122.1430,
  "university": "Stanford University"
}

// 获取附近用户
GET /v1/lbs/nearby?lat=37.4419&lng=-122.1430&radius=100

// 获取奖励历史
GET /v1/lbs/rewards?user_id=me&timeframe=month
```

#### 透明支付相关API
```javascript
// 创建支付订单
POST /v1/payments/create
{
  "amount": 25.00,
  "currency": "USD",
  "payment_method": "stripe",
  "transaction_type": "prank_payment",
  "prank_data": {
    "latitude": 37.4419,
    "longitude": -122.1430,
    "smell_intensity": 9
  }
}

// 获取收支明细
GET /v1/payments/transactions?type=all&timeframe=month
// 返回：{ payments, rewards, platform_fees, net_balance, ... }

// 获取税务报表
GET /v1/payments/tax-report?year=2024
```

#### 社交分享相关API
```javascript
// 生成分享链接
POST /v1/social/share-link
{
  "prank_id": "uuid",
  "platform": "twitter",
  "custom_message": "快来看这个搞笑的恶搞！"
}

// 追踪分享效果
GET /v1/social/share-analytics/:prank_id
// 返回：{ total_shares, platform_breakdown, click_through_rate, ... }

// 获取病毒传播数据
GET /v1/social/viral-tracking/:prank_id
```

#### 国际化相关API
```javascript
// 获取翻译文本
GET /v1/i18n/translations?lang=zh&version=latest

// 切换语言
POST /v1/i18n/switch-language
{
  "language": "zh",
  "user_id": "uuid"
}

// 获取支持的语言列表
GET /v1/i18n/languages
```

#### 内容审核相关API
```javascript
// 管理员审核恶搞
POST /v1/admin/moderate/:prank_id
{
  "action": "approve", // approve, reject, hide
  "reason": "符合社区规范"
}

// 获取待审核内容
GET /v1/admin/pending-moderation?limit=20

// 用户举报处理
GET /v1/admin/reports?status=pending&limit=20

// 获取用户管理数据
GET /v1/admin/users?university=Stanford&status=active&limit=50

// 确认支付
POST /v1/payments/:id/confirm

// 获取支付历史
GET /v1/payments/history
```

## 4. 安全设计

### 4.1 认证与授权

#### JWT Token设计
```javascript
// Token结构
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_id",
    "iat": 1640995200,
    "exp": 1641081600,
    "scope": ["read", "write"]
  }
}

// Token刷新机制
- Access Token: 1小时过期
- Refresh Token: 30天过期
- 自动刷新机制
```

#### 权限控制
```javascript
// 角色定义
const ROLES = {
  USER: 'user',           // 普通用户
  MODERATOR: 'moderator', // 版主
  ADMIN: 'admin'          // 管理员
};

// 权限定义
const PERMISSIONS = {
  CREATE_ANNOTATION: 'create:annotation',
  UPDATE_ANNOTATION: 'update:annotation',
  DELETE_ANNOTATION: 'delete:annotation',
  MODERATE_CONTENT: 'moderate:content',
  VIEW_ANALYTICS: 'view:analytics'
};
```

### 4.2 数据安全

#### 敏感数据加密
```javascript
// 密码加密
const bcrypt = require('bcrypt');
const saltRounds = 12;
const hashedPassword = await bcrypt.hash(password, saltRounds);

// 个人信息加密
const crypto = require('crypto');
const algorithm = 'aes-256-gcm';
const key = process.env.ENCRYPTION_KEY;

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher(algorithm, key, iv);
  // ... 加密逻辑
}
```

#### API安全
```javascript
// 限流配置
const rateLimit = {
  windowMs: 15 * 60 * 1000, // 15分钟
  max: 100, // 最多100次请求
  message: '请求过于频繁，请稍后再试'
};

// CORS配置
const corsOptions = {
  origin: ['https://smellpin.com', 'https://app.smellpin.com'],
  credentials: true,
  optionsSuccessStatus: 200
};

// 输入验证
const Joi = require('joi');
const annotationSchema = Joi.object({
  latitude: Joi.number().min(-90).max(90).required(),
  longitude: Joi.number().min(-180).max(180).required(),
  smell_intensity: Joi.number().integer().min(1).max(10).required(),
  description: Joi.string().max(500).optional()
});
```

## 5. 性能优化

### 5.1 数据库优化

#### 索引策略
```sql
-- 地理位置索引（PostGIS）
CREATE INDEX idx_annotations_location_gist ON annotations USING GIST(location);

-- 复合索引
CREATE INDEX idx_annotations_status_created ON annotations(status, created_at DESC);
CREATE INDEX idx_annotations_user_created ON annotations(user_id, created_at DESC);

-- 部分索引
CREATE INDEX idx_annotations_active ON annotations(created_at) WHERE status = 'approved';
```

#### 查询优化
```sql
-- 地理位置查询优化
SELECT id, latitude, longitude, smell_intensity
FROM annotations
WHERE ST_DWithin(
  location,
  ST_GeogFromText('POINT(116.4074 39.9042)'),
  1000  -- 1公里范围
)
AND status = 'approved'
ORDER BY created_at DESC
LIMIT 50;

-- 分页查询优化
SELECT *
FROM annotations
WHERE created_at < $1  -- 游标分页
ORDER BY created_at DESC
LIMIT 20;
```

### 5.2 缓存策略

#### 多级缓存
```javascript
// L1: 应用内存缓存
const NodeCache = require('node-cache');
const memoryCache = new NodeCache({ stdTTL: 300 }); // 5分钟

// L2: Redis缓存
const redis = require('redis');
const redisClient = redis.createClient();

// L3: CDN缓存
// CloudFlare缓存配置
const cacheHeaders = {
  'Cache-Control': 'public, max-age=3600', // 1小时
  'Vary': 'Accept-Encoding'
};

// 缓存穿透防护
async function getAnnotationWithCache(id) {
  // 1. 检查内存缓存
  let annotation = memoryCache.get(`annotation:${id}`);
  if (annotation) return annotation;
  
  // 2. 检查Redis缓存
  annotation = await redisClient.get(`annotation:${id}`);
  if (annotation) {
    annotation = JSON.parse(annotation);
    memoryCache.set(`annotation:${id}`, annotation);
    return annotation;
  }
  
  // 3. 查询数据库
  annotation = await db.annotations.findById(id);
  if (annotation) {
    await redisClient.setex(`annotation:${id}`, 3600, JSON.stringify(annotation));
    memoryCache.set(`annotation:${id}`, annotation);
  }
  
  return annotation;
}
```

### 5.3 前端性能优化

#### 代码分割
```javascript
// 路由级别代码分割
const MapPage = lazy(() => import('./pages/MapPage'));
const ProfilePage = lazy(() => import('./pages/ProfilePage'));

// 组件级别代码分割
const HeavyChart = lazy(() => import('./components/HeavyChart'));

// 预加载关键资源
const preloadMapData = () => {
  import('./utils/mapUtils');
  import('./components/MapMarker');
};
```

#### 图片优化
```javascript
// 响应式图片
<picture>
  <source media="(max-width: 768px)" srcSet="image-mobile.webp" />
  <source media="(min-width: 769px)" srcSet="image-desktop.webp" />
  <img src="image-fallback.jpg" alt="标注图片" loading="lazy" />
</picture>

// 图片压缩和格式转换
const sharp = require('sharp');

async function optimizeImage(inputBuffer) {
  return await sharp(inputBuffer)
    .resize(800, 600, { fit: 'inside', withoutEnlargement: true })
    .webp({ quality: 80 })
    .toBuffer();
}
```

## 6. 监控与日志

### 6.1 应用监控

#### Prometheus指标
```javascript
const prometheus = require('prom-client');

// 自定义指标
const httpRequestDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP请求耗时',
  labelNames: ['method', 'route', 'status']
});

const annotationCounter = new prometheus.Counter({
  name: 'annotations_total',
  help: '标注总数',
  labelNames: ['country', 'intensity_level']
});

const activeUsers = new prometheus.Gauge({
  name: 'active_users',
  help: '活跃用户数'
});
```

#### 健康检查
```javascript
// 健康检查端点
app.get('/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    services: {
      database: await checkDatabase(),
      redis: await checkRedis(),
      storage: await checkStorage()
    }
  };
  
  const isHealthy = Object.values(health.services).every(service => service.status === 'ok');
  
  res.status(isHealthy ? 200 : 503).json(health);
});
```

### 6.2 日志系统

#### 结构化日志
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// 使用示例
logger.info('用户创建标注', {
  userId: 'uuid',
  annotationId: 'uuid',
  location: { lat: 39.9042, lng: 116.4074 },
  intensity: 8
});
```

## 7. 部署架构

### 7.1 Docker容器化

#### Dockerfile示例
```dockerfile
# Node.js服务
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

USER node

CMD ["npm", "start"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:pass@db:5432/smellpin
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis

  db:
    image: postgis/postgis:15-3.3
    environment:
      - POSTGRES_DB=smellpin
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### 7.2 Kubernetes部署

#### 应用部署配置
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: smellpin-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: smellpin-api
  template:
    metadata:
      labels:
        app: smellpin-api
    spec:
      containers:
      - name: api
        image: smellpin/api:latest
        ports:
        - containerPort: 3000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: smellpin-secrets
              key: database-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

---

**文档版本**：v1.0  
**创建日期**：2024年12月  
**维护团队**：技术架构组