# SmellPin 技术文档

## 项目架构概览

### 系统架构图
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Database      │
│   (React)       │◄──►│ (Cloudflare     │◄──►│   (Neon         │
│   Port: 5176    │    │  Workers)       │    │   PostgreSQL)   │
│                 │    │   Port: 8787    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CDN/Static    │    │   External      │    │   File Storage  │
│   Assets        │    │   Services      │    │   (Cloudflare   │
│                 │    │   - Stripe      │    │    R2)          │
│                 │    │   - SendGrid    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 技术栈

#### 前端技术栈
- **框架**: React 18 + TypeScript
- **构建工具**: Vite 5.4.19
- **状态管理**: Redux Toolkit + RTK Query
- **UI组件**: Ant Design + Tailwind CSS
- **地图服务**: Mapbox GL JS
- **HTTP客户端**: Axios
- **路由**: React Router v6
- **表单处理**: React Hook Form
- **图标**: Lucide React
- **支付**: Stripe Elements

#### 后端技术栈
- **运行时**: Cloudflare Workers
- **框架**: Hono.js
- **数据库**: Neon PostgreSQL
- **ORM**: Drizzle ORM
- **认证**: JWT + bcrypt
- **支付**: Stripe API
- **邮件**: SendGrid
- **文件存储**: Cloudflare R2
- **实时通信**: WebSocket

#### 数据库设计
- **主数据库**: Neon PostgreSQL
- **缓存**: Cloudflare KV
- **会话存储**: JWT Token
- **文件存储**: Cloudflare R2

## 项目结构

### 前端项目结构
```
frontend/
├── public/                 # 静态资源
├── src/
│   ├── components/         # 可复用组件
│   │   ├── common/        # 通用组件
│   │   ├── forms/         # 表单组件
│   │   └── maps/          # 地图相关组件
│   ├── pages/             # 页面组件
│   │   ├── auth/          # 认证页面
│   │   ├── dashboard/     # 仪表板
│   │   ├── map/           # 地图页面
│   │   └── profile/       # 用户资料
│   ├── hooks/             # 自定义Hooks
│   ├── store/             # Redux状态管理
│   ├── services/          # API服务
│   ├── utils/             # 工具函数
│   ├── types/             # TypeScript类型定义
│   └── styles/            # 样式文件
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

### 后端项目结构
```
workers/
├── src/
│   ├── routes/            # API路由
│   │   ├── auth.ts        # 认证路由
│   │   ├── annotations.ts # 标注路由
│   │   ├── users.ts       # 用户路由
│   │   ├── payments.ts    # 支付路由
│   │   └── lbs.ts         # 位置服务路由
│   ├── middleware/        # 中间件
│   │   ├── auth.ts        # 认证中间件
│   │   ├── cors.ts        # CORS中间件
│   │   └── validation.ts  # 数据验证
│   ├── services/          # 业务逻辑服务
│   ├── db/                # 数据库相关
│   │   ├── schema.ts      # 数据库模式
│   │   └── migrations/    # 数据库迁移
│   ├── utils/             # 工具函数
│   └── types/             # TypeScript类型
├── wrangler.toml          # Cloudflare配置
├── package.json
└── tsconfig.json
```

## 数据库设计

### 核心表结构

#### users 表
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    bio TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    is_premium BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### annotations 表
```sql
CREATE TABLE annotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    smell_type VARCHAR(50) NOT NULL,
    intensity INTEGER CHECK (intensity >= 1 AND intensity <= 10),
    description TEXT,
    image_urls TEXT[],
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 地理位置索引
CREATE INDEX idx_annotations_location ON annotations USING GIST (
    ll_to_earth(latitude, longitude)
);
```

#### payments 表
```sql
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    stripe_payment_intent_id VARCHAR(255) UNIQUE,
    amount INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'usd',
    status VARCHAR(20) NOT NULL,
    plan_type VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 索引优化
```sql
-- 用户查询优化
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);

-- 标注查询优化
CREATE INDEX idx_annotations_user_id ON annotations(user_id);
CREATE INDEX idx_annotations_created_at ON annotations(created_at DESC);
CREATE INDEX idx_annotations_smell_type ON annotations(smell_type);

-- 支付查询优化
CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_status ON payments(status);
```

## API 接口设计

### 认证接口

#### POST /api/auth/register
```typescript
interface RegisterRequest {
  email: string;
  username: string;
  password: string;
}

interface RegisterResponse {
  success: boolean;
  message: string;
  user?: {
    id: string;
    email: string;
    username: string;
  };
}
```

#### POST /api/auth/login
```typescript
interface LoginRequest {
  email: string;
  password: string;
}

interface LoginResponse {
  success: boolean;
  token?: string;
  user?: {
    id: string;
    email: string;
    username: string;
    is_premium: boolean;
  };
}
```

### 标注接口

#### POST /api/annotations
```typescript
interface CreateAnnotationRequest {
  latitude: number;
  longitude: number;
  smell_type: string;
  intensity: number;
  description?: string;
  image_urls?: string[];
}

interface AnnotationResponse {
  id: string;
  user_id: string;
  latitude: number;
  longitude: number;
  smell_type: string;
  intensity: number;
  description?: string;
  image_urls?: string[];
  created_at: string;
  user: {
    username: string;
    avatar_url?: string;
  };
}
```

#### GET /api/lbs/nearby
```typescript
interface NearbyRequest {
  lat: number;
  lng: number;
  radius: number; // 米
  limit?: number;
  offset?: number;
}

interface NearbyResponse {
  annotations: AnnotationResponse[];
  total: number;
  has_more: boolean;
}
```

## 部署指南

### 环境要求
- Node.js 18+
- npm 或 yarn
- Cloudflare账户
- Neon PostgreSQL数据库
- Stripe账户
- SendGrid账户

### 本地开发环境搭建

#### 1. 克隆项目
```bash
git clone <repository-url>
cd smellpin
```

#### 2. 安装依赖
```bash
# 前端依赖
cd frontend
npm install

# 后端依赖
cd ../workers
npm install
```

#### 3. 环境变量配置

**前端 (.env)**
```env
VITE_API_BASE_URL=http://localhost:8787
VITE_MAPBOX_ACCESS_TOKEN=your_mapbox_token
VITE_STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
```

**后端 (.env)**
```env
DATABASE_URL=your_neon_database_url
JWT_SECRET=your_jwt_secret
STRIPE_SECRET_KEY=your_stripe_secret_key
SENDGRID_API_KEY=your_sendgrid_api_key
CLOUDFLARE_R2_ACCESS_KEY=your_r2_access_key
CLOUDFLARE_R2_SECRET_KEY=your_r2_secret_key
```

#### 4. 数据库迁移
```bash
cd workers
npm run db:migrate
npm run db:seed
```

#### 5. 启动开发服务器
```bash
# 启动后端
cd workers
npm run dev

# 启动前端
cd frontend
npm run dev
```

### 生产环境部署

#### 1. 前端部署 (Vercel)
```bash
# 构建前端
cd frontend
npm run build

# 部署到Vercel
npx vercel --prod
```

#### 2. 后端部署 (Cloudflare Workers)
```bash
# 配置wrangler
cd workers
npx wrangler login

# 设置环境变量
npx wrangler secret put DATABASE_URL
npx wrangler secret put JWT_SECRET
npx wrangler secret put STRIPE_SECRET_KEY

# 部署
npm run deploy
```

#### 3. 数据库配置
- 在Neon控制台创建生产数据库
- 运行生产环境迁移
- 配置连接池和备份策略

## 性能优化

### 前端优化

#### 1. 代码分割
```typescript
// 路由级别的代码分割
const MapPage = lazy(() => import('../pages/MapPage'));
const ProfilePage = lazy(() => import('../pages/ProfilePage'));
```

#### 2. 图片优化
```typescript
// 图片懒加载
const LazyImage = ({ src, alt }: { src: string; alt: string }) => {
  const [isLoaded, setIsLoaded] = useState(false);
  
  return (
    <img
      src={src}
      alt={alt}
      loading="lazy"
      onLoad={() => setIsLoaded(true)}
      className={`transition-opacity ${isLoaded ? 'opacity-100' : 'opacity-0'}`}
    />
  );
};
```

#### 3. 状态管理优化
```typescript
// RTK Query缓存配置
export const apiSlice = createApi({
  reducerPath: 'api',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api',
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.token;
      if (token) {
        headers.set('authorization', `Bearer ${token}`);
      }
      return headers;
    },
  }),
  tagTypes: ['Annotation', 'User'],
  keepUnusedDataFor: 300, // 5分钟缓存
});
```

### 后端优化

#### 1. 数据库查询优化
```typescript
// 使用索引优化地理位置查询
export const getNearbyAnnotations = async (
  lat: number,
  lng: number,
  radius: number
) => {
  return await db
    .select()
    .from(annotations)
    .where(
      sql`earth_distance(
        ll_to_earth(${lat}, ${lng}),
        ll_to_earth(latitude, longitude)
      ) <= ${radius}`
    )
    .orderBy(sql`created_at DESC`)
    .limit(50);
};
```

#### 2. 缓存策略
```typescript
// Cloudflare KV缓存
export const getCachedData = async (key: string) => {
  try {
    const cached = await KV.get(key);
    if (cached) {
      return JSON.parse(cached);
    }
  } catch (error) {
    console.error('Cache error:', error);
  }
  return null;
};

export const setCachedData = async (
  key: string,
  data: any,
  ttl: number = 300
) => {
  try {
    await KV.put(key, JSON.stringify(data), { expirationTtl: ttl });
  } catch (error) {
    console.error('Cache set error:', error);
  }
};
```

## 安全措施

### 认证和授权

#### JWT Token管理
```typescript
// Token生成
export const generateToken = (userId: string): string => {
  return jwt.sign(
    { userId, iat: Math.floor(Date.now() / 1000) },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// Token验证中间件
export const authMiddleware = async (c: Context, next: Next) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };
    c.set('userId', payload.userId);
    await next();
  } catch (error) {
    return c.json({ error: 'Invalid token' }, 401);
  }
};
```

#### 数据验证
```typescript
// 输入验证
import { z } from 'zod';

const createAnnotationSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  smell_type: z.string().min(1).max(50),
  intensity: z.number().int().min(1).max(10),
  description: z.string().max(1000).optional(),
});

export const validateCreateAnnotation = (data: unknown) => {
  return createAnnotationSchema.parse(data);
};
```

### 数据保护

#### 密码加密
```typescript
import bcrypt from 'bcryptjs';

export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

export const verifyPassword = async (
  password: string,
  hash: string
): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};
```

#### SQL注入防护
```typescript
// 使用参数化查询
export const getUserByEmail = async (email: string) => {
  return await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);
};
```

## 监控和日志

### 错误监控
```typescript
// 全局错误处理
export const errorHandler = (error: Error, c: Context) => {
  console.error('Application error:', {
    message: error.message,
    stack: error.stack,
    url: c.req.url,
    method: c.req.method,
    timestamp: new Date().toISOString(),
  });
  
  return c.json(
    { error: 'Internal server error' },
    500
  );
};
```

### 性能监控
```typescript
// 请求时间监控
export const performanceMiddleware = async (c: Context, next: Next) => {
  const start = Date.now();
  await next();
  const duration = Date.now() - start;
  
  console.log(`${c.req.method} ${c.req.url} - ${duration}ms`);
  
  // 记录慢查询
  if (duration > 1000) {
    console.warn('Slow request detected:', {
      method: c.req.method,
      url: c.req.url,
      duration,
    });
  }
};
```

## 测试策略

### 单元测试
```typescript
// 服务层测试
import { describe, it, expect } from 'vitest';
import { createAnnotation } from '../services/annotations';

describe('Annotation Service', () => {
  it('should create annotation with valid data', async () => {
    const annotationData = {
      latitude: 40.7128,
      longitude: -74.0060,
      smell_type: 'food',
      intensity: 5,
      description: 'Test annotation',
    };
    
    const result = await createAnnotation('user-id', annotationData);
    
    expect(result).toBeDefined();
    expect(result.latitude).toBe(40.7128);
    expect(result.smell_type).toBe('food');
  });
});
```

### 集成测试
```typescript
// API端点测试
import { describe, it, expect } from 'vitest';
import { testClient } from 'hono/testing';
import app from '../src/index';

describe('Annotations API', () => {
  it('should create annotation', async () => {
    const res = await testClient(app).api.annotations.$post({
      json: {
        latitude: 40.7128,
        longitude: -74.0060,
        smell_type: 'food',
        intensity: 5,
      },
      header: {
        Authorization: 'Bearer test-token',
      },
    });
    
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.success).toBe(true);
  });
});
```

## 维护手册

### 日常维护任务

#### 1. 数据库维护
```sql
-- 清理过期数据
DELETE FROM sessions WHERE expires_at < NOW();

-- 更新统计信息
ANALYZE;

-- 检查索引使用情况
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC;
```

#### 2. 日志分析
```bash
# 查看错误日志
npx wrangler tail --format pretty

# 分析访问模式
grep "POST /api/annotations" logs.txt | wc -l
```

#### 3. 性能监控
```typescript
// 监控关键指标
const metrics = {
  activeUsers: await getActiveUserCount(),
  annotationsToday: await getTodayAnnotationCount(),
  averageResponseTime: await getAverageResponseTime(),
  errorRate: await getErrorRate(),
};

console.log('Daily metrics:', metrics);
```

### 故障排除

#### 常见问题诊断

**数据库连接问题**
```typescript
// 检查数据库连接
export const healthCheck = async () => {
  try {
    await db.select().from(users).limit(1);
    return { database: 'healthy' };
  } catch (error) {
    return { database: 'unhealthy', error: error.message };
  }
};
```

**API响应慢**
```typescript
// 查询性能分析
EXPLAIN ANALYZE SELECT * FROM annotations 
WHERE earth_distance(
  ll_to_earth(40.7128, -74.0060),
  ll_to_earth(latitude, longitude)
) <= 1000;
```

### 备份和恢复

#### 数据库备份
```bash
# 创建备份
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql

# 恢复备份
psql $DATABASE_URL < backup_20240101_120000.sql
```

#### 配置备份
```bash
# 备份环境变量
cp .env .env.backup

# 备份Cloudflare配置
cp wrangler.toml wrangler.toml.backup
```

---

*文档版本: v1.0*  
*最后更新: 2024年1月*