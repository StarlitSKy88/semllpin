# SmellPin 迁移方案：Cloudflare Workers + Supabase + Vercel

## 1. 当前架构分析

### 1.1 现有技术栈
- **前端**: React 19 + TypeScript + Vite + Tailwind CSS (已部署在 Vercel)
- **后端**: Express.js + TypeScript + Node.js
- **数据库**: SQLite (开发) / PostgreSQL (生产)
- **实时通信**: Socket.IO WebSocket
- **文件存储**: 本地文件系统 (uploads 目录)
- **支付**: Stripe 集成
- **缓存**: Redis
- **部署**: Docker + 传统服务器

### 1.2 现有功能模块
- 用户认证系统 (JWT)
- 地理位置标注 (臭味标记)
- 支付系统 (Stripe)
- 实时通知 (WebSocket)
- 文件上传 (图片/视频)
- 社交功能 (评论、点赞、关注)
- 管理后台
- LBS 奖励系统

## 2. 目标架构设计

### 2.1 新技术栈
- **前端**: React 19 + TypeScript + Vite + Tailwind CSS (保持 Vercel 部署)
- **后端**: Cloudflare Workers + TypeScript
- **数据库**: Supabase (PostgreSQL + 实时功能)
- **认证**: Supabase Auth
- **文件存储**: Supabase Storage
- **实时通信**: Supabase Realtime
- **支付**: Stripe (通过 Workers 集成)
- **缓存**: Cloudflare KV Storage
- **部署**: Cloudflare Workers + Vercel

### 2.2 架构优势
- **全球分布**: Cloudflare 边缘网络，低延迟
- **无服务器**: 自动扩缩容，按需付费
- **实时功能**: Supabase 原生实时数据库
- **简化运维**: 无需管理服务器和数据库
- **成本优化**: 免费额度 + 按使用量付费

## 3. Supabase 数据库重新设计

### 3.1 数据库表结构

#### 3.1.1 用户表 (users)
```sql
-- 用户基础信息表
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL,
  display_name VARCHAR(100),
  bio TEXT,
  avatar_url TEXT,
  university VARCHAR(100), -- 大学信息
  role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin')),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  email_verified BOOLEAN DEFAULT false,
  last_login_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_university ON users(university);
CREATE INDEX idx_users_status ON users(status);
```

#### 3.1.2 臭味标注表 (annotations)
```sql
-- 臭味标注表
CREATE TABLE annotations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  smell_intensity INTEGER NOT NULL CHECK (smell_intensity BETWEEN 1 AND 10),
  description TEXT,
  country VARCHAR(2), -- ISO 国家代码
  region VARCHAR(100),
  city VARCHAR(100),
  address TEXT,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
  payment_amount DECIMAL(10, 2) NOT NULL, -- 支付金额
  payment_id VARCHAR(255), -- Stripe payment ID
  media_files JSONB DEFAULT '[]', -- 媒体文件数组
  view_count INTEGER DEFAULT 0,
  like_count INTEGER DEFAULT 0,
  comment_count INTEGER DEFAULT 0,
  current_reward_pool DECIMAL(10, 2) DEFAULT 0, -- 当前奖励池
  total_cleanup_time INTEGER DEFAULT 0, -- 总清理时间(分钟)
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 地理索引
CREATE INDEX idx_annotations_location ON annotations USING GIST (ST_Point(longitude, latitude));
CREATE INDEX idx_annotations_user_id ON annotations(user_id);
CREATE INDEX idx_annotations_smell_intensity ON annotations(smell_intensity);
CREATE INDEX idx_annotations_city ON annotations(city);
CREATE INDEX idx_annotations_status ON annotations(status);
```

#### 3.1.3 用户钱包表 (wallets)
```sql
-- 用户钱包表
CREATE TABLE wallets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  balance DECIMAL(10, 2) DEFAULT 0.00,
  total_earned DECIMAL(10, 2) DEFAULT 0.00,
  total_spent DECIMAL(10, 2) DEFAULT 0.00,
  stripe_customer_id VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_wallets_user_id ON wallets(user_id);
```

#### 3.1.4 交易记录表 (transactions)
```sql
-- 交易记录表
CREATE TABLE transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  annotation_id UUID REFERENCES annotations(id) ON DELETE SET NULL,
  type VARCHAR(20) NOT NULL CHECK (type IN ('payment', 'reward', 'withdrawal', 'refund')),
  amount DECIMAL(10, 2) NOT NULL,
  description TEXT,
  stripe_payment_id VARCHAR(255),
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_type ON transactions(type);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at DESC);
```

#### 3.1.5 LBS 奖励记录表 (lbs_rewards)
```sql
-- LBS 奖励记录表
CREATE TABLE lbs_rewards (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
  start_time TIMESTAMP WITH TIME ZONE NOT NULL,
  end_time TIMESTAMP WITH TIME ZONE,
  duration_minutes INTEGER DEFAULT 0,
  reward_amount DECIMAL(10, 2) DEFAULT 0.00,
  participants_count INTEGER DEFAULT 1,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'completed', 'cancelled')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_lbs_rewards_user_id ON lbs_rewards(user_id);
CREATE INDEX idx_lbs_rewards_annotation_id ON lbs_rewards(annotation_id);
CREATE INDEX idx_lbs_rewards_status ON lbs_rewards(status);
```

#### 3.1.6 评论表 (comments)
```sql
-- 评论表
CREATE TABLE comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES comments(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
  like_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_comments_annotation_id ON comments(annotation_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);
CREATE INDEX idx_comments_parent_id ON comments(parent_id);
```

#### 3.1.7 用户关注表 (user_follows)
```sql
-- 用户关注表
CREATE TABLE user_follows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(follower_id, following_id)
);

CREATE INDEX idx_user_follows_follower ON user_follows(follower_id);
CREATE INDEX idx_user_follows_following ON user_follows(following_id);
```

### 3.2 Row Level Security (RLS) 策略

```sql
-- 启用 RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE annotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_follows ENABLE ROW LEVEL SECURITY;

-- 用户表策略
CREATE POLICY "Users can view all profiles" ON users FOR SELECT USING (true);
CREATE POLICY "Users can update own profile" ON users FOR UPDATE USING (auth.uid() = id);

-- 标注表策略
CREATE POLICY "Anyone can view active annotations" ON annotations FOR SELECT USING (status = 'active');
CREATE POLICY "Users can create annotations" ON annotations FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own annotations" ON annotations FOR UPDATE USING (auth.uid() = user_id);

-- 钱包表策略
CREATE POLICY "Users can view own wallet" ON wallets FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can update own wallet" ON wallets FOR UPDATE USING (auth.uid() = user_id);

-- 交易记录策略
CREATE POLICY "Users can view own transactions" ON transactions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can create transactions" ON transactions FOR INSERT WITH CHECK (auth.uid() = user_id);

-- 评论表策略
CREATE POLICY "Anyone can view active comments" ON comments FOR SELECT USING (status = 'active');
CREATE POLICY "Users can create comments" ON comments FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own comments" ON comments FOR UPDATE USING (auth.uid() = user_id);
```

## 4. Cloudflare Workers API 重构计划

### 4.1 Workers 项目结构
```
workers/
├── src/
│   ├── handlers/
│   │   ├── auth.ts          # 认证相关
│   │   ├── annotations.ts   # 标注管理
│   │   ├── payments.ts      # 支付处理
│   │   ├── lbs.ts          # LBS 奖励
│   │   ├── social.ts       # 社交功能
│   │   └── admin.ts        # 管理功能
│   ├── middleware/
│   │   ├── auth.ts         # 认证中间件
│   │   ├── cors.ts         # CORS 处理
│   │   └── validation.ts   # 数据验证
│   ├── services/
│   │   ├── supabase.ts     # Supabase 客户端
│   │   ├── stripe.ts       # Stripe 集成
│   │   └── cache.ts        # KV 缓存
│   ├── types/
│   │   └── index.ts        # 类型定义
│   ├── utils/
│   │   ├── response.ts     # 响应工具
│   │   └── validation.ts   # 验证工具
│   └── index.ts            # 主入口
├── wrangler.toml           # Workers 配置
└── package.json
```

### 4.2 核心 API 端点重构

#### 4.2.1 认证 API
```typescript
// src/handlers/auth.ts
import { createClient } from '@supabase/supabase-js';

export async function handleAuth(request: Request, env: Env): Promise<Response> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY);
  
  const url = new URL(request.url);
  const path = url.pathname;
  
  switch (path) {
    case '/api/auth/register':
      return handleRegister(request, supabase);
    case '/api/auth/login':
      return handleLogin(request, supabase);
    case '/api/auth/logout':
      return handleLogout(request, supabase);
    default:
      return new Response('Not Found', { status: 404 });
  }
}

async function handleRegister(request: Request, supabase: any) {
  const { email, password, username, university } = await request.json();
  
  // 使用 Supabase Auth 注册
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        username,
        university
      }
    }
  });
  
  if (error) {
    return Response.json({ error: error.message }, { status: 400 });
  }
  
  return Response.json({ user: data.user });
}
```

#### 4.2.2 标注 API
```typescript
// src/handlers/annotations.ts
export async function handleAnnotations(request: Request, env: Env): Promise<Response> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_KEY);
  
  switch (request.method) {
    case 'GET':
      return getAnnotations(request, supabase);
    case 'POST':
      return createAnnotation(request, supabase, env);
    case 'PUT':
      return updateAnnotation(request, supabase);
    case 'DELETE':
      return deleteAnnotation(request, supabase);
    default:
      return new Response('Method Not Allowed', { status: 405 });
  }
}

async function createAnnotation(request: Request, supabase: any, env: Env) {
  const { latitude, longitude, smell_intensity, description, payment_amount } = await request.json();
  const user = await getAuthUser(request, supabase);
  
  // 处理 Stripe 支付
  const stripe = new Stripe(env.STRIPE_SECRET_KEY);
  const paymentIntent = await stripe.paymentIntents.create({
    amount: Math.round(payment_amount * 100), // 转换为分
    currency: 'usd',
    metadata: {
      user_id: user.id,
      type: 'annotation'
    }
  });
  
  // 创建标注记录
  const { data, error } = await supabase
    .from('annotations')
    .insert({
      user_id: user.id,
      latitude,
      longitude,
      smell_intensity,
      description,
      payment_amount,
      payment_id: paymentIntent.id
    })
    .select()
    .single();
    
  if (error) {
    return Response.json({ error: error.message }, { status: 400 });
  }
  
  return Response.json({ annotation: data, client_secret: paymentIntent.client_secret });
}
```

### 4.3 环境变量配置
```toml
# wrangler.toml
name = "smellpin-api"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[env.production.vars]
SUPABASE_URL = "https://your-project.supabase.co"
SUPABASE_ANON_KEY = "your-anon-key"
SUPABASE_SERVICE_KEY = "your-service-key"
STRIPE_SECRET_KEY = "sk_live_..."
STRIPE_WEBHOOK_SECRET = "whsec_..."

[[env.production.kv_namespaces]]
binding = "CACHE"
id = "your-kv-namespace-id"
```

## 5. 存储方案

### 5.1 Supabase Storage 配置
```sql
-- 创建存储桶
INSERT INTO storage.buckets (id, name, public) VALUES 
('avatars', 'avatars', true),
('annotations', 'annotations', true),
('media', 'media', true);

-- 设置存储策略
CREATE POLICY "Avatar images are publicly accessible" ON storage.objects
FOR SELECT USING (bucket_id = 'avatars');

CREATE POLICY "Users can upload their own avatar" ON storage.objects
FOR INSERT WITH CHECK (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Annotation media is publicly accessible" ON storage.objects
FOR SELECT USING (bucket_id = 'annotations');

CREATE POLICY "Users can upload annotation media" ON storage.objects
FOR INSERT WITH CHECK (bucket_id = 'annotations' AND auth.uid()::text = (storage.foldername(name))[1]);
```

### 5.2 文件上传 API
```typescript
// src/handlers/upload.ts
export async function handleFileUpload(request: Request, env: Env): Promise<Response> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_KEY);
  const user = await getAuthUser(request, supabase);
  
  const formData = await request.formData();
  const file = formData.get('file') as File;
  const bucket = formData.get('bucket') as string;
  
  if (!file) {
    return Response.json({ error: 'No file provided' }, { status: 400 });
  }
  
  // 生成文件路径
  const fileExt = file.name.split('.').pop();
  const fileName = `${user.id}/${Date.now()}.${fileExt}`;
  
  // 上传到 Supabase Storage
  const { data, error } = await supabase.storage
    .from(bucket)
    .upload(fileName, file, {
      cacheControl: '3600',
      upsert: false
    });
    
  if (error) {
    return Response.json({ error: error.message }, { status: 400 });
  }
  
  // 获取公共 URL
  const { data: { publicUrl } } = supabase.storage
    .from(bucket)
    .getPublicUrl(fileName);
    
  return Response.json({ url: publicUrl, path: fileName });
}
```

## 6. WebSocket 替代方案

### 6.1 Supabase Realtime 配置
```typescript
// frontend/src/services/realtimeService.ts
import { createClient } from '@supabase/supabase-js';

class RealtimeService {
  private supabase;
  private subscriptions: Map<string, any> = new Map();
  
  constructor() {
    this.supabase = createClient(
      import.meta.env.VITE_SUPABASE_URL,
      import.meta.env.VITE_SUPABASE_ANON_KEY
    );
  }
  
  // 订阅新标注
  subscribeToAnnotations(callback: (payload: any) => void) {
    const subscription = this.supabase
      .channel('annotations')
      .on('postgres_changes', {
        event: 'INSERT',
        schema: 'public',
        table: 'annotations'
      }, callback)
      .subscribe();
      
    this.subscriptions.set('annotations', subscription);
  }
  
  // 订阅用户通知
  subscribeToNotifications(userId: string, callback: (payload: any) => void) {
    const subscription = this.supabase
      .channel(`notifications:${userId}`)
      .on('postgres_changes', {
        event: 'INSERT',
        schema: 'public',
        table: 'notifications',
        filter: `user_id=eq.${userId}`
      }, callback)
      .subscribe();
      
    this.subscriptions.set('notifications', subscription);
  }
  
  // 取消订阅
  unsubscribe(channel: string) {
    const subscription = this.subscriptions.get(channel);
    if (subscription) {
      subscription.unsubscribe();
      this.subscriptions.delete(channel);
    }
  }
}

export default new RealtimeService();
```

### 6.2 实时位置追踪
```typescript
// 使用 Supabase Realtime 替代 WebSocket 进行位置追踪
class LocationTracker {
  private supabase;
  private currentSession: string | null = null;
  
  async startTracking(annotationId: string, userId: string) {
    // 创建 LBS 会话
    const { data, error } = await this.supabase
      .from('lbs_rewards')
      .insert({
        user_id: userId,
        annotation_id: annotationId,
        start_time: new Date().toISOString(),
        status: 'active'
      })
      .select()
      .single();
      
    if (!error) {
      this.currentSession = data.id;
      this.startLocationUpdates();
    }
  }
  
  private startLocationUpdates() {
    // 每分钟更新一次位置和奖励
    setInterval(async () => {
      if (this.currentSession) {
        await this.updateReward();
      }
    }, 60000); // 1分钟
  }
  
  private async updateReward() {
    // 更新奖励记录
    await this.supabase
      .from('lbs_rewards')
      .update({
        duration_minutes: this.supabase.raw('duration_minutes + 1'),
        reward_amount: this.supabase.raw('reward_amount + 1.00')
      })
      .eq('id', this.currentSession);
  }
}
```

## 7. 详细迁移步骤

### 7.1 阶段一：Supabase 环境准备 (1-2天)

1. **创建 Supabase 项目**
   ```bash
   # 安装 Supabase CLI
   npm install -g supabase
   
   # 初始化项目
   supabase init
   
   # 链接到远程项目
   supabase link --project-ref your-project-ref
   ```

2. **执行数据库迁移**
   ```bash
   # 创建迁移文件
   supabase migration new create_smellpin_schema
   
   # 应用迁移
   supabase db push
   ```

3. **配置 RLS 和存储策略**
   - 执行上述 SQL 脚本
   - 配置存储桶和策略
   - 测试权限设置

4. **数据迁移**
   ```typescript
   // 创建数据迁移脚本
   async function migrateData() {
     // 从现有数据库导出数据
     const users = await oldDb.select('*').from('users');
     const annotations = await oldDb.select('*').from('annotations');
     
     // 导入到 Supabase
     await supabase.from('users').insert(users);
     await supabase.from('annotations').insert(annotations);
   }
   ```

### 7.2 阶段二：Cloudflare Workers 开发 (3-5天)

1. **初始化 Workers 项目**
   ```bash
   npm create cloudflare@latest smellpin-api
   cd smellpin-api
   npm install @supabase/supabase-js stripe
   ```

2. **开发核心 API**
   - 认证模块 (1天)
   - 标注管理 (1天)
   - 支付集成 (1天)
   - LBS 奖励 (1天)
   - 社交功能 (1天)

3. **本地测试**
   ```bash
   # 启动本地开发服务器
   npm run dev
   
   # 运行测试
   npm test
   ```

### 7.3 阶段三：前端适配 (2-3天)

1. **更新 API 服务**
   ```typescript
   // frontend/src/services/api.ts
   export const api = axios.create({
     baseURL: 'https://smellpin-api.your-subdomain.workers.dev',
     timeout: 10000,
   });
   ```

2. **集成 Supabase 客户端**
   ```bash
   cd frontend
   npm install @supabase/supabase-js
   ```
   
   ```typescript
   // frontend/src/lib/supabase.ts
   import { createClient } from '@supabase/supabase-js';
   
   export const supabase = createClient(
     import.meta.env.VITE_SUPABASE_URL,
     import.meta.env.VITE_SUPABASE_ANON_KEY
   );
   ```

3. **替换 WebSocket 为 Realtime**
   - 移除 socket.io-client
   - 实现 Supabase Realtime 订阅
   - 更新通知系统

4. **更新文件上传**
   ```typescript
   // 使用 Supabase Storage
   async function uploadFile(file: File, bucket: string) {
     const fileExt = file.name.split('.').pop();
     const fileName = `${user.id}/${Date.now()}.${fileExt}`;
     
     const { data, error } = await supabase.storage
       .from(bucket)
       .upload(fileName, file);
       
     if (error) throw error;
     
     const { data: { publicUrl } } = supabase.storage
       .from(bucket)
       .getPublicUrl(fileName);
       
     return publicUrl;
   }
   ```

### 7.4 阶段四：部署和测试 (1-2天)

1. **部署 Cloudflare Workers**
   ```bash
   # 设置环境变量
   wrangler secret put SUPABASE_URL
   wrangler secret put SUPABASE_SERVICE_KEY
   wrangler secret put STRIPE_SECRET_KEY
   
   # 部署到生产环境
   npm run deploy
   ```

2. **更新前端环境变量**
   ```bash
   # Vercel 环境变量
   vercel env add VITE_SUPABASE_URL
   vercel env add VITE_SUPABASE_ANON_KEY
   vercel env add VITE_API_URL
   ```

3. **重新部署前端**
   ```bash
   # 自动部署到 Vercel
   git push origin main
   ```

4. **端到端测试**
   - 用户注册/登录
   - 创建标注和支付
   - LBS 奖励功能
   - 实时通知
   - 文件上传

### 7.5 阶段五：性能优化和监控 (1天)

1. **配置 Cloudflare Analytics**
2. **设置 Supabase 监控**
3. **性能测试和优化**
4. **错误监控和日志**

## 8. 部署配置

### 8.1 Cloudflare Workers 配置
```toml
# wrangler.toml
name = "smellpin-api"
main = "src/index.ts"
compatibility_date = "2024-01-01"
node_compat = true

[env.production]
name = "smellpin-api-prod"
vars = { ENVIRONMENT = "production" }

[env.staging]
name = "smellpin-api-staging"
vars = { ENVIRONMENT = "staging" }

[[kv_namespaces]]
binding = "CACHE"
id = "your-kv-namespace-id"
preview_id = "your-preview-kv-namespace-id"

[triggers]
crons = ["0 0 * * *"] # 每日清理任务
```

### 8.2 Vercel 前端配置
```json
{
  "builds": [
    {
      "src": "frontend/package.json",
      "use": "@vercel/static-build",
      "config": {
        "distDir": "dist"
      }
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "https://smellpin-api.your-subdomain.workers.dev/api/$1"
    },
    {
      "src": "/(.*)",
      "dest": "/frontend/$1"
    }
  ]
}
```

### 8.3 环境变量清单

#### Cloudflare Workers
- `SUPABASE_URL`: Supabase 项目 URL
- `SUPABASE_ANON_KEY`: Supabase 匿名密钥
- `SUPABASE_SERVICE_KEY`: Supabase 服务密钥
- `STRIPE_SECRET_KEY`: Stripe 密钥
- `STRIPE_WEBHOOK_SECRET`: Stripe Webhook 密钥
- `JWT_SECRET`: JWT 签名密钥

#### Vercel 前端
- `VITE_SUPABASE_URL`: Supabase 项目 URL
- `VITE_SUPABASE_ANON_KEY`: Supabase 匿名密钥
- `VITE_API_URL`: Workers API 地址
- `VITE_STRIPE_PUBLISHABLE_KEY`: Stripe 公钥

## 9. 成本分析

### 9.1 免费额度
- **Cloudflare Workers**: 100,000 请求/天
- **Supabase**: 500MB 数据库 + 1GB 存储 + 2GB 带宽
- **Vercel**: 100GB 带宽 + 无限部署

### 9.2 付费阶梯
- **Cloudflare Workers**: $5/月 (1000万请求)
- **Supabase Pro**: $25/月 (8GB 数据库 + 100GB 存储)
- **Vercel Pro**: $20/月 (1TB 带宽)

### 9.3 预估成本 (月活 10K 用户)
- Cloudflare Workers: $5-10/月
- Supabase: $25/月
- Vercel: 免费额度内
- **总计**: $30-35/月

## 10. 风险评估和应对

### 10.1 技术风险
- **Cloudflare Workers 限制**: CPU 时间限制 (10ms)
  - 应对: 优化算法，使用异步处理
- **Supabase 连接限制**: 并发连接数限制
  - 应对: 连接池管理，缓存策略

### 10.2 数据迁移风险
- **数据丢失**: 迁移过程中的数据完整性
  - 应对: 完整备份，分批迁移，验证脚本
- **停机时间**: 服务中断影响用户体验
  - 应对: 蓝绿部署，DNS 切换

### 10.3 性能风险
- **冷启动延迟**: Workers 冷启动可能影响响应时间
  - 应对: 预热策略，缓存优化
- **地理分布**: 某些地区访问延迟
  - 应对: CDN 配置，边缘缓存

## 11. 迁移时间表

| 阶段 | 任务 | 预计时间 | 负责人 |
|------|------|----------|--------|
| 1 | Supabase 环境准备 | 2天 | 后端开发 |
| 2 | Workers API 开发 | 5天 | 后端开发 |
| 3 | 前端适配 | 3天 | 前端开发 |
| 4 | 部署测试 | 2天 | 全栈开发 |
| 5 | 优化监控 | 1天 | DevOps |
| **总计** | **完整迁移** | **13天** | **团队协作** |

## 12. 成功指标

### 12.1 性能指标
- API 响应时间 < 200ms (P95)
- 页面加载时间 < 2s
- 系统可用性 > 99.9%

### 12.2 功能指标
- 所有现有功能正常工作
- 实时功能延迟 < 1s
- 文件上传成功率 > 99%

### 12.3 成本指标
- 月运营成本 < $50
- 相比现有架构成本降低 > 60%

---

**迁移完成后，SmellPin 将拥有一个现代化、可扩展、成本效益高的全栈架构，为未来的快速发展奠定坚实基础。**