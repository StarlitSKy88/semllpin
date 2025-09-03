-- SmellPin 数据库表创建脚本 (API兼容版本)
-- 请在 Supabase 控制台的 SQL 编辑器中执行此脚本
-- 此版本的表结构与API代码完全匹配

-- ========================================
-- 第一步：删除所有现有表（如果存在）
-- ========================================

-- 删除表时需要按照依赖关系的逆序进行
DROP TABLE IF EXISTS user_follows CASCADE;
DROP TABLE IF EXISTS comments CASCADE;
DROP TABLE IF EXISTS lbs_rewards CASCADE;
DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS annotations CASCADE;
DROP TABLE IF EXISTS wallets CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ========================================
-- 第二步：按正确顺序创建所有表
-- ========================================

-- 1. 创建用户表（基础表，无外键依赖）
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL,
  full_name VARCHAR(100),
  bio TEXT,
  avatar_url TEXT,
  university VARCHAR(100),
  role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin')),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  email_verified BOOLEAN DEFAULT false,
  is_verified BOOLEAN DEFAULT false,
  last_login_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. 创建钱包表（依赖users表）
CREATE TABLE wallets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  balance DECIMAL(10, 2) DEFAULT 0.00,
  total_earned DECIMAL(10, 2) DEFAULT 0.00,
  total_spent DECIMAL(10, 2) DEFAULT 0.00,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. 创建标注表（依赖users表）
CREATE TABLE annotations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  location JSONB NOT NULL, -- {latitude: number, longitude: number, address?: string, place_name?: string}
  media_urls JSONB DEFAULT '[]', -- Array of media URLs
  tags JSONB DEFAULT '[]', -- Array of tags
  visibility VARCHAR(20) DEFAULT 'public' CHECK (visibility IN ('public', 'friends', 'private')),
  smell_intensity INTEGER CHECK (smell_intensity BETWEEN 1 AND 10),
  smell_category VARCHAR(100),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
  likes_count INTEGER DEFAULT 0,
  comments_count INTEGER DEFAULT 0,
  view_count INTEGER DEFAULT 0,
  payment_amount DECIMAL(10, 2) DEFAULT 0.00,
  payment_id VARCHAR(255),
  current_reward_pool DECIMAL(10, 2) DEFAULT 0,
  total_cleanup_time INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. 创建交易表（依赖users、wallets、annotations表）
CREATE TABLE transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  annotation_id UUID REFERENCES annotations(id) ON DELETE SET NULL,
  type VARCHAR(20) NOT NULL CHECK (type IN ('deposit', 'withdrawal', 'reward', 'payment', 'refund')),
  amount DECIMAL(10, 2) NOT NULL,
  description TEXT,
  status VARCHAR(20) DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  payment_method VARCHAR(50),
  external_transaction_id VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. 创建LBS奖励表（依赖users、annotations表）
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

-- 6. 创建评论表（依赖annotations、users表）
CREATE TABLE comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES comments(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
  likes_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 7. 创建用户关注表（依赖users表）
CREATE TABLE user_follows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(follower_id, following_id),
  CHECK (follower_id != following_id)
);

-- ========================================
-- 第三步：创建所有索引
-- ========================================

-- 为location JSONB字段创建GIN索引以支持地理位置查询
CREATE INDEX idx_annotations_location_gin ON annotations USING GIN (location);
-- 为快速地理位置查询创建表达式索引
CREATE INDEX idx_annotations_latitude ON annotations ((location->>'latitude'));
CREATE INDEX idx_annotations_longitude ON annotations ((location->>'longitude'));
CREATE INDEX idx_annotations_user_id ON annotations(user_id);
CREATE INDEX idx_annotations_created_at ON annotations(created_at);
CREATE INDEX idx_annotations_visibility ON annotations(visibility);
CREATE INDEX idx_annotations_status ON annotations(status);
CREATE INDEX idx_annotations_tags ON annotations USING GIN (tags);
CREATE INDEX idx_annotations_smell_category ON annotations(smell_category);

CREATE INDEX idx_lbs_rewards_user_id ON lbs_rewards(user_id);
CREATE INDEX idx_lbs_rewards_annotation_id ON lbs_rewards(annotation_id);
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_wallet_id ON transactions(wallet_id);
CREATE INDEX idx_comments_annotation_id ON comments(annotation_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);
CREATE INDEX idx_user_follows_follower_id ON user_follows(follower_id);
CREATE INDEX idx_user_follows_following_id ON user_follows(following_id);
CREATE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);

-- ========================================
-- 第四步：启用行级安全 (RLS)
-- ========================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE annotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE lbs_rewards ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_follows ENABLE ROW LEVEL SECURITY;

-- ========================================
-- 第五步：设置基本权限
-- ========================================

GRANT SELECT ON users TO anon;
GRANT ALL PRIVILEGES ON users TO authenticated;
GRANT SELECT ON annotations TO anon;
GRANT ALL PRIVILEGES ON annotations TO authenticated;
GRANT ALL PRIVILEGES ON lbs_rewards TO authenticated;
GRANT ALL PRIVILEGES ON wallets TO authenticated;
GRANT ALL PRIVILEGES ON transactions TO authenticated;
GRANT ALL PRIVILEGES ON comments TO authenticated;
GRANT ALL PRIVILEGES ON user_follows TO authenticated;

-- ========================================
-- 第六步：创建RLS策略
-- ========================================

-- 用户表策略
CREATE POLICY "Users can view all profiles" ON users FOR SELECT USING (true);
CREATE POLICY "Users can update own profile" ON users FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Users can insert own profile" ON users FOR INSERT WITH CHECK (auth.uid() = id);

-- 标注表策略
CREATE POLICY "Anyone can view public annotations" ON annotations FOR SELECT USING (
  visibility = 'public' OR 
  (auth.uid() IS NOT NULL AND user_id = auth.uid())
);
CREATE POLICY "Users can create annotations" ON annotations FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own annotations" ON annotations FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own annotations" ON annotations FOR DELETE USING (auth.uid() = user_id);

-- 钱包表策略
CREATE POLICY "Users can view own wallet" ON wallets FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can update own wallet" ON wallets FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can create own wallet" ON wallets FOR INSERT WITH CHECK (auth.uid() = user_id);

-- 交易表策略
CREATE POLICY "Users can view own transactions" ON transactions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can create own transactions" ON transactions FOR INSERT WITH CHECK (auth.uid() = user_id);

-- LBS奖励表策略
CREATE POLICY "Users can view all lbs_rewards" ON lbs_rewards FOR SELECT USING (true);
CREATE POLICY "Users can create lbs_rewards" ON lbs_rewards FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own lbs_rewards" ON lbs_rewards FOR UPDATE USING (auth.uid() = user_id);

-- 评论表策略
CREATE POLICY "Anyone can view active comments" ON comments FOR SELECT USING (status = 'active');
CREATE POLICY "Users can create comments" ON comments FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own comments" ON comments FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own comments" ON comments FOR DELETE USING (auth.uid() = user_id);

-- 关注表策略
CREATE POLICY "Anyone can view follows" ON user_follows FOR SELECT USING (true);
CREATE POLICY "Users can manage own follows" ON user_follows FOR ALL USING (auth.uid() = follower_id);

-- ========================================
-- 完成提示
-- ========================================

SELECT 'SmellPin数据库表创建完成！表结构已与API代码完全匹配，包括索引、RLS策略和权限设置。' as message;