-- SmellPin 数据库迁移脚本
-- 删除现有的小说写作相关表，创建社交应用表结构

-- 1. 删除现有表（如果存在）
DROP TABLE IF EXISTS writing_templates CASCADE;
DROP TABLE IF EXISTS ai_writing_history CASCADE;
DROP TABLE IF EXISTS horror_elements CASCADE;
DROP TABLE IF EXISTS battle_scenes CASCADE;
DROP TABLE IF EXISTS characters CASCADE;
DROP TABLE IF EXISTS chapters CASCADE;
DROP TABLE IF EXISTS outlines CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;

-- 2. 创建用户表 (users)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    bio TEXT,
    avatar_url TEXT,
    university VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin')),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    email_verified BOOLEAN DEFAULT false,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 创建用户表索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_university ON users(university);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at DESC);

-- 3. 创建标注表 (annotations)
CREATE TABLE annotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    smell_intensity INTEGER NOT NULL CHECK (smell_intensity BETWEEN 1 AND 10),
    description TEXT,
    country VARCHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    address TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
    payment_amount DECIMAL(10, 2) NOT NULL,
    payment_id VARCHAR(255),
    media_files JSONB DEFAULT '[]',
    view_count INTEGER DEFAULT 0,
    like_count INTEGER DEFAULT 0,
    comment_count INTEGER DEFAULT 0,
    current_reward_pool DECIMAL(10, 2) DEFAULT 0,
    total_cleanup_time INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 创建标注表索引
CREATE INDEX idx_annotations_user_id ON annotations(user_id);
CREATE INDEX idx_annotations_smell_intensity ON annotations(smell_intensity);
CREATE INDEX idx_annotations_city ON annotations(city);
CREATE INDEX idx_annotations_status ON annotations(status);
CREATE INDEX idx_annotations_created_at ON annotations(created_at DESC);

-- 4. 创建钱包表 (wallets)
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

-- 创建钱包表索引
CREATE UNIQUE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE INDEX idx_wallets_stripe_customer ON wallets(stripe_customer_id);

-- 5. 创建交易记录表 (transactions)
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

-- 创建交易记录表索引
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_annotation_id ON transactions(annotation_id);
CREATE INDEX idx_transactions_type ON transactions(type);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_stripe_payment ON transactions(stripe_payment_id);
CREATE INDEX idx_transactions_created_at ON transactions(created_at DESC);

-- 6. 创建 LBS 奖励表 (lbs_rewards)
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

-- 创建 LBS 奖励表索引
CREATE INDEX idx_lbs_rewards_user_id ON lbs_rewards(user_id);
CREATE INDEX idx_lbs_rewards_annotation_id ON lbs_rewards(annotation_id);
CREATE INDEX idx_lbs_rewards_status ON lbs_rewards(status);
CREATE INDEX idx_lbs_rewards_start_time ON lbs_rewards(start_time DESC);

-- 7. 创建评论表 (comments)
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

-- 创建评论表索引
CREATE INDEX idx_comments_annotation_id ON comments(annotation_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);
CREATE INDEX idx_comments_parent_id ON comments(parent_id);
CREATE INDEX idx_comments_status ON comments(status);
CREATE INDEX idx_comments_created_at ON comments(created_at DESC);

-- 8. 创建用户关注表 (user_follows)
CREATE TABLE user_follows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(follower_id, following_id),
    CHECK (follower_id != following_id)
);

-- 创建用户关注表索引
CREATE INDEX idx_user_follows_follower ON user_follows(follower_id);
CREATE INDEX idx_user_follows_following ON user_follows(following_id);
CREATE INDEX idx_user_follows_created_at ON user_follows(created_at DESC);

-- 9. 启用 RLS (Row Level Security)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE annotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lbs_rewards ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_follows ENABLE ROW LEVEL SECURITY;

-- 10. 创建 RLS 策略

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
CREATE POLICY "System can create wallets" ON wallets FOR INSERT WITH CHECK (true);

-- 交易记录表策略
CREATE POLICY "Users can view own transactions" ON transactions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "System can create transactions" ON transactions FOR INSERT WITH CHECK (true);

-- LBS 奖励表策略
CREATE POLICY "Users can view own rewards" ON lbs_rewards FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "System can manage rewards" ON lbs_rewards FOR ALL WITH CHECK (true);

-- 评论表策略
CREATE POLICY "Anyone can view active comments" ON comments FOR SELECT USING (status = 'active');
CREATE POLICY "Users can create comments" ON comments FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own comments" ON comments FOR UPDATE USING (auth.uid() = user_id);

-- 用户关注表策略
CREATE POLICY "Users can view all follows" ON user_follows FOR SELECT USING (true);
CREATE POLICY "Users can manage own follows" ON user_follows FOR ALL USING (auth.uid() = follower_id);

-- 11. 设置权限

-- 用户表权限
GRANT SELECT ON users TO anon;
GRANT ALL PRIVILEGES ON users TO authenticated;

-- 标注表权限
GRANT SELECT ON annotations TO anon;
GRANT ALL PRIVILEGES ON annotations TO authenticated;

-- 钱包表权限
GRANT ALL PRIVILEGES ON wallets TO authenticated;

-- 交易记录表权限
GRANT ALL PRIVILEGES ON transactions TO authenticated;

-- LBS 奖励表权限
GRANT ALL PRIVILEGES ON lbs_rewards TO authenticated;

-- 评论表权限
GRANT SELECT ON comments TO anon;
GRANT ALL PRIVILEGES ON comments TO authenticated;

-- 用户关注表权限
GRANT SELECT ON user_follows TO anon;
GRANT ALL PRIVILEGES ON user_follows TO authenticated;

-- 12. 创建存储桶（如果不存在）
INSERT INTO storage.buckets (id, name, public) VALUES 
('avatars', 'avatars', true),
('annotations', 'annotations', true),
('media', 'media', true)
ON CONFLICT (id) DO NOTHING;

-- 13. 创建示例管理员用户数据
INSERT INTO users (email, username, display_name, university, role) VALUES
('admin@smellpin.com', 'admin', 'System Admin', 'SmellPin University', 'admin')
ON CONFLICT (email) DO NOTHING;

-- 迁移完成
COMMIT;