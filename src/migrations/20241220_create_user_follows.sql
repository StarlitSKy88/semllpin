-- 创建用户关注表
CREATE TABLE IF NOT EXISTS user_follows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- 确保不能关注自己
    CONSTRAINT check_not_self_follow CHECK (follower_id != following_id),
    
    -- 确保同一对用户只能有一个关注关系
    UNIQUE(follower_id, following_id)
);

-- 创建索引以提高查询性能
CREATE INDEX IF NOT EXISTS idx_user_follows_follower_id ON user_follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_following_id ON user_follows(following_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_created_at ON user_follows(created_at);

-- 为用户表添加关注数和粉丝数字段（如果不存在）
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS followers_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS following_count INTEGER DEFAULT 0;

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_users_followers_count ON users(followers_count);
CREATE INDEX IF NOT EXISTS idx_users_following_count ON users(following_count);

-- 创建触发器函数来自动更新关注数和粉丝数
CREATE OR REPLACE FUNCTION update_follow_counts()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- 增加关注者的关注数
        UPDATE users SET following_count = following_count + 1 WHERE id = NEW.follower_id;
        -- 增加被关注者的粉丝数
        UPDATE users SET followers_count = followers_count + 1 WHERE id = NEW.following_id;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        -- 减少关注者的关注数
        UPDATE users SET following_count = following_count - 1 WHERE id = OLD.follower_id;
        -- 减少被关注者的粉丝数
        UPDATE users SET followers_count = followers_count - 1 WHERE id = OLD.following_id;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- 创建触发器
DROP TRIGGER IF EXISTS trigger_update_follow_counts ON user_follows;
CREATE TRIGGER trigger_update_follow_counts
    AFTER INSERT OR DELETE ON user_follows
    FOR EACH ROW
    EXECUTE FUNCTION update_follow_counts();

-- 初始化现有用户的关注数和粉丝数
UPDATE users SET 
    followers_count = (
        SELECT COUNT(*) FROM user_follows WHERE following_id = users.id
    ),
    following_count = (
        SELECT COUNT(*) FROM user_follows WHERE follower_id = users.id
    )
WHERE followers_count IS NULL OR following_count IS NULL;

COMMIT;