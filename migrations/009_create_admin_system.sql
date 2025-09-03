-- 管理员系统相关表结构

-- 1. 更新用户表，添加管理员相关字段
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active',
ADD COLUMN IF NOT EXISTS last_login TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;

-- 添加状态字段的检查约束
ALTER TABLE users 
ADD CONSTRAINT check_user_status 
CHECK (status IN ('active', 'suspended', 'banned', 'pending'));

-- 为状态字段添加索引
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);

-- 2. 创建内容举报表
CREATE TABLE IF NOT EXISTS content_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reported_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(20) NOT NULL CHECK (content_type IN ('annotation', 'comment', 'media')),
    content_id UUID NOT NULL,
    reason VARCHAR(50) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 内容举报表索引
CREATE INDEX IF NOT EXISTS idx_content_reports_reporter ON content_reports(reporter_id);
CREATE INDEX IF NOT EXISTS idx_content_reports_reported_user ON content_reports(reported_user_id);
CREATE INDEX IF NOT EXISTS idx_content_reports_content ON content_reports(content_type, content_id);
CREATE INDEX IF NOT EXISTS idx_content_reports_status ON content_reports(status);
CREATE INDEX IF NOT EXISTS idx_content_reports_created_at ON content_reports(created_at);

-- 3. 创建管理员操作日志表
CREATE TABLE IF NOT EXISTS admin_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    admin_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    target_type VARCHAR(20) NOT NULL,
    target_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 管理员日志表索引
CREATE INDEX IF NOT EXISTS idx_admin_logs_admin ON admin_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action);
CREATE INDEX IF NOT EXISTS idx_admin_logs_target ON admin_logs(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_admin_logs_created_at ON admin_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_admin_logs_details ON admin_logs USING GIN(details);

-- 4. 更新标注表，添加审核状态
ALTER TABLE annotations 
ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'approved',
ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS review_reason TEXT;

-- 添加状态字段的检查约束
ALTER TABLE annotations 
ADD CONSTRAINT check_annotation_status 
CHECK (status IN ('pending', 'approved', 'rejected'));

-- 为审核状态添加索引
CREATE INDEX IF NOT EXISTS idx_annotations_status ON annotations(status);
CREATE INDEX IF NOT EXISTS idx_annotations_reviewed_by ON annotations(reviewed_by);

-- 5. 更新评论表，添加审核状态
ALTER TABLE comments 
ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'visible',
ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE;

-- 添加状态字段的检查约束
ALTER TABLE comments 
ADD CONSTRAINT check_comment_status 
CHECK (status IN ('visible', 'hidden', 'deleted'));

-- 为评论状态添加索引
CREATE INDEX IF NOT EXISTS idx_comments_status ON comments(status);
CREATE INDEX IF NOT EXISTS idx_comments_reviewed_by ON comments(reviewed_by);

-- 6. 创建系统配置表
CREATE TABLE IF NOT EXISTS system_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 系统配置表索引
CREATE INDEX IF NOT EXISTS idx_system_configs_key ON system_configs(config_key);
CREATE INDEX IF NOT EXISTS idx_system_configs_created_by ON system_configs(created_by);

-- 7. 创建平台统计表（用于缓存统计数据）
CREATE TABLE IF NOT EXISTS platform_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    stat_date DATE NOT NULL,
    stat_type VARCHAR(50) NOT NULL,
    stat_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(stat_date, stat_type)
);

-- 平台统计表索引
CREATE INDEX IF NOT EXISTS idx_platform_stats_date ON platform_stats(stat_date);
CREATE INDEX IF NOT EXISTS idx_platform_stats_type ON platform_stats(stat_type);
CREATE INDEX IF NOT EXISTS idx_platform_stats_data ON platform_stats USING GIN(stat_data);

-- 8. 插入默认系统配置
INSERT INTO system_configs (config_key, config_value, description) VALUES
('auto_moderation', '{"enabled": true, "sensitivity": "medium"}', '自动审核配置'),
('user_registration', '{"enabled": true, "email_verification": true}', '用户注册配置'),
('content_limits', '{"max_annotations_per_day": 50, "max_comments_per_day": 100}', '内容限制配置'),
('notification_settings', '{"email_enabled": true, "push_enabled": true}', '通知设置'),
('payment_settings', '{"min_amount": 1, "max_amount": 100, "fee_rate": 0.05}', '支付设置')
ON CONFLICT (config_key) DO NOTHING;

-- 9. 创建更新时间触发器函数（如果不存在）
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 为新表添加更新时间触发器
DROP TRIGGER IF EXISTS update_content_reports_updated_at ON content_reports;
CREATE TRIGGER update_content_reports_updated_at
    BEFORE UPDATE ON content_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_system_configs_updated_at ON system_configs;
CREATE TRIGGER update_system_configs_updated_at
    BEFORE UPDATE ON system_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_platform_stats_updated_at ON platform_stats;
CREATE TRIGGER update_platform_stats_updated_at
    BEFORE UPDATE ON platform_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 10. 创建管理员角色（如果不存在）
INSERT INTO users (email, password_hash, username, role, status, created_at)
SELECT 
    'admin@smellpin.com',
    '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- password: 'admin123'
    'admin',
    'admin',
    'active',
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'admin@smellpin.com'
);

-- 11. 添加一些示例举报数据（仅用于开发测试）
-- 注意：生产环境中应该删除这部分
/*
INSERT INTO content_reports (reporter_id, content_type, content_id, reason, description)
SELECT 
    u.id,
    'annotation',
    a.id,
    'inappropriate_content',
    '包含不当内容'
FROM users u, annotations a 
WHERE u.role = 'user' AND a.id IS NOT NULL
LIMIT 5;
*/

COMMIT;