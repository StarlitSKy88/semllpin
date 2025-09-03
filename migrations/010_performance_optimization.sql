-- 性能优化迁移文件
-- 添加数据库索引和查询优化

-- 1. 标注表索引优化
CREATE INDEX IF NOT EXISTS idx_annotations_location ON annotations USING GIST (ST_Point(longitude, latitude));
CREATE INDEX IF NOT EXISTS idx_annotations_created_at ON annotations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_annotations_user_id ON annotations(user_id);
CREATE INDEX IF NOT EXISTS idx_annotations_category ON annotations(category);
CREATE INDEX IF NOT EXISTS idx_annotations_intensity ON annotations(smell_intensity DESC);
CREATE INDEX IF NOT EXISTS idx_annotations_status ON annotations(status);
CREATE INDEX IF NOT EXISTS idx_annotations_composite ON annotations(user_id, created_at DESC, status);

-- 2. 用户表索引优化
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- 3. 评论表索引优化
CREATE INDEX IF NOT EXISTS idx_comments_annotation_id ON comments(annotation_id);
CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id);
CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_parent_id ON comments(parent_id);
CREATE INDEX IF NOT EXISTS idx_comments_composite ON comments(annotation_id, created_at DESC);

-- 4. 关注表索引优化
CREATE INDEX IF NOT EXISTS idx_user_follows_follower ON user_follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_following ON user_follows(following_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_created_at ON user_follows(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_follows_composite ON user_follows(follower_id, following_id);

-- 5. 支付表索引优化
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_amount ON payments(amount DESC);
CREATE INDEX IF NOT EXISTS idx_payments_stripe_session ON payments(stripe_session_id);

-- 6. 钱包交易表索引优化
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_user_id ON wallet_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_type ON wallet_transactions(transaction_type);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_created_at ON wallet_transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_composite ON wallet_transactions(user_id, created_at DESC);

-- 7. 通知表索引优化
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type);
CREATE INDEX IF NOT EXISTS idx_notifications_composite ON notifications(user_id, is_read, created_at DESC);

-- 8. 媒体文件表索引优化
CREATE INDEX IF NOT EXISTS idx_media_files_annotation_id ON media_files(annotation_id);
CREATE INDEX IF NOT EXISTS idx_media_files_user_id ON media_files(user_id);
CREATE INDEX IF NOT EXISTS idx_media_files_type ON media_files(file_type);
CREATE INDEX IF NOT EXISTS idx_media_files_created_at ON media_files(created_at DESC);

-- 9. 举报表索引优化（如果存在）
CREATE INDEX IF NOT EXISTS idx_content_reports_content_type ON content_reports(content_type);
CREATE INDEX IF NOT EXISTS idx_content_reports_status ON content_reports(status);
CREATE INDEX IF NOT EXISTS idx_content_reports_created_at ON content_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_reports_reporter ON content_reports(reporter_id);

-- 10. 管理员日志表索引优化（如果存在）
CREATE INDEX IF NOT EXISTS idx_admin_logs_admin_id ON admin_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action);
CREATE INDEX IF NOT EXISTS idx_admin_logs_created_at ON admin_logs(created_at DESC);

-- 11. 创建物化视图用于统计查询
CREATE MATERIALIZED VIEW IF NOT EXISTS user_stats AS
SELECT 
    u.id,
    u.username,
    u.email,
    COUNT(DISTINCT a.id) as annotation_count,
    COUNT(DISTINCT c.id) as comment_count,
    COUNT(DISTINCT f1.id) as follower_count,
    COUNT(DISTINCT f2.id) as following_count,
    COALESCE(SUM(wt.amount), 0) as total_earnings,
    MAX(a.created_at) as last_annotation_at,
    MAX(u.last_login_at) as last_login_at
FROM users u
LEFT JOIN annotations a ON u.id = a.user_id AND a.status = 'published'
LEFT JOIN comments c ON u.id = c.user_id
LEFT JOIN user_follows f1 ON u.id = f1.following_id
LEFT JOIN user_follows f2 ON u.id = f2.follower_id
LEFT JOIN wallet_transactions wt ON u.id = wt.user_id AND wt.transaction_type = 'credit'
GROUP BY u.id, u.username, u.email, u.last_login_at;

-- 创建物化视图的索引
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_stats_id ON user_stats(id);
CREATE INDEX IF NOT EXISTS idx_user_stats_annotation_count ON user_stats(annotation_count DESC);
CREATE INDEX IF NOT EXISTS idx_user_stats_total_earnings ON user_stats(total_earnings DESC);
CREATE INDEX IF NOT EXISTS idx_user_stats_last_login ON user_stats(last_login_at DESC);

-- 12. 创建热门标注物化视图
CREATE MATERIALIZED VIEW IF NOT EXISTS popular_annotations AS
SELECT 
    a.id,
    a.user_id,
    a.latitude,
    a.longitude,
    a.smell_intensity,
    a.description,
    a.category,
    a.created_at,
    COUNT(DISTINCT c.id) as comment_count,
    COUNT(DISTINCT l.id) as like_count,
    (COUNT(DISTINCT c.id) * 2 + COUNT(DISTINCT l.id) + a.smell_intensity) as popularity_score
FROM annotations a
LEFT JOIN comments c ON a.id = c.annotation_id
LEFT JOIN annotation_likes l ON a.id = l.annotation_id
WHERE a.status = 'published'
GROUP BY a.id, a.user_id, a.latitude, a.longitude, a.smell_intensity, a.description, a.category, a.created_at;

-- 创建热门标注物化视图的索引
CREATE UNIQUE INDEX IF NOT EXISTS idx_popular_annotations_id ON popular_annotations(id);
CREATE INDEX IF NOT EXISTS idx_popular_annotations_score ON popular_annotations(popularity_score DESC);
CREATE INDEX IF NOT EXISTS idx_popular_annotations_location ON popular_annotations USING GIST (ST_Point(longitude, latitude));
CREATE INDEX IF NOT EXISTS idx_popular_annotations_category ON popular_annotations(category);

-- 13. 创建刷新物化视图的函数
CREATE OR REPLACE FUNCTION refresh_materialized_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY user_stats;
    REFRESH MATERIALIZED VIEW CONCURRENTLY popular_annotations;
END;
$$ LANGUAGE plpgsql;

-- 14. 创建定时刷新物化视图的任务（需要pg_cron扩展）
-- SELECT cron.schedule('refresh-stats', '0 */6 * * *', 'SELECT refresh_materialized_views();');

-- 15. 分析表统计信息
ANALYZE users;
ANALYZE annotations;
ANALYZE comments;
ANALYZE user_follows;
ANALYZE payments;
ANALYZE wallet_transactions;
ANALYZE notifications;
ANALYZE media_files;