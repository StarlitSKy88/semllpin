-- LBS奖励系统数据库表结构 - Neon PostgreSQL兼容版本
-- 创建时间: 2025-01-14
-- 说明: 基于项目规则，使用Neon PostgreSQL，严格禁止Supabase

-- 启用PostGIS扩展（用于地理位置计算）
CREATE EXTENSION IF NOT EXISTS postgis;

-- 1. LBS奖励记录表
CREATE TABLE IF NOT EXISTS lbs_rewards (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    reward_type VARCHAR(50) NOT NULL CHECK (reward_type IN ('discovery', 'checkin', 'duration', 'social')),
    location_point GEOMETRY(POINT, 4326) NOT NULL,
    location_name VARCHAR(255),
    reward_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    base_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    time_decay_factor DECIMAL(5,4) NOT NULL DEFAULT 1.0000,
    is_first_discoverer BOOLEAN DEFAULT FALSE,
    discovery_bonus DECIMAL(10,2) DEFAULT 0.00,
    geofence_id BIGINT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. 地理围栏配置表
CREATE TABLE IF NOT EXISTS geofence_configs (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    center_point GEOMETRY(POINT, 4326) NOT NULL,
    radius_meters INTEGER NOT NULL DEFAULT 100,
    reward_type VARCHAR(50) NOT NULL,
    base_reward_amount DECIMAL(10,2) NOT NULL DEFAULT 1.00,
    max_daily_rewards INTEGER DEFAULT 10,
    min_stay_duration INTEGER DEFAULT 300, -- 秒
    is_active BOOLEAN DEFAULT TRUE,
    priority_level INTEGER DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. 位置上报记录表
CREATE TABLE IF NOT EXISTS location_reports (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    location_point GEOMETRY(POINT, 4326) NOT NULL,
    accuracy_meters DECIMAL(8,2),
    altitude_meters DECIMAL(10,2),
    speed_mps DECIMAL(8,2),
    heading_degrees DECIMAL(6,2),
    timestamp_client TIMESTAMP WITH TIME ZONE NOT NULL,
    timestamp_server TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    device_info JSONB DEFAULT '{}',
    is_processed BOOLEAN DEFAULT FALSE,
    processing_result JSONB DEFAULT '{}'
);

-- 4. 防作弊检测记录表
CREATE TABLE IF NOT EXISTS anti_fraud_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    detection_type VARCHAR(50) NOT NULL,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    location_point GEOMETRY(POINT, 4326),
    suspicious_data JSONB NOT NULL DEFAULT '{}',
    action_taken VARCHAR(100),
    is_blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. LBS奖励统计表
CREATE TABLE IF NOT EXISTS lbs_reward_stats (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    date_recorded DATE NOT NULL DEFAULT CURRENT_DATE,
    total_rewards DECIMAL(12,2) DEFAULT 0.00,
    discovery_rewards DECIMAL(12,2) DEFAULT 0.00,
    checkin_rewards DECIMAL(12,2) DEFAULT 0.00,
    duration_rewards DECIMAL(12,2) DEFAULT 0.00,
    social_rewards DECIMAL(12,2) DEFAULT 0.00,
    total_checkins INTEGER DEFAULT 0,
    unique_locations INTEGER DEFAULT 0,
    total_duration_minutes INTEGER DEFAULT 0,
    first_discovery_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, date_recorded)
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_user_id ON lbs_rewards(user_id);
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_location ON lbs_rewards USING GIST(location_point);
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_created_at ON lbs_rewards(created_at);
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_reward_type ON lbs_rewards(reward_type);

CREATE INDEX IF NOT EXISTS idx_geofence_configs_center ON geofence_configs USING GIST(center_point);
CREATE INDEX IF NOT EXISTS idx_geofence_configs_active ON geofence_configs(is_active);

CREATE INDEX IF NOT EXISTS idx_location_reports_user_id ON location_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_location_reports_location ON location_reports USING GIST(location_point);
CREATE INDEX IF NOT EXISTS idx_location_reports_timestamp ON location_reports(timestamp_server);
CREATE INDEX IF NOT EXISTS idx_location_reports_processed ON location_reports(is_processed);

CREATE INDEX IF NOT EXISTS idx_anti_fraud_user_id ON anti_fraud_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_risk_level ON anti_fraud_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_created_at ON anti_fraud_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_lbs_stats_user_date ON lbs_reward_stats(user_id, date_recorded);
CREATE INDEX IF NOT EXISTS idx_lbs_stats_date ON lbs_reward_stats(date_recorded);

-- 创建更新时间触发器函数
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 为相关表添加更新时间触发器
CREATE TRIGGER update_lbs_rewards_updated_at BEFORE UPDATE ON lbs_rewards
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_geofence_configs_updated_at BEFORE UPDATE ON geofence_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_lbs_reward_stats_updated_at BEFORE UPDATE ON lbs_reward_stats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 核心业务函数

-- 1. 计算时间衰减因子
CREATE OR REPLACE FUNCTION calculate_time_decay_factor(
    location_point GEOMETRY,
    hours_since_last_visit INTEGER DEFAULT 0
) RETURNS DECIMAL(5,4) AS $$
DECLARE
    decay_factor DECIMAL(5,4);
BEGIN
    -- 基础衰减公式：factor = 1 - (hours / 168) * 0.5
    -- 168小时 = 7天，最大衰减50%
    decay_factor := GREATEST(0.5, 1.0 - (hours_since_last_visit::DECIMAL / 168.0) * 0.5);
    
    RETURN LEAST(1.0, decay_factor);
END;
$$ LANGUAGE plpgsql;

-- 2. 检查是否为首次发现者
CREATE OR REPLACE FUNCTION check_first_discoverer(
    user_id_param BIGINT,
    location_point GEOMETRY,
    radius_meters INTEGER DEFAULT 50
) RETURNS BOOLEAN AS $$
DECLARE
    existing_count INTEGER;
BEGIN
    -- 检查指定半径内是否有其他用户的奖励记录
    SELECT COUNT(*) INTO existing_count
    FROM lbs_rewards
    WHERE user_id != user_id_param
      AND ST_DWithin(location_point, lbs_rewards.location_point, radius_meters)
      AND created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    RETURN existing_count = 0;
END;
$$ LANGUAGE plpgsql;

-- 3. 计算奖励金额
CREATE OR REPLACE FUNCTION calculate_reward_amount(
    reward_type_param VARCHAR(50),
    base_amount DECIMAL(10,2),
    time_decay_factor DECIMAL(5,4) DEFAULT 1.0,
    is_first_discoverer BOOLEAN DEFAULT FALSE,
    duration_minutes INTEGER DEFAULT 0
) RETURNS DECIMAL(10,2) AS $$
DECLARE
    final_amount DECIMAL(10,2);
    discovery_bonus DECIMAL(10,2) := 0.00;
BEGIN
    -- 基础金额应用时间衰减
    final_amount := base_amount * time_decay_factor;
    
    -- 首次发现者奖励
    IF is_first_discoverer THEN
        discovery_bonus := base_amount * 0.5; -- 50%首发奖励
        final_amount := final_amount + discovery_bonus;
    END IF;
    
    -- 持续时间奖励（duration类型）
    IF reward_type_param = 'duration' AND duration_minutes > 0 THEN
        final_amount := final_amount + (duration_minutes::DECIMAL / 60.0) * 0.1; -- 每小时0.1元
    END IF;
    
    RETURN ROUND(final_amount, 2);
END;
$$ LANGUAGE plpgsql;

-- 4. 地理围栏检测函数
CREATE OR REPLACE FUNCTION detect_geofence_entry(
    user_location GEOMETRY,
    user_id_param BIGINT
) RETURNS TABLE(
    geofence_id BIGINT,
    geofence_name VARCHAR(255),
    reward_type VARCHAR(50),
    base_reward_amount DECIMAL(10,2),
    distance_meters DECIMAL(10,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        gc.id,
        gc.name,
        gc.reward_type,
        gc.base_reward_amount,
        ST_Distance(gc.center_point, user_location) as distance_meters
    FROM geofence_configs gc
    WHERE gc.is_active = TRUE
      AND ST_DWithin(gc.center_point, user_location, gc.radius_meters)
    ORDER BY ST_Distance(gc.center_point, user_location) ASC;
END;
$$ LANGUAGE plpgsql;

-- 插入示例地理围栏配置
INSERT INTO geofence_configs (name, center_point, radius_meters, reward_type, base_reward_amount, max_daily_rewards, min_stay_duration) VALUES
('商业中心A', ST_GeomFromText('POINT(116.397428 39.90923)', 4326), 200, 'checkin', 2.00, 5, 300),
('公园B', ST_GeomFromText('POINT(116.407526 39.90403)', 4326), 150, 'discovery', 3.00, 3, 600),
('地铁站C', ST_GeomFromText('POINT(116.387428 39.91423)', 4326), 100, 'checkin', 1.50, 10, 180),
('景点D', ST_GeomFromText('POINT(116.417428 39.89923)', 4326), 300, 'duration', 5.00, 2, 900),
('购物中心E', ST_GeomFromText('POINT(116.377428 39.92423)', 4326), 250, 'social', 2.50, 8, 450)
ON CONFLICT DO NOTHING;

-- 创建用于统计的视图
CREATE OR REPLACE VIEW lbs_reward_summary AS
SELECT 
    user_id,
    COUNT(*) as total_rewards_count,
    SUM(reward_amount) as total_reward_amount,
    COUNT(CASE WHEN reward_type = 'discovery' THEN 1 END) as discovery_count,
    COUNT(CASE WHEN reward_type = 'checkin' THEN 1 END) as checkin_count,
    COUNT(CASE WHEN reward_type = 'duration' THEN 1 END) as duration_count,
    COUNT(CASE WHEN reward_type = 'social' THEN 1 END) as social_count,
    COUNT(CASE WHEN is_first_discoverer = TRUE THEN 1 END) as first_discovery_count,
    AVG(reward_amount) as avg_reward_amount,
    MAX(created_at) as last_reward_time
FROM lbs_rewards
GROUP BY user_id;

COMMENT ON TABLE lbs_rewards IS 'LBS奖励记录表 - 存储用户位置相关的奖励信息';
COMMENT ON TABLE geofence_configs IS '地理围栏配置表 - 定义奖励触发的地理区域';
COMMENT ON TABLE location_reports IS '位置上报记录表 - 存储用户位置上报的原始数据';
COMMENT ON TABLE anti_fraud_logs IS '防作弊检测记录表 - 记录可疑行为和检测结果';
COMMENT ON TABLE lbs_reward_stats IS 'LBS奖励统计表 - 按日统计用户奖励数据';