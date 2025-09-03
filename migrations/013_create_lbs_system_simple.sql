-- LBS奖励系统数据库表结构 - 简化版本（不使用PostGIS）
-- 创建时间: 2025-01-14
-- 说明: 使用普通经纬度字段替代PostGIS的GEOMETRY类型

-- 1. 用户表（如果不存在）
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. LBS奖励记录表
CREATE TABLE IF NOT EXISTS lbs_rewards (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reward_type VARCHAR(50) NOT NULL CHECK (reward_type IN ('discovery', 'checkin', 'duration', 'social')),
    latitude DECIMAL(10,8) NOT NULL,
    longitude DECIMAL(11,8) NOT NULL,
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

-- 3. 地理围栏配置表
CREATE TABLE IF NOT EXISTS geofence_configs (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    center_latitude DECIMAL(10,8) NOT NULL,
    center_longitude DECIMAL(11,8) NOT NULL,
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

-- 4. 位置上报记录表
CREATE TABLE IF NOT EXISTS location_reports (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10,8) NOT NULL,
    longitude DECIMAL(11,8) NOT NULL,
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

-- 5. 防作弊检测记录表
CREATE TABLE IF NOT EXISTS anti_fraud_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    geofence_id VARCHAR(50),
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
    violations JSONB DEFAULT '[]'::jsonb,
    detection_details JSONB DEFAULT '{}'::jsonb,
    is_valid BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. LBS奖励统计表
CREATE TABLE IF NOT EXISTS lbs_reward_stats (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_location ON lbs_rewards(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_created_at ON lbs_rewards(created_at);
CREATE INDEX IF NOT EXISTS idx_lbs_rewards_reward_type ON lbs_rewards(reward_type);

CREATE INDEX IF NOT EXISTS idx_geofence_configs_center ON geofence_configs(center_latitude, center_longitude);
CREATE INDEX IF NOT EXISTS idx_geofence_configs_active ON geofence_configs(is_active);

CREATE INDEX IF NOT EXISTS idx_location_reports_user_id ON location_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_location_reports_location ON location_reports(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_location_reports_timestamp ON location_reports(timestamp_server);
CREATE INDEX IF NOT EXISTS idx_location_reports_processed ON location_reports(is_processed);

CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_user_id ON anti_fraud_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_created_at ON anti_fraud_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_risk_level ON anti_fraud_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_is_valid ON anti_fraud_logs(is_valid);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_geofence_id ON anti_fraud_logs(geofence_id);

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

CREATE TRIGGER update_anti_fraud_logs_updated_at BEFORE UPDATE ON anti_fraud_logs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 插入示例地理围栏数据
INSERT INTO geofence_configs (name, center_latitude, center_longitude, radius_meters, reward_type, base_reward_amount, metadata) VALUES
('天安门广场', 39.9042, 116.4074, 200, 'checkin', 5.00, '{"description": "北京著名景点", "category": "landmark"}'),
('故宫博物院', 39.9163, 116.3972, 150, 'discovery', 10.00, '{"description": "明清皇宫", "category": "museum"}'),
('颐和园', 39.9999, 116.2755, 300, 'duration', 3.00, '{"description": "皇家园林", "category": "park"}'),
('北京大学', 39.9990, 116.3161, 500, 'checkin', 2.00, '{"description": "著名高等学府", "category": "university"}'),
('清华大学', 40.0042, 116.3261, 500, 'checkin', 2.00, '{"description": "著名高等学府", "category": "university"}');

-- 添加表注释
COMMENT ON TABLE users IS '用户表';
COMMENT ON TABLE lbs_rewards IS 'LBS奖励记录表';
COMMENT ON TABLE geofence_configs IS '地理围栏配置表';
COMMENT ON TABLE location_reports IS '位置上报记录表';
COMMENT ON TABLE anti_fraud_logs IS '防作弊检测日志表';
COMMENT ON TABLE lbs_reward_stats IS 'LBS奖励统计表';