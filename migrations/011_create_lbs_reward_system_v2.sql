-- LBS奖励系统 v2.0 - 基于后续开发需求规划文档
-- 创建符合规划文档要求的LBS奖励系统表结构

-- 1. LBS奖励记录表
CREATE TABLE lbs_rewards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    reward_amount DECIMAL(10,2) NOT NULL,
    reward_type VARCHAR(50) NOT NULL CHECK (reward_type IN ('discovery', 'first_finder', 'combo', 'time_bonus')),
    location_verified BOOLEAN DEFAULT false,
    verification_data JSONB DEFAULT '{}'::jsonb, -- GPS精度、移动轨迹等验证数据
    gps_accuracy DECIMAL(8,2), -- GPS精度(米)
    movement_speed DECIMAL(8,2), -- 移动速度(km/h)
    stay_duration INTEGER, -- 停留时间(秒)
    distance_to_annotation DECIMAL(8,2), -- 到标注点的距离(米)
    time_decay_factor DECIMAL(3,2) DEFAULT 1.0, -- 时间衰减因子
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    claimed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'claimed', 'rejected', 'expired')),
    anti_fraud_score DECIMAL(3,2) DEFAULT 1.0, -- 防作弊评分
    device_fingerprint VARCHAR(255), -- 设备指纹
    ip_address INET, -- IP地址
    metadata JSONB DEFAULT '{}'::jsonb -- 额外元数据
);

-- 2. 地理围栏配置表
CREATE TABLE geofence_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    radius_meters INTEGER DEFAULT 100 CHECK (radius_meters BETWEEN 50 AND 200),
    detection_frequency INTEGER DEFAULT 30, -- 检测频率(秒)
    min_accuracy_meters INTEGER DEFAULT 20, -- 最小GPS精度要求(米)
    min_stay_duration INTEGER DEFAULT 30, -- 最小停留时间(秒)
    max_speed_kmh DECIMAL(5,2) DEFAULT 50.0, -- 最大允许速度(km/h)
    is_active BOOLEAN DEFAULT true,
    reward_base_percentage DECIMAL(5,2) DEFAULT 50.0, -- 基础奖励百分比
    time_decay_enabled BOOLEAN DEFAULT true, -- 是否启用时间衰减
    first_finder_bonus DECIMAL(5,2) DEFAULT 20.0, -- 首次发现奖励百分比
    combo_bonus_enabled BOOLEAN DEFAULT true, -- 是否启用连击奖励
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. 位置上报记录表
CREATE TABLE location_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10,8) NOT NULL,
    longitude DECIMAL(11,8) NOT NULL,
    accuracy DECIMAL(8,2) NOT NULL, -- GPS精度(米)
    speed DECIMAL(8,2), -- 移动速度(km/h)
    heading DECIMAL(5,2), -- 移动方向(度)
    altitude DECIMAL(10,2), -- 海拔高度(米)
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    device_info JSONB DEFAULT '{}'::jsonb, -- 设备信息
    battery_level INTEGER, -- 电池电量百分比
    network_type VARCHAR(20), -- 网络类型
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. 防作弊检测记录表
CREATE TABLE anti_fraud_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    detection_type VARCHAR(50) NOT NULL, -- 检测类型
    risk_score DECIMAL(3,2) NOT NULL, -- 风险评分(0-1)
    details JSONB NOT NULL, -- 检测详情
    action_taken VARCHAR(50), -- 采取的行动
    location_report_id UUID REFERENCES location_reports(id) ON DELETE SET NULL,
    lbs_reward_id UUID REFERENCES lbs_rewards(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. 奖励统计表
CREATE TABLE lbs_reward_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    total_rewards_earned DECIMAL(12,2) DEFAULT 0, -- 总奖励金额
    total_discoveries INTEGER DEFAULT 0, -- 总发现次数
    first_finder_count INTEGER DEFAULT 0, -- 首次发现次数
    combo_count INTEGER DEFAULT 0, -- 连击次数
    max_combo_streak INTEGER DEFAULT 0, -- 最大连击数
    current_combo_streak INTEGER DEFAULT 0, -- 当前连击数
    last_discovery_at TIMESTAMP WITH TIME ZONE, -- 最后发现时间
    fraud_detection_count INTEGER DEFAULT 0, -- 被检测作弊次数
    verification_success_rate DECIMAL(5,2) DEFAULT 100.0, -- 验证成功率
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 创建索引

-- lbs_rewards表索引
CREATE INDEX idx_lbs_rewards_user_id ON lbs_rewards(user_id);
CREATE INDEX idx_lbs_rewards_annotation_id ON lbs_rewards(annotation_id);
CREATE INDEX idx_lbs_rewards_created_at ON lbs_rewards(created_at DESC);
CREATE INDEX idx_lbs_rewards_status ON lbs_rewards(status);
CREATE INDEX idx_lbs_rewards_reward_type ON lbs_rewards(reward_type);
CREATE INDEX idx_lbs_rewards_user_status ON lbs_rewards(user_id, status);
CREATE INDEX idx_lbs_rewards_expires_at ON lbs_rewards(expires_at) WHERE expires_at IS NOT NULL;

-- geofence_configs表索引
CREATE INDEX idx_geofence_configs_annotation_id ON geofence_configs(annotation_id);
CREATE INDEX idx_geofence_configs_active ON geofence_configs(is_active);
CREATE INDEX idx_geofence_configs_radius ON geofence_configs(radius_meters);

-- location_reports表索引
CREATE INDEX idx_location_reports_user_id ON location_reports(user_id);
CREATE INDEX idx_location_reports_timestamp ON location_reports(timestamp DESC);
CREATE INDEX idx_location_reports_coords ON location_reports(latitude, longitude);
CREATE INDEX idx_location_reports_user_timestamp ON location_reports(user_id, timestamp DESC);
CREATE INDEX idx_location_reports_accuracy ON location_reports(accuracy);

-- anti_fraud_logs表索引
CREATE INDEX idx_anti_fraud_logs_user_id ON anti_fraud_logs(user_id);
CREATE INDEX idx_anti_fraud_logs_type ON anti_fraud_logs(detection_type);
CREATE INDEX idx_anti_fraud_logs_score ON anti_fraud_logs(risk_score DESC);
CREATE INDEX idx_anti_fraud_logs_created_at ON anti_fraud_logs(created_at DESC);

-- lbs_reward_stats表索引
CREATE INDEX idx_lbs_reward_stats_total_rewards ON lbs_reward_stats(total_rewards_earned DESC);
CREATE INDEX idx_lbs_reward_stats_discoveries ON lbs_reward_stats(total_discoveries DESC);
CREATE INDEX idx_lbs_reward_stats_combo ON lbs_reward_stats(max_combo_streak DESC);

-- 创建更新时间触发器函数（如果不存在）
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 为需要的表添加更新时间触发器
CREATE TRIGGER update_geofence_configs_updated_at
    BEFORE UPDATE ON geofence_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_lbs_reward_stats_updated_at
    BEFORE UPDATE ON lbs_reward_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 创建LBS奖励系统相关函数

-- 1. 计算时间衰减因子
CREATE OR REPLACE FUNCTION calculate_time_decay_factor(
    annotation_created_at TIMESTAMP WITH TIME ZONE
) RETURNS DECIMAL(3,2) AS $$
DECLARE
    hours_diff INTEGER;
    decay_factor DECIMAL(3,2);
BEGIN
    hours_diff := EXTRACT(EPOCH FROM (NOW() - annotation_created_at)) / 3600;
    
    CASE 
        WHEN hours_diff <= 24 THEN decay_factor := 0.70; -- 24小时内：70%
        WHEN hours_diff <= 168 THEN decay_factor := 0.50; -- 1-7天：50%
        WHEN hours_diff <= 720 THEN decay_factor := 0.30; -- 7-30天：30%
        ELSE decay_factor := 0.10; -- 30天后：10%
    END CASE;
    
    RETURN decay_factor;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- 2. 检查是否为首次发现者
CREATE OR REPLACE FUNCTION is_first_finder(
    annotation_id_param UUID,
    user_id_param UUID
) RETURNS BOOLEAN AS $$
DECLARE
    existing_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO existing_count
    FROM lbs_rewards
    WHERE annotation_id = annotation_id_param
      AND status IN ('verified', 'claimed')
      AND user_id != user_id_param;
    
    RETURN existing_count = 0;
END;
$$ LANGUAGE plpgsql;

-- 3. 计算奖励金额
CREATE OR REPLACE FUNCTION calculate_lbs_reward_amount(
    annotation_id_param UUID,
    user_id_param UUID,
    reward_type_param VARCHAR(50)
) RETURNS DECIMAL(10,2) AS $$
DECLARE
    base_amount DECIMAL(10,2);
    decay_factor DECIMAL(3,2);
    final_amount DECIMAL(10,2);
    is_first BOOLEAN;
    geofence_config RECORD;
BEGIN
    -- 获取标注的基础金额
    SELECT amount INTO base_amount
    FROM annotations
    WHERE id = annotation_id_param;
    
    -- 获取地理围栏配置
    SELECT * INTO geofence_config
    FROM geofence_configs
    WHERE annotation_id = annotation_id_param AND is_active = true;
    
    -- 如果没有配置，使用默认值
    IF geofence_config IS NULL THEN
        geofence_config.reward_base_percentage := 50.0;
        geofence_config.first_finder_bonus := 20.0;
        geofence_config.time_decay_enabled := true;
    END IF;
    
    -- 计算基础奖励
    final_amount := base_amount * (geofence_config.reward_base_percentage / 100.0);
    
    -- 应用时间衰减
    IF geofence_config.time_decay_enabled THEN
        SELECT calculate_time_decay_factor(created_at) INTO decay_factor
        FROM annotations
        WHERE id = annotation_id_param;
        
        final_amount := final_amount * decay_factor;
    END IF;
    
    -- 首次发现奖励
    IF reward_type_param = 'first_finder' THEN
        is_first := is_first_finder(annotation_id_param, user_id_param);
        IF is_first THEN
            final_amount := final_amount * (1 + geofence_config.first_finder_bonus / 100.0);
        END IF;
    END IF;
    
    -- 连击奖励（简化版本，可以后续扩展）
    IF reward_type_param = 'combo' THEN
        final_amount := final_amount * 1.1; -- 10%连击奖励
    END IF;
    
    RETURN GREATEST(final_amount, 0.01); -- 最小0.01
END;
$$ LANGUAGE plpgsql;

-- 4. 地理围栏检测函数（使用PostGIS的ST_DWithin）
CREATE OR REPLACE FUNCTION check_geofence_trigger(
    user_id_param UUID,
    latitude_param DECIMAL(10,8),
    longitude_param DECIMAL(11,8),
    accuracy_param DECIMAL(8,2)
) RETURNS TABLE(
    annotation_id UUID,
    distance_meters DECIMAL(8,2),
    reward_eligible BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.id as annotation_id,
        ST_Distance(
            ST_GeogFromText('POINT(' || longitude_param || ' ' || latitude_param || ')'),
            ST_GeogFromText('POINT(' || a.longitude || ' ' || a.latitude || ')')
        ) as distance_meters,
        (
            ST_DWithin(
                ST_GeogFromText('POINT(' || longitude_param || ' ' || latitude_param || ')'),
                ST_GeogFromText('POINT(' || a.longitude || ' ' || a.latitude || ')'),
                COALESCE(gc.radius_meters, 100)
            )
            AND accuracy_param <= COALESCE(gc.min_accuracy_meters, 20)
            AND NOT EXISTS (
                SELECT 1 FROM lbs_rewards lr
                WHERE lr.user_id = user_id_param
                  AND lr.annotation_id = a.id
                  AND lr.status IN ('verified', 'claimed')
                  AND lr.created_at > NOW() - INTERVAL '24 hours'
            )
        ) as reward_eligible
    FROM annotations a
    LEFT JOIN geofence_configs gc ON gc.annotation_id = a.id AND gc.is_active = true
    WHERE a.status = 'active'
      AND ST_DWithin(
          ST_GeogFromText('POINT(' || longitude_param || ' ' || latitude_param || ')'),
          ST_GeogFromText('POINT(' || a.longitude || ' ' || a.latitude || ')'),
          COALESCE(gc.radius_meters, 100) * 2 -- 扩大搜索范围
      )
    ORDER BY distance_meters;
END;
$$ LANGUAGE plpgsql;

-- 插入默认的地理围栏配置（为现有标注）
INSERT INTO geofence_configs (annotation_id, radius_meters, is_active)
SELECT id, 100, true
FROM annotations
WHERE NOT EXISTS (
    SELECT 1 FROM geofence_configs gc WHERE gc.annotation_id = annotations.id
);

COMMIT;