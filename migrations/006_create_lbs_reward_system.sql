-- Create LBS Reward System Tables

-- 1. User Locations Table (用户位置表)
CREATE TABLE user_locations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  location_name VARCHAR(255), -- 地点名称
  address TEXT, -- 详细地址
  accuracy DECIMAL(8, 2), -- GPS精度(米)
  altitude DECIMAL(10, 2), -- 海拔高度
  speed DECIMAL(8, 2), -- 移动速度(km/h)
  heading DECIMAL(5, 2), -- 移动方向(度)
  location_type VARCHAR(50) DEFAULT 'manual' CHECK (location_type IN ('manual', 'auto', 'checkin')),
  is_current BOOLEAN DEFAULT false, -- 是否为当前位置
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Check-in Records Table (签到记录表)
CREATE TABLE checkin_records (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  location_id UUID REFERENCES user_locations(id) ON DELETE SET NULL,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  location_name VARCHAR(255),
  address TEXT,
  checkin_type VARCHAR(50) DEFAULT 'manual' CHECK (checkin_type IN ('manual', 'auto', 'scheduled')),
  points_earned INTEGER DEFAULT 0, -- 获得的积分
  bonus_multiplier DECIMAL(3, 2) DEFAULT 1.0, -- 奖励倍数
  consecutive_days INTEGER DEFAULT 1, -- 连续签到天数
  is_first_time BOOLEAN DEFAULT false, -- 是否首次在此地点签到
  weather_condition VARCHAR(50), -- 天气状况
  temperature DECIMAL(5, 2), -- 温度
  notes TEXT, -- 签到备注
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Reward Records Table (奖励记录表)
CREATE TABLE reward_records (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reward_type VARCHAR(50) NOT NULL CHECK (reward_type IN (
    'checkin', 'distance', 'exploration', 'social', 'annotation', 'payment', 'referral', 'achievement'
  )),
  reward_category VARCHAR(50) NOT NULL, -- 奖励类别
  points INTEGER NOT NULL DEFAULT 0, -- 积分奖励
  coins DECIMAL(10, 2) DEFAULT 0, -- 虚拟货币奖励
  cash_value DECIMAL(10, 2) DEFAULT 0, -- 现金价值
  description TEXT NOT NULL, -- 奖励描述
  source_id UUID, -- 来源ID(如标注ID、签到ID等)
  source_type VARCHAR(50), -- 来源类型
  location_id UUID REFERENCES user_locations(id) ON DELETE SET NULL,
  latitude DECIMAL(10, 8),
  longitude DECIMAL(11, 8),
  multiplier DECIMAL(3, 2) DEFAULT 1.0, -- 奖励倍数
  expires_at TIMESTAMP WITH TIME ZONE, -- 奖励过期时间
  claimed_at TIMESTAMP WITH TIME ZONE, -- 领取时间
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'expired', 'cancelled')),
  metadata JSONB DEFAULT '{}'::jsonb, -- 额外元数据
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. User Stats Table (用户统计表)
CREATE TABLE user_stats (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  total_points INTEGER DEFAULT 0, -- 总积分
  available_points INTEGER DEFAULT 0, -- 可用积分
  total_coins DECIMAL(10, 2) DEFAULT 0, -- 总虚拟货币
  available_coins DECIMAL(10, 2) DEFAULT 0, -- 可用虚拟货币
  total_checkins INTEGER DEFAULT 0, -- 总签到次数
  consecutive_checkins INTEGER DEFAULT 0, -- 连续签到天数
  max_consecutive_checkins INTEGER DEFAULT 0, -- 最大连续签到天数
  total_distance DECIMAL(10, 2) DEFAULT 0, -- 总移动距离(km)
  unique_locations INTEGER DEFAULT 0, -- 独特位置数量
  exploration_score INTEGER DEFAULT 0, -- 探索分数
  social_score INTEGER DEFAULT 0, -- 社交分数
  level_id INTEGER DEFAULT 1, -- 用户等级
  experience_points INTEGER DEFAULT 0, -- 经验值
  last_checkin_at TIMESTAMP WITH TIME ZONE, -- 最后签到时间
  last_location_update TIMESTAMP WITH TIME ZONE, -- 最后位置更新时间
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Nearby Users Table (附近用户表)
CREATE TABLE nearby_users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nearby_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  distance DECIMAL(8, 2) NOT NULL, -- 距离(米)
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  nearby_latitude DECIMAL(10, 8) NOT NULL,
  nearby_longitude DECIMAL(11, 8) NOT NULL,
  interaction_type VARCHAR(50), -- 交互类型
  interaction_count INTEGER DEFAULT 0, -- 交互次数
  last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, nearby_user_id)
);

-- 6. Location Hotspots Table (热点位置表)
CREATE TABLE location_hotspots (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  radius DECIMAL(8, 2) DEFAULT 100, -- 热点半径(米)
  category VARCHAR(50) NOT NULL, -- 热点类别
  popularity_score INTEGER DEFAULT 0, -- 热度分数
  checkin_count INTEGER DEFAULT 0, -- 签到次数
  annotation_count INTEGER DEFAULT 0, -- 标注数量
  reward_multiplier DECIMAL(3, 2) DEFAULT 1.0, -- 奖励倍数
  is_active BOOLEAN DEFAULT true,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Indexes

-- User Locations Indexes
CREATE INDEX idx_user_locations_user_id ON user_locations(user_id);
CREATE INDEX idx_user_locations_coords ON user_locations(latitude, longitude);
CREATE INDEX idx_user_locations_current ON user_locations(user_id, is_current);
CREATE INDEX idx_user_locations_created_at ON user_locations(created_at);
CREATE INDEX idx_user_locations_type ON user_locations(location_type);

-- Check-in Records Indexes
CREATE INDEX idx_checkin_records_user_id ON checkin_records(user_id);
CREATE INDEX idx_checkin_records_coords ON checkin_records(latitude, longitude);
CREATE INDEX idx_checkin_records_created_at ON checkin_records(created_at);
CREATE INDEX idx_checkin_records_user_date ON checkin_records(user_id, created_at);
CREATE INDEX idx_checkin_records_location_id ON checkin_records(location_id);

-- Reward Records Indexes
CREATE INDEX idx_reward_records_user_id ON reward_records(user_id);
CREATE INDEX idx_reward_records_type ON reward_records(reward_type);
CREATE INDEX idx_reward_records_status ON reward_records(status);
CREATE INDEX idx_reward_records_created_at ON reward_records(created_at);
CREATE INDEX idx_reward_records_source ON reward_records(source_type, source_id);
CREATE INDEX idx_reward_records_location ON reward_records(latitude, longitude);

-- User Stats Indexes
CREATE INDEX idx_user_stats_points ON user_stats(total_points);
CREATE INDEX idx_user_stats_level ON user_stats(level_id);
CREATE INDEX idx_user_stats_checkins ON user_stats(consecutive_checkins);

-- Nearby Users Indexes
CREATE INDEX idx_nearby_users_user_id ON nearby_users(user_id);
CREATE INDEX idx_nearby_users_nearby_id ON nearby_users(nearby_user_id);
CREATE INDEX idx_nearby_users_distance ON nearby_users(distance);
CREATE INDEX idx_nearby_users_last_seen ON nearby_users(last_seen_at);

-- Location Hotspots Indexes
CREATE INDEX idx_location_hotspots_coords ON location_hotspots(latitude, longitude);
CREATE INDEX idx_location_hotspots_category ON location_hotspots(category);
CREATE INDEX idx_location_hotspots_popularity ON location_hotspots(popularity_score);
CREATE INDEX idx_location_hotspots_active ON location_hotspots(is_active);

-- Create Triggers

-- Update triggers for updated_at columns
CREATE TRIGGER update_user_locations_updated_at
  BEFORE UPDATE ON user_locations
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reward_records_updated_at
  BEFORE UPDATE ON reward_records
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_stats_updated_at
  BEFORE UPDATE ON user_stats
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_location_hotspots_updated_at
  BEFORE UPDATE ON location_hotspots
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create Functions for LBS Reward System

-- Function to calculate distance between two points (Haversine formula)
CREATE OR REPLACE FUNCTION calculate_distance(
  lat1 DECIMAL(10, 8),
  lon1 DECIMAL(11, 8),
  lat2 DECIMAL(10, 8),
  lon2 DECIMAL(11, 8)
) RETURNS DECIMAL(8, 2) AS $$
DECLARE
  R CONSTANT DECIMAL := 6371000; -- Earth radius in meters
  dlat DECIMAL;
  dlon DECIMAL;
  a DECIMAL;
  c DECIMAL;
  distance DECIMAL;
BEGIN
  dlat := RADIANS(lat2 - lat1);
  dlon := RADIANS(lon2 - lon1);
  
  a := SIN(dlat/2) * SIN(dlat/2) + COS(RADIANS(lat1)) * COS(RADIANS(lat2)) * SIN(dlon/2) * SIN(dlon/2);
  c := 2 * ATAN2(SQRT(a), SQRT(1-a));
  
  distance := R * c;
  
  RETURN distance;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to find nearby users
CREATE OR REPLACE FUNCTION find_nearby_users(
  user_id_param UUID,
  latitude_param DECIMAL(10, 8),
  longitude_param DECIMAL(11, 8),
  radius_param DECIMAL(8, 2) DEFAULT 1000
) RETURNS TABLE(
  nearby_user_id UUID,
  distance DECIMAL(8, 2),
  nearby_latitude DECIMAL(10, 8),
  nearby_longitude DECIMAL(11, 8)
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    ul.user_id,
    calculate_distance(latitude_param, longitude_param, ul.latitude, ul.longitude) as dist,
    ul.latitude,
    ul.longitude
  FROM user_locations ul
  WHERE ul.user_id != user_id_param
    AND ul.is_current = true
    AND calculate_distance(latitude_param, longitude_param, ul.latitude, ul.longitude) <= radius_param
  ORDER BY dist;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate reward points based on activity
CREATE OR REPLACE FUNCTION calculate_reward_points(
  reward_type_param VARCHAR(50),
  base_points INTEGER DEFAULT 10,
  multiplier_param DECIMAL(3, 2) DEFAULT 1.0
) RETURNS INTEGER AS $$
DECLARE
  final_points INTEGER;
BEGIN
  CASE reward_type_param
    WHEN 'checkin' THEN
      final_points := base_points * multiplier_param;
    WHEN 'distance' THEN
      final_points := (base_points * 0.5) * multiplier_param;
    WHEN 'exploration' THEN
      final_points := (base_points * 2) * multiplier_param;
    WHEN 'social' THEN
      final_points := (base_points * 1.5) * multiplier_param;
    WHEN 'annotation' THEN
      final_points := (base_points * 3) * multiplier_param;
    ELSE
      final_points := base_points * multiplier_param;
  END CASE;
  
  RETURN GREATEST(final_points, 1); -- Minimum 1 point
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to update user stats after reward
CREATE OR REPLACE FUNCTION update_user_stats_after_reward(
  user_id_param UUID,
  points_param INTEGER,
  coins_param DECIMAL(10, 2) DEFAULT 0
) RETURNS VOID AS $$
BEGIN
  INSERT INTO user_stats (user_id, total_points, available_points, total_coins, available_coins)
  VALUES (user_id_param, points_param, points_param, coins_param, coins_param)
  ON CONFLICT (user_id) DO UPDATE SET
    total_points = user_stats.total_points + points_param,
    available_points = user_stats.available_points + points_param,
    total_coins = user_stats.total_coins + coins_param,
    available_coins = user_stats.available_coins + coins_param,
    updated_at = CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Create initial location hotspots (sample data)
INSERT INTO location_hotspots (name, description, latitude, longitude, category, reward_multiplier) VALUES
('University Campus', 'Main university campus area', 40.7589, -73.9851, 'education', 1.5),
('Central Park', 'Popular park for recreation', 40.7812, -73.9665, 'recreation', 1.2),
('Times Square', 'Busy commercial area', 40.7580, -73.9855, 'commercial', 2.0),
('Brooklyn Bridge', 'Historic landmark', 40.7061, -73.9969, 'landmark', 1.8),
('Coffee Shop District', 'Popular coffee shop area', 40.7505, -73.9934, 'food', 1.3);

COMMIT;