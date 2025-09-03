-- 创建LBS系统所需的表结构
-- 这些表是LBS功能必需的，但在主要的数据库创建脚本中缺失

-- 1. 用户位置表
CREATE TABLE IF NOT EXISTS user_locations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  address TEXT,
  place_name VARCHAR(255),
  location_type VARCHAR(50) DEFAULT 'manual',
  accuracy DECIMAL(8, 2),
  is_current BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. 签到记录表 (使用integer类型的user_id以兼容现有代码)
CREATE TABLE IF NOT EXISTS checkin_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER NOT NULL, -- 使用integer类型以兼容现有的哈希转换逻辑
  location_id UUID REFERENCES user_locations(id) ON DELETE SET NULL,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  location_name VARCHAR(255),
  address TEXT,
  checkin_type VARCHAR(50) DEFAULT 'manual',
  points_earned INTEGER DEFAULT 0,
  bonus_multiplier DECIMAL(3, 2) DEFAULT 1.0,
  consecutive_days INTEGER DEFAULT 1,
  is_first_time BOOLEAN DEFAULT false,
  weather_condition VARCHAR(50),
  temperature DECIMAL(5, 2),
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. 奖励记录表 (使用integer类型的user_id以兼容现有代码)
CREATE TABLE IF NOT EXISTS reward_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER NOT NULL, -- 使用integer类型以兼容现有的哈希转换逻辑
  reward_type VARCHAR(50) NOT NULL,
  reward_category VARCHAR(50) NOT NULL,
  points INTEGER NOT NULL DEFAULT 0,
  coins DECIMAL(10, 2) DEFAULT 0,
  cash_value DECIMAL(10, 2) DEFAULT 0,
  description TEXT NOT NULL,
  source_id UUID,
  source_type VARCHAR(50),
  location_id UUID REFERENCES user_locations(id) ON DELETE SET NULL,
  latitude DECIMAL(10, 8),
  longitude DECIMAL(11, 8),
  multiplier DECIMAL(3, 2) DEFAULT 1.0,
  expires_at TIMESTAMP WITH TIME ZONE,
  claimed_at TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) DEFAULT 'pending',
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. 用户统计表
CREATE TABLE IF NOT EXISTS user_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  total_points INTEGER DEFAULT 0,
  available_points INTEGER DEFAULT 0,
  total_coins DECIMAL(10, 2) DEFAULT 0,
  available_coins DECIMAL(10, 2) DEFAULT 0,
  total_checkins INTEGER DEFAULT 0,
  consecutive_checkins INTEGER DEFAULT 0,
  max_consecutive_checkins INTEGER DEFAULT 0,
  total_distance DECIMAL(10, 2) DEFAULT 0,
  unique_locations INTEGER DEFAULT 0,
  exploration_score INTEGER DEFAULT 0,
  social_score INTEGER DEFAULT 0,
  level_id INTEGER DEFAULT 1,
  experience_points INTEGER DEFAULT 0,
  last_checkin_at TIMESTAMP WITH TIME ZONE,
  last_location_update TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_user_locations_user_id ON user_locations(user_id);
CREATE INDEX IF NOT EXISTS idx_user_locations_coords ON user_locations(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_user_locations_current ON user_locations(user_id, is_current);

CREATE INDEX IF NOT EXISTS idx_checkin_records_user_id ON checkin_records(user_id);
CREATE INDEX IF NOT EXISTS idx_checkin_records_coords ON checkin_records(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_checkin_records_created_at ON checkin_records(created_at);
CREATE INDEX IF NOT EXISTS idx_checkin_records_user_date ON checkin_records(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_reward_records_user_id ON reward_records(user_id);
CREATE INDEX IF NOT EXISTS idx_reward_records_type ON reward_records(reward_type);
CREATE INDEX IF NOT EXISTS idx_reward_records_status ON reward_records(status);
CREATE INDEX IF NOT EXISTS idx_reward_records_created_at ON reward_records(created_at);
CREATE INDEX IF NOT EXISTS idx_reward_records_source ON reward_records(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_reward_records_location ON reward_records(latitude, longitude);

CREATE INDEX IF NOT EXISTS idx_user_stats_points ON user_stats(total_points);
CREATE INDEX IF NOT EXISTS idx_user_stats_level ON user_stats(level_id);
CREATE INDEX IF NOT EXISTS idx_user_stats_checkins ON user_stats(consecutive_checkins);

SELECT 'LBS系统表创建完成！' as message;