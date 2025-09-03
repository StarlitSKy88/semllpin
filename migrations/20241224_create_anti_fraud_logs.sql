-- 创建防作弊日志表
CREATE TABLE IF NOT EXISTS anti_fraud_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    geofence_id VARCHAR(50),
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
    violations JSONB DEFAULT '[]'::jsonb,
    detection_details JSONB DEFAULT '{}'::jsonb,
    is_valid BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_user_id ON anti_fraud_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_created_at ON anti_fraud_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_risk_level ON anti_fraud_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_is_valid ON anti_fraud_logs(is_valid);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_geofence_id ON anti_fraud_logs(geofence_id);

-- 创建复合索引用于查询优化
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_user_date ON anti_fraud_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_anti_fraud_logs_geofence_date ON anti_fraud_logs(geofence_id, created_at);

-- 添加表注释
COMMENT ON TABLE anti_fraud_logs IS '防作弊检测日志表';
COMMENT ON COLUMN anti_fraud_logs.id IS '主键ID';
COMMENT ON COLUMN anti_fraud_logs.user_id IS '用户ID';
COMMENT ON COLUMN anti_fraud_logs.geofence_id IS '地理围栏ID';
COMMENT ON COLUMN anti_fraud_logs.risk_score IS '风险评分(0-100)';
COMMENT ON COLUMN anti_fraud_logs.risk_level IS '风险等级: low, medium, high, critical';
COMMENT ON COLUMN anti_fraud_logs.violations IS '违规类型数组';
COMMENT ON COLUMN anti_fraud_logs.detection_details IS '检测详情JSON';
COMMENT ON COLUMN anti_fraud_logs.is_valid IS '是否通过检测';
COMMENT ON COLUMN anti_fraud_logs.created_at IS '创建时间';
COMMENT ON COLUMN anti_fraud_logs.updated_at IS '更新时间';

-- 创建更新时间触发器
CREATE OR REPLACE FUNCTION update_anti_fraud_logs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_anti_fraud_logs_updated_at
    BEFORE UPDATE ON anti_fraud_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_anti_fraud_logs_updated_at();

-- 添加设备信息字段到location_reports表（如果不存在）
ALTER TABLE location_reports 
ADD COLUMN IF NOT EXISTS device_info JSONB DEFAULT '{}'::jsonb;

-- 为device_info字段添加索引
CREATE INDEX IF NOT EXISTS idx_location_reports_device_info ON location_reports USING GIN(device_info);

-- 添加注释
COMMENT ON COLUMN location_reports.device_info IS '设备信息JSON，包含userAgent、platform等';