-- ========================================
-- 创建实时奖励分发系统数据库表
-- 迁移编号: 008
-- 创建时间: 2025-09-01
-- 描述: 为SmellPin项目添加完整的实时奖励分发引擎和奖励池管理系统
-- ========================================

-- 开始事务
BEGIN;

-- ========================================
-- 第一部分：奖励分发系统表
-- ========================================

-- 1. 奖励分发记录表
-- 记录所有奖励分发的详细信息，包括地理围栏验证和反作弊检查结果
CREATE TABLE IF NOT EXISTS reward_distributions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
  reward_amount DECIMAL(10, 2) NOT NULL,
  distribution_method VARCHAR(50) NOT NULL DEFAULT 'geofence_trigger',
  geofence_distance DECIMAL(10, 2),
  fraud_risk_score DECIMAL(3, 2) DEFAULT 0,
  user_level_at_distribution INTEGER DEFAULT 1,
  status VARCHAR(20) DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  metadata JSONB DEFAULT '{}'::jsonb,
  
  -- 防止重复奖励的唯一约束
  UNIQUE(user_id, annotation_id)
);

-- 为奖励分发表创建索引
CREATE INDEX IF NOT EXISTS idx_reward_distributions_user_id ON reward_distributions(user_id);
CREATE INDEX IF NOT EXISTS idx_reward_distributions_annotation_id ON reward_distributions(annotation_id);
CREATE INDEX IF NOT EXISTS idx_reward_distributions_created_at ON reward_distributions(created_at);
CREATE INDEX IF NOT EXISTS idx_reward_distributions_status ON reward_distributions(status);
CREATE INDEX IF NOT EXISTS idx_reward_distributions_method ON reward_distributions(distribution_method);

-- 2. 奖励配置表
-- 存储每个标注的奖励算法参数配置
CREATE TABLE IF NOT EXISTS reward_configurations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  annotation_id UUID NOT NULL UNIQUE REFERENCES annotations(id) ON DELETE CASCADE,
  base_fee DECIMAL(10, 2) DEFAULT 1.0,
  time_decay_factor DECIMAL(3, 2) DEFAULT 0.95,
  user_level_multiplier DECIMAL(3, 2) DEFAULT 1.0,
  max_rewards_per_day INTEGER DEFAULT 10,
  min_reward_amount DECIMAL(10, 2) DEFAULT 0.10,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 为奖励配置表创建索引
CREATE INDEX IF NOT EXISTS idx_reward_configurations_annotation_id ON reward_configurations(annotation_id);

-- 3. 用户奖励统计表
-- 跟踪每个用户的奖励统计信息
CREATE TABLE IF NOT EXISTS user_reward_statistics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  total_rewards_received INTEGER DEFAULT 0,
  total_reward_amount DECIMAL(10, 2) DEFAULT 0,
  last_reward_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 为用户奖励统计表创建索引
CREATE INDEX IF NOT EXISTS idx_user_reward_statistics_user_id ON user_reward_statistics(user_id);
CREATE INDEX IF NOT EXISTS idx_user_reward_statistics_total_amount ON user_reward_statistics(total_reward_amount);

-- ========================================
-- 第二部分：奖励池管理系统表
-- ========================================

-- 4. 奖励池状态表
-- 跟踪每个标注奖励池的当前状态
CREATE TABLE IF NOT EXISTS reward_pools (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  annotation_id UUID NOT NULL UNIQUE REFERENCES annotations(id) ON DELETE CASCADE,
  current_balance DECIMAL(10, 2) DEFAULT 0,
  reserved_amount DECIMAL(10, 2) DEFAULT 0,
  total_deposited DECIMAL(10, 2) DEFAULT 0,
  total_distributed DECIMAL(10, 2) DEFAULT 0,
  total_withdrawn DECIMAL(10, 2) DEFAULT 0,
  last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 为奖励池状态表创建索引
CREATE INDEX IF NOT EXISTS idx_reward_pools_annotation_id ON reward_pools(annotation_id);
CREATE INDEX IF NOT EXISTS idx_reward_pools_balance ON reward_pools(current_balance);
CREATE INDEX IF NOT EXISTS idx_reward_pools_activity ON reward_pools(last_activity_at);

-- 5. 奖励池配置表
-- 存储奖励池的规则和配置参数
CREATE TABLE IF NOT EXISTS reward_pool_configurations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  annotation_id UUID NOT NULL UNIQUE REFERENCES annotations(id) ON DELETE CASCADE,
  initial_pool_size DECIMAL(10, 2) NOT NULL,
  min_pool_threshold DECIMAL(10, 2) DEFAULT 0,
  max_pool_size DECIMAL(10, 2) DEFAULT 1000,
  auto_refill_enabled BOOLEAN DEFAULT true,
  refill_threshold DECIMAL(3, 2) DEFAULT 0.2,
  commission_rate DECIMAL(3, 2) DEFAULT 0.3,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 为奖励池配置表创建索引
CREATE INDEX IF NOT EXISTS idx_reward_pool_configs_annotation_id ON reward_pool_configurations(annotation_id);

-- 6. 奖励池操作记录表
-- 记录所有奖励池相关的操作历史，用于审计和分析
CREATE TABLE IF NOT EXISTS reward_pool_operations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
  operation_type VARCHAR(20) NOT NULL CHECK (operation_type IN ('deposit', 'withdraw', 'reserve', 'release', 'distribute', 'refill')),
  amount DECIMAL(10, 2) NOT NULL,
  source VARCHAR(100) NOT NULL,
  description TEXT,
  balance_before DECIMAL(10, 2) NOT NULL,
  balance_after DECIMAL(10, 2) NOT NULL,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 为奖励池操作记录表创建索引
CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_annotation_id ON reward_pool_operations(annotation_id);
CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_created_at ON reward_pool_operations(created_at);
CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_operation_type ON reward_pool_operations(operation_type);
CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_source ON reward_pool_operations(source);

-- ========================================
-- 第三部分：增强现有表结构
-- ========================================

-- 7. 增强钱包表结构（如果需要的话）
-- 为钱包表添加货币字段和更新时间戳（如果不存在）
DO $$
BEGIN
    -- 检查并添加货币字段
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'wallets' AND column_name = 'currency') THEN
        ALTER TABLE wallets ADD COLUMN currency VARCHAR(10) DEFAULT 'usd';
    END IF;
    
    -- 检查并添加更新时间戳
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'wallets' AND column_name = 'updated_at') THEN
        ALTER TABLE wallets ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
    END IF;
END
$$;

-- 8. 增强交易表结构
-- 为交易表添加必要的字段（如果不存在）
DO $$
BEGIN
    -- 检查并添加货币字段
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'transactions' AND column_name = 'currency') THEN
        ALTER TABLE transactions ADD COLUMN currency VARCHAR(10) DEFAULT 'usd';
    END IF;
    
    -- 检查并添加完成时间字段
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'transactions' AND column_name = 'completed_at') THEN
        ALTER TABLE transactions ADD COLUMN completed_at TIMESTAMP WITH TIME ZONE;
    END IF;
    
    -- 检查并添加元数据字段
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'transactions' AND column_name = 'metadata') THEN
        ALTER TABLE transactions ADD COLUMN metadata JSONB DEFAULT '{}'::jsonb;
    END IF;
END
$$;

-- ========================================
-- 第四部分：创建触发器和函数
-- ========================================

-- 9. 创建自动更新时间戳的触发器函数
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 为需要的表创建更新时间戳触发器
CREATE TRIGGER update_reward_distributions_updated_at
    BEFORE UPDATE ON reward_distributions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reward_configurations_updated_at
    BEFORE UPDATE ON reward_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_reward_statistics_updated_at
    BEFORE UPDATE ON user_reward_statistics
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reward_pools_updated_at
    BEFORE UPDATE ON reward_pools
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reward_pool_configurations_updated_at
    BEFORE UPDATE ON reward_pool_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ========================================
-- 第五部分：数据完整性约束
-- ========================================

-- 10. 添加检查约束以确保数据完整性
ALTER TABLE reward_distributions 
ADD CONSTRAINT check_reward_amount_positive 
CHECK (reward_amount >= 0);

ALTER TABLE reward_distributions 
ADD CONSTRAINT check_fraud_risk_score_range 
CHECK (fraud_risk_score >= 0 AND fraud_risk_score <= 1);

ALTER TABLE reward_distributions 
ADD CONSTRAINT check_user_level_range 
CHECK (user_level_at_distribution >= 1 AND user_level_at_distribution <= 5);

ALTER TABLE reward_configurations 
ADD CONSTRAINT check_time_decay_factor_range 
CHECK (time_decay_factor >= 0 AND time_decay_factor <= 1);

ALTER TABLE reward_configurations 
ADD CONSTRAINT check_user_level_multiplier_positive 
CHECK (user_level_multiplier > 0);

ALTER TABLE reward_pools 
ADD CONSTRAINT check_balances_non_negative 
CHECK (current_balance >= 0 AND reserved_amount >= 0 AND total_deposited >= 0 AND total_distributed >= 0 AND total_withdrawn >= 0);

ALTER TABLE reward_pools 
ADD CONSTRAINT check_reserved_amount_valid 
CHECK (reserved_amount <= current_balance);

ALTER TABLE reward_pool_configurations 
ADD CONSTRAINT check_thresholds_valid 
CHECK (refill_threshold >= 0 AND refill_threshold <= 1 AND commission_rate >= 0 AND commission_rate <= 1);

ALTER TABLE reward_pool_operations 
ADD CONSTRAINT check_operation_amount_positive 
CHECK (amount >= 0);

-- ========================================
-- 第六部分：初始化数据
-- ========================================

-- 11. 为现有的标注创建默认奖励池（如果需要）
-- 这个步骤是可选的，因为奖励池可以按需创建
-- INSERT INTO reward_pools (annotation_id, current_balance, total_deposited)
-- SELECT id, COALESCE(current_reward_pool, 0), COALESCE(payment_amount * 0.7, 0)
-- FROM annotations 
-- WHERE status = 'active' 
-- AND id NOT IN (SELECT annotation_id FROM reward_pools);

-- 12. 创建索引以支持复杂查询
-- 复合索引用于优化常见的查询模式
CREATE INDEX IF NOT EXISTS idx_reward_distributions_user_date 
ON reward_distributions(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reward_distributions_annotation_status 
ON reward_distributions(annotation_id, status);

CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_annotation_type_date 
ON reward_pool_operations(annotation_id, operation_type, created_at DESC);

-- 用于地理查询的索引（如果启用PostGIS）
-- CREATE INDEX IF NOT EXISTS idx_reward_distributions_location 
-- ON reward_distributions USING GIST(ST_Point(geofence_distance, 0)) 
-- WHERE geofence_distance IS NOT NULL;

-- ========================================
-- 第七部分：权限和安全
-- ========================================

-- 13. 创建视图以便安全访问敏感数据
-- 奖励分发汇总视图（隐藏敏感信息）
CREATE OR REPLACE VIEW reward_distribution_summary AS
SELECT 
    rd.id,
    rd.user_id,
    rd.annotation_id,
    rd.reward_amount,
    rd.distribution_method,
    rd.user_level_at_distribution,
    rd.status,
    rd.created_at,
    u.username,
    a.smell_category,
    a.location->>'latitude' as annotation_latitude,
    a.location->>'longitude' as annotation_longitude
FROM reward_distributions rd
LEFT JOIN users u ON rd.user_id = u.id
LEFT JOIN annotations a ON rd.annotation_id = a.id
WHERE rd.status = 'completed';

-- 奖励池状态汇总视图
CREATE OR REPLACE VIEW reward_pool_summary AS
SELECT 
    rp.annotation_id,
    rp.current_balance,
    rp.total_distributed,
    rp.last_activity_at,
    rpc.initial_pool_size,
    rpc.auto_refill_enabled,
    a.content as annotation_content,
    a.smell_category,
    a.created_at as annotation_created_at,
    u.username as annotation_creator
FROM reward_pools rp
LEFT JOIN reward_pool_configurations rpc ON rp.annotation_id = rpc.annotation_id
LEFT JOIN annotations a ON rp.annotation_id = a.id
LEFT JOIN users u ON a.user_id = u.id;

-- ========================================
-- 第八部分：性能优化
-- ========================================

-- 14. 分析表以更新统计信息
ANALYZE reward_distributions;
ANALYZE reward_configurations;
ANALYZE user_reward_statistics;
ANALYZE reward_pools;
ANALYZE reward_pool_configurations;
ANALYZE reward_pool_operations;

-- 提交事务
COMMIT;

-- ========================================
-- 迁移完成日志
-- ========================================
INSERT INTO migration_log (version, description, executed_at) 
VALUES ('008', 'Create reward system tables with distribution engine and pool management', NOW())
ON CONFLICT DO NOTHING;

-- 输出完成信息
SELECT '实时奖励分发系统数据库迁移完成！' as message,
       '已创建6个核心表、多个索引、触发器和视图' as details,
       '支持动态奖励计算、奖励池管理、防重复分发和完整审计日志' as features;