# SmellPin 实时奖励分发引擎

这是SmellPin项目的核心商业化功能，实现了完整的实时奖励分发引擎和奖励池管理系统。

## 功能概述

### 🎯 核心功能
1. **动态奖励计算算法** - 根据多种因素实时计算奖励金额
2. **奖励池管理系统** - 管理每个标注的资金池和分配
3. **实时分发机制** - 在用户进入地理围栏时立即分发奖励
4. **防重复奖励系统** - 确保每个用户对同一标注只能获得一次奖励
5. **完整的审计日志** - 记录所有奖励操作和资金流动

### ⚡ 技术特点
- 与现有地理围栏系统无缝集成
- 集成防作弊系统，自动检测可疑行为
- 支持事务处理，确保数据一致性
- 高性能缓存机制，提升响应速度
- 完整的错误处理和异常恢复

## 系统架构

```
┌─────────────────────────────────────┐
│          前端应用                    │
│    (地理位置触发奖励请求)              │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│        API 路由层                   │
│     /rewards/* 端点                 │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│      奖励分发引擎                   │
│  RewardDistributionEngine           │
│  • 地理围栏验证                      │
│  • 防作弊检查                       │
│  • 动态奖励计算                      │
│  • 实时分发执行                      │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│      奖励池管理器                    │
│    RewardPoolManager                │
│  • 资金池管理                       │
│  • 余额追踪                         │
│  • 自动补充                         │
│  • 操作审计                         │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│      PostgreSQL 数据库              │
│  • reward_distributions             │
│  • reward_pools                     │
│  • reward_configurations            │
│  • user_reward_statistics           │
└─────────────────────────────────────┘
```

## 数据库表结构

### 奖励分发记录表 (reward_distributions)
```sql
CREATE TABLE reward_distributions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  annotation_id UUID NOT NULL,
  reward_amount DECIMAL(10, 2) NOT NULL,
  distribution_method VARCHAR(50) DEFAULT 'geofence_trigger',
  geofence_distance DECIMAL(10, 2),
  fraud_risk_score DECIMAL(3, 2),
  user_level_at_distribution INTEGER,
  status VARCHAR(20) DEFAULT 'completed',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  metadata JSONB DEFAULT '{}',
  UNIQUE(user_id, annotation_id) -- 防重复约束
);
```

### 奖励池状态表 (reward_pools)
```sql
CREATE TABLE reward_pools (
  id UUID PRIMARY KEY,
  annotation_id UUID NOT NULL UNIQUE,
  current_balance DECIMAL(10, 2) DEFAULT 0,
  reserved_amount DECIMAL(10, 2) DEFAULT 0,
  total_deposited DECIMAL(10, 2) DEFAULT 0,
  total_distributed DECIMAL(10, 2) DEFAULT 0,
  total_withdrawn DECIMAL(10, 2) DEFAULT 0,
  last_activity_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 奖励配置表 (reward_configurations)
```sql
CREATE TABLE reward_configurations (
  id UUID PRIMARY KEY,
  annotation_id UUID NOT NULL UNIQUE,
  base_fee DECIMAL(10, 2) DEFAULT 1.0,
  time_decay_factor DECIMAL(3, 2) DEFAULT 0.95,
  user_level_multiplier DECIMAL(3, 2) DEFAULT 1.0,
  max_rewards_per_day INTEGER DEFAULT 10,
  min_reward_amount DECIMAL(10, 2) DEFAULT 0.10,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## API 端点

### 奖励分发
```http
POST /rewards/distribute
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "annotation_id": "uuid",
  "user_location": {
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "trigger_timestamp": "2025-09-01T10:00:00Z" // 可选
}
```

**响应示例:**
```json
{
  "success": true,
  "data": {
    "success": true,
    "reward_id": "reward-uuid",
    "user_id": "user-uuid",
    "annotation_id": "annotation-uuid",
    "calculated_reward": 1.85,
    "actual_reward": 1.85,
    "distribution_reason": "Reward distributed successfully",
    "geofence_verification": {
      "is_within_geofence": true,
      "distance_meters": 45.2,
      "reward_eligible": true,
      "reward_radius": 100
    },
    "fraud_check_result": {
      "is_suspicious": false,
      "risk_score": 0.12,
      "flags": []
    },
    "metadata": {
      "user_level": 3,
      "time_decay_applied": 0.93,
      "pool_balance_before": 15.50,
      "pool_balance_after": 13.65,
      "daily_reward_count": 2
    }
  }
}
```

### 创建奖励池
```http
POST /rewards/pools
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "annotation_id": "uuid",
  "initial_pool_size": 20.00,
  "min_pool_threshold": 2.00,
  "max_pool_size": 100.00,
  "auto_refill_enabled": true,
  "refill_threshold": 0.2,
  "commission_rate": 0.3
}
```

### 查询奖励池状态
```http
GET /rewards/pools/status?annotation_id=uuid
```

### 向奖励池存入资金
```http
POST /rewards/pools/deposit
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "annotation_id": "uuid",
  "amount": 10.00,
  "source": "user_deposit",
  "description": "Additional funding for rewards"
}
```

### 获取奖励历史
```http
GET /rewards/history?user_id=uuid&limit=20&offset=0
Authorization: Bearer <jwt_token>
```

### 获取奖励统计
```http
GET /rewards/statistics?start_date=2025-08-01&end_date=2025-09-01
Authorization: Bearer <jwt_token>
```

### 配置奖励参数
```http
POST /rewards/configure
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "annotation_id": "uuid",
  "base_fee": 2.50,
  "time_decay_factor": 0.90,
  "max_rewards_per_day": 15,
  "min_reward_amount": 0.25
}
```

### 获取奖励池分析
```http
GET /rewards/pools/analytics?annotation_id=uuid&days=30
Authorization: Bearer <jwt_token>
```

## 奖励计算算法

### 动态奖励计算公式

```javascript
reward_amount = base_fee * 0.7 * factors

factors = time_decay_factor^days_since_creation 
        * user_level_multiplier 
        * distance_factor 
        * fraud_penalty 
        * category_multiplier 
        * scarcity_multiplier
```

### 各因子说明

1. **基础金额** (`base_fee * 0.7`): 标注费用的70%作为奖励池
2. **时间衰减** (`time_decay_factor^days`): 每天衰减5%（默认0.95）
3. **用户等级倍数**: 新手1.0x，专家2.0x
4. **距离奖励**: 距离越近奖励越高（最大200米）
5. **反作弊惩罚**: 风险评分越高奖励越少
6. **分类倍数**: 化学气味2.0x，垃圾1.3x等
7. **稀缺性奖励**: 该区域标注越少奖励越高

### 用户等级系统

| 等级 | 条件 | 倍数 |
|-----|------|------|
| 1 - 新手 | 总收入 < $5 或 奖励次数 < 3 | 1.0x |
| 2 - 普通 | 总收入 $5-20 或 奖励次数 3-10 | 1.1x |
| 3 - 活跃 | 总收入 $20-50 或 奖励次数 10-25 | 1.25x |
| 4 - 专家 | 总收入 $50-100 或 奖励次数 25-50 | 1.5x |
| 5 - 大师 | 总收入 > $100 或 奖励次数 > 50 | 2.0x |

## 部署和初始化

### 1. 运行数据库迁移

```bash
# 执行迁移脚本
psql -f workers/migrations/008-create-reward-system-tables.sql

# 或通过API初始化
curl -X POST "https://your-api.com/admin/rewards/initialize" \
  -H "Authorization: Bearer <admin_token>"
```

### 2. 环境变量配置

```env
DATABASE_URL=postgresql://user:password@host:port/database
JWT_SECRET=your_jwt_secret
ENVIRONMENT=production
```

### 3. 验证系统健康状态

```http
GET /admin/rewards/health
Authorization: Bearer <admin_token>
```

## 安全考虑

### 防作弊机制
1. **地理围栏验证**: 必须在指定半径内
2. **位置模式分析**: 检测异常移动模式
3. **频率限制**: 每日奖励次数限制
4. **风险评分**: 综合多种因素评估用户风险
5. **行为分析**: 检测刷奖励等可疑行为

### 资金安全
1. **事务处理**: 所有资金操作支持原子性
2. **余额验证**: 严格验证可用余额
3. **操作审计**: 完整记录所有资金流动
4. **权限控制**: 分级权限管理
5. **异常监控**: 实时监控异常操作

## 性能优化

### 缓存策略
- **奖励池状态缓存**: 2分钟TTL
- **分发防重复缓存**: 30分钟TTL
- **用户信息缓存**: 5分钟TTL
- **地理围栏配置缓存**: 5分钟TTL

### 数据库优化
- **复合索引**: 支持复杂查询
- **分区表**: 按时间分区大表
- **连接池**: 复用数据库连接
- **查询优化**: 避免N+1问题

## 监控和运维

### 关键指标监控
1. **奖励分发成功率**
2. **奖励池余额预警**
3. **API响应时间**
4. **作弊检测准确率**
5. **用户参与度**

### 日志记录
- **操作日志**: 所有API调用
- **错误日志**: 异常和失败操作
- **审计日志**: 资金变动记录
- **性能日志**: 响应时间统计

### 管理工具
```http
# 清理缓存
DELETE /admin/rewards/cache

# 系统健康检查
GET /admin/rewards/health

# 奖励系统统计
GET /rewards/statistics
```

## 故障排除

### 常见问题

1. **奖励分发失败**
   - 检查地理围栏配置
   - 验证用户认证状态
   - 确认奖励池余额充足

2. **奖励金额异常**
   - 检查奖励配置参数
   - 验证用户等级计算
   - 确认时间衰减设置

3. **性能问题**
   - 检查缓存命中率
   - 监控数据库连接数
   - 优化查询索引

### 调试工具

```javascript
// 检查用户奖励资格
const checkEligibility = async (userId, annotationId, location) => {
  const response = await fetch('/rewards/distribute', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      annotation_id: annotationId,
      user_location: location
    })
  });
  
  const result = await response.json();
  console.log('奖励资格检查:', result);
  return result;
};

// 检查奖励池状态
const checkPoolStatus = async (annotationId) => {
  const response = await fetch(`/rewards/pools/status?annotation_id=${annotationId}`);
  const result = await response.json();
  console.log('奖励池状态:', result);
  return result;
};
```

## 扩展开发

### 自定义奖励策略

```typescript
// 自定义奖励计算器
class CustomRewardCalculator {
  calculateReward(params: RewardCalculationParams): number {
    // 实现自定义奖励逻辑
    return baseAmount * customMultiplier;
  }
}

// 注册自定义策略
rewardEngine.registerStrategy('custom', new CustomRewardCalculator());
```

### 扩展反作弊规则

```typescript
// 自定义反作弊检测器
class CustomFraudDetector {
  async analyzeUserBehavior(userId: string, context: any): Promise<FraudCheckResult> {
    // 实现自定义检测逻辑
    return {
      is_suspicious: false,
      risk_score: 0.1,
      flags: []
    };
  }
}
```

## 版本更新日志

### v1.0.0 (2025-09-01)
- ✅ 实现核心奖励分发引擎
- ✅ 完成奖励池管理系统
- ✅ 集成地理围栏验证
- ✅ 添加防作弊检测
- ✅ 支持动态奖励计算
- ✅ 完整的API端点
- ✅ 数据库迁移脚本
- ✅ 综合测试套件

## 贡献指南

1. Fork 项目仓库
2. 创建特性分支 (`git checkout -b feature/reward-enhancement`)
3. 提交更改 (`git commit -am 'Add reward enhancement'`)
4. 推送到分支 (`git push origin feature/reward-enhancement`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](../LICENSE) 文件

---

**联系方式**
- 项目主页: [SmellPin](https://github.com/your-org/smellpin)
- 问题反馈: [Issues](https://github.com/your-org/smellpin/issues)
- 文档: [Wiki](https://github.com/your-org/smellpin/wiki)