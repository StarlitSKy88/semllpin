# SmellPin GPS 防作弊系统

## 概述

SmellPin GPS 防作弊系统是一个全面的位置验证和欺诈检测系统，专门设计用于防止GPS位置欺骗和确保位置数据的真实性。该系统是SmellPin平台安全基础设施的核心组件。

## 系统架构

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   前端客户端     │ => │   Workers API    │ => │  Neon PostgreSQL │
│  设备指纹采集    │    │  防作弊验证      │    │   防作弊数据存储  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  防作弊服务组件   │
                       │ - GPS欺骗检测     │
                       │ - 行为模式分析    │
                       │ - 设备指纹识别    │
                       │ - 实时风险评分    │
                       └──────────────────┘
```

## 核心功能

### 1. GPS欺骗检测算法

#### 信号分析
- **精度异常检测**: 识别不可能的GPS精度值（< 1米或 > 1000米）
- **坐标精度分析**: 检测可疑的圆整坐标（小数位过少）
- **时间戳一致性**: 验证位置时间戳的合理性
- **设备能力匹配**: 验证设备类型与GPS精度的匹配性

#### 高级算法
```typescript
// 使用Vincenty公式进行高精度距离计算
const distance = calculateVincentyDistance(lat1, lng1, lat2, lng2);

// 多维度分析
const gpsAnalysis = GPSDetectionAlgorithms.analyzeGPSAuthenticity(
  location,
  deviceInfo,
  historyPoints,
  context
);
```

### 2. 用户行为模式分析

#### 移动模式验证
- **速度限制检查**: 检测不可能的移动速度（> 300 km/h）
- **位置跳跃检测**: 识别瞬间大距离移动
- **方向变化分析**: 检测不自然的方向变化模式
- **停留模式分析**: 验证停留和移动的自然性

#### 提交行为分析
- **频率分析**: 检测异常高频提交
- **时间模式**: 识别机器人式的规律性提交
- **设备切换**: 监控多设备使用模式

### 3. 设备指纹识别

#### 指纹生成
```typescript
const fingerprintData = {
  userAgent: deviceInfo.userAgent,
  screen: deviceInfo.screen,
  timezone: deviceInfo.timezone,
  language: deviceInfo.language,
  platform: deviceInfo.platform
};

const fingerprintHash = crypto
  .createHash('sha256')
  .update(JSON.stringify(fingerprintData))
  .digest('hex');
```

#### 设备一致性检查
- **多设备检测**: 识别用户使用过多设备
- **设备农场检测**: 发现批量自动化设备
- **指纹变化监控**: 跟踪设备特征变化

### 4. 实时风险评分系统

#### 风险因子权重
- **GPS欺骗检测**: 25% 权重
- **移动模式分析**: 20% 权重
- **设备一致性**: 20% 权重
- **行为模式**: 20% 权重
- **时间模式分析**: 15% 权重

#### 风险等级
- **0-25分**: 最小风险 - 标准处理
- **25-50分**: 低风险 - 标准处理但监控
- **50-75分**: 中等风险 - 需要人工审核
- **75-90分**: 高风险 - 拦截提交
- **90-100分**: 严重风险 - 阻止并标记账户

## API 接口

### 主要验证接口

#### POST /anti-fraud/verify-location
验证GPS位置的真实性

```typescript
// 请求示例
{
  "annotation_id": "550e8400-e29b-41d4-a716-446655440000",
  "location": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "accuracy": 10,
    "altitude": 100,
    "speed": 0,
    "heading": 45,
    "timestamp": 1640995200000
  },
  "device_info": {
    "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
    "screen": {
      "width": 390,
      "height": 844,
      "colorDepth": 24,
      "pixelRatio": 3
    },
    "timezone": "America/New_York",
    "language": "en-US",
    "platform": "iPhone",
    "cookieEnabled": true,
    "plugins": ["Plugin1", "Plugin2"]
  }
}

// 响应示例
{
  "success": true,
  "verification_result": {
    "status": "passed", // "passed" | "failed" | "manual_review"
    "risk_score": 15,
    "risk_level": "low",
    "requires_manual_review": false,
    "decision_reason": "Location verification passed",
    "risk_factors": {
      "gps_spoofing_detected": false,
      "impossible_speed": false,
      "location_jump_detected": false,
      "device_inconsistency": false,
      "behavioral_anomaly": false,
      "poor_gps_accuracy": false,
      "rapid_submissions": false,
      "mock_location_detected": false
    },
    "auto_action": "none" // "none" | "flag" | "block" | "suspend"
  },
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

### 用户风险查询

#### GET /anti-fraud/user-risk/:userId
获取用户风险档案

```typescript
// 响应示例
{
  "success": true,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "risk_score": 25,
  "risk_level": "low",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

### 管理接口（仅管理员）

#### GET /anti-fraud/incidents
获取欺诈事件列表

#### GET /anti-fraud/stats  
获取防作弊统计数据

#### POST /anti-fraud/manual-review/:verificationId
提交人工审核决定

## 数据库架构

### 核心表结构

```sql
-- 设备指纹表
CREATE TABLE device_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    fingerprint_hash VARCHAR(64) NOT NULL,
    device_info JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT false,
    risk_score INTEGER DEFAULT 0
);

-- 位置历史表
CREATE TABLE location_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    device_fingerprint_id UUID REFERENCES device_fingerprints(id),
    location POINT NOT NULL, -- PostGIS point
    accuracy_meters REAL,
    altitude_meters REAL,
    speed_mps REAL,
    heading_degrees REAL,
    timestamp_recorded TIMESTAMP WITH TIME ZONE NOT NULL,
    source VARCHAR(50) DEFAULT 'gps'
);

-- GPS验证记录表
CREATE TABLE gps_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    annotation_id UUID REFERENCES annotations(id),
    submitted_location POINT NOT NULL,
    verification_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_factors JSONB DEFAULT '{}',
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    decision_reason TEXT
);

-- 用户风险档案表
CREATE TABLE user_risk_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) UNIQUE,
    overall_risk_score INTEGER NOT NULL DEFAULT 0,
    trust_level VARCHAR(20) DEFAULT 'neutral',
    total_submissions INTEGER DEFAULT 0,
    verified_submissions INTEGER DEFAULT 0,
    fraud_incidents_count INTEGER DEFAULT 0,
    device_consistency_score INTEGER DEFAULT 100,
    location_pattern_score INTEGER DEFAULT 50,
    behavioral_score INTEGER DEFAULT 50,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## 部署和配置

### 环境变量
```bash
DATABASE_URL=postgresql://username:password@localhost:5432/database
JWT_SECRET=your-jwt-secret
ENVIRONMENT=production
```

### 数据库迁移
```bash
# 运行防作弊系统表迁移
psql -d $DATABASE_URL -f migrations/007-create-anti-fraud-tables.sql
```

### 初始化
```typescript
// 初始化防作弊服务
const antiFraudService = new AntiFraudService(env);

// 初始化表结构（如果需要）
await antiFraudService.initializeAntiFraudTables();
```

## 集成指南

### 前端集成

#### 设备信息收集
```javascript
// 收集设备指纹信息
const deviceInfo = {
  userAgent: navigator.userAgent,
  screen: {
    width: screen.width,
    height: screen.height,
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio
  },
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  language: navigator.language,
  platform: navigator.platform,
  cookieEnabled: navigator.cookieEnabled,
  plugins: Array.from(navigator.plugins).map(p => p.name)
};
```

#### GPS位置获取
```javascript
// 获取高精度GPS位置
navigator.geolocation.getCurrentPosition(
  (position) => {
    const location = {
      latitude: position.coords.latitude,
      longitude: position.coords.longitude,
      accuracy: position.coords.accuracy,
      altitude: position.coords.altitude,
      speed: position.coords.speed,
      heading: position.coords.heading,
      timestamp: position.timestamp
    };
    
    // 发送到防作弊验证
    verifyLocation(location, deviceInfo);
  },
  (error) => console.error('GPS error:', error),
  {
    enableHighAccuracy: true,
    timeout: 10000,
    maximumAge: 60000
  }
);
```

### 后端集成

#### 注解创建验证
```typescript
// 在创建注解前进行GPS验证
app.post('/annotations', authenticateJWT, async (c) => {
  const user = c.get('user');
  const data = await c.req.json();
  
  // GPS位置验证
  const antiFraudService = new AntiFraudService(c.env);
  const verification = await antiFraudService.verifyGPSLocation({
    user_id: user.id,
    annotation_id: crypto.randomUUID(),
    location: data.location,
    device_info: data.device_info,
    ip_address: c.req.header('CF-Connecting-IP') || 'unknown'
  });
  
  // 根据验证结果决定处理方式
  if (verification.verification_status === 'failed') {
    return c.json({
      success: false,
      error: 'Location verification failed',
      reason: verification.decision_reason
    }, 400);
  }
  
  if (verification.verification_status === 'manual_review') {
    // 标记为需要人工审核
    data.review_required = true;
  }
  
  // 继续正常创建注解...
});
```

## 监控和告警

### 系统监控指标
- **验证成功率**: 通过/失败/需审核的比例
- **风险分布**: 各风险等级的用户分布
- **欺诈检测率**: 检测到的欺诈案例数量
- **响应时间**: GPS验证处理时间
- **设备多样性**: 用户设备使用模式

### 告警规则
```typescript
// 高风险用户告警
if (riskScore >= 80) {
  sendAlert({
    type: 'high_risk_user',
    user_id: userId,
    risk_score: riskScore,
    timestamp: new Date()
  });
}

// 批量欺诈检测告警
if (fraudIncidentsInLastHour > 10) {
  sendAlert({
    type: 'fraud_spike',
    incident_count: fraudIncidentsInLastHour,
    timestamp: new Date()
  });
}
```

## 性能优化

### 缓存策略
- **用户风险档案缓存**: 10分钟TTL
- **设备指纹缓存**: 30分钟TTL
- **检测规则缓存**: 1小时TTL

### 数据库优化
```sql
-- 重要索引
CREATE INDEX idx_location_history_user_timestamp 
ON location_history(user_id, timestamp_recorded);

CREATE INDEX idx_gps_verifications_status_timestamp 
ON gps_verifications(verification_status, verification_timestamp);

CREATE INDEX idx_device_fingerprints_user_lastseen 
ON device_fingerprints(user_id, last_seen);
```

### 异步处理
```typescript
// 风险评估异步处理
const backgroundAnalysis = async (userId: string) => {
  const context: RiskAssessmentContext = {
    user_id: userId,
    assessment_time: new Date(),
    lookback_period_days: 30,
    include_device_analysis: true,
    include_behavioral_analysis: true,
    include_location_analysis: true
  };
  
  const assessment = await riskAssessmentService.assessUserRisk(context);
  // 更新用户风险档案...
};
```

## 安全考虑

### 数据隐私
- 位置数据加密存储
- 设备指纹哈希化
- 定期清理历史数据
- 遵循GDPR/隐私法规

### 防绕过措施
- 多重验证机制
- 动态检测规则
- 机器学习增强
- 实时规则更新

## 故障排除

### 常见问题

#### 1. 验证失败率过高
```bash
# 检查GPS精度阈值设置
SELECT AVG(accuracy_meters) FROM location_history WHERE accuracy_meters IS NOT NULL;

# 调整检测规则
UPDATE antifraud_rules 
SET rule_config = '{"min_gps_accuracy": 200}' 
WHERE rule_name = 'GPS Accuracy Check';
```

#### 2. 性能问题
```bash
# 检查数据库查询性能
EXPLAIN ANALYZE SELECT * FROM gps_verifications 
WHERE user_id = 'xxx' AND verification_timestamp >= NOW() - INTERVAL '1 hour';

# 添加缺失的索引
CREATE INDEX IF NOT EXISTS idx_missing_index ON table_name(column_name);
```

#### 3. 误报问题
```typescript
// 调整风险阈值
const RISK_THRESHOLDS = {
  LOW: 30,      // 从25提高到30
  MEDIUM: 55,   // 从50提高到55
  HIGH: 80,     // 从75提高到80
  CRITICAL: 95  // 从90提高到95
};
```

## 未来增强

### 机器学习集成
- 基于历史数据训练欺诈检测模型
- 异常行为模式自动识别
- 动态风险阈值调整

### 地理围栏增强
- 与现有地理围栏系统深度集成
- 基于区域的风险评估
- 热点区域监控

### 实时流处理
- Apache Kafka/Redis Streams集成
- 实时异常检测
- 流式数据分析

---

*该文档最后更新于: 2024年1月*

**版本**: v1.0.0  
**维护者**: SmellPin开发团队  
**许可证**: 专有软件