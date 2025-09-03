# SmellPin 社交互动功能文档

## 概述

SmellPin 项目已成功集成完善的社交互动功能，旨在提升用户粘性和实现病毒式增长。本文档详细介绍了所有新增的社交功能及其技术实现。

## 功能概览

### 1. 用户关注系统 👥
- ✅ 关注/取消关注用户
- ✅ 粉丝列表和关注列表查看
- ✅ 共同关注者推荐
- ✅ 关注状态实时更新

**API端点:**
- `POST /api/v1/social/follow/:userId` - 关注用户
- `DELETE /api/v1/social/follow/:userId` - 取消关注
- `GET /api/v1/social/following/:userId` - 获取关注列表
- `GET /api/v1/social/followers/:userId` - 获取粉丝列表

### 2. 用户动态流系统 📱
- ✅ 关注用户的活动动态
- ✅ 个人活动时间线
- ✅ 多种动态类型：标注、点赞、评论、关注、分享
- ✅ 隐私级别控制（公开/仅关注者/私有）

**核心组件:**
- `UserFeedModel` - 动态流数据模型
- `FeedController` - 动态流控制器

**API端点:**
- `GET /api/v1/feed` - 获取用户动态流
- `GET /api/v1/users/:userId/activity` - 获取用户活动历史

### 3. 评论和点赞系统 💬❤️
- ✅ 标注评论功能（支持回复）
- ✅ 评论点赞系统
- ✅ 标注点赞和收藏
- ✅ 实时通知推送

**增强功能:**
- 评论嵌套回复
- 点赞数统计和缓存
- 评论排序（最新/最热/点赞数）
- 垃圾评论过滤

### 4. 用户个人资料页面 👤
- ✅ 完整的用户资料展示
- ✅ 社交统计数据
- ✅ 用户成就系统
- ✅ 隐私设置控制

**统计数据包括:**
- 标注数量、评论数量、点赞数
- 关注者和关注数量
- 声誉分数和活跃度
- 个人成就徽章

**API端点:**
- `GET /api/v1/users/:userId/profile` - 获取用户资料
- `PUT /api/v1/users/:userId/profile` - 更新资料
- `GET /api/v1/users/:userId/achievements` - 获取成就
- `GET /api/v1/users/:userId/timeline` - 活动时间线

### 5. 社交推荐算法 🤖
- ✅ 智能用户推荐
- ✅ 个性化内容推荐
- ✅ 基于地理位置的推荐
- ✅ 兴趣标签匹配

**推荐策略:**
- 共同关注推荐（40%权重）
- 兴趣相似度推荐（40%权重）
- 地理位置推荐（30%权重）
- 活跃用户推荐（30%权重）

**API端点:**
- `GET /api/v1/recommendations/users` - 用户推荐
- `GET /api/v1/recommendations/content` - 内容推荐
- `GET /api/v1/recommendations/users/nearby` - 附近用户
- `GET /api/v1/recommendations/content/trending` - 热门内容

### 6. 隐私设置和内容审核 🛡️
- ✅ 细粒度隐私控制
- ✅ 内容举报系统
- ✅ 管理员审核工具
- ✅ 自动内容过滤

**隐私设置:**
- 资料可见性（公开/仅关注者/私有）
- 活动可见性控制
- 位置信息隐私设置

**审核功能:**
- 用户举报内容
- 管理员审核队列
- 自动垃圾内容检测
- 违规用户警告系统

**API端点:**
- `POST /api/v1/moderation/reports` - 举报内容
- `GET /api/v1/moderation/queue` - 审核队列（管理员）
- `POST /api/v1/moderation/reports/:id/moderate` - 处理举报

### 7. 实时通知系统 🔔
- ✅ WebSocket 实时推送
- ✅ 多类型通知支持
- ✅ 通知优先级管理
- ✅ 邮件通知集成

**通知类型:**
- 新关注者通知
- 点赞和评论通知
- 回复和提及通知
- 系统公告通知

### 8. 性能优化和缓存 ⚡
- ✅ Redis 缓存策略
- ✅ 查询性能优化
- ✅ 批量操作支持
- ✅ 缓存失效策略

**缓存策略:**
- 用户统计数据缓存（5分钟）
- 动态流缓存（10分钟）
- 推荐内容缓存（30分钟）
- 热门内容缓存（1小时）

## 技术架构

### 数据库设计

#### 新增数据表

1. **user_feeds** - 用户动态流
   ```sql
   - id: string (主键)
   - user_id: string (接收者ID)
   - actor_id: string (执行者ID)
   - action_type: enum (动作类型)
   - target_type: enum (目标类型)
   - target_id: string (目标ID)
   - metadata: text (JSON元数据)
   - privacy_level: enum (隐私级别)
   - created_at: timestamp
   ```

2. **user_privacy_settings** - 隐私设置
   ```sql
   - user_id: string (主键)
   - profile_visibility: enum
   - activity_visibility: enum
   - location_visibility: enum
   - email_notifications: boolean
   - push_notifications: boolean
   - created_at/updated_at: timestamp
   ```

3. **user_interest_tags** - 用户兴趣标签
   ```sql
   - id: string (主键)
   - user_id: string
   - tag_name: string
   - tag_category: string
   - confidence_score: decimal
   - interaction_count: integer
   - last_updated/created_at: timestamp
   ```

4. **content_moderation** - 内容审核
   ```sql
   - id: string (主键)
   - content_type: enum
   - content_id: string
   - reported_by: string
   - moderator_id: string
   - reason: enum
   - status: enum
   - moderator_notes: text
   - reported_at/moderated_at: timestamp
   ```

5. **user_activity_stats** - 活动统计缓存
   ```sql
   - user_id: string (主键)
   - total_annotations: integer
   - total_comments: integer
   - total_likes_given/received: integer
   - followers_count/following_count: integer
   - reputation_score: decimal
   - last_calculated/updated_at: timestamp
   ```

### 核心组件

#### 模型层 (Models)
- `UserFeedModel` - 动态流管理
- `SocialRecommendationModel` - 推荐算法
- 扩展的 `UserModel` - 增强用户统计

#### 控制器层 (Controllers)
- `FeedController` - 动态流API
- `RecommendationController` - 推荐API
- `ProfileController` - 用户资料API
- `ModerationController` - 内容审核API

#### 服务层 (Services)
- `SocialCacheService` - 缓存管理
- `WebSocketManager` - 实时通知
- `EmailService` - 邮件通知

### API路由结构

```
/api/v1/
├── feed                    # 动态流
├── recommendations/        # 推荐系统
│   ├── users              # 用户推荐
│   ├── content            # 内容推荐
│   └── users/nearby       # 附近用户
├── users/:id/
│   ├── profile            # 用户资料
│   ├── annotations        # 用户标注
│   ├── achievements       # 用户成就
│   └── timeline           # 活动时间线
├── social/
│   ├── follow/:userId     # 关注操作
│   ├── following/:userId  # 关注列表
│   ├── followers/:userId  # 粉丝列表
│   └── notifications      # 通知管理
└── moderation/            # 内容审核
    ├── reports            # 举报管理
    └── queue              # 审核队列
```

## 部署和运行

### 1. 数据库迁移

```bash
# 运行新的社交功能迁移
npm run migrate

# 应用的迁移文件
migrations/015_add_enhanced_social_features.js
```

### 2. 环境变量配置

确保以下环境变量已正确设置：
```env
# Redis 缓存
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=

# WebSocket 配置
WEBSOCKET_PORT=3001
WEBSOCKET_CORS_ORIGIN=http://localhost:3000

# 通知配置
EMAIL_SERVICE_ENABLED=true
PUSH_NOTIFICATIONS_ENABLED=true

# 推荐算法配置
RECOMMENDATION_UPDATE_INTERVAL=3600000  # 1小时
TRENDING_CONTENT_TTL=7200000           # 2小时
```

### 3. 启动服务

```bash
# 启动后端服务
npm run dev

# 启动Workers服务
cd workers && npm run dev

# 启动前端
cd frontend && npm run dev
```

## 性能优化建议

### 1. 数据库优化
- 为高频查询字段添加索引
- 使用数据库连接池
- 实施读写分离（如需要）

### 2. 缓存策略
- 热点数据预加载
- 缓存穿透保护
- 分布式缓存一致性

### 3. 查询优化
- 使用分页查询
- 避免N+1查询问题
- 批量操作优化

### 4. 实时通知优化
- WebSocket连接池管理
- 消息去重和合并
- 离线消息存储

## 监控和维护

### 1. 关键指标监控
- 用户活跃度统计
- 社交互动频率
- 推荐算法效果
- 缓存命中率
- API响应时间

### 2. 日志记录
- 用户行为日志
- 错误和异常日志
- 性能指标日志
- 安全事件日志

### 3. 定期维护任务
- 清理过期动态数据
- 重新计算推荐权重
- 缓存预热任务
- 数据库统计更新

## 安全考虑

### 1. 数据保护
- 用户隐私数据加密
- 敏感信息脱敏
- 访问权限控制

### 2. 防滥用机制
- 频率限制和节流
- 垃圾内容检测
- 恶意用户识别

### 3. 内容审核
- 自动违规检测
- 人工审核流程
- 用户举报处理

## 未来扩展

### 1. 推荐算法改进
- 机器学习模型集成
- 深度学习推荐引擎
- A/B测试框架

### 2. 社交功能增强
- 群组和社区功能
- 直播和实时互动
- 游戏化元素

### 3. 移动端优化
- 推送通知优化
- 离线功能支持
- 性能优化

---

## 技术支持

如有技术问题，请查看：
- 项目日志文件
- 数据库监控面板
- Redis监控工具
- API文档和测试

## 更新记录

- **v1.0** - 基础社交功能实现
- **v1.1** - 推荐算法优化
- **v1.2** - 性能优化和缓存策略
- **v1.3** - 内容审核和隐私设置

---

*本文档最后更新：2025-01-09*