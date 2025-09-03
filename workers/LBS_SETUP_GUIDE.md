
# LBS系统手动设置指南

## 问题概述
LBS系统需要特定的数据库表结构，但这些表在当前数据库中缺失或结构不正确。

## 解决方案

### 方案1: 使用Docker Compose (推荐)
```bash
# 启动PostgreSQL数据库
docker-compose up -d postgres

# 等待数据库启动完成
sleep 10

# 连接到数据库并执行SQL脚本
docker-compose exec postgres psql -U postgres -d smellpin -f /docker-entrypoint-initdb.d/create-lbs-tables.sql
```

### 方案2: 使用本地PostgreSQL
```bash
# 启动PostgreSQL服务
brew services start postgresql

# 创建数据库（如果不存在）
createdb smellpin

# 执行SQL脚本
psql -U postgres -d smellpin -f create-lbs-tables.sql
```

### 方案3: 使用云数据库
1. 在Neon、Supabase或其他云服务中创建PostgreSQL数据库
2. 获取连接字符串并设置DATABASE_URL环境变量
3. 在云数据库的SQL编辑器中执行create-lbs-tables.sql脚本

## 验证步骤
1. 确认以下表已创建：
   - checkin_records
   - reward_records
   - user_stats
   - user_locations

2. 验证checkin_records表的user_id字段类型为integer
3. 验证reward_records表的user_id字段类型为integer
4. 运行LBS系统测试确认功能正常

## 故障排除
- 如果遇到权限问题，确保数据库用户有CREATE TABLE权限
- 如果遇到连接问题，检查数据库服务是否正在运行
- 如果表已存在但结构不正确，可以先删除表再重新创建

## 联系支持
如果按照以上步骤仍无法解决问题，请提供以下信息：
- 错误消息的完整内容
- 数据库类型和版本
- 操作系统信息
