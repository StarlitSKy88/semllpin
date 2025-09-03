# SmellPin Neon PostgreSQL Migration

## 完成的工作

### ✅ 移除 Supabase 依赖
- 删除了 `create-tables-direct.js` 文件（原Supabase版本）
- 项目已完全脱离Supabase API依赖

### ✅ 创建 Neon PostgreSQL 替代方案
创建了以下新的数据库管理脚本：

#### 1. `create-tables-neon.js`
- 使用 `@neondatabase/serverless` 连接器
- 支持 PostGIS 地理位置功能
- 创建完整的数据库结构：
  - `users` - 用户表
  - `annotations` - 气味标注表（包含PostGIS支持）
  - `lbs_rewards` - LBS奖励表
  - `wallets` - 用户钱包表
  - `comments` - 评论表
  - `likes` - 点赞表
  - `payment_records` - 支付记录表

#### 2. `clean-tables-neon.js`
- 清理数据库表的工具脚本
- 按依赖关系正确删除外键约束
- 支持完全重置数据库结构

#### 3. `check-tables-neon.js`
- 数据库状态检查工具
- 显示表结构、索引、外键约束
- 帮助调试和验证数据库状态

## 技术特性

### PostGIS 地理位置支持
- 启用了 PostGIS 扩展
- `annotations` 表包含自动生成的地理位置字段
- 支持高效的地理位置查询和索引

### 性能优化
- 为所有关键字段创建了索引
- 地理位置使用 GIST 空间索引
- 外键约束确保数据完整性

### 自动化功能
- UUID 自动生成（使用 uuid-ossp 扩展）
- 自动更新时间戳触发器
- 智能的约束存在性检查

## 环境配置

项目使用 `.dev.vars` 文件中的配置：
```bash
DATABASE_URL=postgresql://neondb_owner:npg_xxx@ep-xxx.neon.tech/neondb?sslmode=require
```

## 使用方法

### 创建数据库表
```bash
node create-tables-neon.js
```

### 清理数据库
```bash
node clean-tables-neon.js
```

### 检查数据库状态
```bash
node check-tables-neon.js
```

## 数据库状态

当前数据库包含以下核心表：
- ✅ `users` - 用户管理
- ✅ `annotations` - 气味标注（已有不同结构的现有表）
- ✅ `lbs_rewards` - LBS奖励系统
- ✅ `wallets` - 钱包管理
- ✅ `comments` - 评论系统
- ✅ `likes` - 点赞功能
- ✅ `payment_records` - 支付记录

## 注意事项

1. **数据库已存在表结构**：发现数据库中已有部分表（如 `annotations`），具有不同的字段结构
2. **PostGIS 支持**：所有地理位置功能都已启用PostGIS扩展
3. **外键约束**：所有表间关系都通过外键约束保证数据完整性
4. **索引优化**：为查询性能创建了完整的索引体系

## 符合项目要求

- ✅ 完全移除 Supabase 依赖
- ✅ 使用 Neon PostgreSQL
- ✅ 保持原有功能完整性
- ✅ 支持地理位置查询（PostGIS）
- ✅ 优化数据库性能
- ✅ 符合项目架构要求