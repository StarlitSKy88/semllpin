# SmellPin项目迁移到Neon数据库指南

## 第一步：注册Neon账号并创建项目

### 1. 访问Neon官网
- 打开浏览器，访问：https://neon.com
- 点击右上角的 "Sign Up" 按钮

### 2. 注册账号
- 使用GitHub账号快速注册（推荐）
- 或者使用邮箱注册
- 完成邮箱验证（如果需要）

### 3. 创建新项目
- 登录后，点击 "Create Project" 按钮
- 项目设置：
  - **Project Name**: `smellpin-database`
  - **Database Name**: `smellpin`
  - **Region**: 选择 `US East (N. Virginia)` 或 `Asia Pacific (Singapore)`（推荐亚太地区）
  - **PostgreSQL Version**: 保持默认（最新版本）

### 4. 获取连接信息
创建项目后，Neon会显示连接字符串，格式类似：
```
postgresql://username:password@ep-xxx-xxx.us-east-2.aws.neon.tech/smellpin?sslmode=require
```

**重要：请复制并保存这个连接字符串！**

## Neon免费套餐限制
- 1个项目
- 10个分支
- 每个分支3GB存储空间
- 共享计算资源（1GB RAM）
- 5分钟不活动后自动休眠
- 无限制的数据传输

## 下一步
完成注册后，请告诉我您已经：
1. ✅ 成功注册了Neon账号
2. ✅ 创建了名为 `smellpin-database` 的项目
3. ✅ 获取了数据库连接字符串

然后我们将继续更新项目配置文件。