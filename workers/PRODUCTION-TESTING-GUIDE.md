# 线上环境测试指南

## 概述

本指南将帮助您完成完整的线上环境测试，验证腾讯云CloudBase前端、Cloudflare Workers后端和Neon PostgreSQL数据库的部署状态。

## 测试文件说明

- `test-production-environment.js` - 主要测试脚本
- `production-config.json` - 生产环境配置文件
- `production-test-report.json` - 测试结果报告（运行后生成）

## 配置步骤

### 1. 配置生产环境URL

编辑 `production-config.json` 文件，将占位符URL替换为您的实际生产环境地址：

```json
{
  "frontend": {
    "url": "https://your-actual-cloudbase-app.tcloudbaseapp.com",
    "name": "腾讯云CloudBase前端",
    "description": "您的腾讯云CloudBase应用URL"
  },
  "backend": {
    "url": "https://your-actual-workers.your-subdomain.workers.dev",
    "name": "Cloudflare Workers后端",
    "description": "您的Cloudflare Workers部署URL"
  },
  "database": {
    "name": "Neon PostgreSQL数据库",
    "description": "通过后端API访问，无需直接配置"
  }
}
```

### 2. 获取实际URL地址

#### 腾讯云CloudBase前端URL
1. 登录腾讯云控制台
2. 进入CloudBase服务
3. 选择您的环境
4. 在「静态网站托管」中找到默认域名
5. 格式通常为：`https://your-env-id-xxx.tcloudbaseapp.com`

#### Cloudflare Workers后端URL
1. 登录Cloudflare Dashboard
2. 进入Workers & Pages
3. 选择您的Worker
4. 在「Settings」→「Triggers」中找到路由
5. 格式通常为：`https://your-worker-name.your-subdomain.workers.dev`

## 运行测试

### 完整测试
```bash
node test-production-environment.js
```

### 测试内容

#### 1. 🚀 部署验证
- 前端部署状态检查
- 后端健康检查
- API端点可用性验证
- 关键路由响应测试

#### 2. ⚙️ 环境配置验证
- CORS配置检查
- 数据库连接验证
- 环境变量配置检查
- API密钥有效性验证

#### 3. 🔄 端到端测试
- 用户注册流程
- 用户登录验证
- 认证API访问测试
- 完整业务流程验证

#### 4. ⚡ 性能测试
- 前端页面加载速度
- API响应时间测试
- 数据库查询性能
- 静态资源加载速度

#### 5. 🔒 安全测试
- HTTPS配置验证
- 安全头部检查
- CORS策略验证
- 未授权访问保护测试

## 测试结果解读

### 成功率标准
- **优秀**: 90%以上
- **良好**: 80-90%
- **及格**: 70-80%
- **需要改进**: 70%以下

### 关键指标
- **前端加载时间**: < 3秒
- **API响应时间**: < 1秒
- **数据库查询**: < 500ms
- **HTTPS覆盖率**: 100%

## 常见问题排查

### 1. 连接超时
- 检查URL是否正确
- 确认服务是否已部署
- 验证网络连接

### 2. 认证失败
- 检查API密钥配置
- 验证环境变量设置
- 确认权限配置

### 3. CORS错误
- 检查后端CORS配置
- 验证允许的源域名
- 确认请求头设置

### 4. 数据库连接失败
- 检查数据库连接字符串
- 验证数据库服务状态
- 确认网络访问权限

## 报告分析

测试完成后，详细报告将保存在 `production-test-report.json` 中，包含：

- 测试时间戳
- 各类别成功率统计
- 详细的测试结果
- 响应时间数据
- 错误信息记录

## 后续步骤

1. **分析测试结果**：重点关注失败的测试项
2. **修复问题**：根据错误信息进行相应修复
3. **重新测试**：修复后重新运行测试验证
4. **性能优化**：针对响应时间较慢的项目进行优化
5. **安全加固**：确保所有安全测试项目通过

## 联系支持

如果在测试过程中遇到问题，请：
1. 查看详细的错误日志
2. 检查配置文件设置
3. 验证生产环境状态
4. 参考本指南的排查步骤

---

**注意**: 请确保在生产环境中运行测试时不会影响正常用户使用。建议在维护窗口期间进行完整测试。