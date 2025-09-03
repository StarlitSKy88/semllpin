# SmellPin 支付系统设置指南

## 概述

SmellPin 集成了 Stripe 支付系统，支持用户为恶搞标注进行支付。本文档介绍如何配置和使用支付功能。

## 功能特性

- ✅ Stripe Checkout 集成
- ✅ 安全的支付处理
- ✅ 支付会话管理
- ✅ Webhook 事件处理
- ✅ 支付历史记录
- ✅ 退款功能
- ✅ 测试模式支持

## 配置步骤

### 1. Stripe 账户设置

1. 访问 [Stripe Dashboard](https://dashboard.stripe.com/)
2. 创建账户或登录现有账户
3. 获取 API 密钥：
   - 测试环境：`sk_test_...`
   - 生产环境：`sk_live_...`

### 2. 环境变量配置

复制 `.env.example` 到 `.env` 并配置以下变量：

```bash
# Stripe 配置
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here

# 前端URL（用于支付成功/取消重定向）
FRONTEND_URL=http://localhost:5173
```

### 3. Webhook 配置

#### 开发环境（使用 ngrok）

1. 安装 ngrok：
   ```bash
   npm install -g ngrok
   ```

2. 启动后端服务器：
   ```bash
   npm run dev
   ```

3. 在新终端中启动 ngrok：
   ```bash
   ngrok http 3000
   ```

4. 在 Stripe Dashboard 中添加 Webhook 端点：
   - URL: `https://your-ngrok-url.ngrok.io/api/v1/payments/webhook`
   - 事件: `checkout.session.completed`, `checkout.session.expired`, `payment_intent.payment_failed`

#### 生产环境

在 Stripe Dashboard 中配置 Webhook：
- URL: `https://your-domain.com/api/v1/payments/webhook`
- 事件: 同上

## API 端点

### 创建支付会话
```http
POST /api/v1/payments/create-session
Authorization: Bearer <token>
Content-Type: application/json

{
  "prankId": "prank_123",
  "amount": 5.00,
  "currency": "usd",
  "description": "恶搞标注支付"
}
```

### 获取支付会话状态
```http
GET /api/v1/payments/session/:sessionId
Authorization: Bearer <token>
```

### 获取支付历史
```http
GET /api/v1/payments/history?page=1&limit=10
Authorization: Bearer <token>
```

### 申请退款
```http
POST /api/v1/payments/refund
Authorization: Bearer <token>
Content-Type: application/json

{
  "paymentIntentId": "pi_xxx",
  "reason": "requested_by_customer"
}
```

## 测试

### 测试卡号

| 卡号 | 用途 |
|------|------|
| 4242 4242 4242 4242 | 成功支付 |
| 4000 0025 0000 3155 | 需要 3D Secure 验证 |
| 4000 0000 0000 0002 | 卡被拒绝 |
| 4000 0000 0000 9995 | 余额不足 |

### 测试流程

1. 访问测试页面：`http://localhost:5173/payment/test`
2. 点击"测试支付功能"按钮
3. 填写支付信息
4. 使用测试卡号完成支付
5. 验证支付成功页面

## 前端集成

### 打开支付模态框

```typescript
import { useDispatch } from 'react-redux';
import { openModal } from '../store/slices/uiSlice';

const dispatch = useDispatch();

// 打开支付模态框
dispatch(openModal({
  type: 'payment',
  props: {
    prankId: 'prank_123',
    amount: 5.00
  }
}));
```

### 支付成功处理

支付成功后，用户会被重定向到：
- 成功页面：`/payment/success?session_id=cs_xxx`
- 取消页面：`/payment/cancel`

## 安全注意事项

1. **密钥安全**：
   - 永远不要在前端代码中暴露 Stripe 密钥
   - 使用环境变量存储敏感信息
   - 定期轮换 API 密钥

2. **Webhook 验证**：
   - 始终验证 Webhook 签名
   - 使用 HTTPS 端点
   - 实现幂等性处理

3. **金额验证**：
   - 在服务器端验证支付金额
   - 设置合理的金额限制
   - 防止金额篡改

## 监控和日志

### 支付事件日志

系统会记录以下支付事件：
- 支付会话创建
- 支付成功/失败
- 退款申请
- Webhook 事件

### Stripe Dashboard

在 Stripe Dashboard 中可以监控：
- 支付统计
- 失败原因分析
- Webhook 事件日志
- 客户争议处理

## 故障排除

### 常见问题

1. **支付会话创建失败**
   - 检查 Stripe 密钥配置
   - 验证请求参数格式
   - 查看服务器日志

2. **Webhook 未触发**
   - 确认 Webhook URL 可访问
   - 检查 Webhook 签名验证
   - 查看 Stripe Dashboard 中的 Webhook 日志

3. **支付重定向失败**
   - 检查 `FRONTEND_URL` 配置
   - 确认路由配置正确
   - 验证 CORS 设置

### 调试工具

- Stripe CLI：用于本地 Webhook 测试
- ngrok：用于本地开发的公网隧道
- Stripe Dashboard：查看支付和事件日志

## 生产部署

### 检查清单

- [ ] 使用生产环境 Stripe 密钥
- [ ] 配置生产环境 Webhook 端点
- [ ] 启用 HTTPS
- [ ] 设置适当的 CORS 策略
- [ ] 配置监控和告警
- [ ] 测试完整支付流程
- [ ] 验证退款功能
- [ ] 检查错误处理

## 支持

如有问题，请联系：
- 技术支持：tech@smellpin.com
- Stripe 文档：https://stripe.com/docs
- 项目 Issues：GitHub Issues