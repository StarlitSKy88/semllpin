# PayPal支付集成使用指南

本指南详细说明如何使用SmellPin项目中集成的PayPal支付功能。

## 🔧 配置要求

### 环境变量

确保在 `.env` 文件中配置以下PayPal相关环境变量：

```env
# PayPal支付配置
PAYPAL_CLIENT_ID=AR3lanKZLAf8blcwdG3mlJOyLvUxjM7gn2QsFTLIwWDlf1sALN7vnQJQwa-J0krqIxwgu6Oruj3gqETQ
PAYPAL_CLIENT_SECRET=EER7aD7W-cypjMSSXdQK4LhOOKPIKZS77PODN2TLFSZn3g0k6fx3q-XjyQsOSvyAmTr2AJS3KgGq0iGs
PAYPAL_MODE=sandbox  # 生产环境使用 live
PAYPAL_ENVIRONMENT=sandbox
PAYPAL_WEBHOOK_ID=your_paypal_webhook_id_here  # webhook验证用
APP_BASE_URL=http://localhost:3002

# 前端环境变量
NEXT_PUBLIC_PAYPAL_CLIENT_ID=AR3lanKZLAf8blcwdG3mlJOyLvUxjM7gn2QsFTLIwWDlf1sALN7vnQJQwa-J0krqIxwgu6Oruj3gqETQ
```

### 依赖包

项目已自动安装以下依赖：

**后端:**
- `paypal-rest-sdk` - PayPal服务端SDK

**前端:**
- `@paypal/react-paypal-js` - PayPal React组件

## 🚀 快速开始

### 1. 启动服务

```bash
# 后端服务
npm run dev

# 前端服务 (在frontend目录)
cd frontend
npm run dev
```

### 2. 基本使用

#### 前端集成

```tsx
import { PayPalQuickButton } from '@/components/payment/paypal-button';

function PaymentPage() {
  const handleSuccess = (data) => {
    console.log('支付成功:', data);
    // 处理支付成功逻辑
  };

  const handleError = (error) => {
    console.error('支付失败:', error);
    // 处理支付失败逻辑
  };

  return (
    <PayPalQuickButton
      clientId={process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID}
      amount={5.99}
      currency="USD"
      description="SmellPin气味标注费用"
      annotationId="annotation-123"
      onSuccess={handleSuccess}
      onError={handleError}
    />
  );
}
```

#### API调用

**创建支付订单:**
```javascript
POST /api/payments/create
Content-Type: application/json
Authorization: Bearer <your-jwt-token>

{
  "amount": 5.99,
  "currency": "USD",
  "description": "SmellPin气味标注费用",
  "annotationId": "annotation-123",
  "paymentMethod": "paypal"
}
```

**捕获支付:**
```javascript
POST /api/payments/capture
Content-Type: application/json
Authorization: Bearer <your-jwt-token>

{
  "orderId": "paypal-order-id",
  "payerId": "paypal-payer-id",
  "paymentMethod": "paypal"
}
```

## 📦 组件说明

### PayPalButton

基础PayPal支付按钮组件。

```tsx
<PayPalButton
  amount={10.00}
  currency="USD"
  description="购买商品"
  onSuccess={(data) => console.log('支付成功', data)}
  onError={(error) => console.log('支付失败', error)}
  onCancel={() => console.log('支付取消')}
  style={{
    layout: 'vertical',
    color: 'gold',
    shape: 'rect',
    label: 'paypal',
    height: 45
  }}
/>
```

### PayPalQuickButton

带PayPal Provider包装的快捷按钮组件。

```tsx
<PayPalQuickButton
  clientId="your-paypal-client-id"
  environment="sandbox"
  amount={10.00}
  currency="USD"
  description="购买商品"
  onSuccess={handleSuccess}
  onError={handleError}
/>
```

### PayPalPaymentInfo

支付信息显示组件。

```tsx
<PayPalPaymentInfo
  amount={10.00}
  currency="USD"
  description="购买商品"
/>
```

### PayPalStatus

支付状态显示组件。

```tsx
<PayPalStatus
  status="loading"  // idle | loading | success | error | cancelled
  message="处理支付中..."
/>
```

## 🔒 安全考虑

### Webhook验证

生产环境中应该实现完整的webhook验证：

```typescript
// 在 PayPalService.verifyWebhook 中实现
const isValid = await PayPalService.verifyWebhook(headers, body, webhookId);
```

### 支付验证

- 所有支付请求都需要用户认证
- 检查重复支付（5分钟内相同金额和标注）
- 验证支付金额是否符合货币最小限制

## 🧪 测试

### 运行集成测试

```bash
node test-paypal-integration.js
```

### 测试账户

在沙盒环境中，使用PayPal提供的测试买家账户：

- 邮箱: `sb-buyer@example.com`
- 密码: `testpassword`

### 测试卡信息

沙盒环境支持的测试信用卡：
- Visa: 4111 1111 1111 1111
- MasterCard: 5555 5555 5555 4444
- American Express: 3411 1111 1111 117

## 🔧 故障排除

### 常见错误

1. **PayPal service is not configured**
   - 检查环境变量是否正确配置
   - 确保服务器启动时PayPal服务已初始化

2. **Invalid webhook signature**
   - 检查PAYPAL_WEBHOOK_ID是否正确
   - 确保webhook URL在PayPal开发者控制台中正确配置

3. **Payment not found**
   - 检查PayPal订单ID是否正确传递
   - 确保数据库中存在对应的支付记录

### 调试技巧

1. 启用详细日志记录
2. 检查网络请求和响应
3. 验证JWT token有效性
4. 确认PayPal沙盒环境配置

## 📚 参考资料

- [PayPal Developer Documentation](https://developer.paypal.com/)
- [PayPal React SDK](https://paypal.github.io/react-paypal-js/)
- [PayPal REST API Reference](https://developer.paypal.com/api/rest/)

## 🔄 支付流程图

```
用户点击支付按钮
      ↓
前端调用 /api/payments/create
      ↓
后端创建PayPal订单
      ↓
返回PayPal审批URL
      ↓
用户在PayPal完成支付
      ↓
PayPal重定向回应用
      ↓
前端调用 /api/payments/capture
      ↓
后端捕获支付并更新状态
      ↓
支付完成，创建标注
```

## ⚙️ 生产环境部署

### 切换到生产环境

1. 更新环境变量：
```env
PAYPAL_MODE=live
PAYPAL_ENVIRONMENT=production
PAYPAL_CLIENT_ID=your_live_client_id
PAYPAL_CLIENT_SECRET=your_live_client_secret
```

2. 配置生产Webhook URL
3. 更新前端环境变量
4. 进行充分的生产测试

### 监控与日志

- 监控支付成功率
- 记录所有支付相关的错误
- 设置支付异常告警
- 定期检查webhook事件处理