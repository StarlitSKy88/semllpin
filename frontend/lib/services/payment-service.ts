import { apiClient } from './api';

// 支付相关接口定义
export interface PaymentIntent {
  id: string;
  clientSecret: string;
  amount: number;
  currency: string;
  status: 'requires_payment_method' | 'requires_confirmation' | 'requires_action' | 'processing' | 'requires_capture' | 'canceled' | 'succeeded';
  metadata?: Record<string, string>;
}

export interface PaymentMethod {
  id: string;
  type: 'card' | 'alipay' | 'wechat_pay';
  card?: {
    brand: string;
    last4: string;
    expMonth: number;
    expYear: number;
  };
  billing_details?: {
    name?: string;
    email?: string;
    phone?: string;
  };
}

export interface CreatePaymentIntentRequest {
  amount: number; // 金额（分）
  currency: string; // 货币类型
  annotationId?: string; // 标注ID
  description?: string; // 支付描述
  metadata?: Record<string, string>; // 元数据
}

export interface PaymentHistory {
  id: string;
  amount: number;
  currency: string;
  status: string;
  description: string;
  createdAt: string;
  annotationId?: string;
  type: 'payment' | 'refund' | 'reward';
}

export interface WalletBalance {
  available: number; // 可用余额
  pending: number; // 待处理余额
  currency: string;
  lastUpdated: string;
}

export interface WithdrawRequest {
  amount: number;
  method: 'bank_transfer' | 'alipay' | 'wechat_pay';
  accountInfo: {
    accountNumber?: string;
    accountName?: string;
    bankName?: string;
    alipayAccount?: string;
    wechatAccount?: string;
  };
}

class PaymentService {
  private baseUrl = '/api/v1/payments';

  /**
   * 创建支付意图
   */
  async createPaymentIntent(request: CreatePaymentIntentRequest): Promise<PaymentIntent> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const mockPaymentIntent: PaymentIntent = {
      id: `pi_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      clientSecret: `pi_${Date.now()}_secret_${Math.random().toString(36).substr(2, 9)}`,
      amount: request.amount,
      currency: request.currency,
      status: 'requires_payment_method',
      metadata: request.metadata
    };
    
    return mockPaymentIntent;
  }

  /**
   * 确认支付
   */
  async confirmPayment(paymentIntentId: string, paymentMethodId: string): Promise<PaymentIntent> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // 模拟支付成功
    const mockConfirmedPayment: PaymentIntent = {
      id: paymentIntentId,
      clientSecret: `${paymentIntentId}_secret`,
      amount: 1000, // 示例金额
      currency: 'cny',
      status: 'succeeded',
      metadata: {}
    };
    
    return mockConfirmedPayment;
  }

  /**
   * 获取支付方法列表
   */
  async getPaymentMethods(): Promise<PaymentMethod[]> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 600));
    
    const mockPaymentMethods: PaymentMethod[] = [
      {
        id: 'pm_card_visa',
        type: 'card',
        card: {
          brand: 'visa',
          last4: '4242',
          expMonth: 12,
          expYear: 2025
        },
        billing_details: {
          name: '张三',
          email: 'zhangsan@example.com'
        }
      },
      {
        id: 'pm_alipay',
        type: 'alipay',
        billing_details: {
          name: '张三',
          email: 'zhangsan@example.com'
        }
      }
    ];
    
    return mockPaymentMethods;
  }

  /**
   * 添加支付方法
   */
  async addPaymentMethod(paymentMethod: Omit<PaymentMethod, 'id'>): Promise<PaymentMethod> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const newPaymentMethod: PaymentMethod = {
      id: `pm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...paymentMethod
    };
    
    return newPaymentMethod;
  }

  /**
   * 删除支付方法
   */
  async deletePaymentMethod(paymentMethodId: string): Promise<void> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // 模拟删除成功
    console.log(`Payment method ${paymentMethodId} deleted`);
  }

  /**
   * 获取钱包余额
   */
  async getWalletBalance(): Promise<WalletBalance> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 400));
    
    const mockBalance: WalletBalance = {
      available: 12580, // 125.80元
      pending: 350, // 3.50元
      currency: 'cny',
      lastUpdated: new Date().toISOString()
    };
    
    return mockBalance;
  }

  /**
   * 获取支付历史
   */
  async getPaymentHistory(page: number = 1, pageSize: number = 20): Promise<{
    payments: PaymentHistory[];
    total: number;
    page: number;
    pageSize: number;
  }> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 700));
    
    const mockPayments: PaymentHistory[] = [
      {
        id: 'pay_001',
        amount: 1000,
        currency: 'cny',
        status: 'succeeded',
        description: '创建恶搞标注 - 北京三里屯',
        createdAt: '2024-01-15T10:30:00Z',
        annotationId: 'ann_001',
        type: 'payment'
      },
      {
        id: 'reward_001',
        amount: 500,
        currency: 'cny',
        status: 'completed',
        description: '发现标注奖励 - 上海外滩',
        createdAt: '2024-01-14T16:45:00Z',
        annotationId: 'ann_002',
        type: 'reward'
      },
      {
        id: 'pay_002',
        amount: 2000,
        currency: 'cny',
        status: 'succeeded',
        description: '创建恶搞标注 - 广州天河城',
        createdAt: '2024-01-13T14:20:00Z',
        annotationId: 'ann_003',
        type: 'payment'
      }
    ];
    
    return {
      payments: mockPayments,
      total: mockPayments.length,
      page,
      pageSize
    };
  }

  /**
   * 申请提现
   */
  async requestWithdraw(request: WithdrawRequest): Promise<{
    id: string;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    estimatedArrival: string;
  }> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 1200));
    
    const withdrawId = `wd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // 计算预计到账时间（1-3个工作日）
    const estimatedDays = Math.floor(Math.random() * 3) + 1;
    const estimatedArrival = new Date();
    estimatedArrival.setDate(estimatedArrival.getDate() + estimatedDays);
    
    return {
      id: withdrawId,
      status: 'pending',
      estimatedArrival: estimatedArrival.toISOString()
    };
  }

  /**
   * 获取提现历史
   */
  async getWithdrawHistory(): Promise<Array<{
    id: string;
    amount: number;
    method: string;
    status: string;
    createdAt: string;
    completedAt?: string;
  }>> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return [
      {
        id: 'wd_001',
        amount: 5000,
        method: 'alipay',
        status: 'completed',
        createdAt: '2024-01-10T09:00:00Z',
        completedAt: '2024-01-12T15:30:00Z'
      },
      {
        id: 'wd_002',
        amount: 3000,
        method: 'bank_transfer',
        status: 'processing',
        createdAt: '2024-01-14T11:20:00Z'
      }
    ];
  }

  /**
   * 格式化金额显示
   */
  formatAmount(amount: number, currency: string = 'cny'): string {
    const formattedAmount = (amount / 100).toFixed(2);
    
    switch (currency.toLowerCase()) {
      case 'cny':
        return `¥${formattedAmount}`;
      case 'usd':
        return `$${formattedAmount}`;
      case 'eur':
        return `€${formattedAmount}`;
      default:
        return `${formattedAmount} ${currency.toUpperCase()}`;
    }
  }

  /**
   * 验证支付金额
   */
  validatePaymentAmount(amount: number): {
    isValid: boolean;
    error?: string;
  } {
    if (amount < 100) { // 最小1元
      return {
        isValid: false,
        error: '支付金额不能少于1元'
      };
    }
    
    if (amount > 100000) { // 最大1000元
      return {
        isValid: false,
        error: '单次支付金额不能超过1000元'
      };
    }
    
    return { isValid: true };
  }

  /**
   * 获取支付状态描述
   */
  getPaymentStatusText(status: string): string {
    const statusMap: Record<string, string> = {
      'requires_payment_method': '等待支付方式',
      'requires_confirmation': '等待确认',
      'requires_action': '需要验证',
      'processing': '处理中',
      'succeeded': '支付成功',
      'canceled': '已取消',
      'failed': '支付失败'
    };
    
    return statusMap[status] || status;
  }
}

export const paymentService = new PaymentService();
export default paymentService;