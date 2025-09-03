import paypal from 'paypal-rest-sdk';

// PayPal配置接口
export interface PayPalConfig {
  mode: 'live' | 'sandbox';
  client_id: string;
  client_secret: string;
}

// PayPal订单创建请求
export interface PayPalCreateOrderRequest {
  amount: string;
  currency: string;
  description: string;
  orderId?: string;
  userId?: string;
  annotationId?: string;
}

// PayPal订单响应
export interface PayPalOrderResponse {
  id: string;
  status: string;
  links?: Array<{
    href: string;
    rel: string;
    method: string;
  }>;
  create_time?: string;
  update_time?: string;
  intent?: string;
  payer?: any;
  purchase_units?: any[];
}

// PayPal捕获响应
export interface PayPalCaptureResponse {
  id: string;
  status: string;
  purchase_units?: any[];
  payer?: any;
  create_time?: string;
  update_time?: string;
}

/**
 * PayPal支付服务类
 * 处理PayPal支付订单创建、捕获和管理
 */
export class PayPalService {
  private static isConfigured = false;

  /**
   * 初始化PayPal配置
   */
  static configure(config: PayPalConfig): void {
    paypal.configure({
      mode: config.mode,
      client_id: config.client_id,
      client_secret: config.client_secret,
    });
    
    this.isConfigured = true;
    console.log(`PayPal configured in ${config.mode} mode`);
  }

  /**
   * 检查PayPal是否已配置
   */
  private static checkConfiguration(): void {
    if (!this.isConfigured) {
      throw new Error('PayPal service is not configured. Please call configure() first.');
    }
  }

  /**
   * 创建PayPal支付订单
   */
  static async createOrder(request: PayPalCreateOrderRequest): Promise<PayPalOrderResponse> {
    this.checkConfiguration();

    const paymentData = {
      intent: 'sale',
      payer: {
        payment_method: 'paypal'
      },
      transactions: [{
        amount: {
          total: request.amount,
          currency: request.currency || 'USD'
        },
        description: request.description,
        custom: JSON.stringify({
          orderId: request.orderId,
          userId: request.userId,
          annotationId: request.annotationId,
          timestamp: new Date().toISOString()
        })
      }],
      redirect_urls: {
        return_url: `${process.env.APP_BASE_URL}/api/payments/success`,
        cancel_url: `${process.env.APP_BASE_URL}/api/payments/cancel`
      }
    };

    return new Promise((resolve, reject) => {
      paypal.payment.create(paymentData, (error: any, payment: any) => {
        if (error) {
          console.error('PayPal create order error:', error);
          reject(new Error(`PayPal order creation failed: ${error.message}`));
        } else {
          console.log('PayPal order created successfully:', payment.id);
          resolve({
            id: payment.id,
            status: payment.state,
            links: payment.links,
            create_time: payment.create_time,
            update_time: payment.update_time,
            intent: payment.intent,
            payer: payment.payer,
            purchase_units: payment.transactions
          });
        }
      });
    });
  }

  /**
   * 捕获PayPal支付
   */
  static async captureOrder(paymentId: string, payerId: string): Promise<PayPalCaptureResponse> {
    this.checkConfiguration();

    const executePaymentJson = {
      payer_id: payerId
    };

    return new Promise((resolve, reject) => {
      paypal.payment.execute(paymentId, executePaymentJson, (error: any, payment: any) => {
        if (error) {
          console.error('PayPal capture error:', error);
          reject(new Error(`PayPal payment capture failed: ${error.message}`));
        } else {
          console.log('PayPal payment captured successfully:', payment.id);
          resolve({
            id: payment.id,
            status: payment.state,
            purchase_units: payment.transactions,
            payer: payment.payer,
            create_time: payment.create_time,
            update_time: payment.update_time
          });
        }
      });
    });
  }

  /**
   * 获取PayPal支付详情
   */
  static async getOrderDetails(paymentId: string): Promise<PayPalOrderResponse | null> {
    this.checkConfiguration();

    return new Promise((resolve, reject) => {
      paypal.payment.get(paymentId, (error: any, payment: any) => {
        if (error) {
          console.error('PayPal get payment error:', error);
          if (error.httpStatusCode === 404) {
            resolve(null);
          } else {
            reject(new Error(`Failed to get PayPal payment details: ${error.message}`));
          }
        } else {
          resolve({
            id: payment.id,
            status: payment.state,
            links: payment.links,
            create_time: payment.create_time,
            update_time: payment.update_time,
            intent: payment.intent,
            payer: payment.payer,
            purchase_units: payment.transactions
          });
        }
      });
    });
  }

  /**
   * 退款PayPal支付
   */
  static async refundPayment(
    paymentId: string, 
    amount?: string, 
    currency: string = 'USD',
    reason?: string
  ): Promise<any> {
    this.checkConfiguration();

    // 首先获取支付详情以找到sale交易
    const payment = await this.getOrderDetails(paymentId);
    if (!payment || !payment.purchase_units) {
      throw new Error('Payment not found or invalid');
    }

    // 查找已完成的sale交易
    let saleId: string | null = null;
    for (const transaction of payment.purchase_units) {
      if (transaction.related_resources) {
        for (const resource of transaction.related_resources) {
          if (resource.sale && resource.sale.state === 'completed') {
            saleId = resource.sale.id;
            break;
          }
        }
      }
      if (saleId) break;
    }

    if (!saleId) {
      throw new Error('No completed sale found for this payment');
    }

    const refundData: any = {};
    if (amount) {
      refundData.amount = {
        total: amount,
        currency: currency
      };
    }
    if (reason) {
      refundData.reason = reason;
    }

    return new Promise((resolve, reject) => {
      paypal.sale.refund(saleId, refundData, (error: any, refund: any) => {
        if (error) {
          console.error('PayPal refund error:', error);
          reject(new Error(`PayPal refund failed: ${error.message}`));
        } else {
          console.log('PayPal refund processed successfully:', refund.id);
          resolve(refund);
        }
      });
    });
  }

  /**
   * 验证PayPal Webhook事件
   */
  static async verifyWebhook(headers: any, body: string, webhookId: string): Promise<boolean> {
    this.checkConfiguration();
    
    // PayPal webhook验证逻辑
    // 在生产环境中，你应该实现完整的webhook验证
    try {
      // 这里简化处理，实际应该验证webhook签名
      const event = JSON.parse(body);
      return event && event.event_type && event.resource;
    } catch (error) {
      console.error('PayPal webhook verification error:', error);
      return false;
    }
  }

  /**
   * 获取支持的货币列表
   */
  static getSupportedCurrencies(): string[] {
    return [
      'USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY',
      'CNY', 'HKD', 'SGD', 'KRW', 'THB', 'PHP',
      'INR', 'MYR', 'TWD', 'VND', 'IDR'
    ];
  }

  /**
   * 格式化金额（PayPal要求特定格式）
   */
  static formatAmount(amount: number, currency: string = 'USD'): string {
    // 大多数货币保留2位小数
    const decimalPlaces = ['JPY', 'KRW', 'VND', 'IDR'].includes(currency) ? 0 : 2;
    return amount.toFixed(decimalPlaces);
  }

  /**
   * 验证支付金额
   */
  static validateAmount(amount: string, currency: string = 'USD'): boolean {
    const numericAmount = parseFloat(amount);
    
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return false;
    }

    // 检查最小金额限制
    const minAmounts: Record<string, number> = {
      'USD': 0.01,
      'EUR': 0.01,
      'GBP': 0.01,
      'CAD': 0.01,
      'AUD': 0.01,
      'JPY': 1,
      'CNY': 0.01,
      'HKD': 0.01,
      'SGD': 0.01,
      'KRW': 1,
      'THB': 0.01,
      'PHP': 0.01,
      'INR': 0.01,
      'MYR': 0.01,
      'TWD': 0.01,
      'VND': 1,
      'IDR': 1
    };

    const minAmount = minAmounts[currency] || 0.01;
    return numericAmount >= minAmount;
  }
}

export default PayPalService;