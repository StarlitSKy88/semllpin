// PayPal前端支付库
export interface PayPalOrderRequest {
  amount: number;
  currency?: string;
  description: string;
  annotationId?: string;
}

export interface PayPalOrderResponse {
  id: string;
  status: string;
  approvalUrl?: string;
}

export interface PayPalCaptureRequest {
  orderId: string;
  payerId: string;
}

export interface PayPalCaptureResponse {
  id: string;
  status: string;
  captureId?: string;
}

/**
 * PayPal前端支付客户端
 */
export class PayPalClient {
  private baseUrl: string;

  constructor(baseUrl: string = '/api') {
    this.baseUrl = baseUrl;
  }

  /**
   * 创建PayPal支付订单
   */
  async createOrder(request: PayPalOrderRequest): Promise<PayPalOrderResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/payments/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': this.getAuthHeader(),
        },
        body: JSON.stringify({
          amount: request.amount.toString(),
          currency: request.currency || 'USD',
          description: request.description,
          annotationId: request.annotationId,
          paymentMethod: 'paypal'
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      // 从PayPal响应中提取approval URL
      let approvalUrl: string | undefined;
      if (data.links) {
        const approvalLink = data.links.find((link: any) => link.rel === 'approval_url');
        approvalUrl = approvalLink?.href;
      }

      return {
        id: data.id,
        status: data.status,
        approvalUrl
      };
    } catch (error) {
      console.error('PayPal create order error:', error);
      throw error;
    }
  }

  /**
   * 捕获PayPal支付
   */
  async captureOrder(request: PayPalCaptureRequest): Promise<PayPalCaptureResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/payments/capture`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': this.getAuthHeader(),
        },
        body: JSON.stringify({
          orderId: request.orderId,
          payerId: request.payerId,
          paymentMethod: 'paypal'
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      return {
        id: data.id,
        status: data.status,
        captureId: data.captureId
      };
    } catch (error) {
      console.error('PayPal capture order error:', error);
      throw error;
    }
  }

  /**
   * 获取认证头部
   */
  private getAuthHeader(): string {
    const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    return token ? `Bearer ${token}` : '';
  }
}

/**
 * PayPal支付配置
 */
export interface PayPalConfig {
  clientId: string;
  currency: string;
  intent: 'capture' | 'authorize';
  environment: 'sandbox' | 'production';
}

/**
 * PayPal JavaScript SDK管理器
 */
export class PayPalSDKManager {
  private static instance: PayPalSDKManager;
  private sdkLoaded = false;
  private sdkPromise: Promise<void> | null = null;
  private config: PayPalConfig;

  private constructor(config: PayPalConfig) {
    this.config = config;
  }

  /**
   * 获取PayPal SDK管理器实例
   */
  static getInstance(config: PayPalConfig): PayPalSDKManager {
    if (!PayPalSDKManager.instance) {
      PayPalSDKManager.instance = new PayPalSDKManager(config);
    }
    return PayPalSDKManager.instance;
  }

  /**
   * 加载PayPal JavaScript SDK
   */
  async loadSDK(): Promise<void> {
    if (this.sdkLoaded) {
      return;
    }

    if (this.sdkPromise) {
      return this.sdkPromise;
    }

    this.sdkPromise = new Promise((resolve, reject) => {
      // 检查SDK是否已经加载
      if (typeof window !== 'undefined' && (window as any).paypal) {
        this.sdkLoaded = true;
        resolve();
        return;
      }

      // 创建script标签
      const script = document.createElement('script');
      script.src = `https://www.paypal.com/sdk/js?client-id=${this.config.clientId}&currency=${this.config.currency}&intent=${this.config.intent}`;
      script.async = true;
      
      script.onload = () => {
        this.sdkLoaded = true;
        resolve();
      };
      
      script.onerror = () => {
        reject(new Error('Failed to load PayPal SDK'));
      };

      // 添加到head
      document.head.appendChild(script);
    });

    return this.sdkPromise;
  }

  /**
   * 获取PayPal对象
   */
  getPayPal(): any {
    if (typeof window === 'undefined') {
      throw new Error('PayPal SDK can only be used in browser environment');
    }
    
    if (!this.sdkLoaded || !(window as any).paypal) {
      throw new Error('PayPal SDK is not loaded. Call loadSDK() first.');
    }
    
    return (window as any).paypal;
  }

  /**
   * 检查SDK是否已加载
   */
  isSDKLoaded(): boolean {
    return this.sdkLoaded && typeof window !== 'undefined' && !!(window as any).paypal;
  }

  /**
   * 获取配置
   */
  getConfig(): PayPalConfig {
    return { ...this.config };
  }

  /**
   * 更新配置
   */
  updateConfig(newConfig: Partial<PayPalConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }
}

/**
 * PayPal支付错误类
 */
export class PayPalError extends Error {
  public code?: string;
  public details?: any;

  constructor(message: string, code?: string, details?: any) {
    super(message);
    this.name = 'PayPalError';
    this.code = code;
    this.details = details;
  }
}

/**
 * PayPal支付状态枚举
 */
export enum PayPalStatus {
  CREATED = 'CREATED',
  SAVED = 'SAVED',
  APPROVED = 'APPROVED',
  VOIDED = 'VOIDED',
  COMPLETED = 'COMPLETED',
  PAYER_ACTION_REQUIRED = 'PAYER_ACTION_REQUIRED'
}

/**
 * PayPal支付按钮样式配置
 */
export interface PayPalButtonStyle {
  layout?: 'vertical' | 'horizontal';
  color?: 'gold' | 'blue' | 'silver' | 'black';
  shape?: 'rect' | 'pill';
  size?: 'small' | 'medium' | 'large';
  label?: 'paypal' | 'checkout' | 'buynow' | 'pay';
  height?: number;
}

/**
 * 默认PayPal客户端实例
 */
export const paypalClient = new PayPalClient();

/**
 * PayPal工具函数
 */
export const PayPalUtils = {
  /**
   * 格式化金额
   */
  formatAmount: (amount: number, currency: string = 'USD'): string => {
    const decimalPlaces = ['JPY', 'KRW', 'VND', 'IDR'].includes(currency) ? 0 : 2;
    return amount.toFixed(decimalPlaces);
  },

  /**
   * 验证金额
   */
  validateAmount: (amount: number, currency: string = 'USD'): boolean => {
    if (isNaN(amount) || amount <= 0) {
      return false;
    }

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
    return amount >= minAmount;
  },

  /**
   * 获取支持的货币列表
   */
  getSupportedCurrencies: (): string[] => {
    return [
      'USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY',
      'CNY', 'HKD', 'SGD', 'KRW', 'THB', 'PHP',
      'INR', 'MYR', 'TWD', 'VND', 'IDR'
    ];
  },

  /**
   * 解析PayPal错误
   */
  parseError: (error: any): PayPalError => {
    if (error instanceof PayPalError) {
      return error;
    }

    if (error?.details) {
      return new PayPalError(
        error.message || 'PayPal payment failed',
        error.code,
        error.details
      );
    }

    return new PayPalError(
      error?.message || 'Unknown PayPal error occurred'
    );
  }
};

export default PayPalClient;