// 支付测试数据工厂
import { TestDataFactory } from './index';

export interface TestPaymentData {
  id?: string;
  userId: string;
  annotationId?: string;
  amount: number;
  currency?: string;
  paymentMethod: 'stripe' | 'paypal' | 'alipay' | 'wechat';
  status: 'pending' | 'completed' | 'failed' | 'refunded' | 'cancelled';
  transactionId?: string;
  paymentIntentId?: string;
  description?: string;
  metadata?: any;
  feeAmount?: number;
  netAmount?: number;
  refundedAmount?: number;
  createdAt?: Date;
  updatedAt?: Date;
  completedAt?: Date;
  failureReason?: string;
  receiptUrl?: string;
}

class PaymentFactoryClass implements TestDataFactory<TestPaymentData> {
  private counter = 0;
  
  create(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    this.counter++;
    
    const amount = overrides.amount ?? Math.floor(Math.random() * 50) + 1; // 1-50元
    const feeAmount = Math.round(amount * 0.029 * 100) / 100; // 2.9%手续费
    
    const basePayment: TestPaymentData = {
      id: overrides.id || `test-payment-${this.counter}`,
      userId: overrides.userId || `test-user-${this.counter}`,
      annotationId: overrides.annotationId || `test-annotation-${this.counter}`,
      amount: amount,
      currency: overrides.currency || 'CNY',
      paymentMethod: overrides.paymentMethod || this.getRandomPaymentMethod(),
      status: overrides.status || 'completed',
      transactionId: overrides.transactionId || `test_txn_${this.counter}_${Date.now()}`,
      paymentIntentId: overrides.paymentIntentId || `pi_test_${this.counter}_${Math.random().toString(36).substr(2, 9)}`,
      description: overrides.description || `SmellPin标注支付 #${this.counter}`,
      metadata: overrides.metadata || {
        platform: 'web',
        userAgent: 'test-browser',
        ipAddress: '127.0.0.1',
      },
      feeAmount: overrides.feeAmount ?? feeAmount,
      netAmount: overrides.netAmount ?? Math.round((amount - feeAmount) * 100) / 100,
      refundedAmount: overrides.refundedAmount ?? 0,
      createdAt: overrides.createdAt || new Date(),
      updatedAt: overrides.updatedAt || new Date(),
      completedAt: overrides.completedAt || (overrides.status === 'completed' ? new Date() : null),
      failureReason: overrides.failureReason || null,
      receiptUrl: overrides.receiptUrl || (overrides.status === 'completed' ? `https://test.stripe.com/receipts/test_${this.counter}` : null),
    };
    
    return { ...basePayment, ...overrides };
  }
  
  private getRandomPaymentMethod(): 'stripe' | 'paypal' | 'alipay' | 'wechat' {
    const methods = ['stripe', 'paypal', 'alipay', 'wechat'] as const;
    return methods[Math.floor(Math.random() * methods.length)];
  }
  
  createMultiple(count: number, overrides: Partial<TestPaymentData> = {}): TestPaymentData[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }
  
  build(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    const tempCounter = this.counter;
    const payment = this.create(overrides);
    this.counter = tempCounter;
    return payment;
  }
  
  buildList(count: number, overrides: Partial<TestPaymentData> = {}): TestPaymentData[] {
    return Array.from({ length: count }, () => this.build(overrides));
  }
  
  createStripePayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    return this.create({
      paymentMethod: 'stripe',
      transactionId: `ch_test_${this.counter}_${Math.random().toString(36).substr(2, 9)}`,
      paymentIntentId: `pi_test_${this.counter}_${Math.random().toString(36).substr(2, 9)}`,
      ...overrides,
    });
  }
  
  createPayPalPayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    return this.create({
      paymentMethod: 'paypal',
      transactionId: `PAY-${this.counter}${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
      paymentIntentId: null,
      ...overrides,
    });
  }
  
  createAlipayPayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    return this.create({
      paymentMethod: 'alipay',
      currency: 'CNY',
      transactionId: `2024${String(this.counter).padStart(8, '0')}${Date.now()}`,
      ...overrides,
    });
  }
  
  createWechatPayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    return this.create({
      paymentMethod: 'wechat',
      currency: 'CNY',
      transactionId: `wx${Date.now()}${String(this.counter).padStart(6, '0')}`,
      ...overrides,
    });
  }
  
  createFailedPayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    const failureReasons = [
      'insufficient_funds',
      'card_declined',
      'expired_card',
      'invalid_cvc',
      'network_error',
    ];
    
    return this.create({
      status: 'failed',
      completedAt: null,
      receiptUrl: null,
      failureReason: failureReasons[Math.floor(Math.random() * failureReasons.length)],
      ...overrides,
    });
  }
  
  createRefundedPayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
    const amount = overrides.amount ?? Math.floor(Math.random() * 50) + 1;
    const refundedAmount = overrides.refundedAmount ?? amount;
    
    return this.create({
      amount: amount,
      status: 'refunded',
      refundedAmount: refundedAmount,
      ...overrides,
    });
  }
  
  reset(): void {
    this.counter = 0;
  }
}

export const PaymentFactory = new PaymentFactoryClass();

export function createTestPayment(overrides: Partial<TestPaymentData> = {}): TestPaymentData {
  return PaymentFactory.create(overrides);
}