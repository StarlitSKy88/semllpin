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
declare class PaymentFactoryClass implements TestDataFactory<TestPaymentData> {
    private counter;
    create(overrides?: Partial<TestPaymentData>): TestPaymentData;
    private getRandomPaymentMethod;
    createMultiple(count: number, overrides?: Partial<TestPaymentData>): TestPaymentData[];
    build(overrides?: Partial<TestPaymentData>): TestPaymentData;
    buildList(count: number, overrides?: Partial<TestPaymentData>): TestPaymentData[];
    createStripePayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
    createPayPalPayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
    createAlipayPayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
    createWechatPayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
    createFailedPayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
    createRefundedPayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
    reset(): void;
}
export declare const PaymentFactory: PaymentFactoryClass;
export declare function createTestPayment(overrides?: Partial<TestPaymentData>): TestPaymentData;
export {};
//# sourceMappingURL=paymentFactory.d.ts.map