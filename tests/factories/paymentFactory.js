"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaymentFactory = void 0;
exports.createTestPayment = createTestPayment;
class PaymentFactoryClass {
    constructor() {
        this.counter = 0;
    }
    create(overrides = {}) {
        this.counter++;
        const amount = overrides.amount ?? Math.floor(Math.random() * 50) + 1;
        const feeAmount = Math.round(amount * 0.029 * 100) / 100;
        const basePayment = {
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
    getRandomPaymentMethod() {
        const methods = ['stripe', 'paypal', 'alipay', 'wechat'];
        return methods[Math.floor(Math.random() * methods.length)];
    }
    createMultiple(count, overrides = {}) {
        return Array.from({ length: count }, () => this.create(overrides));
    }
    build(overrides = {}) {
        const tempCounter = this.counter;
        const payment = this.create(overrides);
        this.counter = tempCounter;
        return payment;
    }
    buildList(count, overrides = {}) {
        return Array.from({ length: count }, () => this.build(overrides));
    }
    createStripePayment(overrides = {}) {
        return this.create({
            paymentMethod: 'stripe',
            transactionId: `ch_test_${this.counter}_${Math.random().toString(36).substr(2, 9)}`,
            paymentIntentId: `pi_test_${this.counter}_${Math.random().toString(36).substr(2, 9)}`,
            ...overrides,
        });
    }
    createPayPalPayment(overrides = {}) {
        return this.create({
            paymentMethod: 'paypal',
            transactionId: `PAY-${this.counter}${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
            paymentIntentId: null,
            ...overrides,
        });
    }
    createAlipayPayment(overrides = {}) {
        return this.create({
            paymentMethod: 'alipay',
            currency: 'CNY',
            transactionId: `2024${String(this.counter).padStart(8, '0')}${Date.now()}`,
            ...overrides,
        });
    }
    createWechatPayment(overrides = {}) {
        return this.create({
            paymentMethod: 'wechat',
            currency: 'CNY',
            transactionId: `wx${Date.now()}${String(this.counter).padStart(6, '0')}`,
            ...overrides,
        });
    }
    createFailedPayment(overrides = {}) {
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
    createRefundedPayment(overrides = {}) {
        const amount = overrides.amount ?? Math.floor(Math.random() * 50) + 1;
        const refundedAmount = overrides.refundedAmount ?? amount;
        return this.create({
            amount: amount,
            status: 'refunded',
            refundedAmount: refundedAmount,
            ...overrides,
        });
    }
    reset() {
        this.counter = 0;
    }
}
exports.PaymentFactory = new PaymentFactoryClass();
function createTestPayment(overrides = {}) {
    return exports.PaymentFactory.create(overrides);
}
//# sourceMappingURL=paymentFactory.js.map