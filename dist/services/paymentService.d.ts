import { Payment, CreatePaymentData, PaymentStats, PaymentMethodStats } from '@/models/Payment';
export declare class PaymentService {
    static create(paymentData: CreatePaymentData): Promise<Payment>;
    static findById(id: string): Promise<Payment | null>;
    static findByPayPalOrderId(orderId: string): Promise<Payment | null>;
    static updateStatus(id: string, status: Payment['status'], metadata?: any): Promise<Payment | null>;
    static getUserPayments(userId: string, options?: {
        page?: number;
        limit?: number;
        status?: Payment['status'];
        startDate?: Date;
        endDate?: Date;
    }): Promise<{
        payments: Payment[];
        total: number;
    }>;
    static getPaymentStats(options?: {
        startDate?: Date;
        endDate?: Date;
        userId?: string;
    }): Promise<PaymentStats>;
    static processRefund(paymentId: string, refundAmount: number, reason?: string): Promise<Payment | null>;
    static checkDuplicatePayment(userId: string, annotationId: string, amount: number, timeWindow?: number): Promise<boolean>;
    static getPaymentMethodStats(options?: {
        startDate?: Date;
        endDate?: Date;
    }): Promise<PaymentMethodStats[]>;
}
export default PaymentService;
//# sourceMappingURL=paymentService.d.ts.map