export interface Payment {
    id: string;
    user_id: string;
    annotation_id?: string;
    amount: number;
    currency: string;
    payment_method: 'stripe' | 'paypal' | 'alipay' | 'wechat';
    payment_intent_id?: string;
    session_id?: string;
    transaction_id?: string;
    status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled' | 'refunded';
    description?: string;
    metadata?: Record<string, any>;
    fee_amount?: number;
    net_amount?: number;
    refund_amount?: number;
    refund_reason?: string;
    processed_at?: Date;
    created_at: Date;
    updated_at: Date;
}
export interface CreatePaymentData {
    user_id: string;
    annotation_id?: string;
    amount: number;
    currency: string;
    payment_method: 'stripe' | 'paypal' | 'alipay' | 'wechat';
    payment_intent_id?: string;
    session_id?: string;
    description?: string;
    metadata?: Record<string, any>;
}
export interface UpdatePaymentData {
    status?: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled' | 'refunded';
    transaction_id?: string;
    fee_amount?: number;
    net_amount?: number;
    refund_amount?: number;
    refund_reason?: string;
    processed_at?: Date;
    metadata?: Record<string, any>;
}
export interface PaymentStats {
    total_revenue: number;
    total_transactions: number;
    average_amount: number;
    success_rate: number;
    refund_rate: number;
    monthly_data: Array<{
        month: string;
        revenue: number;
        transactions: number;
    }>;
}
export interface PaymentMethodStats {
    payment_method: string;
    transaction_count: number;
    total_revenue: number;
    success_rate: number;
}
export declare class PaymentModel {
    static create(paymentData: CreatePaymentData): Promise<Payment>;
    static findById(id: string): Promise<Payment | null>;
    static findByStripeSessionId(sessionId: string): Promise<Payment | null>;
    static findByStripePaymentIntentId(paymentIntentId: string): Promise<Payment | null>;
    static updateStatus(id: string, updateData: UpdatePaymentData): Promise<Payment | null>;
    static getUserPayments(userId: string, options?: {
        page?: number;
        limit?: number;
        status?: string;
        startDate?: Date;
        endDate?: Date;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }): Promise<{
        payments: Payment[];
        total: number;
    }>;
    static getPaymentStats(options?: {
        startDate?: Date;
        endDate?: Date;
        userId?: string;
    }): Promise<PaymentStats>;
    static processRefund(id: string, refundAmount: number, reason?: string): Promise<Payment | null>;
    static checkDuplicatePayment(userId: string, annotationId: string, amount: number, timeWindow?: number): Promise<Payment | null>;
    static getPaymentMethodStats(options?: {
        startDate?: Date;
        endDate?: Date;
    }): Promise<PaymentMethodStats[]>;
    static getList(options?: {
        page?: number;
        limit?: number;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
        status?: string;
        paymentMethod?: string;
        startDate?: Date;
        endDate?: Date;
        search?: string;
    }): Promise<{
        payments: Payment[];
        total: number;
    }>;
    static delete(id: string): Promise<boolean>;
}
export default PaymentModel;
//# sourceMappingURL=Payment.d.ts.map