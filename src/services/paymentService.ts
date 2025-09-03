import { PaymentModel, Payment, CreatePaymentData, PaymentStats, PaymentMethodStats } from '@/models/Payment';

// 支付服务类
export class PaymentService {

  /**
   * 创建支付记录
   */
  static async create(paymentData: CreatePaymentData): Promise<Payment> {
    return await PaymentModel.create(paymentData);
  }

  /**
   * 根据ID查找支付记录
   */
  static async findById(id: string): Promise<Payment | null> {
    return await PaymentModel.findById(id);
  }

  /**
   * 根据PayPal订单ID查找支付记录
   */
  static async findByPayPalOrderId(orderId: string): Promise<Payment | null> {
    return await PaymentModel.findByPayPalOrderId(orderId);
  }

  /**
   * 更新支付状态
   */
  static async updateStatus(
    id: string,
    status: Payment['status'],
    metadata?: any,
  ): Promise<Payment | null> {
    return await PaymentModel.updateStatus(id, { status, metadata });
  }

  /**
   * 获取用户支付历史
   */
  static async getUserPayments(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      status?: Payment['status'];
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<{ payments: Payment[]; total: number }> {
    return await PaymentModel.getUserPayments(userId, options);
  }

  /**
   * 获取支付统计数据
   */
  static async getPaymentStats(
    options: {
      startDate?: Date;
      endDate?: Date;
      userId?: string;
    } = {},
  ): Promise<PaymentStats> {
    return await PaymentModel.getPaymentStats(options);
  }

  /**
   * 处理退款
   */
  static async processRefund(
    paymentId: string,
    refundAmount: number,
    reason?: string,
  ): Promise<Payment | null> {
    return await PaymentModel.processRefund(paymentId, refundAmount, reason);
  }

  /**
   * 检查重复支付
   */
  static async checkDuplicatePayment(
    userId: string,
    annotationId: string,
    amount: number,
    timeWindow: number = 300000, // 5分钟
  ): Promise<boolean> {
    const payment = await PaymentModel.checkDuplicatePayment(userId, annotationId, amount, timeWindow);
    return !!payment;
  }

  /**
   * 获取支付方法统计
   */
  static async getPaymentMethodStats(
    options: {
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<PaymentMethodStats[]> {
    return await PaymentModel.getPaymentMethodStats(options);
  }
}

export default PaymentService;
