import { v4 as uuidv4 } from 'uuid';
import { db } from '@/config/database';
import { logger } from '@/utils/logger';

export interface Payment {
  id: string;
  user_id: string;
  annotation_id?: string;
  amount: number;
  currency: string;
  payment_method: 'paypal' | 'alipay' | 'wechat';
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
  userId?: string;  // 新增：支持两种命名风格
  user_id?: string;
  annotationId?: string;  // 新增：支持两种命名风格
  annotation_id?: string;
  amount: number;
  currency: string;
  method?: 'paypal' | 'alipay' | 'wechat';  // 新增：支持两种命名风格
  payment_method?: 'paypal' | 'alipay' | 'wechat';
  paymentIntentId?: string;  // 新增：支持两种命名风格
  payment_intent_id?: string;
  sessionId?: string;  // 新增：支持两种命名风格
  session_id?: string;
  paypalOrderId?: string;  // 新增：PayPal订单ID
  stripeSessionId?: string;  // 新增：Stripe会话ID
  stripePaymentIntentId?: string;  // 新增：Stripe支付意图ID
  description?: string;
  status?: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled' | 'refunded';
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

const TABLE_NAME = 'payments';

export class PaymentModel {
  // Create a new payment
  static async create(paymentData: CreatePaymentData): Promise<Payment> {
    try {
      // 支持两种命名风格的数据转换
      const normalizedData = {
        id: uuidv4(),
        user_id: paymentData.userId || paymentData.user_id,
        annotation_id: paymentData.annotationId || paymentData.annotation_id,
        amount: paymentData.amount,
        currency: paymentData.currency,
        payment_method: paymentData.method || paymentData.payment_method,
        payment_intent_id: paymentData.paymentIntentId || paymentData.payment_intent_id || paymentData.stripePaymentIntentId,
        session_id: paymentData.sessionId || paymentData.session_id || paymentData.stripeSessionId || paymentData.paypalOrderId,
        description: paymentData.description,
        metadata: JSON.stringify(paymentData.metadata || {}),
        status: paymentData.status || 'pending',
      };

      const [payment] = await db(TABLE_NAME)
        .insert(normalizedData)
        .returning('*');

      // Parse metadata back to object
      payment.metadata = JSON.parse(payment.metadata || '{}');

      logger.info('支付记录创建成功', {
        paymentId: payment.id,
        userId: payment.user_id,
        amount: payment.amount,
        method: payment.payment_method,
      });

      return payment;
    } catch (error) {
      logger.error('支付记录创建失败', error);
      throw error;
    }
  }

  // Find payment by ID
  static async findById(id: string): Promise<Payment | null> {
    try {
      const payment = await db(TABLE_NAME)
        .where({ id })
        .first();

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      }

      return payment || null;
    } catch (error) {
      logger.error('查找支付记录失败', { paymentId: id, error });
      throw error;
    }
  }

  // Find payment by Stripe session ID
  static async findByStripeSessionId(sessionId: string): Promise<Payment | null> {
    try {
      const payment = await db(TABLE_NAME)
        .where({ session_id: sessionId })
        .first();

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      }

      return payment || null;
    } catch (error) {
      logger.error('通过Stripe会话ID查找支付记录失败', { sessionId, error });
      throw error;
    }
  }

  // Find payment by Stripe payment intent ID
  static async findByStripePaymentIntentId(paymentIntentId: string): Promise<Payment | null> {
    try {
      const payment = await db(TABLE_NAME)
        .where({ payment_intent_id: paymentIntentId })
        .first();

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      }

      return payment || null;
    } catch (error) {
      logger.error('通过Stripe支付意图ID查找支付记录失败', { paymentIntentId, error });
      throw error;
    }
  }

  // Find payment by PayPal order ID (使用session_id字段存储PayPal订单ID)
  static async findByPayPalOrderId(orderId: string): Promise<Payment | null> {
    try {
      const payment = await db(TABLE_NAME)
        .where({ session_id: orderId })
        .where({ payment_method: 'paypal' })
        .first();

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      }

      return payment || null;
    } catch (error) {
      logger.error('通过PayPal订单ID查找支付记录失败', { orderId, error });
      throw error;
    }
  }

  // Update payment status
  static async updateStatus(
    id: string,
    updateData: UpdatePaymentData,
  ): Promise<Payment | null> {
    try {
      const updatePayload: any = {
        ...updateData,
        updated_at: new Date(),
      };

      // Handle metadata serialization
      if (updateData.metadata) {
        updatePayload.metadata = JSON.stringify(updateData.metadata);
      }

      // Set processed_at when status becomes completed
      if (updateData.status === 'completed' && !updateData.processed_at) {
        updatePayload.processed_at = new Date();
      }

      const [payment] = await db(TABLE_NAME)
        .where({ id })
        .update(updatePayload)
        .returning('*');

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
        logger.info('支付状态更新成功', {
          paymentId: id,
          status: updateData.status,
        });
      }

      return payment || null;
    } catch (error) {
      logger.error('支付状态更新失败', { paymentId: id, error });
      throw error;
    }
  }

  // Get user payments with pagination and filters
  static async getUserPayments(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      status?: string;
      startDate?: Date;
      endDate?: Date;
      sortBy?: string;
      sortOrder?: 'asc' | 'desc';
    } = {},
  ): Promise<{ payments: Payment[]; total: number }> {
    try {
      const {
        page = 1,
        limit = 20,
        status,
        startDate,
        endDate,
        sortBy = 'created_at',
        sortOrder = 'desc',
      } = options;

      let query = db(TABLE_NAME)
        .select(
          'payments.*',
          'annotations.description as annotation_description',
          'annotations.latitude',
          'annotations.longitude',
        )
        .leftJoin('annotations', 'payments.annotation_id', 'annotations.id')
        .where('payments.user_id', userId);

      // Apply filters
      if (status) {
        query = query.where('payments.status', status);
      }

      if (startDate) {
        query = query.where('payments.created_at', '>=', startDate);
      }

      if (endDate) {
        query = query.where('payments.created_at', '<=', endDate);
      }

      // Get total count
      const countResult = await query.clone().count('payments.id as count');
      const total = parseInt((countResult[0] as any).count as string, 10);

      // Apply pagination and sorting
      const payments = await query
        .orderBy(`payments.${sortBy}`, sortOrder)
        .limit(limit)
        .offset((page - 1) * limit);

      // Parse metadata for each payment
      payments.forEach(payment => {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      });

      return { payments, total };
    } catch (error) {
      logger.error('获取用户支付历史失败', { userId, error });
      throw error;
    }
  }

  // Get payment statistics
  static async getPaymentStats(options: {
    startDate?: Date;
    endDate?: Date;
    userId?: string;
  } = {}): Promise<PaymentStats> {
    try {
      const { startDate, endDate, userId } = options;

      let query = db(TABLE_NAME).where('status', 'completed');

      if (userId) {
        query = query.where('user_id', userId);
      }

      if (startDate) {
        query = query.where('created_at', '>=', startDate);
      }

      if (endDate) {
        query = query.where('created_at', '<=', endDate);
      }

      // Get basic stats
      const [basicStats] = await query.clone()
        .sum('amount as total_revenue')
        .count('* as total_transactions')
        .avg('amount as average_amount');

      const totalRevenue = parseFloat(basicStats?.['total_revenue'] || '0');
      const totalTransactions = parseInt(basicStats?.['total_transactions'] || '0', 10);
      const averageAmount = parseFloat(basicStats?.['average_amount'] || '0');

      // Get success rate
      const [allPayments] = await db(TABLE_NAME)
        .count('* as total')
        .where(function () {
          if (userId) {
            this.where('user_id', userId);
          }
          if (startDate) {
            this.where('created_at', '>=', startDate);
          }
          if (endDate) {
            this.where('created_at', '<=', endDate);
          }
        });

      const totalAllPayments = parseInt(String(allPayments?.['total'] || '0'), 10);
      const successRate = totalAllPayments > 0 ? (totalTransactions / totalAllPayments) * 100 : 0;

      // Get refund rate
      const [refundStats] = await query.clone()
        .count('* as refund_count')
        .where('status', 'refunded');

      const refundCount = parseInt(String(refundStats?.['refund_count'] || '0'), 10);
      const refundRate = totalTransactions > 0 ? (refundCount / totalTransactions) * 100 : 0;

      // Get monthly data
      const monthlyResults = await query.clone()
        .select(db.raw('DATE_TRUNC(\'month\', created_at) as month'))
        .sum('amount as revenue')
        .count('* as transactions')
        .groupBy(db.raw('DATE_TRUNC(\'month\', created_at)'))
        .orderBy('month', 'desc')
        .limit(12);

      const monthlyData = monthlyResults.map((row: any) => ({
        month: new Date(row.month).toISOString().substring(0, 7), // YYYY-MM
        revenue: parseFloat(row.revenue || '0'),
        transactions: parseInt(row.transactions || '0', 10),
      }));

      return {
        total_revenue: Math.round(totalRevenue * 100) / 100,
        total_transactions: totalTransactions,
        average_amount: Math.round(averageAmount * 100) / 100,
        success_rate: Math.round(successRate * 100) / 100,
        refund_rate: Math.round(refundRate * 100) / 100,
        monthly_data: monthlyData,
      };
    } catch (error) {
      logger.error('获取支付统计失败', error);
      throw error;
    }
  }

  // Process refund
  static async processRefund(
    id: string,
    refundAmount: number,
    reason?: string,
  ): Promise<Payment | null> {
    try {
      const [payment] = await db(TABLE_NAME)
        .where({ id })
        .update({
          status: 'refunded',
          refund_amount: refundAmount,
          refund_reason: reason,
          updated_at: new Date(),
        })
        .returning('*');

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
        logger.info('退款处理成功', {
          paymentId: id,
          refundAmount,
          reason,
        });
      }

      return payment || null;
    } catch (error) {
      logger.error('退款处理失败', { paymentId: id, error });
      throw error;
    }
  }

  // Check for duplicate payments
  static async checkDuplicatePayment(
    userId: string,
    annotationId: string,
    amount: number,
    timeWindow: number = 300000, // 5 minutes in milliseconds
  ): Promise<Payment | null> {
    try {
      const cutoffTime = new Date(Date.now() - timeWindow);

      const payment = await db(TABLE_NAME)
        .where({
          user_id: userId,
          annotation_id: annotationId,
          amount,
        })
        .where('created_at', '>=', cutoffTime)
        .whereIn('status', ['pending', 'processing', 'completed'])
        .first();

      if (payment) {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      }

      return payment || null;
    } catch (error) {
      logger.error('检查重复支付失败', { userId, annotationId, error });
      throw error;
    }
  }

  // Get payment method statistics
  static async getPaymentMethodStats(options: {
    startDate?: Date;
    endDate?: Date;
  } = {}): Promise<PaymentMethodStats[]> {
    try {
      const { startDate, endDate } = options;

      let query = db(TABLE_NAME)
        .select('payment_method')
        .count('* as transaction_count')
        .sum('amount as total_revenue')
        .groupBy('payment_method');

      if (startDate) {
        query = query.where('created_at', '>=', startDate);
      }

      if (endDate) {
        query = query.where('created_at', '<=', endDate);
      }

      const results = await query;

      // Calculate success rates for each payment method
      const statsWithSuccessRate = await Promise.all(
        results.map(async (result: any) => {
          const [successCount] = await db(TABLE_NAME)
            .count('* as success_count')
            .where('payment_method', result.payment_method)
            .where('status', 'completed')
            .where(function () {
              if (startDate) {
                this.where('created_at', '>=', startDate);
              }
              if (endDate) {
                this.where('created_at', '<=', endDate);
              }
            });

          const totalCount = parseInt(result.transaction_count, 10);
          const successCountNum = parseInt(String(successCount?.['success_count'] || '0'), 10);
          const successRate = totalCount > 0 ? (successCountNum / totalCount) * 100 : 0;

          return {
            payment_method: result.payment_method,
            transaction_count: totalCount,
            total_revenue: parseFloat(result.total_revenue || '0'),
            success_rate: Math.round(successRate * 100) / 100,
          };
        }),
      );

      return statsWithSuccessRate;
    } catch (error) {
      logger.error('获取支付方式统计失败', error);
      throw error;
    }
  }

  // Get payments list (admin)
  static async getList(options: {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
    status?: string;
    paymentMethod?: string;
    startDate?: Date;
    endDate?: Date;
    search?: string;
  } = {}): Promise<{ payments: Payment[]; total: number }> {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'created_at',
        sortOrder = 'desc',
        status,
        paymentMethod,
        startDate,
        endDate,
        search,
      } = options;

      let query = db(TABLE_NAME)
        .select(
          'payments.*',
          'users.username',
          'users.email',
          'annotations.description as annotation_description',
        )
        .leftJoin('users', 'payments.user_id', 'users.id')
        .leftJoin('annotations', 'payments.annotation_id', 'annotations.id');

      // Apply filters
      if (status) {
        query = query.where('payments.status', status);
      }

      if (paymentMethod) {
        query = query.where('payments.payment_method', paymentMethod);
      }

      if (startDate) {
        query = query.where('payments.created_at', '>=', startDate);
      }

      if (endDate) {
        query = query.where('payments.created_at', '<=', endDate);
      }

      if (search) {
        query = query.where(function () {
          this.where('users.username', 'ilike', `%${search}%`)
            .orWhere('users.email', 'ilike', `%${search}%`)
            .orWhere('payments.transaction_id', 'ilike', `%${search}%`)
            .orWhere('payments.payment_intent_id', 'ilike', `%${search}%`);
        });
      }

      // Get total count
      const countResult = await query.clone().count('payments.id as count');
      const total = parseInt((countResult[0] as any).count as string, 10);

      // Apply pagination and sorting
      const payments = await query
        .orderBy(`payments.${sortBy}`, sortOrder)
        .limit(limit)
        .offset((page - 1) * limit);

      // Parse metadata for each payment
      payments.forEach(payment => {
        payment.metadata = JSON.parse(payment.metadata || '{}');
      });

      return { payments, total };
    } catch (error) {
      logger.error('获取支付列表失败', error);
      throw error;
    }
  }

  // Delete payment (soft delete by updating status)
  static async delete(id: string): Promise<boolean> {
    try {
      const result = await db(TABLE_NAME)
        .where({ id })
        .update({
          status: 'cancelled',
          updated_at: new Date(),
        });

      if (result > 0) {
        logger.info('支付记录删除成功', { paymentId: id });
        return true;
      }

      return false;
    } catch (error) {
      logger.error('支付记录删除失败', { paymentId: id, error });
      throw error;
    }
  }
}

export default PaymentModel;
