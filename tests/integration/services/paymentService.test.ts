import { PaymentService } from '../../../src/services/paymentService';
import { PaymentModel, Payment, CreatePaymentData } from '../../../src/models/Payment';
import { db } from '../../../src/config/database';
import { v4 as uuidv4 } from 'uuid';

// Mock the PaymentModel
jest.mock('../../../src/models/Payment');

describe('PaymentService Integration Tests', () => {
  let mockPaymentModel: jest.Mocked<typeof PaymentModel>;

  beforeEach(() => {
    mockPaymentModel = PaymentModel as jest.Mocked<typeof PaymentModel>;
    jest.clearAllMocks();
  });

  describe('Payment Creation and Management', () => {
    const mockPaymentData: CreatePaymentData = {
      id: uuidv4(),
      userId: 'user-123',
      annotationId: 'annotation-456',
      amount: 50.00,
      currency: 'USD',
      paymentMethod: 'paypal',
      status: 'pending',
      paypalOrderId: 'PAYID-EXAMPLE-123',
      metadata: {
        annotationType: 'smell_report',
        location: 'Beijing, China',
      },
    };

    const mockPayment: Payment = {
      ...mockPaymentData,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('should create payment successfully', async () => {
      mockPaymentModel.create.mockResolvedValue(mockPayment);

      const result = await PaymentService.create(mockPaymentData);

      expect(mockPaymentModel.create).toHaveBeenCalledWith(mockPaymentData);
      expect(result).toEqual(mockPayment);
      expect(result.id).toBeDefined();
      expect(result.status).toBe('pending');
    });

    it('should handle payment creation with validation errors', async () => {
      const invalidPaymentData = {
        ...mockPaymentData,
        amount: -10, // Invalid negative amount
      };

      mockPaymentModel.create.mockRejectedValue(new Error('Invalid payment amount'));

      await expect(PaymentService.create(invalidPaymentData)).rejects.toThrow('Invalid payment amount');
    });

    it('should find payment by ID', async () => {
      const paymentId = 'payment-123';
      mockPaymentModel.findById.mockResolvedValue(mockPayment);

      const result = await PaymentService.findById(paymentId);

      expect(mockPaymentModel.findById).toHaveBeenCalledWith(paymentId);
      expect(result).toEqual(mockPayment);
    });

    it('should return null for non-existent payment', async () => {
      const paymentId = 'non-existent-payment';
      mockPaymentModel.findById.mockResolvedValue(null);

      const result = await PaymentService.findById(paymentId);

      expect(result).toBeNull();
    });

    it('should find payment by Stripe session ID', async () => {
      const sessionId = 'cs_session_123';
      mockPaymentModel.findByStripeSessionId.mockResolvedValue(mockPayment);

      const result = await PaymentService.findByStripeSessionId(sessionId);

      expect(mockPaymentModel.findByStripeSessionId).toHaveBeenCalledWith(sessionId);
      expect(result).toEqual(mockPayment);
    });

    it('should find payment by Stripe payment intent ID', async () => {
      const paymentIntentId = 'pi_intent_123';
      mockPaymentModel.findByStripePaymentIntentId.mockResolvedValue(mockPayment);

      const result = await PaymentService.findByStripePaymentIntentId(paymentIntentId);

      expect(mockPaymentModel.findByStripePaymentIntentId).toHaveBeenCalledWith(paymentIntentId);
      expect(result).toEqual(mockPayment);
    });
  });

  describe('Payment Status Management', () => {
    it('should update payment status successfully', async () => {
      const paymentId = 'payment-123';
      const newStatus = 'completed';
      const metadata = { transactionId: 'txn_123' };

      const updatedPayment: Payment = {
        ...mockPaymentData,
        id: paymentId,
        status: newStatus,
        metadata,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPaymentModel.updateStatus.mockResolvedValue(updatedPayment);

      const result = await PaymentService.updateStatus(paymentId, newStatus, metadata);

      expect(mockPaymentModel.updateStatus).toHaveBeenCalledWith(paymentId, {
        status: newStatus,
        metadata,
      });
      expect(result?.status).toBe(newStatus);
      expect(result?.metadata).toEqual(metadata);
    });

    it('should handle status update for non-existent payment', async () => {
      const paymentId = 'non-existent-payment';
      mockPaymentModel.updateStatus.mockResolvedValue(null);

      const result = await PaymentService.updateStatus(paymentId, 'completed');

      expect(result).toBeNull();
    });

    it('should update status to failed with error metadata', async () => {
      const paymentId = 'payment-123';
      const errorMetadata = {
        error: 'Card declined',
        errorCode: 'card_declined',
        stripeError: 'Your card was declined.',
      };

      const failedPayment: Payment = {
        ...mockPaymentData,
        id: paymentId,
        status: 'failed',
        metadata: errorMetadata,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPaymentModel.updateStatus.mockResolvedValue(failedPayment);

      const result = await PaymentService.updateStatus(paymentId, 'failed', errorMetadata);

      expect(result?.status).toBe('failed');
      expect(result?.metadata).toEqual(errorMetadata);
    });
  });

  describe('Payment History and Queries', () => {
    const mockPayments: Payment[] = [
      {
        id: 'payment-1',
        userId: 'user-123',
        annotationId: 'annotation-1',
        amount: 25.00,
        currency: 'USD',
        paymentMethod: 'stripe',
        status: 'completed',
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-01'),
      },
      {
        id: 'payment-2',
        userId: 'user-123',
        annotationId: 'annotation-2',
        amount: 35.00,
        currency: 'USD',
        paymentMethod: 'stripe',
        status: 'completed',
        createdAt: new Date('2024-01-02'),
        updatedAt: new Date('2024-01-02'),
      },
    ];

    it('should get user payments with pagination', async () => {
      const userId = 'user-123';
      const options = { page: 1, limit: 10 };

      mockPaymentModel.getUserPayments.mockResolvedValue({
        payments: mockPayments,
        total: 2,
      });

      const result = await PaymentService.getUserPayments(userId, options);

      expect(mockPaymentModel.getUserPayments).toHaveBeenCalledWith(userId, options);
      expect(result.payments).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should filter user payments by status', async () => {
      const userId = 'user-123';
      const options = { status: 'completed' as const };

      const completedPayments = mockPayments.filter(p => p.status === 'completed');
      mockPaymentModel.getUserPayments.mockResolvedValue({
        payments: completedPayments,
        total: completedPayments.length,
      });

      const result = await PaymentService.getUserPayments(userId, options);

      expect(result.payments).toEqual(completedPayments);
      expect(result.payments.every(p => p.status === 'completed')).toBe(true);
    });

    it('should filter user payments by date range', async () => {
      const userId = 'user-123';
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');
      const options = { startDate, endDate };

      mockPaymentModel.getUserPayments.mockResolvedValue({
        payments: mockPayments,
        total: 2,
      });

      const result = await PaymentService.getUserPayments(userId, options);

      expect(mockPaymentModel.getUserPayments).toHaveBeenCalledWith(userId, options);
      expect(result.payments).toHaveLength(2);
    });

    it('should handle empty payment history', async () => {
      const userId = 'user-with-no-payments';
      
      mockPaymentModel.getUserPayments.mockResolvedValue({
        payments: [],
        total: 0,
      });

      const result = await PaymentService.getUserPayments(userId);

      expect(result.payments).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Payment Statistics', () => {
    const mockStats = {
      totalAmount: 1000.00,
      totalPayments: 20,
      completedPayments: 18,
      failedPayments: 2,
      averageAmount: 50.00,
      totalRevenue: 900.00,
    };

    it('should get payment statistics', async () => {
      mockPaymentModel.getPaymentStats.mockResolvedValue(mockStats);

      const result = await PaymentService.getPaymentStats();

      expect(mockPaymentModel.getPaymentStats).toHaveBeenCalledWith({});
      expect(result).toEqual(mockStats);
    });

    it('should get payment statistics for date range', async () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');
      const options = { startDate, endDate };

      mockPaymentModel.getPaymentStats.mockResolvedValue(mockStats);

      const result = await PaymentService.getPaymentStats(options);

      expect(mockPaymentModel.getPaymentStats).toHaveBeenCalledWith(options);
      expect(result).toEqual(mockStats);
    });

    it('should get payment statistics for specific user', async () => {
      const userId = 'user-123';
      const userStats = {
        ...mockStats,
        totalAmount: 100.00,
        totalPayments: 3,
      };

      mockPaymentModel.getPaymentStats.mockResolvedValue(userStats);

      const result = await PaymentService.getPaymentStats({ userId });

      expect(mockPaymentModel.getPaymentStats).toHaveBeenCalledWith({ userId });
      expect(result).toEqual(userStats);
    });
  });

  describe('Refund Processing', () => {
    it('should process refund successfully', async () => {
      const paymentId = 'payment-123';
      const refundAmount = 25.00;
      const reason = 'Customer request';

      const refundedPayment: Payment = {
        ...mockPaymentData,
        id: paymentId,
        status: 'refunded',
        metadata: {
          refundAmount,
          refundReason: reason,
          refundedAt: new Date().toISOString(),
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPaymentModel.processRefund.mockResolvedValue(refundedPayment);

      const result = await PaymentService.processRefund(paymentId, refundAmount, reason);

      expect(mockPaymentModel.processRefund).toHaveBeenCalledWith(paymentId, refundAmount, reason);
      expect(result?.status).toBe('refunded');
      expect(result?.metadata?.refundAmount).toBe(refundAmount);
      expect(result?.metadata?.refundReason).toBe(reason);
    });

    it('should handle partial refund', async () => {
      const paymentId = 'payment-123';
      const originalAmount = 50.00;
      const refundAmount = 20.00; // Partial refund

      const partiallyRefundedPayment: Payment = {
        ...mockPaymentData,
        id: paymentId,
        amount: originalAmount,
        status: 'partially_refunded',
        metadata: {
          refundAmount,
          remainingAmount: originalAmount - refundAmount,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPaymentModel.processRefund.mockResolvedValue(partiallyRefundedPayment);

      const result = await PaymentService.processRefund(paymentId, refundAmount);

      expect(result?.status).toBe('partially_refunded');
      expect(result?.metadata?.refundAmount).toBe(refundAmount);
    });

    it('should handle refund failure', async () => {
      const paymentId = 'payment-123';
      const refundAmount = 25.00;

      mockPaymentModel.processRefund.mockResolvedValue(null);

      const result = await PaymentService.processRefund(paymentId, refundAmount);

      expect(result).toBeNull();
    });
  });

  describe('Duplicate Payment Detection', () => {
    it('should detect duplicate payment', async () => {
      const userId = 'user-123';
      const annotationId = 'annotation-456';
      const amount = 50.00;

      const duplicatePayment: Payment = {
        id: 'existing-payment',
        userId,
        annotationId,
        amount,
        currency: 'USD',
        paymentMethod: 'stripe',
        status: 'completed',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPaymentModel.checkDuplicatePayment.mockResolvedValue(duplicatePayment);

      const result = await PaymentService.checkDuplicatePayment(userId, annotationId, amount);

      expect(mockPaymentModel.checkDuplicatePayment).toHaveBeenCalledWith(
        userId,
        annotationId,
        amount,
        300000 // Default 5-minute window
      );
      expect(result).toBe(true);
    });

    it('should not detect duplicate for new payment', async () => {
      const userId = 'user-123';
      const annotationId = 'annotation-456';
      const amount = 50.00;

      mockPaymentModel.checkDuplicatePayment.mockResolvedValue(null);

      const result = await PaymentService.checkDuplicatePayment(userId, annotationId, amount);

      expect(result).toBe(false);
    });

    it('should use custom time window for duplicate detection', async () => {
      const userId = 'user-123';
      const annotationId = 'annotation-456';
      const amount = 50.00;
      const customTimeWindow = 600000; // 10 minutes

      mockPaymentModel.checkDuplicatePayment.mockResolvedValue(null);

      await PaymentService.checkDuplicatePayment(userId, annotationId, amount, customTimeWindow);

      expect(mockPaymentModel.checkDuplicatePayment).toHaveBeenCalledWith(
        userId,
        annotationId,
        amount,
        customTimeWindow
      );
    });
  });

  describe('Payment Method Statistics', () => {
    const mockPaymentMethodStats = [
      {
        paymentMethod: 'stripe',
        totalAmount: 800.00,
        totalPayments: 16,
        averageAmount: 50.00,
      },
      {
        paymentMethod: 'paypal',
        totalAmount: 200.00,
        totalPayments: 4,
        averageAmount: 50.00,
      },
    ];

    it('should get payment method statistics', async () => {
      mockPaymentModel.getPaymentMethodStats.mockResolvedValue(mockPaymentMethodStats);

      const result = await PaymentService.getPaymentMethodStats();

      expect(mockPaymentModel.getPaymentMethodStats).toHaveBeenCalledWith({});
      expect(result).toEqual(mockPaymentMethodStats);
      expect(result).toHaveLength(2);
    });

    it('should get payment method statistics for date range', async () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');
      const options = { startDate, endDate };

      mockPaymentModel.getPaymentMethodStats.mockResolvedValue(mockPaymentMethodStats);

      const result = await PaymentService.getPaymentMethodStats(options);

      expect(mockPaymentModel.getPaymentMethodStats).toHaveBeenCalledWith(options);
      expect(result).toEqual(mockPaymentMethodStats);
    });

    it('should handle empty payment method statistics', async () => {
      mockPaymentModel.getPaymentMethodStats.mockResolvedValue([]);

      const result = await PaymentService.getPaymentMethodStats();

      expect(result).toHaveLength(0);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle database connection errors', async () => {
      mockPaymentModel.create.mockRejectedValue(new Error('Database connection failed'));

      await expect(PaymentService.create(mockPaymentData)).rejects.toThrow('Database connection failed');
    });

    it('should handle concurrent payment creation', async () => {
      const paymentData1 = { ...mockPaymentData, id: 'payment-1' };
      const paymentData2 = { ...mockPaymentData, id: 'payment-2' };

      mockPaymentModel.create
        .mockResolvedValueOnce({ ...paymentData1, createdAt: new Date(), updatedAt: new Date() })
        .mockResolvedValueOnce({ ...paymentData2, createdAt: new Date(), updatedAt: new Date() });

      const [result1, result2] = await Promise.all([
        PaymentService.create(paymentData1),
        PaymentService.create(paymentData2),
      ]);

      expect(result1.id).toBe('payment-1');
      expect(result2.id).toBe('payment-2');
    });

    it('should handle malformed payment data', async () => {
      const malformedData = {
        ...mockPaymentData,
        amount: 'invalid-amount' as any,
      };

      mockPaymentModel.create.mockRejectedValue(new Error('Invalid amount format'));

      await expect(PaymentService.create(malformedData)).rejects.toThrow('Invalid amount format');
    });

    it('should handle very large amounts', async () => {
      const largeAmountData = {
        ...mockPaymentData,
        amount: 999999.99, // Large amount
      };

      const largeAmountPayment = {
        ...largeAmountData,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPaymentModel.create.mockResolvedValue(largeAmountPayment);

      const result = await PaymentService.create(largeAmountData);

      expect(result.amount).toBe(999999.99);
    });

    it('should handle zero amount payments', async () => {
      const zeroAmountData = {
        ...mockPaymentData,
        amount: 0,
      };

      mockPaymentModel.create.mockRejectedValue(new Error('Amount must be greater than zero'));

      await expect(PaymentService.create(zeroAmountData)).rejects.toThrow('Amount must be greater than zero');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle multiple payment queries efficiently', async () => {
      const userIds = Array.from({ length: 10 }, (_, i) => `user-${i}`);
      
      mockPaymentModel.getUserPayments.mockImplementation((userId) => 
        Promise.resolve({
          payments: [{ 
            ...mockPaymentData, 
            id: `payment-${userId}`,
            userId,
            createdAt: new Date(),
            updatedAt: new Date(),
          }],
          total: 1,
        })
      );

      const startTime = Date.now();
      const promises = userIds.map(userId => PaymentService.getUserPayments(userId));
      await Promise.all(promises);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
      expect(mockPaymentModel.getUserPayments).toHaveBeenCalledTimes(10);
    });

    it('should handle large result sets with pagination', async () => {
      const largeResultSet = Array.from({ length: 1000 }, (_, i) => ({
        ...mockPaymentData,
        id: `payment-${i}`,
        createdAt: new Date(),
        updatedAt: new Date(),
      }));

      mockPaymentModel.getUserPayments.mockResolvedValue({
        payments: largeResultSet.slice(0, 50), // First page
        total: 1000,
      });

      const result = await PaymentService.getUserPayments('user-123', { page: 1, limit: 50 });

      expect(result.payments).toHaveLength(50);
      expect(result.total).toBe(1000);
    });
  });
});