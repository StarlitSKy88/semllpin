import { Request, Response } from 'express';
import { PayPalService } from '@/services/paypal';
import { PaymentService } from '@/services/paymentService';
import { CreatePaymentData } from '@/models/Payment';

/**
 * PayPal支付控制器
 * 处理PayPal支付订单创建、捕获等操作
 */
export class PayPalPaymentController {
  
  /**
   * 创建PayPal支付订单
   */
  async createPayment(req: Request, res: Response): Promise<void> {
    try {
      const { amount, currency = 'USD', description, annotationId, paymentMethod } = req.body;
      const userId = (req as any).user?.id;

      // 验证支付方式
      if (paymentMethod !== 'paypal') {
        res.status(400).json({
          success: false,
          message: '无效的支付方式，必须是 paypal'
        });
        return;
      }

      // 验证用户身份
      if (!userId) {
        res.status(401).json({
          success: false,
          message: '用户未认证'
        });
        return;
      }

      // 验证金额
      if (!PayPalService.validateAmount(amount.toString(), currency)) {
        res.status(400).json({
          success: false,
          message: `支付金额不符合 ${currency} 货币的最小限制`
        });
        return;
      }

      // 格式化金额
      const formattedAmount = PayPalService.formatAmount(parseFloat(amount), currency);

      // 检查重复支付
      if (annotationId) {
        const isDuplicate = await PaymentService.checkDuplicatePayment(
          userId,
          annotationId,
          parseFloat(formattedAmount),
          300000 // 5分钟
        );

        if (isDuplicate) {
          res.status(409).json({
            success: false,
            message: '检测到重复支付，请稍后再试'
          });
          return;
        }
      }

      // 创建PayPal订单
      const paypalOrder = await PayPalService.createOrder({
        amount: formattedAmount,
        currency,
        description,
        userId,
        annotationId
      });

      // 在数据库中创建支付记录
      const paymentData: CreatePaymentData = {
        userId,
        annotationId: annotationId || null,
        amount: parseFloat(formattedAmount),
        currency,
        method: 'paypal',
        status: 'pending',
        paypalOrderId: paypalOrder.id,
        metadata: {
          paypalOrderStatus: paypalOrder.status,
          description,
          createdAt: new Date().toISOString()
        }
      };

      const payment = await PaymentService.create(paymentData);

      // 查找approval URL
      let approvalUrl: string | undefined;
      if (paypalOrder.links) {
        const approvalLink = paypalOrder.links.find(link => link.rel === 'approval_url');
        approvalUrl = approvalLink?.href;
      }

      res.status(201).json({
        success: true,
        message: 'PayPal支付订单创建成功',
        data: {
          paymentId: payment.id,
          orderId: paypalOrder.id,
          status: paypalOrder.status,
          approvalUrl,
          amount: formattedAmount,
          currency
        }
      });

    } catch (error) {
      console.error('PayPal create payment error:', error);
      res.status(500).json({
        success: false,
        message: '创建PayPal支付订单失败',
        error: error instanceof Error ? error.message : '未知错误'
      });
    }
  }

  /**
   * 捕获PayPal支付
   */
  async capturePayment(req: Request, res: Response): Promise<void> {
    try {
      const { orderId, payerId } = req.body;
      const userId = (req as any).user?.id;

      // 验证用户身份
      if (!userId) {
        res.status(401).json({
          success: false,
          message: '用户未认证'
        });
        return;
      }

      // 通过PayPal订单ID查找数据库中的支付记录
      const payment = await PaymentService.findByPayPalOrderId(orderId);
      
      if (!payment) {
        res.status(404).json({
          success: false,
          message: '支付记录未找到'
        });
        return;
      }

      // 验证支付所有权
      if (payment.userId !== userId) {
        res.status(403).json({
          success: false,
          message: '无权访问此支付记录'
        });
        return;
      }

      // 检查支付状态
      if (payment.status === 'completed') {
        res.status(409).json({
          success: false,
          message: '支付已完成，无法重复捕获'
        });
        return;
      }

      // 捕获PayPal支付
      const captureResult = await PayPalService.captureOrder(orderId, payerId);

      // 更新数据库中的支付状态
      const updatedPayment = await PaymentService.updateStatus(
        payment.id,
        captureResult.status === 'approved' ? 'completed' : 'failed',
        {
          ...payment.metadata,
          paypalCaptureId: captureResult.id,
          paypalCaptureStatus: captureResult.status,
          capturedAt: new Date().toISOString(),
          payerId
        }
      );

      if (!updatedPayment) {
        throw new Error('Failed to update payment status');
      }

      // 如果支付成功且关联了标注，创建标注
      if (captureResult.status === 'approved' && payment.annotationId) {
        // 这里可以触发标注创建逻辑
        // 可以通过事件系统或直接调用相关服务
        console.log(`Payment captured for annotation: ${payment.annotationId}`);
      }

      res.json({
        success: true,
        message: 'PayPal支付捕获成功',
        data: {
          paymentId: payment.id,
          orderId: captureResult.id,
          status: captureResult.status,
          amount: payment.amount,
          currency: payment.currency,
          capturedAt: updatedPayment.metadata?.capturedAt
        }
      });

    } catch (error) {
      console.error('PayPal capture payment error:', error);
      res.status(500).json({
        success: false,
        message: '捕获PayPal支付失败',
        error: error instanceof Error ? error.message : '未知错误'
      });
    }
  }

  /**
   * 获取PayPal支付详情
   */
  async getPaymentDetails(req: Request, res: Response): Promise<void> {
    try {
      const { orderId } = req.params;
      const userId = (req as any).user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: '用户未认证'
        });
        return;
      }

      // 从PayPal获取订单详情
      const orderDetails = await PayPalService.getOrderDetails(orderId);
      
      if (!orderDetails) {
        res.status(404).json({
          success: false,
          message: 'PayPal订单未找到'
        });
        return;
      }

      // 获取数据库中的支付记录
      const payment = await PaymentService.findByPayPalOrderId(orderId);
      
      if (!payment || payment.userId !== userId) {
        res.status(403).json({
          success: false,
          message: '无权访问此支付记录'
        });
        return;
      }

      res.json({
        success: true,
        data: {
          payment: {
            id: payment.id,
            amount: payment.amount,
            currency: payment.currency,
            status: payment.status,
            createdAt: payment.createdAt,
            updatedAt: payment.updatedAt
          },
          paypalOrder: {
            id: orderDetails.id,
            status: orderDetails.status,
            createTime: orderDetails.create_time,
            updateTime: orderDetails.update_time,
            intent: orderDetails.intent
          }
        }
      });

    } catch (error) {
      console.error('Get PayPal payment details error:', error);
      res.status(500).json({
        success: false,
        message: '获取PayPal支付详情失败',
        error: error instanceof Error ? error.message : '未知错误'
      });
    }
  }

  /**
   * 处理PayPal支付退款
   */
  async refundPayment(req: Request, res: Response): Promise<void> {
    try {
      const { paymentId, amount, reason } = req.body;
      const userId = (req as any).user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: '用户未认证'
        });
        return;
      }

      // 获取支付记录
      const payment = await PaymentService.findById(paymentId);
      
      if (!payment) {
        res.status(404).json({
          success: false,
          message: '支付记录未找到'
        });
        return;
      }

      // 验证支付所有权（或管理员权限）
      if (payment.userId !== userId) {
        // 这里可以添加管理员权限检查
        res.status(403).json({
          success: false,
          message: '无权操作此支付记录'
        });
        return;
      }

      // 检查支付状态
      if (payment.status !== 'completed') {
        res.status(400).json({
          success: false,
          message: '只有已完成的支付才能退款'
        });
        return;
      }

      // 检查是否已经退款
      if (payment.status === 'refunded') {
        res.status(409).json({
          success: false,
          message: '支付已退款'
        });
        return;
      }

      // 执行PayPal退款
      const refundAmount = amount ? amount.toString() : payment.amount.toString();
      const refundResult = await PayPalService.refundPayment(
        payment.paypalOrderId || payment.stripeSessionId || '',
        refundAmount,
        payment.currency,
        reason
      );

      // 更新支付状态
      const updatedPayment = await PaymentService.updateStatus(
        payment.id,
        'refunded',
        {
          ...payment.metadata,
          refundId: refundResult.id,
          refundAmount: refundAmount,
          refundReason: reason,
          refundedAt: new Date().toISOString()
        }
      );

      res.json({
        success: true,
        message: '退款处理成功',
        data: {
          paymentId: payment.id,
          refundId: refundResult.id,
          refundAmount: refundAmount,
          refundedAt: updatedPayment?.metadata?.refundedAt
        }
      });

    } catch (error) {
      console.error('PayPal refund payment error:', error);
      res.status(500).json({
        success: false,
        message: '退款处理失败',
        error: error instanceof Error ? error.message : '未知错误'
      });
    }
  }

  /**
   * 处理PayPal Webhook事件
   */
  async handleWebhook(req: Request, res: Response): Promise<void> {
    try {
      const webhookBody = JSON.stringify(req.body);
      const headers = req.headers;
      const webhookId = process.env.PAYPAL_WEBHOOK_ID || '';

      // 验证webhook
      const isValid = await PayPalService.verifyWebhook(headers, webhookBody, webhookId);
      
      if (!isValid) {
        res.status(401).json({
          success: false,
          message: 'Invalid webhook signature'
        });
        return;
      }

      const event = req.body;
      
      // 处理不同的webhook事件
      switch (event.event_type) {
        case 'PAYMENT.CAPTURE.COMPLETED':
          await this.handlePaymentCompleted(event);
          break;
        case 'PAYMENT.CAPTURE.DENIED':
          await this.handlePaymentDenied(event);
          break;
        case 'PAYMENT.CAPTURE.REFUNDED':
          await this.handlePaymentRefunded(event);
          break;
        default:
          console.log(`Unhandled PayPal webhook event: ${event.event_type}`);
      }

      res.json({ received: true });

    } catch (error) {
      console.error('PayPal webhook error:', error);
      res.status(500).json({
        success: false,
        message: 'Webhook处理失败',
        error: error instanceof Error ? error.message : '未知错误'
      });
    }
  }

  /**
   * 处理支付完成事件
   */
  private async handlePaymentCompleted(event: any): Promise<void> {
    try {
      const resource = event.resource;
      const orderId = resource.supplementary_data?.related_ids?.order_id;
      
      if (orderId) {
        const payment = await PaymentService.findByPayPalOrderId(orderId);
        if (payment && payment.status !== 'completed') {
          await PaymentService.updateStatus(payment.id, 'completed', {
            ...payment.metadata,
            webhookEventId: event.id,
            completedAt: new Date().toISOString()
          });
        }
      }
    } catch (error) {
      console.error('Handle payment completed error:', error);
    }
  }

  /**
   * 处理支付拒绝事件
   */
  private async handlePaymentDenied(event: any): Promise<void> {
    try {
      const resource = event.resource;
      const orderId = resource.supplementary_data?.related_ids?.order_id;
      
      if (orderId) {
        const payment = await PaymentService.findByPayPalOrderId(orderId);
        if (payment && payment.status === 'pending') {
          await PaymentService.updateStatus(payment.id, 'failed', {
            ...payment.metadata,
            webhookEventId: event.id,
            failedAt: new Date().toISOString(),
            failureReason: 'Payment denied'
          });
        }
      }
    } catch (error) {
      console.error('Handle payment denied error:', error);
    }
  }

  /**
   * 处理退款事件
   */
  private async handlePaymentRefunded(event: any): Promise<void> {
    try {
      const resource = event.resource;
      const orderId = resource.supplementary_data?.related_ids?.order_id;
      
      if (orderId) {
        const payment = await PaymentService.findByPayPalOrderId(orderId);
        if (payment && payment.status === 'completed') {
          await PaymentService.updateStatus(payment.id, 'refunded', {
            ...payment.metadata,
            webhookEventId: event.id,
            refundedAt: new Date().toISOString(),
            refundAmount: resource.amount?.value
          });
        }
      }
    } catch (error) {
      console.error('Handle payment refunded error:', error);
    }
  }
}

// 导出控制器实例
export const paypalPaymentController = new PayPalPaymentController();