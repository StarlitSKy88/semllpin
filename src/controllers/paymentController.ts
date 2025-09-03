import { Request, Response } from 'express';
import { paypalPaymentController } from './paypalPaymentController';

/**
 * 支付控制器
 * 重定向到PayPal支付控制器，因为项目只使用PayPal支付
 */
export class PaymentController {

  /**
   * 创建支付订单 - 重定向到PayPal
   */
  async createPaymentIntent(req: Request, res: Response): Promise<void> {
    return paypalPaymentController.createPayment(req, res);
  }

  /**
   * 创建支付会话 - 重定向到PayPal
   */
  async createCheckoutSession(req: Request, res: Response): Promise<void> {
    return paypalPaymentController.createPayment(req, res);
  }

  /**
   * 验证并完成支付 - 重定向到PayPal
   */
  async confirmPayment(req: Request, res: Response): Promise<void> {
    return paypalPaymentController.capturePayment(req, res);
  }

  /**
   * 获取支付详情 - 重定向到PayPal
   */
  async getPaymentDetails(req: Request, res: Response): Promise<void> {
    return paypalPaymentController.getPaymentDetails(req, res);
  }

  /**
   * 处理退款 - 重定向到PayPal
   */
  async refundPayment(req: Request, res: Response): Promise<void> {
    return paypalPaymentController.refundPayment(req, res);
  }

  /**
   * 处理Webhook事件 - 重定向到PayPal
   */
  async handleWebhook(req: Request, res: Response): Promise<void> {
    return paypalPaymentController.handleWebhook(req, res);
  }
}

// 导出控制器实例
export const paymentController = new PaymentController();

// 保持向后兼容的导出
export const createPaymentSession = paymentController.createPaymentIntent.bind(paymentController);
export const confirmPayment = paymentController.confirmPayment.bind(paymentController);
export const getPaymentDetails = paymentController.getPaymentDetails.bind(paymentController);
export const refundPayment = paymentController.refundPayment.bind(paymentController);
export const handleWebhook = paymentController.handleWebhook.bind(paymentController);

export default paymentController;