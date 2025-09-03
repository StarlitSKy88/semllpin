import { Request, Response } from 'express';
export declare class PaymentController {
    createPaymentIntent(req: Request, res: Response): Promise<void>;
    createCheckoutSession(req: Request, res: Response): Promise<void>;
    confirmPayment(req: Request, res: Response): Promise<void>;
    getPaymentDetails(req: Request, res: Response): Promise<void>;
    refundPayment(req: Request, res: Response): Promise<void>;
    handleWebhook(req: Request, res: Response): Promise<void>;
}
export declare const paymentController: PaymentController;
export declare const createPaymentSession: (req: Request, res: Response) => Promise<void>;
export declare const confirmPayment: (req: Request, res: Response) => Promise<void>;
export declare const getPaymentDetails: (req: Request, res: Response) => Promise<void>;
export declare const refundPayment: (req: Request, res: Response) => Promise<void>;
export declare const handleWebhook: (req: Request, res: Response) => Promise<void>;
export default paymentController;
//# sourceMappingURL=paymentController.d.ts.map