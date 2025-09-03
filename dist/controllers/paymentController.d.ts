import { Request, Response, NextFunction } from 'express';
interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        username: string;
        role: string;
    };
}
export declare const createPaymentSession: (req: Request, res: Response, next: NextFunction) => void;
export declare const getPaymentSession: (req: Request, res: Response, next: NextFunction) => void;
export declare const handleStripeWebhook: (req: Request, res: Response, next: NextFunction) => void;
export declare const getUserPayments: (req: AuthRequest, res: Response) => Promise<void>;
export declare const requestRefund: (req: AuthRequest, res: Response) => Promise<void>;
export declare const getPaymentStats: (req: AuthRequest, res: Response) => Promise<void>;
export declare const getBalanceReport: (req: Request, res: Response, next: NextFunction) => void;
export declare const retryFailedPayments: (req: Request, res: Response, next: NextFunction) => void;
export declare const getPaymentHealth: (req: Request, res: Response, next: NextFunction) => void;
export declare const batchProcessRefunds: (req: Request, res: Response, next: NextFunction) => void;
export declare const processAutoRefunds: (req: Request, res: Response, next: NextFunction) => void;
export declare const getRefundAnalysis: (req: Request, res: Response, next: NextFunction) => void;
declare const _default: {
    createPaymentSession: (req: Request, res: Response, next: NextFunction) => void;
    getPaymentSession: (req: Request, res: Response, next: NextFunction) => void;
    handleStripeWebhook: (req: Request, res: Response, next: NextFunction) => void;
    getUserPayments: (req: AuthRequest, res: Response) => Promise<void>;
    requestRefund: (req: AuthRequest, res: Response) => Promise<void>;
    getPaymentStats: (req: AuthRequest, res: Response) => Promise<void>;
    getBalanceReport: (req: Request, res: Response, next: NextFunction) => void;
    retryFailedPayments: (req: Request, res: Response, next: NextFunction) => void;
    getPaymentHealth: (req: Request, res: Response, next: NextFunction) => void;
    batchProcessRefunds: (req: Request, res: Response, next: NextFunction) => void;
    processAutoRefunds: (req: Request, res: Response, next: NextFunction) => void;
    getRefundAnalysis: (req: Request, res: Response, next: NextFunction) => void;
};
export default _default;
//# sourceMappingURL=paymentController.d.ts.map