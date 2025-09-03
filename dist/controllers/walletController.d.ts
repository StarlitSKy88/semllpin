import { Request, Response } from 'express';
interface AuthenticatedRequest extends Request {
    user?: {
        id: string;
        email: string;
        username: string;
        role: string;
    };
}
declare class WalletController {
    getWallet(req: AuthenticatedRequest, res: Response): Promise<void>;
    getTransactionHistory(req: AuthenticatedRequest, res: Response): Promise<void>;
    getTransactionSummary(req: AuthenticatedRequest, res: Response): Promise<void>;
    exportTransactions(req: AuthenticatedRequest, res: Response): Promise<void>;
    createTopUpSession(req: AuthenticatedRequest, res: Response): Promise<void>;
    handleTopUpSuccess(req: AuthenticatedRequest, res: Response): Promise<void>;
    getLBSRewards(req: AuthenticatedRequest, res: Response): Promise<void>;
}
declare const _default: WalletController;
export default _default;
export { WalletController };
//# sourceMappingURL=walletController.d.ts.map