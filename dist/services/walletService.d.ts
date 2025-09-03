import { Wallet, Transaction, CreateWalletData, CreateTransactionData, WalletStats, LBSReward, CreateLBSRewardData } from '@/models/Wallet';
export { Wallet, Transaction, CreateWalletData, CreateTransactionData, WalletStats, LBSReward, CreateLBSRewardData };
export declare class WalletService {
    static createWallet(walletData: CreateWalletData): Promise<Wallet>;
    static getUserWallet(userId: string): Promise<Wallet | null>;
    static getOrCreateWallet(userId: string): Promise<Wallet>;
    static createTransaction(transactionData: CreateTransactionData): Promise<Transaction>;
    static getUserTransactions(userId: string, options?: {
        page?: number;
        limit?: number;
        type?: string;
        status?: string;
        startDate?: Date;
        endDate?: Date;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }): Promise<{
        transactions: Transaction[];
        total: number;
    }>;
    static getWalletStats(userId: string, options?: {
        startDate?: Date;
        endDate?: Date;
    }): Promise<WalletStats>;
    static processLBSReward(userId: string, annotationId: string, rewardAmount: number, latitude: number, longitude: number, distance: number, rewardType?: 'discovery' | 'proximity' | 'engagement'): Promise<LBSReward>;
    static checkBalance(userId: string, amount: number): Promise<boolean>;
    static freezeFunds(userId: string, amount: number, description?: string, relatedId?: string): Promise<Transaction>;
    static unfreezeFunds(userId: string, amount: number, description?: string, relatedId?: string): Promise<Transaction>;
    static getUserLBSRewards(userId: string, options?: {
        page?: number;
        limit?: number;
        status?: string;
        rewardType?: string;
        startDate?: Date;
        endDate?: Date;
    }): Promise<{
        rewards: LBSReward[];
        total: number;
    }>;
    static getTransactionById(id: string): Promise<Transaction | null>;
    static getLBSRewardById(id: string): Promise<LBSReward | null>;
    static updateWalletStatus(userId: string, status: 'active' | 'frozen' | 'closed'): Promise<Wallet | null>;
}
export default WalletService;
//# sourceMappingURL=walletService.d.ts.map