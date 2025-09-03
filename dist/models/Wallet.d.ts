export interface Wallet {
    id: string;
    user_id: string;
    balance: number;
    frozen_balance: number;
    currency: string;
    status: 'active' | 'frozen' | 'closed';
    total_income: number;
    total_expense: number;
    created_at: Date;
    updated_at: Date;
}
export interface Transaction {
    id: string;
    user_id: string;
    wallet_id: string;
    type: 'deposit' | 'withdraw' | 'payment' | 'refund' | 'reward' | 'freeze' | 'unfreeze';
    amount: number;
    balance_before: number;
    balance_after: number;
    frozen_balance_before: number;
    frozen_balance_after: number;
    status: 'pending' | 'completed' | 'failed' | 'cancelled';
    description?: string;
    related_id?: string;
    payment_method?: string;
    external_transaction_id?: string;
    metadata?: Record<string, any>;
    processed_at?: Date;
    created_at: Date;
    updated_at: Date;
}
export interface LBSReward {
    id: string;
    user_id: string;
    annotation_id: string;
    transaction_id?: string;
    reward_amount: number;
    latitude: number;
    longitude: number;
    distance: number;
    reward_type: 'discovery' | 'proximity' | 'engagement';
    status: 'pending' | 'paid' | 'expired' | 'cancelled';
    discovered_at: Date;
    paid_at?: Date;
    expires_at: Date;
    created_at: Date;
    updated_at: Date;
}
export interface CreateWalletData {
    user_id: string;
    currency?: string;
}
export interface CreateTransactionData {
    user_id: string;
    wallet_id: string;
    type: 'deposit' | 'withdraw' | 'payment' | 'refund' | 'reward' | 'freeze' | 'unfreeze';
    amount: number;
    description?: string;
    related_id?: string | undefined;
    payment_method?: string;
    external_transaction_id?: string;
    metadata?: Record<string, any>;
}
export interface CreateLBSRewardData {
    user_id: string;
    annotation_id: string;
    reward_amount: number;
    latitude: number;
    longitude: number;
    distance: number;
    reward_type: 'discovery' | 'proximity' | 'engagement';
    expires_at: Date;
}
export interface WalletStats {
    total_balance: number;
    total_income: number;
    total_expense: number;
    transaction_count: number;
    recent_transactions: Transaction[];
    monthly_income: Array<{
        month: string;
        income: number;
        expense: number;
    }>;
}
export declare class WalletModel {
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
    static processLBSReward(rewardData: CreateLBSRewardData): Promise<LBSReward>;
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
export default WalletModel;
//# sourceMappingURL=Wallet.d.ts.map