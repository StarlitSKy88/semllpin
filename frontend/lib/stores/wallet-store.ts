import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { Wallet, walletApi, LBSReward, lbsApi } from '../services/api';

interface Transaction {
  id: string;
  type: 'recharge' | 'withdraw' | 'reward' | 'payment';
  amount: number;
  status: 'pending' | 'completed' | 'failed';
  description: string;
  createdAt: string;
}

interface WalletState {
  // 钱包数据
  wallet: Wallet | null;
  transactions: Transaction[];
  rewards: LBSReward[];
  
  // 分页信息
  transactionPage: number;
  rewardPage: number;
  hasMoreTransactions: boolean;
  hasMoreRewards: boolean;
  
  // 加载状态
  isLoading: boolean;
  isLoadingTransactions: boolean;
  isLoadingRewards: boolean;
  error: string | null;
  
  // 操作
  loadWallet: () => Promise<void>;
  loadTransactions: (page?: number, refresh?: boolean) => Promise<void>;
  loadRewards: (page?: number, refresh?: boolean) => Promise<void>;
  recharge: (amount: number, paymentMethod: string) => Promise<string>;
  withdraw: (amount: number, account: string) => Promise<void>;
  
  // 工具函数
  clearError: () => void;
  setLoading: (loading: boolean) => void;
  refreshWallet: () => Promise<void>;
}

export const useWalletStore = create<WalletState>()(
  persist(
    (set, get) => ({
      // 初始状态
      wallet: null,
      transactions: [],
      rewards: [],
      
      transactionPage: 1,
      rewardPage: 1,
      hasMoreTransactions: true,
      hasMoreRewards: true,
      
      isLoading: false,
      isLoadingTransactions: false,
      isLoadingRewards: false,
      error: null,
      
      // 加载钱包信息
      loadWallet: async () => {
        try {
          set({ isLoading: true, error: null });
          const response = await walletApi.getWallet();
          set({ 
            wallet: response.data,
            isLoading: false 
          });
        } catch (error: any) {
          set({ 
            error: error.message || '加载钱包信息失败',
            isLoading: false 
          });
        }
      },
      
      // 加载交易记录
      loadTransactions: async (page = 1, refresh = false) => {
        try {
          set({ isLoadingTransactions: true, error: null });
          
          const response = await walletApi.getTransactions(page, 20);
          const { data: newTransactions, total } = response.data;
          
          set(state => ({
            transactions: refresh ? newTransactions : [...state.transactions, ...newTransactions],
            transactionPage: page,
            hasMoreTransactions: (page * 20) < total,
            isLoadingTransactions: false
          }));
        } catch (error: any) {
          set({ 
            error: error.message || '加载交易记录失败',
            isLoadingTransactions: false 
          });
        }
      },
      
      // 加载奖励记录
      loadRewards: async (page = 1, refresh = false) => {
        try {
          set({ isLoadingRewards: true, error: null });
          
          const response = await lbsApi.getMyRewards(page, 20);
          const { rewards: newRewards, total } = response.data;
          
          set(state => ({
            rewards: refresh ? newRewards : [...state.rewards, ...newRewards],
            rewardPage: page,
            hasMoreRewards: (page * 20) < total,
            isLoadingRewards: false
          }));
        } catch (error: any) {
          set({ 
            error: error.message || '加载奖励记录失败',
            isLoadingRewards: false 
          });
        }
      },
      
      // 充值
      recharge: async (amount: number, paymentMethod: string) => {
        try {
          set({ isLoading: true, error: null });
          const response = await walletApi.recharge(amount, paymentMethod);
          
          set({ isLoading: false });
          
          // 返回支付URL
          return response.data.paymentUrl;
        } catch (error: any) {
          set({ 
            error: error.message || '充值失败',
            isLoading: false 
          });
          throw error;
        }
      },
      
      // 提现
      withdraw: async (amount: number, account: string) => {
        try {
          set({ isLoading: true, error: null });
          await walletApi.withdraw(amount, account);
          
          // 提现成功后刷新钱包信息
          await get().loadWallet();
          
          set({ isLoading: false });
        } catch (error: any) {
          set({ 
            error: error.message || '提现失败',
            isLoading: false 
          });
          throw error;
        }
      },
      
      // 工具函数
      clearError: () => set({ error: null }),
      setLoading: (loading: boolean) => set({ isLoading: loading }),
      
      // 刷新钱包信息
      refreshWallet: async () => {
        await Promise.all([
          get().loadWallet(),
          get().loadTransactions(1, true),
          get().loadRewards(1, true)
        ]);
      },
    }),
    {
      name: 'wallet-storage',
      partialize: (state) => ({
        wallet: state.wallet,
      }),
    }
  )
);

// 格式化金额显示
export const formatAmount = (amount: number) => {
  return `¥${amount.toFixed(2)}`;
};

// 获取交易类型显示文本
export const getTransactionTypeText = (type: string) => {
  const typeMap: Record<string, string> = {
    recharge: '充值',
    withdraw: '提现',
    reward: '奖励',
    payment: '支付',
  };
  return typeMap[type] || type;
};

// 获取交易状态显示文本
export const getTransactionStatusText = (status: string) => {
  const statusMap: Record<string, string> = {
    pending: '处理中',
    completed: '已完成',
    failed: '失败',
  };
  return statusMap[status] || status;
};

// 获取交易状态颜色
export const getTransactionStatusColor = (status: string) => {
  const colorMap: Record<string, string> = {
    pending: 'text-yellow-600',
    completed: 'text-green-600',
    failed: 'text-red-600',
  };
  return colorMap[status] || 'text-gray-600';
};