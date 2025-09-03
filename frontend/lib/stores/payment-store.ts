import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import { 
  paymentService, 
  PaymentIntent, 
  PaymentMethod, 
  PaymentHistory, 
  WalletBalance,
  CreatePaymentIntentRequest,
  WithdrawRequest
} from '../services/payment-service';

interface PaymentState {
  // 支付状态
  isLoading: boolean;
  error: string | null;
  
  // 支付意图
  currentPaymentIntent: PaymentIntent | null;
  
  // 支付方法
  paymentMethods: PaymentMethod[];
  isLoadingPaymentMethods: boolean;
  
  // 钱包余额
  walletBalance: WalletBalance | null;
  isLoadingBalance: boolean;
  
  // 支付历史
  paymentHistory: PaymentHistory[];
  paymentHistoryTotal: number;
  currentPage: number;
  isLoadingHistory: boolean;
  
  // 提现相关
  isWithdrawing: boolean;
  withdrawHistory: Array<{
    id: string;
    amount: number;
    method: string;
    status: string;
    createdAt: string;
    completedAt?: string;
  }>;
  
  // Actions
  createPaymentIntent: (request: CreatePaymentIntentRequest) => Promise<PaymentIntent>;
  confirmPayment: (paymentIntentId: string, paymentMethodId: string) => Promise<PaymentIntent>;
  loadPaymentMethods: () => Promise<void>;
  addPaymentMethod: (paymentMethod: Omit<PaymentMethod, 'id'>) => Promise<PaymentMethod>;
  deletePaymentMethod: (paymentMethodId: string) => Promise<void>;
  loadWalletBalance: () => Promise<void>;
  loadPaymentHistory: (page?: number, pageSize?: number) => Promise<void>;
  requestWithdraw: (request: WithdrawRequest) => Promise<void>;
  loadWithdrawHistory: () => Promise<void>;
  clearError: () => void;
  reset: () => void;
}

const initialState = {
  isLoading: false,
  error: null,
  currentPaymentIntent: null,
  paymentMethods: [],
  isLoadingPaymentMethods: false,
  walletBalance: null,
  isLoadingBalance: false,
  paymentHistory: [],
  paymentHistoryTotal: 0,
  currentPage: 1,
  isLoadingHistory: false,
  isWithdrawing: false,
  withdrawHistory: []
};

export const usePaymentStore = create<PaymentState>()(devtools(
  (set, get) => ({
    ...initialState,

    createPaymentIntent: async (request: CreatePaymentIntentRequest) => {
      set({ isLoading: true, error: null });
      
      try {
        const paymentIntent = await paymentService.createPaymentIntent(request);
        set({ 
          currentPaymentIntent: paymentIntent,
          isLoading: false 
        });
        return paymentIntent;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '创建支付失败';
        set({ 
          error: errorMessage,
          isLoading: false 
        });
        throw error;
      }
    },

    confirmPayment: async (paymentIntentId: string, paymentMethodId: string) => {
      set({ isLoading: true, error: null });
      
      try {
        const confirmedPayment = await paymentService.confirmPayment(paymentIntentId, paymentMethodId);
        set({ 
          currentPaymentIntent: confirmedPayment,
          isLoading: false 
        });
        
        // 支付成功后刷新余额和历史记录
        if (confirmedPayment.status === 'succeeded') {
          get().loadWalletBalance();
          get().loadPaymentHistory();
        }
        
        return confirmedPayment;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '支付确认失败';
        set({ 
          error: errorMessage,
          isLoading: false 
        });
        throw error;
      }
    },

    loadPaymentMethods: async () => {
      set({ isLoadingPaymentMethods: true, error: null });
      
      try {
        const paymentMethods = await paymentService.getPaymentMethods();
        set({ 
          paymentMethods,
          isLoadingPaymentMethods: false 
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '加载支付方法失败';
        set({ 
          error: errorMessage,
          isLoadingPaymentMethods: false 
        });
      }
    },

    addPaymentMethod: async (paymentMethod: Omit<PaymentMethod, 'id'>) => {
      set({ isLoading: true, error: null });
      
      try {
        const newPaymentMethod = await paymentService.addPaymentMethod(paymentMethod);
        set(state => ({ 
          paymentMethods: [...state.paymentMethods, newPaymentMethod],
          isLoading: false 
        }));
        return newPaymentMethod;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '添加支付方法失败';
        set({ 
          error: errorMessage,
          isLoading: false 
        });
        throw error;
      }
    },

    deletePaymentMethod: async (paymentMethodId: string) => {
      set({ isLoading: true, error: null });
      
      try {
        await paymentService.deletePaymentMethod(paymentMethodId);
        set(state => ({ 
          paymentMethods: state.paymentMethods.filter(pm => pm.id !== paymentMethodId),
          isLoading: false 
        }));
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '删除支付方法失败';
        set({ 
          error: errorMessage,
          isLoading: false 
        });
      }
    },

    loadWalletBalance: async () => {
      set({ isLoadingBalance: true, error: null });
      
      try {
        const balance = await paymentService.getWalletBalance();
        set({ 
          walletBalance: balance,
          isLoadingBalance: false 
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '加载钱包余额失败';
        set({ 
          error: errorMessage,
          isLoadingBalance: false 
        });
      }
    },

    loadPaymentHistory: async (page: number = 1, pageSize: number = 20) => {
      set({ isLoadingHistory: true, error: null });
      
      try {
        const result = await paymentService.getPaymentHistory(page, pageSize);
        set({ 
          paymentHistory: page === 1 ? result.payments : [...get().paymentHistory, ...result.payments],
          paymentHistoryTotal: result.total,
          currentPage: page,
          isLoadingHistory: false 
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '加载支付历史失败';
        set({ 
          error: errorMessage,
          isLoadingHistory: false 
        });
      }
    },

    requestWithdraw: async (request: WithdrawRequest) => {
      set({ isWithdrawing: true, error: null });
      
      try {
        await paymentService.requestWithdraw(request);
        set({ isWithdrawing: false });
        
        // 提现申请成功后刷新余额和提现历史
        get().loadWalletBalance();
        get().loadWithdrawHistory();
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '提现申请失败';
        set({ 
          error: errorMessage,
          isWithdrawing: false 
        });
        throw error;
      }
    },

    loadWithdrawHistory: async () => {
      set({ error: null });
      
      try {
        const withdrawHistory = await paymentService.getWithdrawHistory();
        set({ withdrawHistory });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '加载提现历史失败';
        set({ error: errorMessage });
      }
    },

    clearError: () => {
      set({ error: null });
    },

    reset: () => {
      set(initialState);
    }
  }),
  {
    name: 'payment-store'
  }
));

export default usePaymentStore;