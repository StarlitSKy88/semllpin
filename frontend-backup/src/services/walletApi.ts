import { api } from '../utils/api';

// 钱包数据接口
export interface WalletData {
  balance: number;
  totalIncome: number;
  totalExpense: number;
  lbsRewards: number;
  pendingRewards: number;
  currency: string;
}

// 交易记录接口
export interface Transaction {
  id: string;
  userId: string;
  type: 'payment' | 'refund' | 'reward' | 'topup';
  amount: number;
  currency: string;
  description: string;
  status: 'completed' | 'pending' | 'failed' | 'cancelled';
  prankId?: string;
  sessionId?: string;
  createdAt: string;
  updatedAt: string;
}

// 交易历史响应接口
export interface TransactionHistoryResponse {
  transactions: Transaction[];
  total: number;
  page: number;
  limit: number;
}

// 交易统计接口
export interface TransactionSummary {
  totalTransactions: number;
  totalAmount: number;
  totalIncome: number;
  totalExpense: number;
}

// LBS奖励接口
export interface LBSReward {
  id: string;
  type: 'checkin' | 'discovery' | 'activity';
  amount: number;
  description: string;
  location: string;
  createdAt: string;
}

// LBS奖励响应接口
export interface LBSRewardsResponse {
  rewards: LBSReward[];
  total: number;
  page: number;
  limit: number;
}

// 充值会话接口
export interface TopUpSession {
  id: string;
  url: string;
  amount: number;
  currency: string;
  description: string;
  paymentMethod: string;
  userId: string;
}

// 充值请求接口
export interface TopUpRequest {
  amount: number;
  paymentMethod?: 'stripe' | 'paypal';
  currency?: 'usd' | 'cny';
  description?: string;
}

// 交易历史查询参数
export interface TransactionQuery {
  page?: number;
  limit?: number;
  type?: 'payment' | 'refund' | 'reward' | 'topup';
  status?: 'completed' | 'pending' | 'failed' | 'cancelled';
  dateRange?: string;
  search?: string;
}

// LBS奖励查询参数
export interface LBSRewardQuery {
  page?: number;
  limit?: number;
}

class WalletAPI {
  // 执行带重试机制的API请求
  private async executeWithRetry<T>(
    requestFn: () => Promise<T>
  ): Promise<T> {
    const maxRetries = 2;
    let lastError: unknown;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await requestFn();
      } catch (error: unknown) {
        lastError = error;
        
        // 如果是最后一次尝试或不满足重试条件，抛出错误
        if (attempt === maxRetries || (error && typeof error === 'object' && 'response' in error && 
            (error as { response?: { status: number } }).response && 
            (error as { response: { status: number } }).response.status < 500)) {
          throw error;
        }
        
        // 等待后重试
        await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
      }
    }
    
    throw lastError;
  }

  // 统一API错误处理
  private async safeApiCall<T>(apiCall: () => Promise<T>, operation: string): Promise<T> {
    try {
      return await this.executeWithRetry(apiCall);
    } catch (error: unknown) {
      console.error(`钱包API ${operation} 失败:`, error);
      
      // 根据错误类型提供更友好的错误信息
      if (error && typeof error === 'object' && 'response' in error && 
          (error as { response?: { status: number; data?: { message?: string } } }).response) {
        const response = (error as { response: { status: number; data?: { message?: string } } }).response;
        const { status, data } = response;
        switch (status) {
          case 401:
            throw new Error('用户未登录或登录已过期，请重新登录');
          case 403:
            throw new Error('权限不足，无法执行此操作');
          case 404:
            throw new Error('请求的资源不存在');
          case 429:
            throw new Error('请求过于频繁，请稍后再试');
          case 500:
            throw new Error('服务器内部错误，请稍后重试');
          default:
            throw new Error(data?.message || `${operation}失败，请稍后重试`);
        }
      } else if (error && typeof error === 'object' && 'request' in error) {
        throw new Error('网络连接失败，请检查网络设置');
      } else {
        const message = error && typeof error === 'object' && 'message' in error ? 
          (error as { message: string }).message : '未知错误';
        throw new Error(`${operation}失败: ${message}`);
      }
    }
  }

  // 获取钱包信息
  async getWallet(): Promise<WalletData> {
    return this.safeApiCall(async () => {
      const response = await api.get('/wallet');
      return response.data.data;
    }, '获取钱包信息');
  }

  // 获取交易历史
  async getTransactionHistory(params?: TransactionQuery): Promise<TransactionHistoryResponse> {
    return this.safeApiCall(async () => {
      const response = await api.get('/wallet/transactions', { params });
      return response.data.data;
    }, '获取交易历史');
  }

  // 获取交易统计
  async getTransactionSummary(params?: Partial<TransactionQuery>): Promise<TransactionSummary> {
    return this.safeApiCall(async () => {
      const response = await api.get('/wallet/transactions/summary', { params });
      return response.data.data;
    }, '获取交易统计');
  }

  // 导出交易记录
  async exportTransactions(params?: Partial<TransactionQuery>): Promise<Blob> {
    return this.safeApiCall(async () => {
      const response = await api.get('/wallet/transactions/export', {
        params,
        responseType: 'blob'
      });
      return response.data;
    }, '导出交易记录');
  }

  // 创建充值会话
  async createTopUpSession(data: TopUpRequest): Promise<TopUpSession> {
    return this.safeApiCall(async () => {
      const response = await api.post('/wallet/topup', data);
      return response.data.data;
    }, '创建充值会话');
  }

  // 处理充值成功
  async handleTopUpSuccess(sessionId: string): Promise<void> {
    return this.safeApiCall(async () => {
      await api.post(`/wallet/topup/${sessionId}/success`);
    }, '处理充值成功');
  }

  // 获取LBS奖励记录
  async getLBSRewards(params?: LBSRewardQuery): Promise<LBSRewardsResponse> {
    return this.safeApiCall(async () => {
      const response = await api.get('/wallet/rewards', { params });
      return response.data.data;
    }, '获取LBS奖励记录');
  }

  // 下载交易记录CSV文件
  async downloadTransactionCSV(params?: Partial<TransactionQuery>): Promise<void> {
    try {
      const blob = await this.exportTransactions(params);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `transactions_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('下载交易记录失败:', error);
      throw error;
    }
  }

  // 格式化金额显示
  formatAmount(amount: number, currency: string = 'USD'): string {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase(),
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
  }

  // 格式化交易类型显示
  formatTransactionType(type: string): string {
    const typeMap: Record<string, string> = {
      payment: '支付',
      refund: '退款',
      reward: '奖励',
      topup: '充值'
    };
    return typeMap[type] || type;
  }

  // 格式化交易状态显示
  formatTransactionStatus(status: string): string {
    const statusMap: Record<string, string> = {
      completed: '已完成',
      pending: '处理中',
      failed: '失败',
      cancelled: '已取消'
    };
    return statusMap[status] || status;
  }

  // 获取交易状态颜色
  getTransactionStatusColor(status: string): string {
    const colorMap: Record<string, string> = {
      completed: 'success',
      pending: 'processing',
      failed: 'error',
      cancelled: 'default'
    };
    return colorMap[status] || 'default';
  }

  // 获取交易类型图标
  getTransactionTypeIcon(type: string): string {
    const iconMap: Record<string, string> = {
      payment: 'credit-card',
      refund: 'undo',
      reward: 'gift',
      topup: 'plus-circle'
    };
    return iconMap[type] || 'transaction';
  }
}

export const walletApi = new WalletAPI();
export default walletApi;