import { api } from '../utils/api';

// 管理员角色枚举
export const AdminRole = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator'
} as const;

export type AdminRoleType = typeof AdminRole[keyof typeof AdminRole];

// 用户状态枚举
export const UserStatus = {
  ACTIVE: 'active',
  SUSPENDED: 'suspended',
  BANNED: 'banned',
  PENDING: 'pending'
} as const;

export type UserStatusType = typeof UserStatus[keyof typeof UserStatus];

// 审核状态枚举
export const ReviewStatus = {
  PENDING: 'pending',
  APPROVED: 'approved',
  REJECTED: 'rejected'
} as const;

export type ReviewStatusType = typeof ReviewStatus[keyof typeof ReviewStatus];

// 举报原因枚举
export const ReportReason = {
  SPAM: 'spam',
  INAPPROPRIATE: 'inappropriate',
  HARASSMENT: 'harassment',
  COPYRIGHT: 'copyright',
  FAKE: 'fake',
  OTHER: 'other'
} as const;

export type ReportReasonType = typeof ReportReason[keyof typeof ReportReason];

// 管理员统计接口
export interface AdminStats {
  totalUsers: number;
  activeUsers: number;
  suspendedUsers: number;
  bannedUsers: number;
  totalAnnotations: number;
  pendingAnnotations: number;
  approvedAnnotations: number;
  rejectedAnnotations: number;
  totalRevenue: number;
  monthlyRevenue: number;
  totalTransactions: number;
  pendingReports: number;
}

// 用户管理接口
export interface UserManagement {
  id: string;
  username: string;
  email: string;
  status: UserStatusType;
  role: string;
  created_at: string;
  last_login?: string;
  total_annotations: number;
  total_spent: number;
  total_earned: number;
  reports_count: number;
}

// 内容审核接口
export interface ContentReview {
  id: string;
  type: 'annotation' | 'comment' | 'media';
  content_id: string;
  status: 'pending' | 'approved' | 'rejected';
  reported_by?: string;
  reason?: string;
  created_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  content_preview: string;
  reporter_username?: string;
  reported_username?: string;
}

// 管理员日志接口
export interface AdminLog {
  id: string;
  admin_id: string;
  admin_username: string;
  action: string;
  target_type: string;
  target_id?: string;
  details: Record<string, unknown>;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

// 分页参数接口
export interface PaginationParams {
  page?: number;
  limit?: number;
}

// 用户管理查询参数
export interface UserManagementParams extends PaginationParams {
  status?: UserStatusType;
  search?: string;
  sortBy?: 'created_at' | 'username' | 'email' | 'total_annotations' | 'total_spent' | 'reports_count';
  sortOrder?: 'asc' | 'desc';
}

// 内容审核查询参数
export interface ContentReviewParams extends PaginationParams {
  status?: 'pending' | 'approved' | 'rejected';
  type?: 'annotation' | 'comment' | 'media';
}

// 管理员日志查询参数
export interface AdminLogParams extends PaginationParams {
  action?: string;
  adminId?: string;
  startDate?: string;
  endDate?: string;
}

// 财务管理接口
export interface FinancialOverview {
  totalRevenue: number;
  monthlyRevenue: number;
  dailyRevenue: number;
  totalTransactions: number;
  pendingWithdrawals: number;
  totalWithdrawals: number;
  platformFees: number;
  averageTransactionValue: number;
}

export interface TransactionRecord {
  id: string;
  type: 'payment' | 'reward' | 'withdrawal' | 'refund';
  amount: number;
  fee: number;
  status: 'pending' | 'completed' | 'failed' | 'cancelled';
  user_id: string;
  username: string;
  description: string;
  created_at: string;
  completed_at?: string;
  payment_method?: string;
  transaction_id?: string;
}

export interface WithdrawalRequest {
  id: string;
  user_id: string;
  username: string;
  amount: number;
  fee: number;
  net_amount: number;
  status: 'pending' | 'approved' | 'rejected' | 'completed';
  payment_method: string;
  payment_details: Record<string, unknown>;
  requested_at: string;
  processed_at?: string;
  processed_by?: string;
  rejection_reason?: string;
}

// 数据分析接口
export interface UserBehaviorAnalytics {
  totalUsers: number;
  activeUsers: number;
  newUsers: number;
  retentionRate: number;
  averageSessionDuration: number;
  dailyActiveUsers: number[];
  userGrowthTrend: { date: string; count: number }[];
  userActivityHeatmap: { hour: number; day: number; value: number }[];
}

export interface RevenueAnalytics {
  totalRevenue: number;
  monthlyRevenue: number;
  revenueGrowthRate: number;
  revenueByCategory: { category: string; amount: number }[];
  revenueByRegion: { region: string; amount: number }[];
  revenueTrend: { date: string; amount: number }[];
  averageRevenuePerUser: number;
}

export interface GeographicAnalytics {
  totalAnnotations: number;
  annotationsByRegion: { region: string; count: number; revenue: number }[];
  hotspots: { lat: number; lng: number; count: number; revenue: number }[];
  heatmapData: { lat: number; lng: number; intensity: number }[];
  cityStats: { city: string; annotations: number; revenue: number; users: number }[];
}

export interface ContentAnalytics {
  totalAnnotations: number;
  approvedAnnotations: number;
  rejectedAnnotations: number;
  pendingAnnotations: number;
  averageApprovalTime: number;
  contentByCategory: { category: string; count: number }[];
  reportsByReason: { reason: string; count: number }[];
}

// 查询参数接口
export interface FinancialParams extends PaginationParams {
  type?: 'payment' | 'reward' | 'withdrawal' | 'refund';
  status?: 'pending' | 'completed' | 'failed' | 'cancelled';
  startDate?: string;
  endDate?: string;
  userId?: string;
}

export interface WithdrawalParams extends PaginationParams {
  status?: 'pending' | 'approved' | 'rejected' | 'completed';
  startDate?: string;
  endDate?: string;
}

export interface AnalyticsParams {
  startDate?: string;
  endDate?: string;
  region?: string;
  category?: string;
}

// 分页响应接口
export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

/**
 * 管理员API服务类
 */
class AdminApiService {
  /**
   * 执行带错误处理的API请求
   */
  private async safeApiCall<T>(apiCall: () => Promise<{ data: { data: T } }>): Promise<T> {
    try {
      const response = await apiCall();
      return response.data.data;
    } catch (error: unknown) {
      console.error('Admin API调用失败:', error);
      
      // 根据错误类型提供更友好的错误信息
      if (error && typeof error === 'object' && 'response' in error) {
        const axiosError = error as { response?: { status?: number; data?: { message?: string } } };
        if (axiosError.response?.status === 403) {
          throw new Error('权限不足，无法执行此操作');
        } else if (axiosError.response?.status === 404) {
          throw new Error('请求的资源不存在');
        } else if (axiosError.response?.status && axiosError.response.status >= 500) {
          throw new Error('服务器内部错误，请稍后重试');
        } else {
          throw new Error(axiosError.response?.data?.message || '操作失败，请重试');
        }
      } else {
        throw new Error('操作失败，请重试');
      }
    }
  }
  /**
   * 获取管理员仪表板统计数据
   */
  async getAdminStats(): Promise<AdminStats> {
    return this.safeApiCall(() => api.get('/admin/stats'));
  }

  /**
   * 获取用户管理列表
   */
  async getUserManagement(params: UserManagementParams = {}): Promise<PaginatedResponse<UserManagement>> {
    return this.safeApiCall(() => api.get('/admin/users', { params }));
  }

  /**
   * 更新用户状态
   */
  async updateUserStatus(userId: string, status: UserStatusType, reason?: string): Promise<void> {
    await this.safeApiCall(() => api.put(`/admin/users/${userId}/status`, {
      status,
      reason
    }));
  }

  /**
   * 获取内容审核列表
   */
  async getContentReviews(params: ContentReviewParams = {}): Promise<PaginatedResponse<ContentReview>> {
    return this.safeApiCall(() => api.get('/admin/content-reviews', { params }));
  }

  /**
   * 处理内容审核
   */
  async handleContentReview(reviewId: string, action: 'approve' | 'reject', reason?: string): Promise<void> {
    await this.safeApiCall(() => api.put(`/admin/content-reviews/${reviewId}`, {
      action,
      reason
    }));
  }

  /**
   * 批量操作用户
   */
  async batchUserOperation(
    userIds: string[],
    operation: 'suspend' | 'activate' | 'ban' | 'delete',
    reason?: string
  ): Promise<void> {
    await api.post('/admin/users/batch', {
      userIds,
      operation,
      reason
    });
  }

  /**
   * 获取管理操作日志
   */
  async getAdminLogs(params: AdminLogParams = {}): Promise<PaginatedResponse<AdminLog>> {
    return this.safeApiCall(() => api.get('/admin/logs', { params }));
  }

  // 财务管理相关API
  
  /**
   * 获取财务概览数据
   */
  async getFinancialOverview(): Promise<FinancialOverview> {
    return this.safeApiCall(() => api.get('/admin/financial/overview'));
  }

  /**
   * 获取交易记录列表
   */
  async getTransactionRecords(params: FinancialParams = {}): Promise<PaginatedResponse<TransactionRecord>> {
    return this.safeApiCall(() => api.get('/admin/financial/transactions', { params }));
  }

  /**
   * 获取提现申请列表
   */
  async getWithdrawalRequests(params: WithdrawalParams = {}): Promise<PaginatedResponse<WithdrawalRequest>> {
    return this.safeApiCall(() => api.get('/admin/financial/withdrawals', { params }));
  }

  /**
   * 处理提现申请
   */
  async handleWithdrawalRequest(
    withdrawalId: string, 
    action: 'approve' | 'reject', 
    reason?: string
  ): Promise<void> {
    await api.put(`/admin/financial/withdrawals/${withdrawalId}`, {
      action,
      reason
    });
  }

  /**
   * 批量处理提现申请
   */
  async batchHandleWithdrawals(
    withdrawalIds: string[], 
    action: 'approve' | 'reject', 
    reason?: string
  ): Promise<void> {
    await api.post('/admin/financial/withdrawals/batch', {
      withdrawalIds,
      action,
      reason
    });
  }

  /**
   * 导出财务数据
   */
  async exportFinancialData(params: FinancialParams): Promise<Blob> {
    const response = await api.get('/admin/financial/export', {
      params,
      responseType: 'blob'
    });
    return response.data;
  }

  // 数据分析相关API
  
  /**
   * 获取用户行为分析数据
   */
  async getUserBehaviorAnalytics(params: AnalyticsParams = {}): Promise<UserBehaviorAnalytics> {
    return this.safeApiCall(() => api.get('/admin/analytics/user-behavior', { params }));
  }

  /**
   * 获取收入分析数据
   */
  async getRevenueAnalytics(params: AnalyticsParams = {}): Promise<RevenueAnalytics> {
    return this.safeApiCall(() => api.get('/admin/analytics/revenue', { params }));
  }

  /**
   * 获取地理分析数据
   */
  async getGeographicAnalytics(params: AnalyticsParams = {}): Promise<GeographicAnalytics> {
    return this.safeApiCall(() => api.get('/admin/analytics/geographic', { params }));
  }

  /**
   * 获取内容分析数据
   */
  async getContentAnalytics(params: AnalyticsParams = {}): Promise<ContentAnalytics> {
    return this.safeApiCall(() => api.get('/admin/analytics/content', { params }));
  }

  /**
   * 获取实时监控数据
   */
  async getRealTimeMetrics(): Promise<{
    onlineUsers: number;
    activeAnnotations: number;
    recentTransactions: number;
    systemLoad: number;
  }> {
    return this.safeApiCall(() => api.get('/admin/analytics/realtime'));
  }

  /**
   * 导出分析报告
   */
  async exportAnalyticsReport(type: 'user' | 'revenue' | 'geographic' | 'content', params: AnalyticsParams): Promise<Blob> {
    const response = await api.get(`/admin/analytics/export/${type}`, {
      params,
      responseType: 'blob'
    });
    return response.data;
  }
}

// 创建实例
const adminApi = new AdminApiService();

// 辅助函数

/**
 * 获取用户状态显示文本
 */
export const getUserStatusText = (status: UserStatusType): string => {
  const statusMap = {
    [UserStatus.ACTIVE]: '正常',
    [UserStatus.SUSPENDED]: '暂停',
    [UserStatus.BANNED]: '封禁',
    [UserStatus.PENDING]: '待审核'
  };
  return statusMap[status] || status;
};

/**
 * 获取用户状态颜色
 */
export const getUserStatusColor = (status: UserStatusType): string => {
  const colorMap = {
    [UserStatus.ACTIVE]: 'success',
    [UserStatus.SUSPENDED]: 'warning',
    [UserStatus.BANNED]: 'error',
    [UserStatus.PENDING]: 'processing'
  };
  return colorMap[status] || 'default';
};

/**
 * 获取管理员角色显示文本
 */
export const getAdminRoleText = (role: string): string => {
  const roleMap = {
    [AdminRole.SUPER_ADMIN]: '超级管理员',
    [AdminRole.ADMIN]: '管理员',
    [AdminRole.MODERATOR]: '版主',
    'user': '普通用户'
  };
  return roleMap[role as keyof typeof roleMap] || role;
};

/**
 * 获取内容类型显示文本
 */
export const getContentTypeText = (type: string): string => {
  const typeMap = {
    'annotation': '标注',
    'comment': '评论',
    'media': '媒体文件'
  };
  return typeMap[type as keyof typeof typeMap] || type;
};

/**
 * 获取审核状态显示文本
 */
export const getReviewStatusText = (status: string): string => {
  const statusMap = {
    'pending': '待审核',
    'approved': '已通过',
    'rejected': '已拒绝'
  };
  return statusMap[status as keyof typeof statusMap] || status;
};

/**
 * 获取审核状态颜色
 */
export const getReviewStatusColor = (status: string): string => {
  const colorMap = {
    'pending': 'processing',
    'approved': 'success',
    'rejected': 'error'
  };
  return colorMap[status as keyof typeof colorMap] || 'default';
};

/**
 * 格式化数字显示
 */
export const formatNumber = (num: number): string => {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + 'M';
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + 'K';
  }
  return num.toString();
};

/**
 * 格式化金额显示
 */
export const formatCurrency = (amount: number): string => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2
  }).format(amount);
};

/**
 * 格式化日期显示
 */
export const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
};

/**
 * 格式化相对时间
 */
export const formatRelativeTime = (dateString: string): string => {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) {
    return '刚刚';
  } else if (diffMins < 60) {
    return `${diffMins}分钟前`;
  } else if (diffHours < 24) {
    return `${diffHours}小时前`;
  } else if (diffDays < 30) {
    return `${diffDays}天前`;
  } else {
    return formatDate(dateString);
  }
};

/**
 * 获取操作类型显示文本
 */
export const getActionText = (action: string): string => {
  const actionMap = {
    'update_user_status': '更新用户状态',
    'content_review': '内容审核',
    'batch_suspend': '批量暂停',
    'batch_activate': '批量激活',
    'batch_ban': '批量封禁',
    'batch_delete': '批量删除',
    'create_user': '创建用户',
    'delete_user': '删除用户',
    'update_config': '更新配置'
  };
  return actionMap[action as keyof typeof actionMap] || action;
};

/**
 * 验证管理员权限
 */
export const hasAdminPermission = (userRole: string, requiredRoles: string[]): boolean => {
  return requiredRoles.includes(userRole);
};

/**
 * 检查是否为超级管理员
 */
export const isSuperAdmin = (userRole: string): boolean => {
  return userRole === AdminRole.SUPER_ADMIN;
};

/**
 * 检查是否为管理员
 */
export const isAdmin = (userRole: string): boolean => {
  return userRole === AdminRole.SUPER_ADMIN || userRole === AdminRole.ADMIN;
};

/**
 * 检查是否为版主
 */
export const isModerator = (userRole: string): boolean => {
  return [AdminRole.SUPER_ADMIN, AdminRole.ADMIN, AdminRole.MODERATOR].includes(userRole as AdminRoleType);
};

/**
 * 获取交易类型显示文本
 */
export const getTransactionTypeText = (type: string): string => {
  const typeMap = {
    'payment': '支付',
    'reward': '奖励',
    'withdrawal': '提现',
    'refund': '退款'
  };
  return typeMap[type as keyof typeof typeMap] || type;
};

/**
 * 获取交易状态显示文本
 */
export const getTransactionStatusText = (status: string): string => {
  const statusMap = {
    'pending': '待处理',
    'completed': '已完成',
    'failed': '失败',
    'cancelled': '已取消'
  };
  return statusMap[status as keyof typeof statusMap] || status;
};

/**
 * 获取交易状态颜色
 */
export const getTransactionStatusColor = (status: string): string => {
  const colorMap = {
    'pending': 'processing',
    'completed': 'success',
    'failed': 'error',
    'cancelled': 'default'
  };
  return colorMap[status as keyof typeof colorMap] || 'default';
};

/**
 * 获取提现状态显示文本
 */
export const getWithdrawalStatusText = (status: string): string => {
  const statusMap = {
    'pending': '待审核',
    'approved': '已批准',
    'rejected': '已拒绝',
    'completed': '已完成'
  };
  return statusMap[status as keyof typeof statusMap] || status;
};

/**
 * 获取提现状态颜色
 */
export const getWithdrawalStatusColor = (status: string): string => {
  const colorMap = {
    'pending': 'processing',
    'approved': 'warning',
    'rejected': 'error',
    'completed': 'success'
  };
  return colorMap[status as keyof typeof colorMap] || 'default';
};

/**
 * 格式化百分比显示
 */
export const formatPercentage = (value: number): string => {
  return `${(value * 100).toFixed(1)}%`;
};

/**
 * 格式化文件大小
 */
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * 生成随机颜色
 */
export const generateRandomColor = (): string => {
  const colors = [
    '#1890ff', '#52c41a', '#faad14', '#f5222d', '#722ed1',
    '#fa541c', '#13c2c2', '#eb2f96', '#a0d911', '#fa8c16'
  ];
  return colors[Math.floor(Math.random() * colors.length)];
};

/**
 * 计算增长率
 */
export const calculateGrowthRate = (current: number, previous: number): number => {
  if (previous === 0) return current > 0 ? 100 : 0;
  return ((current - previous) / previous) * 100;
};

/**
 * 格式化增长率显示
 */
export const formatGrowthRate = (rate: number): string => {
  const sign = rate >= 0 ? '+' : '';
  return `${sign}${rate.toFixed(1)}%`;
};

export default adminApi;