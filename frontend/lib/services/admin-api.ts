import { apiClient, ApiResponse } from '../api';
import { User, Annotation } from './api';

// 管理员统计数据类型 - 匹配后端AdminStats接口
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

// 用户管理相关类型 - 匹配后端UserManagement接口
export interface UserManagement {
  id: string;
  username: string;
  email: string;
  status: 'active' | 'suspended' | 'banned' | 'pending';
  role: string;
  created_at: Date;
  last_login?: Date;
  total_annotations: number;
  total_spent: number;
  total_earned: number;
  reports_count: number;
}

// 内容审核相关类型 - 匹配后端ContentReview接口
export interface ContentReview {
  id: string;
  type: 'annotation' | 'comment' | 'media';
  content_id: string;
  status: 'pending' | 'approved' | 'rejected';
  reported_by?: string;
  reason?: string;
  created_at: Date;
  reviewed_at?: Date;
  reviewed_by?: string;
  content_preview: string;
  reporter_username?: string;
  reported_username?: string;
}

// 管理员日志类型
export interface AdminLog {
  id: string;
  admin_id: string;
  action: string;
  target_type: string;
  target_id: string;
  details: any;
  created_at: Date;
  admin_username?: string;
}

// 分页响应类型
export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// 系统设置类型
export interface SystemSettings {
  platformName: string;
  commissionRate: number;
  minRewardAmount: number;
  maxRewardAmount: number;
  autoReviewEnabled: boolean;
  sensitiveWords: string[];
  reviewTimeoutHours: number;
  maxAnnotationsPerDay: number;
  minWithdrawAmount: number;
}

// 数据分析类型
export interface AnalyticsData {
  userGrowth: {
    date: string;
    newUsers: number;
    totalUsers: number;
  }[];
  revenueAnalytics: {
    date: string;
    revenue: number;
    transactions: number;
  }[];
  annotationStats: {
    date: string;
    created: number;
    approved: number;
    rejected: number;
  }[];
  locationStats: {
    city: string;
    count: number;
    revenue: number;
  }[];
}

// 管理员API - 匹配后端实际API端点
export const adminApi = {
  // 获取统计数据 - GET /api/v1/admin/stats
  getStats: () =>
    apiClient.get<ApiResponse<AdminStats>>('/api/v1/admin/stats'),

  // 用户管理 - GET /api/v1/admin/users
  getUsers: (params?: {
    page?: number;
    limit?: number;
    search?: string;
    status?: 'active' | 'suspended' | 'banned' | 'pending';
    sortBy?: 'created_at' | 'username' | 'email' | 'total_annotations' | 'total_spent' | 'reports_count';
    sortOrder?: 'asc' | 'desc';
  }) => {
    const { page = 1, limit = 20, ...rest } = params || {};
    return apiClient.get<ApiResponse<PaginatedResponse<UserManagement>>>(
      '/api/v1/admin/users',
      { params: { page, limit, ...rest } }
    );
  },

  // 更新用户状态 - PUT /api/v1/admin/users/:userId/status
  updateUserStatus: (userId: string, status: 'active' | 'suspended' | 'banned' | 'pending', reason?: string) =>
    apiClient.put<ApiResponse<void>>(`/api/v1/admin/users/${userId}/status`, { status, reason }),

  // 批量用户操作 - POST /api/v1/admin/users/batch
  batchUserOperation: (userIds: string[], operation: 'suspend' | 'activate' | 'ban' | 'delete', reason?: string) =>
    apiClient.post<ApiResponse<void>>('/api/v1/admin/users/batch', { userIds, operation, reason }),

  // 内容审核 - GET /api/v1/admin/content-reviews
  getContentReviews: (params?: {
    page?: number;
    limit?: number;
    status?: 'pending' | 'approved' | 'rejected';
    type?: 'annotation' | 'comment' | 'media';
  }) => {
    const { page = 1, limit = 20, ...rest } = params || {};
    return apiClient.get<ApiResponse<PaginatedResponse<ContentReview>>>(
      '/api/v1/admin/content-reviews',
      { params: { page, limit, ...rest } }
    );
  },

  // 处理内容审核 - PUT /api/v1/admin/content-reviews/:reviewId
  handleContentReview: (reviewId: string, action: 'approve' | 'reject', reason?: string) =>
    apiClient.put<ApiResponse<void>>(`/api/v1/admin/content-reviews/${reviewId}`, { action, reason }),

  // 管理员日志 - GET /api/v1/admin/logs
  getAdminLogs: (params?: {
    page?: number;
    limit?: number;
    action?: string;
    adminId?: string;
    startDate?: string;
    endDate?: string;
  }) => {
    const { page = 1, limit = 50, ...rest } = params || {};
    return apiClient.get<ApiResponse<PaginatedResponse<AdminLog>>>(
      '/api/v1/admin/logs',
      { params: { page, limit, ...rest } }
    );
  },

  // 扩展的数据分析API（需要后端实现）
  getUserGrowthData: (days: number = 30) =>
    apiClient.get<ApiResponse<AnalyticsData['userGrowth']>>('/api/v1/admin/analytics/user-growth', {
      params: { days }
    }),

  getRevenueData: (days: number = 30) =>
    apiClient.get<ApiResponse<AnalyticsData['revenueAnalytics']>>('/api/v1/admin/analytics/revenue', {
      params: { days }
    }),

  getAnnotationStats: (days: number = 30) =>
    apiClient.get<ApiResponse<AnalyticsData['annotationStats']>>('/api/v1/admin/analytics/annotations', {
      params: { days }
    }),

  getLocationStats: (limit: number = 10) =>
    apiClient.get<ApiResponse<AnalyticsData['locationStats']>>('/api/v1/admin/analytics/locations', {
      params: { limit }
    }),

  // 系统设置（需要后端实现）
  getSettings: () =>
    apiClient.get<ApiResponse<SystemSettings>>('/api/v1/admin/settings'),

  updateSettings: (settings: Partial<SystemSettings>) =>
    apiClient.put<ApiResponse<SystemSettings>>('/api/v1/admin/settings', settings),

  // 系统监控（需要后端实现）
  getSystemHealth: () =>
    apiClient.get<ApiResponse<{
      status: 'healthy' | 'warning' | 'error';
      uptime: number;
      memory: { used: number; total: number };
      cpu: number;
      database: { status: string; connections: number };
      redis: { status: string; memory: number };
    }>>('/api/v1/admin/system/health'),

  // 数据导出（需要后端实现）
  exportData: (type: 'users' | 'annotations' | 'transactions', format: 'csv' | 'xlsx') =>
    apiClient.get(`/api/v1/admin/export/${type}`, {
      params: { format },
      responseType: 'blob'
    }),

  // 通知系统（需要后端实现）
  sendNotification: (userIds: string[], title: string, content: string, type?: string) =>
    apiClient.post<ApiResponse<void>>('/api/v1/admin/notifications/send', { userIds, title, content, type }),

  broadcastNotification: (title: string, content: string, type?: string) =>
    apiClient.post<ApiResponse<void>>('/api/v1/admin/notifications/broadcast', { title, content, type }),
};