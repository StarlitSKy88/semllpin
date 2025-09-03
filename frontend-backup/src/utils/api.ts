import axios, { AxiosError, type AxiosRequestConfig, type AxiosResponse } from 'axios';

// 请求重试配置
interface RetryConfig {
  retries: number;
  retryDelay: number;
  retryCondition?: (error: AxiosError) => boolean;
}

// 创建axios实例
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'https://smellpin-workers.dev-small-1.workers.dev',
  timeout: 15000, // 增加超时时间
  headers: {
    'Content-Type': 'application/json',
  },
});

// 请求取消控制器映射
const cancelTokens = new Map<string, AbortController>();

// 导出api实例
export { api };

// 安全的localStorage访问
const getStoredToken = (): string | null => {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return localStorage.getItem('token') || localStorage.getItem('auth_token');
    }
  } catch (error) {
    console.warn('无法访问localStorage:', error);
  }
  return null;
};

// 请求重试函数
const retryRequest = async (config: AxiosRequestConfig, retryConfig: RetryConfig): Promise<AxiosResponse> => {
  const { retries, retryDelay, retryCondition } = retryConfig;
  
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await api(config);
    } catch (error) {
      const axiosError = error as AxiosError;
      
      // 如果是最后一次尝试或不满足重试条件，抛出错误
      if (attempt === retries || (retryCondition && !retryCondition(axiosError))) {
        throw error;
      }
      
      // 等待后重试
      await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
    }
  }
  
  throw new Error('重试失败');
};

// 请求拦截器 - 添加认证token和请求ID
api.interceptors.request.use(
  (config) => {
    // 添加认证token
    const token = getStoredToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // 添加请求ID用于取消请求
    const requestId = `${config.method}-${config.url}-${Date.now()}`;
    (config as AxiosRequestConfig & { metadata?: { requestId: string } }).metadata = { requestId };
    
    // 添加请求时间戳
    config.headers['X-Request-Time'] = Date.now().toString();
    
    return config;
  },
  (error) => {
    console.error('请求拦截器错误:', error);
    return Promise.reject(error);
  }
);

// 默认重试条件
const defaultRetryCondition = (error: AxiosError): boolean => {
  // 网络错误或5xx服务器错误时重试
  return !error.response || (error.response.status >= 500 && error.response.status < 600);
};

// 响应拦截器 - 处理错误和重试
api.interceptors.response.use(
  (response) => {
    // 记录响应时间
    const requestTime = response.config.headers?.['X-Request-Time'];
    if (requestTime) {
      const responseTime = Date.now() - parseInt(requestTime as string);
      if (responseTime > 3000) {
        console.warn(`慢请求警告: ${response.config.url} 耗时 ${responseTime}ms`);
      }
    }
    return response;
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };
    
    // 处理401未授权错误
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        // 尝试刷新token
        const refreshResponse = await api.post('/auth/refresh');
        const newToken = refreshResponse.data.data.token;
        
        // 更新token
        if (typeof window !== 'undefined' && window.localStorage) {
          localStorage.setItem('auth_token', newToken);
        }
        
        // 重新发送原请求
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
        }
        return api(originalRequest);
      } catch (refreshError) {
        // 刷新失败，清除token并重定向
        if (typeof window !== 'undefined') {
          localStorage.removeItem('token');
          localStorage.removeItem('auth_token');
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      }
    }
    
    // 处理网络错误和服务器错误的重试
    if (!originalRequest._retry && defaultRetryCondition(error)) {
      originalRequest._retry = true;
      
      try {
        return await retryRequest(originalRequest, {
          retries: 2,
          retryDelay: 1000,
          retryCondition: defaultRetryCondition
        });
      } catch (retryError) {
        console.error('重试失败:', retryError);
      }
    }
    
    // 统一错误处理
    const errorMessage = (error.response?.data as { message?: string })?.message || error.message || '请求失败';
    console.error('API请求错误:', {
      url: error.config?.url,
      method: error.config?.method,
      status: error.response?.status,
      message: errorMessage
    });
    
    return Promise.reject(error);
  }
);

// 请求取消功能
export const cancelRequest = (requestId: string) => {
  const source = cancelTokens.get(requestId);
  if (source) {
    source.abort();
    cancelTokens.delete(requestId);
  }
};

export const cancelAllRequests = () => {
  cancelTokens.forEach((source) => {
    source.abort();
  });
  cancelTokens.clear();
};

// 导出重试函数供外部使用
export const apiRetryRequest = retryRequest;

// 创建带重试的API请求函数
export const createRetryableRequest = (config: AxiosRequestConfig, retryConfig?: Partial<RetryConfig>) => {
  const finalRetryConfig: RetryConfig = {
    retries: 3,
    retryDelay: 1000,
    retryCondition: defaultRetryCondition,
    ...retryConfig
  };
  
  return retryRequest(config, finalRetryConfig);
};

// 用户关注系统API
export const followUser = async (userId: string) => {
  const response = await api.post(`/users/${userId}/follow`);
  return response.data;
};

export const unfollowUser = async (userId: string) => {
  const response = await api.delete(`/users/${userId}/follow`);
  return response.data;
};

export const getUserFollowing = async (userId: string, page: number = 1, limit: number = 20) => {
  const response = await api.get(`/users/${userId}/following`, {
    params: { page, limit }
  });
  return response.data;
};

export const getUserFollowers = async (userId: string, page: number = 1, limit: number = 20) => {
  const response = await api.get(`/users/${userId}/followers`, {
    params: { page, limit }
  });
  return response.data;
};

export const getMutualFollows = async (userId: string, page: number = 1, limit: number = 20) => {
  const response = await api.get(`/users/${userId}/mutual-follows`, {
    params: { page, limit }
  });
  return response.data;
};

export const checkFollowStatus = async (userId: string) => {
  const response = await api.get(`/users/${userId}/follow-status`);
  return response.data;
};

// ==================== 评论系统 API ====================

// 创建评论
export const createComment = async (annotationId: string, data: { content: string; parentId?: string }) => {
  const response = await api.post(`/annotations/${annotationId}/comments`, data);
  return response.data;
};

// 获取标注的评论列表
export const getAnnotationComments = async (annotationId: string, page = 1, limit = 20) => {
  const response = await api.get(`/annotations/${annotationId}/comments`, {
    params: { page, limit }
  });
  return response.data;
};

// 获取评论的回复列表
export const getCommentReplies = async (commentId: string, page = 1, limit = 10) => {
  const response = await api.get(`/comments/${commentId}/replies`, {
    params: { page, limit }
  });
  return response.data;
};

// 更新评论
export const updateComment = async (commentId: string, data: { content: string }) => {
  const response = await api.put(`/comments/${commentId}`, data);
  return response.data;
};

// 删除评论
export const deleteComment = async (commentId: string) => {
  const response = await api.delete(`/comments/${commentId}`);
  return response.data;
};

// 点赞评论
export const likeComment = async (commentId: string) => {
  const response = await api.post(`/comments/${commentId}/like`);
  return response.data;
};

// 取消点赞评论
export const unlikeComment = async (commentId: string) => {
  const response = await api.delete(`/comments/${commentId}/like`);
  return response.data;
};

// ==================== 分享系统 API ====================

// 生成分享链接
export const generateShareLink = async (annotationId: string, platform = 'general') => {
  const response = await api.get(`/social/annotations/${annotationId}/share-link`, {
    params: { platform }
  });
  return response.data;
};

// 创建分享记录
export const createShareRecord = async (annotationId: string, data: {
  platform: string;
  shareUrl?: string;
  shareData?: unknown;
}) => {
  const response = await api.post(`/social/annotations/${annotationId}/share`, data);
  return response.data;
};

// 获取标注分享统计
export const getAnnotationShareStats = async (annotationId: string) => {
  const response = await api.get(`/social/annotations/${annotationId}/shares/stats`);
  return response.data;
};

// 获取用户分享历史
export const getUserShareHistory = async (page = 1, limit = 20, platform?: string) => {
  const response = await api.get('/social/shares/history', {
    params: { page, limit, platform }
  });
  return response.data;
};

// 获取热门分享
export const getPopularShares = async (timeRange?: string, platform?: string, limit?: number) => {
  const params = new URLSearchParams();
  if (timeRange) params.append('timeRange', timeRange);
  if (platform) params.append('platform', platform);
  if (limit) params.append('limit', limit.toString());
  
  return api.get(`/social/shares/popular?${params.toString()}`);
};

// 通知相关API
// 获取用户通知
export const getUserNotifications = async (page = 1, limit = 20, unreadOnly = false) => {
  const params = new URLSearchParams();
  params.append('page', page.toString());
  params.append('limit', limit.toString());
  if (unreadOnly) params.append('unread_only', 'true');
  
  return api.get(`/social/notifications?${params.toString()}`);
};

// 标记通知为已读
export const markNotificationAsRead = async (notificationId: string) => {
  return api.patch(`/social/notifications/${notificationId}/read`);
};

// 标记所有通知为已读
export const markAllNotificationsAsRead = async () => {
  return api.patch('/social/notifications/read-all');
};

// 通知设置相关API
// 获取通知设置
export const getNotificationSettings = async () => {
  return api.get('/social/notifications/settings');
};

// 更新通知设置
export const updateNotificationSettings = async (settings: Record<string, unknown>) => {
  return api.patch('/social/notifications/settings', settings);
};

// 获取通知统计
export const getNotificationStats = async () => {
  return api.get('/social/notifications/stats');
};

// 发送测试通知
export const sendTestNotification = async (type = 'system') => {
  return api.post('/social/notifications/test', { type });
};

// 删除通知
export const deleteNotifications = async (notificationIds?: string[], deleteAll = false) => {
  return api.delete('/social/notifications', {
    data: { notificationIds, deleteAll }
  });
};

export default api;