import { api } from '../utils/api';

// 用户信息接口
export interface UserInfo {
  id: string;
  username: string;
  email: string;
  avatar?: string;
  followersCount: number;
  followingCount: number;
  isFollowing?: boolean;
  createdAt: string;
  updatedAt: string;
}

// 关注数据接口
export interface FollowData {
  followers: UserInfo[];
  following: UserInfo[];
  total: number;
  page: number;
  limit: number;
}

// 关注统计接口
export interface FollowStats {
  followersCount: number;
  followingCount: number;
  mutualFollowsCount: number;
}

// 评论用户接口
export interface CommentUser {
  id: string;
  username: string;
  avatar?: string;
}

// 评论接口
export interface Comment {
  id: string;
  userId: string;
  annotationId: string;
  content: string;
  parentId?: string;
  likesCount: number;
  repliesCount: number;
  isLiked?: boolean;
  user: CommentUser;
  replies?: Comment[];
  createdAt: string;
  updatedAt: string;
}

// 评论列表数据接口
export interface CommentListData {
  comments: Comment[];
  total: number;
  page: number;
  limit: number;
  sortBy: string;
}

// 创建评论请求接口
export interface CreateCommentRequest {
  content: string;
  parentId?: string;
}

// 更新评论请求接口
export interface UpdateCommentRequest {
  content: string;
}

// 用户搜索参数接口
export interface UserSearchParams {
  query?: string;
  page?: number;
  limit?: number;
  sortBy?: 'relevance' | 'followers' | 'newest';
}

// 关注列表参数接口
export interface FollowListParams {
  page?: number;
  limit?: number;
  search?: string;
}

// 评论列表参数接口
export interface CommentListParams {
  page?: number;
  limit?: number;
  sortBy?: 'newest' | 'oldest' | 'popular';
}

// 社交API服务类
class SocialApiService {
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
        const hasResponse = error && typeof error === 'object' && 'response' in error;
        const status = hasResponse && error.response && typeof error.response === 'object' && 'status' in error.response ? error.response.status : 0;
        if (attempt === maxRetries || (hasResponse && typeof status === 'number' && status < 500)) {
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
      console.error(`社交API ${operation} 失败:`, error);
      
      // 根据错误类型提供更友好的错误信息
      if (error && typeof error === 'object' && 'response' in error && error.response) {
        const response = error.response as { status?: number; data?: { message?: string } };
        const status = response.status;
        const data = response.data;
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
        const message = error && typeof error === 'object' && 'message' in error ? String(error.message) : '未知错误';
        throw new Error(`${operation}失败: ${message}`);
      }
    }
  }

  // ==================== 关注相关 ====================
  
  /**
   * 关注用户
   */
  async followUser(userId: string): Promise<{ message: string; followersCount: number }> {
    return this.safeApiCall(async () => {
      const response = await api.post(`/users/${userId}/follow`);
      return response.data.data;
    }, '关注用户');
  }

  /**
   * 取消关注用户
   */
  async unfollowUser(userId: string): Promise<{ message: string; followersCount: number }> {
    return this.safeApiCall(async () => {
      const response = await api.delete(`/users/${userId}/follow`);
      return response.data.data;
    }, '取消关注用户');
  }

  /**
   * 检查关注状态
   */
  async checkFollowStatus(userId: string): Promise<{ isFollowing: boolean }> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/users/${userId}/follow/status`);
      return response.data.data;
    }, '检查关注状态');
  }

  /**
   * 获取用户粉丝列表
   */
  async getUserFollowers(userId: string, params: FollowListParams = {}): Promise<FollowData> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/users/${userId}/followers`, { params });
      return response.data.data;
    }, '获取用户粉丝列表');
  }

  /**
   * 获取用户关注列表
   */
  async getUserFollowing(userId: string, params: FollowListParams = {}): Promise<FollowData> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/users/${userId}/following`, { params });
      return response.data.data;
    }, '获取用户关注列表');
  }

  /**
   * 获取关注统计
   */
  async getFollowStats(userId: string): Promise<FollowStats> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/users/${userId}/follow/stats`);
      return response.data.data;
    }, '获取关注统计');
  }

  /**
   * 获取互相关注的用户
   */
  async getMutualFollows(userId: string, params: FollowListParams = {}): Promise<FollowData> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/users/${userId}/follow/mutual`, { params });
      return response.data.data;
    }, '获取互相关注用户');
  }

  /**
   * 获取推荐关注用户
   */
  async getRecommendedUsers(params: FollowListParams = {}): Promise<FollowData> {
    return this.safeApiCall(async () => {
      const response = await api.get('/users/recommended', { params });
      return response.data.data;
    }, '获取推荐关注用户');
  }

  // ==================== 评论相关 ====================
  
  /**
   * 获取标注评论列表
   */
  async getAnnotationComments(annotationId: string, params: CommentListParams = {}): Promise<CommentListData> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/annotations/${annotationId}/comments`, { params });
      return response.data.data;
    }, '获取标注评论列表');
  }

  /**
   * 获取评论回复
   */
  async getCommentReplies(commentId: string, params: CommentListParams = {}): Promise<CommentListData> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/comments/${commentId}/replies`, { params });
      return response.data.data;
    }, '获取评论回复');
  }

  /**
   * 创建评论
   */
  async createComment(annotationId: string, data: CreateCommentRequest): Promise<Comment> {
    return this.safeApiCall(async () => {
      const response = await api.post(`/annotations/${annotationId}/comments`, data);
      return response.data.data;
    }, '创建评论');
  }

  /**
   * 更新评论
   */
  async updateComment(commentId: string, data: UpdateCommentRequest): Promise<Comment> {
    return this.safeApiCall(async () => {
      const response = await api.put(`/comments/${commentId}`, data);
      return response.data.data;
    }, '更新评论');
  }

  /**
   * 删除评论
   */
  async deleteComment(commentId: string): Promise<{ message: string }> {
    return this.safeApiCall(async () => {
      const response = await api.delete(`/comments/${commentId}`);
      return response.data.data;
    }, '删除评论');
  }

  /**
   * 点赞评论
   */
  async likeComment(commentId: string): Promise<{ message: string; likesCount: number }> {
    return this.safeApiCall(async () => {
      const response = await api.post(`/comments/${commentId}/like`);
      return response.data.data;
    }, '点赞评论');
  }

  /**
   * 取消点赞评论
   */
  async unlikeComment(commentId: string): Promise<{ message: string; likesCount: number }> {
    return this.safeApiCall(async () => {
      const response = await api.delete(`/comments/${commentId}/like`);
      return response.data.data;
    }, '取消点赞评论');
  }

  /**
   * 举报评论
   */
  async reportComment(commentId: string, reason: string): Promise<{ message: string }> {
    return this.safeApiCall(async () => {
      const response = await api.post(`/comments/${commentId}/report`, { reason });
      return response.data.data;
    }, '举报评论');
  }

  // ==================== 用户搜索相关 ====================
  
  /**
   * 搜索用户
   */
  async searchUsers(params: UserSearchParams): Promise<FollowData> {
    return this.safeApiCall(async () => {
      const response = await api.get('/users/search', { params });
      return response.data.data;
    }, '搜索用户');
  }

  /**
   * 获取用户详情
   */
  async getUserProfile(userId: string): Promise<UserInfo> {
    return this.safeApiCall(async () => {
      const response = await api.get(`/users/${userId}`);
      return response.data.data;
    }, '获取用户详情');
  }

  // ==================== 辅助方法 ====================
  
  /**
   * 格式化关注数量
   */
  formatFollowCount(count: number): string {
    if (count >= 1000000) {
      return `${(count / 1000000).toFixed(1)}M`;
    } else if (count >= 1000) {
      return `${(count / 1000).toFixed(1)}K`;
    }
    return count.toString();
  }

  /**
   * 获取关注状态文本
   */
  getFollowStatusText(isFollowing: boolean): string {
    return isFollowing ? '已关注' : '关注';
  }

  /**
   * 获取评论排序选项
   */
  getCommentSortOptions() {
    return [
      { value: 'newest', label: '最新' },
      { value: 'oldest', label: '最早' },
      { value: 'popular', label: '最热' }
    ];
  }

  /**
   * 获取用户搜索排序选项
   */
  getUserSearchSortOptions() {
    return [
      { value: 'relevance', label: '相关性' },
      { value: 'followers', label: '粉丝数' },
      { value: 'newest', label: '最新注册' }
    ];
  }

  /**
   * 验证评论内容
   */
  validateCommentContent(content: string): { isValid: boolean; message?: string } {
    if (!content || !content.trim()) {
      return { isValid: false, message: '评论内容不能为空' };
    }
    
    if (content.length > 500) {
      return { isValid: false, message: '评论内容不能超过500个字符' };
    }
    
    // 检查是否包含敏感词（这里可以扩展）
    const sensitiveWords = ['垃圾', '废物', '傻逼'];
    const hasSensitiveWord = sensitiveWords.some(word => content.includes(word));
    if (hasSensitiveWord) {
      return { isValid: false, message: '评论内容包含不当词汇' };
    }
    
    return { isValid: true };
  }

  /**
   * 处理API错误
   */
  handleApiError(error: unknown): string {
    if (error && typeof error === 'object' && 'response' in error && error.response) {
      // 服务器响应错误
      const response = error.response as { status?: number; data?: { message?: string } };
      const status = response.status;
      const message = response.data?.message;
      
      switch (status) {
        case 401:
          return '请先登录';
        case 403:
          return '没有权限执行此操作';
        case 404:
          return '请求的资源不存在';
        case 429:
          return '操作过于频繁，请稍后再试';
        case 500:
          return '服务器内部错误';
        default:
          return message || '操作失败';
      }
    } else if (error && typeof error === 'object' && 'request' in error) {
      // 网络错误
      return '网络连接失败，请检查网络设置';
    } else {
      // 其他错误
      const message = error && typeof error === 'object' && 'message' in error ? String(error.message) : '未知错误';
      return message;
    }
  }
}

// 创建并导出社交API服务实例
const socialApi = new SocialApiService();
export default socialApi;