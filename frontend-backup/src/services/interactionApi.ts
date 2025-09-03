import { api } from '../utils/api';
import { message } from 'antd';

// 点赞类型枚举
export const LikeType = {
  ANNOTATION: 'annotation',
  COMMENT: 'comment',
  USER: 'user'
} as const;

export type LikeType = typeof LikeType[keyof typeof LikeType];

// 收藏类型枚举
export const FavoriteType = {
  ANNOTATION: 'annotation',
  USER: 'user'
} as const;

export type FavoriteType = typeof FavoriteType[keyof typeof FavoriteType];

// 点赞接口
export interface Like {
  id: string;
  userId: string;
  targetId: string;
  targetType: LikeType;
  createdAt: string;
  user?: {
    id: string;
    username: string;
    avatar?: string;
  };
}

// 收藏接口
export interface Favorite {
  id: string;
  userId: string;
  targetId: string;
  targetType: FavoriteType;
  createdAt: string;
  annotation?: {
    id: string;
    title: string;
    description: string;
    imageUrl?: string;
    location: string;
    latitude: number;
    longitude: number;
  };
  user?: {
    id: string;
    username: string;
    avatar?: string;
  };
}

// 互动统计接口
export interface InteractionStats {
  targetId: string;
  targetType: string;
  likeCount: number;
  favoriteCount: number;
  isLiked: boolean;
  isFavorited: boolean;
}

// 用户活跃度统计接口
export interface UserActivityStats {
  timeRange: string;
  totalLikes: number;
  totalFavorites: number;
  totalActivity: number;
  likesByType: Record<string, number>;
  favoritesByType: Record<string, number>;
  dailyActivity: {
    date: string;
    likes: number;
    favorites: number;
    total: number;
  }[];
  averageDailyActivity: number;
}

// 热门内容接口
export interface PopularContent {
  targetId: string;
  targetType: string;
  likeCount: number;
  recentLikes: Like[];
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

// 互动API类
class InteractionApi {
  private baseURL = '/interactions';

  // 点赞
  async likeTarget(targetId: string, targetType: LikeType): Promise<{ like: Like }> {
    try {
      const response = await api.post(`${this.baseURL}/like`, {
        targetId,
        targetType
      });
      return response.data;
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '点赞失败'
        : '点赞失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 取消点赞
  async unlikeTarget(targetId: string, targetType: LikeType): Promise<void> {
    try {
      await api.delete(`${this.baseURL}/like`, {
        data: {
          targetId,
          targetType
        }
      });
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '取消点赞失败'
        : '取消点赞失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 收藏
  async favoriteTarget(targetId: string, targetType: FavoriteType): Promise<{ favorite: Favorite }> {
    try {
      const response = await api.post(`${this.baseURL}/favorite`, {
        targetId,
        targetType
      });
      return response.data;
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '收藏失败'
        : '收藏失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 取消收藏
  async unfavoriteTarget(targetId: string, targetType: FavoriteType): Promise<void> {
    try {
      await api.delete(`${this.baseURL}/favorite`, {
        data: {
          targetId,
          targetType
        }
      });
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '取消收藏失败'
        : '取消收藏失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 获取互动统计
  async getInteractionStats(targetId: string, targetType: string): Promise<InteractionStats> {
    try {
      const response = await api.get(`${this.baseURL}/stats/${targetType}/${targetId}`);
      return response.data;
    } catch (error: unknown) {
      console.error('获取互动统计失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '获取互动统计失败'
        : '获取互动统计失败';
      throw new Error(errorMessage);
    }
  }

  // 获取用户点赞历史
  async getUserLikes(params: {
    page?: number;
    limit?: number;
    targetType?: LikeType;
  } = {}): Promise<PaginatedResponse<Like>> {
    try {
      const response = await api.get(`${this.baseURL}/likes`, { params });
      return {
        data: response.data.likes,
        pagination: response.data.pagination
      };
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '获取点赞历史失败'
        : '获取点赞历史失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 获取用户收藏列表
  async getUserFavorites(params: {
    page?: number;
    limit?: number;
    targetType?: FavoriteType;
  } = {}): Promise<PaginatedResponse<Favorite>> {
    try {
      const response = await api.get(`${this.baseURL}/favorites`, { params });
      return {
        data: response.data.favorites,
        pagination: response.data.pagination
      };
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '获取收藏列表失败'
        : '获取收藏列表失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 获取用户活跃度统计
  async getUserActivityStats(timeRange: '1d' | '7d' | '30d' | 'all' = '7d'): Promise<UserActivityStats> {
    try {
      const response = await api.get(`${this.baseURL}/activity/stats`, {
        params: { timeRange }
      });
      return response.data;
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '获取活跃度统计失败'
        : '获取活跃度统计失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 获取热门内容
  async getPopularContent(params: {
    targetType?: string;
    limit?: number;
    timeRange?: '1d' | '7d' | '30d' | 'all';
  } = {}): Promise<{ content: PopularContent[]; timeRange: string; total: number }> {
    try {
      const response = await api.get(`${this.baseURL}/popular`, { params });
      return response.data;
    } catch (error: unknown) {
      const errorMessage = error && typeof error === 'object' && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '获取热门内容失败'
        : '获取热门内容失败';
      message.error(errorMessage);
      throw new Error(errorMessage);
    }
  }

  // 辅助方法：格式化数量显示
  formatCount(count: number): string {
    if (count < 1000) {
      return count.toString();
    } else if (count < 1000000) {
      return `${(count / 1000).toFixed(1)}K`;
    } else {
      return `${(count / 1000000).toFixed(1)}M`;
    }
  }

  // 辅助方法：获取点赞类型显示文本
  getLikeTypeText(type: LikeType): string {
    const typeMap: Record<LikeType, string> = {
      [LikeType.ANNOTATION]: '标注',
      [LikeType.COMMENT]: '评论',
      [LikeType.USER]: '用户'
    };
    return typeMap[type] || '未知';
  }

  // 辅助方法：获取收藏类型显示文本
  getFavoriteTypeText(type: FavoriteType): string {
    const typeMap: Record<FavoriteType, string> = {
      [FavoriteType.ANNOTATION]: '标注',
      [FavoriteType.USER]: '用户'
    };
    return typeMap[type] || '未知';
  }

  // 辅助方法：获取时间范围显示文本
  getTimeRangeText(range: string): string {
    const rangeMap: Record<string, string> = {
      '1d': '24小时',
      '7d': '7天',
      '30d': '30天',
      'all': '全部时间'
    };
    return rangeMap[range] || '7天';
  }

  // 辅助方法：获取活跃度等级
  getActivityLevel(averageDaily: number): {
    level: string;
    color: string;
    description: string;
  } {
    if (averageDaily >= 10) {
      return {
        level: '非常活跃',
        color: '#f5222d',
        description: '您是社区的超级活跃用户！'
      };
    } else if (averageDaily >= 5) {
      return {
        level: '很活跃',
        color: '#fa541c',
        description: '您在社区中非常活跃'
      };
    } else if (averageDaily >= 2) {
      return {
        level: '活跃',
        color: '#fa8c16',
        description: '您是一个活跃的社区成员'
      };
    } else if (averageDaily >= 1) {
      return {
        level: '一般',
        color: '#faad14',
        description: '保持这个节奏很不错'
      };
    } else {
      return {
        level: '较少',
        color: '#d9d9d9',
        description: '多参与互动会更有趣哦'
      };
    }
  }

  // 辅助方法：计算互动增长率
  calculateGrowthRate(current: number, previous: number): number {
    if (previous === 0) {
      return current > 0 ? 100 : 0;
    }
    return Math.round(((current - previous) / previous) * 100);
  }

  // 辅助方法：获取互动类型图标
  getInteractionIcon(type: string): string {
    const iconMap: Record<string, string> = {
      'like': '👍',
      'favorite': '⭐',
      'annotation': '📍',
      'comment': '💬',
      'user': '👤'
    };
    return iconMap[type] || '📊';
  }


}

// 创建并导出API实例
const interactionApi = new InteractionApi();
export default interactionApi;