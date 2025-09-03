import api from '../utils/api';

// 分享数据接口
export interface ShareData {
  title: string;
  description: string;
  url: string;
  imageUrl?: string;
  hashtags?: string[];
}

// 分享记录接口
export interface ShareRecord {
  id: string;
  userId: string;
  annotationId: string;
  platform: string;
  shareUrl: string;
  clickCount: number;
  createdAt: string;
  updatedAt: string;
}

// 分享统计接口
export interface ShareStats {
  platform: string;
  shareCount: number;
  clickCount: number;
  conversionRate: number;
  lastSharedAt: string;
}

// 热门分享接口
export interface PopularShare {
  id: string;
  title: string;
  description: string;
  location: string;
  imageUrl?: string;
  shareCount: number;
  clickCount: number;
  likeCount: number;
  commentCount: number;
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
  createdAt: string;
  lastSharedAt: string;
}

// 创建分享请求接口
export interface CreateShareRequest {
  platform: string;
  shareUrl?: string;
  shareData?: Record<string, unknown>;
  customMessage?: string;
}

// 分享链接生成请求接口
export interface GenerateShareLinkRequest {
  annotationId: string;
  platform: string;
  customMessage?: string;
}

// 分享历史查询参数接口
export interface ShareHistoryParams {
  page?: number;
  limit?: number;
  platform?: string;
}

// 热门分享查询参数接口
export interface PopularSharesParams {
  page?: number;
  limit?: number;
  timeRange?: '1d' | '7d' | '30d' | 'all';
}

// 分享统计查询参数接口
export interface ShareStatsParams {
  platform?: string;
  timeRange?: '1d' | '7d' | '30d' | 'all';
}

/**
 * 社交分享API服务类
 */
class ShareApiService {
  // ==================== 分享记录相关 ====================
  
  /**
   * 创建分享记录
   */
  async createShareRecord(annotationId: string, data: CreateShareRequest): Promise<ShareRecord> {
    try {
      const response = await api.post(`/annotations/${annotationId}/share`, data);
      return response.data.data;
    } catch (error: unknown) {
      console.error('创建分享记录失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error && 
        error.response && typeof error.response === 'object' && 'data' in error.response &&
        error.response.data && typeof error.response.data === 'object' && 'message' in error.response.data
        ? String(error.response.data.message) : '创建分享记录失败';
      throw new Error(errorMessage);
    }
  }

  /**
   * 生成分享链接
   */
  async generateShareLink(data: GenerateShareLinkRequest): Promise<{
    shareId: string;
    shareUrl: string;
    shareData: ShareData;
    platform: string;
    expiresAt: string;
  }> {
    try {
      const response = await api.post('/share/generate', data);
      return response.data.data;
    } catch (error: unknown) {
      console.error('生成分享链接失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error && 
        error.response && typeof error.response === 'object' && 'data' in error.response &&
        error.response.data && typeof error.response.data === 'object' && 'message' in error.response.data
        ? String(error.response.data.message) : '生成分享链接失败';
      throw new Error(errorMessage);
    }
  }

  /**
   * 获取标注分享统计
   */
  async getAnnotationShareStats(annotationId: string, params: ShareStatsParams = {}): Promise<{
    stats: ShareStats[];
    total: {
      totalShares: number;
      totalClicks: number;
      averageConversionRate: number;
      mostPopularPlatform: string;
    };
    timeRange: string;
    annotationId: string;
  }> {
    try {
      const response = await api.get(`/annotations/${annotationId}/share/stats`, { params });
      return response.data.data;
    } catch (error: unknown) {
      console.error('获取分享统计失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error && 
        error.response && typeof error.response === 'object' && 'data' in error.response &&
        error.response.data && typeof error.response.data === 'object' && 'message' in error.response.data
        ? String(error.response.data.message) : '获取分享统计失败';
      throw new Error(errorMessage);
    }
  }

  /**
   * 获取用户分享历史
   */
  async getUserShareHistory(params: ShareHistoryParams = {}): Promise<{
    shares: ShareRecord[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }> {
    try {
      const response = await api.get('/users/shares', { params });
      return response.data.data;
    } catch (error: unknown) {
      console.error('获取分享历史失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error && 
        error.response && typeof error.response === 'object' && 'data' in error.response &&
        error.response.data && typeof error.response.data === 'object' && 'message' in error.response.data
        ? String(error.response.data.message) : '获取分享历史失败';
      throw new Error(errorMessage);
    }
  }

  /**
   * 获取热门分享内容
   */
  async getPopularShares(params: PopularSharesParams = {}): Promise<{
    shares: PopularShare[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
    timeRange: string;
  }> {
    try {
      const response = await api.get('/shares/popular', { params });
      return response.data.data;
    } catch (error: unknown) {
      console.error('获取热门分享失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error && 
        error.response && typeof error.response === 'object' && 'data' in error.response &&
        error.response.data && typeof error.response.data === 'object' && 'message' in error.response.data
        ? String(error.response.data.message) : '获取热门分享失败';
      throw new Error(errorMessage);
    }
  }

  // ==================== 社交媒体分享相关 ====================
  
  /**
   * 分享到Twitter
   */
  async shareToTwitter(shareData: ShareData): Promise<void> {
    try {
      const text = this.formatTwitterText(shareData);
      const twitterUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(shareData.url)}`;
      
      if (shareData.imageUrl) {
        // Twitter不支持直接在URL中包含图片，需要用户手动添加
      }
      
      window.open(twitterUrl, '_blank', 'width=600,height=400');
    } catch (error: unknown) {
      console.error('分享到Twitter失败:', error);
      throw new Error('分享到Twitter失败');
    }
  }

  /**
   * 分享到Facebook
   */
  async shareToFacebook(shareData: ShareData): Promise<void> {
    try {
      const facebookUrl = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareData.url)}&quote=${encodeURIComponent(shareData.description)}`;
      window.open(facebookUrl, '_blank', 'width=600,height=400');
    } catch (error: unknown) {
      console.error('分享到Facebook失败:', error);
      throw new Error('分享到Facebook失败');
    }
  }

  /**
   * 分享到微信
   */
  async shareToWechat(shareData: ShareData): Promise<void> {
    try {
      // 微信分享通常需要微信JS-SDK，这里提供一个简单的实现
      if (navigator.share) {
        await navigator.share({
          title: shareData.title,
          text: shareData.description,
          url: shareData.url
        });
      } else {
        // 降级方案：复制链接到剪贴板
        await navigator.clipboard.writeText(shareData.url);
        alert('链接已复制到剪贴板，请在微信中粘贴分享');
      }
    } catch (error: unknown) {
      console.error('分享到微信失败:', error);
      throw new Error('分享到微信失败');
    }
  }

  /**
   * 分享到Instagram
   */
  async shareToInstagram(shareData: ShareData): Promise<void> {
    try {
      // Instagram不支持直接URL分享，通常需要用户手动操作
      if (navigator.share) {
        await navigator.share({
          title: shareData.title,
          text: shareData.description,
          url: shareData.url
        });
      } else {
        await navigator.clipboard.writeText(`${shareData.title}\n${shareData.description}\n${shareData.url}`);
        alert('内容已复制到剪贴板，请在Instagram中粘贴分享');
      }
    } catch (error: unknown) {
      console.error('分享到Instagram失败:', error);
      throw new Error('分享到Instagram失败');
    }
  }

  /**
   * 分享到TikTok
   */
  async shareToTikTok(shareData: ShareData): Promise<void> {
    try {
      // TikTok分享通常需要特定的SDK或深度链接
      if (navigator.share) {
        await navigator.share({
          title: shareData.title,
          text: shareData.description,
          url: shareData.url
        });
      } else {
        await navigator.clipboard.writeText(`${shareData.title}\n${shareData.description}\n${shareData.url}`);
        alert('内容已复制到剪贴板，请在TikTok中粘贴分享');
      }
    } catch (error: unknown) {
      console.error('分享到TikTok失败:', error);
      throw new Error('分享到TikTok失败');
    }
  }

  /**
   * 通用分享方法
   */
  async shareToSocialMedia(platform: string, shareData: ShareData): Promise<void> {
    switch (platform.toLowerCase()) {
      case 'twitter':
        return this.shareToTwitter(shareData);
      case 'facebook':
        return this.shareToFacebook(shareData);
      case 'wechat':
        return this.shareToWechat(shareData);
      case 'instagram':
        return this.shareToInstagram(shareData);
      case 'tiktok':
        return this.shareToTikTok(shareData);
      default:
        throw new Error(`不支持的分享平台: ${platform}`);
    }
  }

  // ==================== 辅助方法 ====================
  
  /**
   * 格式化Twitter分享文本
   */
  private formatTwitterText(shareData: ShareData): string {
    let text = shareData.title;
    if (shareData.description && shareData.description !== shareData.title) {
      text += ` - ${shareData.description}`;
    }
    
    if (shareData.hashtags && shareData.hashtags.length > 0) {
      const hashtags = shareData.hashtags.map(tag => `#${tag}`).join(' ');
      text += ` ${hashtags}`;
    }
    
    // Twitter字符限制
    const maxLength = 280 - shareData.url.length - 1; // 减去URL和空格
    if (text.length > maxLength) {
      text = text.substring(0, maxLength - 3) + '...';
    }
    
    return text;
  }

  /**
   * 获取平台显示名称
   */
  getPlatformDisplayName(platform: string): string {
    const platformNames: Record<string, string> = {
      twitter: 'Twitter',
      facebook: 'Facebook',
      instagram: 'Instagram',
      tiktok: 'TikTok',
      wechat: '微信',
      weibo: '微博',
      linkedin: 'LinkedIn'
    };
    return platformNames[platform.toLowerCase()] || platform;
  }

  /**
   * 获取平台图标
   */
  getPlatformIcon(platform: string): string {
    const platformIcons: Record<string, string> = {
      twitter: '🐦',
      facebook: '📘',
      instagram: '📷',
      tiktok: '🎵',
      wechat: '💬',
      weibo: '📢',
      linkedin: '💼'
    };
    return platformIcons[platform.toLowerCase()] || '🔗';
  }

  /**
   * 获取支持的分享平台列表
   */
  getSupportedPlatforms(): Array<{ value: string; label: string; icon: string }> {
    return [
      { value: 'twitter', label: 'Twitter', icon: '🐦' },
      { value: 'facebook', label: 'Facebook', icon: '📘' },
      { value: 'instagram', label: 'Instagram', icon: '📷' },
      { value: 'tiktok', label: 'TikTok', icon: '🎵' },
      { value: 'wechat', label: '微信', icon: '💬' },
      { value: 'weibo', label: '微博', icon: '📢' },
      { value: 'linkedin', label: 'LinkedIn', icon: '💼' }
    ];
  }

  /**
   * 格式化分享数量
   */
  formatShareCount(count: number): string {
    if (count >= 1000000) {
      return `${(count / 1000000).toFixed(1)}M`;
    } else if (count >= 1000) {
      return `${(count / 1000).toFixed(1)}K`;
    }
    return count.toString();
  }

  /**
   * 计算转化率
   */
  calculateConversionRate(clicks: number, shares: number): number {
    if (shares === 0) return 0;
    return Number((clicks / shares).toFixed(3));
  }

  /**
   * 验证分享数据
   */
  validateShareData(shareData: ShareData): { isValid: boolean; message?: string } {
    if (!shareData.title || !shareData.title.trim()) {
      return { isValid: false, message: '分享标题不能为空' };
    }
    
    if (!shareData.url || !shareData.url.trim()) {
      return { isValid: false, message: '分享链接不能为空' };
    }
    
    try {
      new URL(shareData.url);
    } catch {
      return { isValid: false, message: '分享链接格式不正确' };
    }
    
    if (shareData.title.length > 100) {
      return { isValid: false, message: '分享标题不能超过100个字符' };
    }
    
    if (shareData.description && shareData.description.length > 500) {
      return { isValid: false, message: '分享描述不能超过500个字符' };
    }
    
    return { isValid: true };
  }

  /**
   * 处理分享错误
   */
  handleShareError(error: unknown, platform: string): string {
    const errorObj = error as {
      response?: {
        status: number;
        data?: { message?: string };
      };
      request?: unknown;
      message?: string;
    };
    
    if (errorObj.response) {
      const status = errorObj.response.status;
      const message = errorObj.response.data?.message;
      
      switch (status) {
        case 401:
          return '请先登录后再分享';
        case 403:
          return '没有权限分享此内容';
        case 404:
          return '要分享的内容不存在';
        case 429:
          return '分享过于频繁，请稍后再试';
        case 500:
          return '服务器错误，分享失败';
        default:
          return message || `分享到${this.getPlatformDisplayName(platform)}失败`;
      }
    } else if (errorObj.request) {
      return '网络连接失败，请检查网络设置';
    } else {
      return errorObj.message || `分享到${this.getPlatformDisplayName(platform)}失败`;
    }
  }
}

// 创建并导出分享API服务实例
const shareApi = new ShareApiService();
export default shareApi;