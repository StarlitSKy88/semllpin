// import { apiClient } from '@/lib/api'; // 暂时注释掉，使用模拟数据

// 新闻文章接口
export interface NewsArticle {
  id: string;
  title: string;
  summary: string;
  content?: string;
  url: string;
  publishedAt: string;
  source: string;
  author?: string;
  imageUrl?: string;
  location?: string;
  category: string;
  tags?: string[];
  language?: string;
}

// 新闻搜索参数
export interface NewsSearchParams {
  query?: string;
  category?: string;
  language?: string;
  country?: string;
  page?: number;
  pageSize?: number;
  sortBy?: 'publishedAt' | 'relevancy' | 'popularity';
  from?: string; // 开始日期
  to?: string;   // 结束日期
}

// 新闻API响应
export interface NewsApiResponse {
  articles: NewsArticle[];
  totalResults: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// 新闻API服务类
class NewsApiService {
  private readonly baseUrl = '/api/news';

  /**
   * 搜索臭味相关新闻
   */
  async searchSmellNews(params: NewsSearchParams = {}): Promise<NewsApiResponse> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // 模拟新闻数据
    const mockArticles: NewsArticle[] = [
      {
        id: 'news-1',
        title: '北京某小区出现异味，居民投诉环保部门介入调查',
        summary: '近日，北京市朝阳区某小区多名居民反映小区内出现刺鼻异味，疑似化工厂排放导致。环保部门已介入调查，初步排查周边工厂排放情况。',
        content: '详细内容...',
        url: 'https://example.com/news/1',
        publishedAt: '2024-01-15T10:30:00Z',
        source: '北京日报',
        author: '记者张三',
        imageUrl: 'https://images.unsplash.com/photo-1573160813959-df05c1b2e5d1?w=400&h=300&fit=crop',
        location: '北京市朝阳区',
        category: 'environment',
        tags: ['环保', '异味', '投诉'],
        language: 'zh'
      },
      {
        id: 'news-2',
        title: '上海黄浦江异味事件调查结果公布',
        summary: '上海市环保局公布黄浦江异味事件调查结果，确认为上游化工企业违规排放所致，相关企业已被责令停产整改。',
        content: '详细内容...',
        url: 'https://example.com/news/2',
        publishedAt: '2024-01-14T15:45:00Z',
        source: '解放日报',
        author: '记者李四',
        imageUrl: 'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=400&h=300&fit=crop',
        location: '上海市',
        category: 'environment',
        tags: ['环保', '污染', '整改'],
        language: 'zh'
      },
      {
        id: 'news-3',
        title: '全球最臭的地方：冰岛地热区硫磺味让游客掩鼻而逃',
        summary: '冰岛雷克雅未克附近的地热区因强烈的硫磺味而闻名，许多游客表示这里的气味令人难以忍受，但仍然吸引着大量游客前来体验。',
        content: '详细内容...',
        url: 'https://example.com/news/3',
        publishedAt: '2024-01-13T09:20:00Z',
        source: '环球旅游网',
        author: '记者王五',
        imageUrl: 'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=400&h=300&fit=crop',
        location: '冰岛雷克雅未克',
        category: 'travel',
        tags: ['旅游', '地热', '硫磺'],
        language: 'zh'
      }
    ];
    
    const page = params.page || 1;
    const pageSize = params.pageSize || 20;
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    
    return {
      articles: mockArticles.slice(startIndex, endIndex),
      totalResults: mockArticles.length,
      page,
      pageSize,
      hasMore: endIndex < mockArticles.length
    };
  }

  /**
   * 获取热门新闻
   */
  async getTrendingNews(params: Partial<NewsSearchParams> = {}): Promise<NewsApiResponse> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const mockTrendingArticles: NewsArticle[] = [
      {
        id: 'trending-1',
        title: '印度德里空气污染严重，居民称街道气味刺鼻',
        summary: '印度首都德里的空气质量持续恶化，当地居民反映街道上弥漫着刺鼻的气味，严重影响日常生活。',
        content: '详细内容...',
        url: 'https://example.com/trending/1',
        publishedAt: '2024-01-12T08:15:00Z',
        source: '国际环保报',
        imageUrl: 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=300&fit=crop',
        location: '印度德里',
        category: 'environment',
        tags: ['空气污染', '环保', '健康'],
        language: 'zh'
      }
    ];
    
    return {
      articles: mockTrendingArticles,
      totalResults: mockTrendingArticles.length,
      page: 1,
      pageSize: params.pageSize || 10,
      hasMore: false
    };
  }

  /**
   * 根据地理位置获取新闻
   */
  async getNewsByLocation(location: string, params: Partial<NewsSearchParams> = {}): Promise<NewsApiResponse> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 600));
    
    const mockLocationArticles: NewsArticle[] = [
      {
        id: `location-${location}-1`,
        title: `${location}地区环境异味问题调查报告`,
        summary: `${location}地区近期出现环境异味问题，相关部门正在进行深入调查，初步确定污染源头。`,
        content: '详细内容...',
        url: `https://example.com/location/${location}/1`,
        publishedAt: '2024-01-11T14:20:00Z',
        source: '地方环保局',
        imageUrl: 'https://images.unsplash.com/photo-1569163139394-de4e5f43e4e3?w=400&h=300&fit=crop',
        location: location,
        category: 'environment',
        tags: ['环保', '异味', '调查'],
        language: 'zh'
      }
    ];
    
    return {
      articles: mockLocationArticles,
      totalResults: mockLocationArticles.length,
      page: params.page || 1,
      pageSize: params.pageSize || 15,
      hasMore: false
    };
  }

  /**
   * 获取新闻详情
   */
  async getNewsDetail(id: string): Promise<NewsArticle> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return {
      id: id,
      title: '详细新闻标题',
      summary: '这是一篇关于环境异味问题的详细报道...',
      content: '这里是完整的新闻内容，包含了详细的调查过程、专家观点、政府回应等信息...',
      url: `https://example.com/news/${id}`,
      publishedAt: '2024-01-10T16:30:00Z',
      source: '环境时报',
      author: '记者赵六',
      imageUrl: 'https://images.unsplash.com/photo-1611273426858-450d8e3c9fce?w=400&h=300&fit=crop',
      location: '全国',
      category: 'environment',
      tags: ['环保', '详细报道', '专家观点'],
      language: 'zh'
    };
  }

  /**
   * 获取相关新闻推荐
   */
  async getRelatedNews(articleId: string, limit: number = 5): Promise<NewsArticle[]> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 400));
    
    const mockRelatedArticles: NewsArticle[] = [
      {
        id: `related-${articleId}-1`,
        title: '相关新闻：环保部门加强异味监测',
        summary: '为了更好地监测和控制环境异味问题，环保部门将加强相关监测设备的部署。',
        url: `https://example.com/related/${articleId}/1`,
        publishedAt: '2024-01-09T12:00:00Z',
        source: '环保快讯',
        imageUrl: 'https://images.unsplash.com/photo-1581833971358-2c8b550f87b3?w=400&h=300&fit=crop',
        location: '全国',
        category: 'environment',
        tags: ['环保', '监测', '设备'],
        language: 'zh'
      }
    ];
    
    return mockRelatedArticles.slice(0, limit);
  }

  /**
   * 搜索国际新闻（英文）
   */
  async searchInternationalNews(params: NewsSearchParams = {}): Promise<NewsApiResponse> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 900));
    
    const mockInternationalArticles: NewsArticle[] = [
      {
        id: 'international-1',
        title: 'Air Quality Crisis: Major Cities Report Foul Odors',
        summary: 'Several major cities worldwide are experiencing air quality issues with residents reporting strong, unpleasant odors affecting daily life.',
        content: 'Detailed content...',
        url: 'https://example.com/international/1',
        publishedAt: '2024-01-08T18:45:00Z',
        source: 'Global Environmental News',
        author: 'John Smith',
        imageUrl: 'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=400&h=300&fit=crop',
        location: 'Global',
        category: 'environment',
        tags: ['air quality', 'pollution', 'global'],
        language: 'en'
      }
    ];
    
    return {
      articles: mockInternationalArticles,
      totalResults: mockInternationalArticles.length,
      page: params.page || 1,
      pageSize: params.pageSize || 15,
      hasMore: false
    };
  }

  /**
   * 获取新闻分类列表
   */
  async getNewsCategories(): Promise<string[]> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 300));
    
    return [
      'environment',
      'health',
      'technology',
      'travel',
      'local',
      'international',
      'science'
    ];
  }

  /**
   * 获取新闻来源列表
   */
  async getNewsSources(): Promise<Array<{ id: string; name: string; url: string }>> {
    // 模拟API延迟
    await new Promise(resolve => setTimeout(resolve, 350));
    
    return [
      { id: 'beijing-daily', name: '北京日报', url: 'https://bjrb.bjd.com.cn' },
      { id: 'liberation-daily', name: '解放日报', url: 'https://www.jfdaily.com' },
      { id: 'env-times', name: '环境时报', url: 'https://example.com/env-times' },
      { id: 'global-env', name: 'Global Environmental News', url: 'https://example.com/global-env' },
      { id: 'travel-net', name: '环球旅游网', url: 'https://example.com/travel' }
    ];
  }
}

// 导出单例实例
export const newsApi = new NewsApiService();

// 导出默认实例
export default newsApi;

// 工具函数：格式化新闻发布时间
export function formatNewsTime(publishedAt: string): string {
  const date = new Date(publishedAt);
  const now = new Date();
  const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
  
  if (diffInHours < 1) return '刚刚';
  if (diffInHours < 24) return `${diffInHours}小时前`;
  
  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays < 7) return `${diffInDays}天前`;
  if (diffInDays < 30) return `${Math.floor(diffInDays / 7)}周前`;
  
  return date.toLocaleDateString('zh-CN');
}

// 工具函数：提取新闻摘要
export function extractNewsSummary(content: string, maxLength: number = 200): string {
  if (!content) return '';
  
  // 移除HTML标签
  const textContent = content.replace(/<[^>]*>/g, '');
  
  // 截取指定长度
  if (textContent.length <= maxLength) {
    return textContent;
  }
  
  // 在句号处截断，避免截断句子
  const truncated = textContent.substring(0, maxLength);
  const lastPeriod = truncated.lastIndexOf('。');
  const lastExclamation = truncated.lastIndexOf('！');
  const lastQuestion = truncated.lastIndexOf('？');
  
  const lastSentenceEnd = Math.max(lastPeriod, lastExclamation, lastQuestion);
  
  if (lastSentenceEnd > maxLength * 0.7) {
    return truncated.substring(0, lastSentenceEnd + 1);
  }
  
  return truncated + '...';
}

// 工具函数：检查新闻是否与臭味相关
export function isSmellRelated(article: NewsArticle): boolean {
  const smellKeywords = [
    '臭味', '异味', '恶臭', '刺鼻', '难闻',
    'smell', 'odor', 'stink', 'stench', 'foul',
    '污染', '环境', '空气质量', 'pollution', 'environmental'
  ];
  
  const content = `${article.title} ${article.summary} ${article.content || ''}`.toLowerCase();
  
  return smellKeywords.some(keyword => 
    content.includes(keyword.toLowerCase())
  );
}

// 工具函数：按地理位置分组新闻
export function groupNewsByLocation(articles: NewsArticle[]): Record<string, NewsArticle[]> {
  return articles.reduce((groups, article) => {
    const location = article.location || '其他地区';
    if (!groups[location]) {
      groups[location] = [];
    }
    groups[location].push(article);
    return groups;
  }, {} as Record<string, NewsArticle[]>);
}