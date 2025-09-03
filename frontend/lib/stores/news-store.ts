import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { newsApi, NewsArticle, NewsSearchParams, NewsApiResponse } from '@/lib/services/news-api';

// 新闻状态接口
interface NewsState {
  // 数据状态
  articles: NewsArticle[];
  trendingNews: NewsArticle[];
  locationNews: Record<string, NewsArticle[]>;
  currentArticle: NewsArticle | null;
  
  // 加载状态
  isLoading: boolean;
  isTrendingLoading: boolean;
  isLocationLoading: boolean;
  isDetailLoading: boolean;
  
  // 分页状态
  currentPage: number;
  totalResults: number;
  hasMore: boolean;
  
  // 搜索状态
  searchParams: NewsSearchParams;
  lastSearchQuery: string;
  
  // 错误状态
  error: string | null;
  
  // 缓存状态
  lastFetchTime: number;
  cacheExpiry: number; // 缓存过期时间（毫秒）
  
  // Actions
  searchNews: (params?: NewsSearchParams) => Promise<void>;
  loadMoreNews: () => Promise<void>;
  getTrendingNews: (refresh?: boolean) => Promise<void>;
  getNewsByLocation: (location: string, refresh?: boolean) => Promise<void>;
  getNewsDetail: (id: string) => Promise<void>;
  refreshNews: () => Promise<void>;
  clearNews: () => void;
  clearError: () => void;
  setSearchParams: (params: NewsSearchParams) => void;
  
  // 工具方法
  isDataFresh: () => boolean;
  getArticleById: (id: string) => NewsArticle | undefined;
  getArticlesByLocation: (location: string) => NewsArticle[];
}

// 默认搜索参数
const defaultSearchParams: NewsSearchParams = {
  query: '臭味 OR 异味 OR 恶臭 OR 污染',
  page: 1,
  pageSize: 20,
  sortBy: 'publishedAt',
  language: 'zh'
};

export const useNewsStore = create<NewsState>()(persist(
  (set, get) => ({
    // 初始状态
    articles: [],
    trendingNews: [],
    locationNews: {},
    currentArticle: null,
    
    isLoading: false,
    isTrendingLoading: false,
    isLocationLoading: false,
    isDetailLoading: false,
    
    currentPage: 1,
    totalResults: 0,
    hasMore: false,
    
    searchParams: defaultSearchParams,
    lastSearchQuery: '',
    
    error: null,
    
    lastFetchTime: 0,
    cacheExpiry: 5 * 60 * 1000, // 5分钟缓存
    
    // 搜索新闻
    searchNews: async (params?: NewsSearchParams) => {
      const state = get();
      const searchParams = { ...state.searchParams, ...params };
      
      // 如果是新的搜索，重置分页
      if (params?.query && params.query !== state.lastSearchQuery) {
        searchParams.page = 1;
        set({ articles: [], currentPage: 1 });
      }
      
      set({ 
        isLoading: true, 
        error: null, 
        searchParams,
        lastSearchQuery: searchParams.query || ''
      });
      
      try {
        const response: NewsApiResponse = await newsApi.searchSmellNews(searchParams);
        
        set(state => ({
          articles: searchParams.page === 1 
            ? response.articles 
            : [...state.articles, ...response.articles],
          currentPage: response.page,
          totalResults: response.totalResults,
          hasMore: response.hasMore,
          lastFetchTime: Date.now(),
          isLoading: false
        }));
      } catch (error: any) {
        set({ 
          error: error.message || '获取新闻失败', 
          isLoading: false 
        });
      }
    },
    
    // 加载更多新闻
    loadMoreNews: async () => {
      const state = get();
      if (!state.hasMore || state.isLoading) return;
      
      const nextPage = state.currentPage + 1;
      await state.searchNews({ ...state.searchParams, page: nextPage });
    },
    
    // 获取热门新闻
    getTrendingNews: async (refresh = false) => {
      const state = get();
      
      // 检查缓存
      if (!refresh && state.trendingNews.length > 0 && state.isDataFresh()) {
        return;
      }
      
      set({ isTrendingLoading: true, error: null });
      
      try {
        const response = await newsApi.getTrendingNews({
          pageSize: 10,
          sortBy: 'popularity'
        });
        
        set({ 
          trendingNews: response.articles,
          lastFetchTime: Date.now(),
          isTrendingLoading: false
        });
      } catch (error: any) {
        set({ 
          error: error.message || '获取热门新闻失败', 
          isTrendingLoading: false 
        });
      }
    },
    
    // 根据地理位置获取新闻
    getNewsByLocation: async (location: string, refresh = false) => {
      const state = get();
      
      // 检查缓存
      if (!refresh && state.locationNews[location] && state.isDataFresh()) {
        return;
      }
      
      set({ isLocationLoading: true, error: null });
      
      try {
        const response = await newsApi.getNewsByLocation(location, {
          pageSize: 15
        });
        
        set(state => ({
          locationNews: {
            ...state.locationNews,
            [location]: response.articles
          },
          lastFetchTime: Date.now(),
          isLocationLoading: false
        }));
      } catch (error: any) {
        set({ 
          error: error.message || '获取地区新闻失败', 
          isLocationLoading: false 
        });
      }
    },
    
    // 获取新闻详情
    getNewsDetail: async (id: string) => {
      const state = get();
      
      // 先检查本地是否已有该文章
      const existingArticle = state.getArticleById(id);
      if (existingArticle && existingArticle.content) {
        set({ currentArticle: existingArticle });
        return;
      }
      
      set({ isDetailLoading: true, error: null });
      
      try {
        const article = await newsApi.getNewsDetail(id);
        set({ 
          currentArticle: article,
          isDetailLoading: false
        });
      } catch (error: any) {
        set({ 
          error: error.message || '获取新闻详情失败', 
          isDetailLoading: false 
        });
      }
    },
    
    // 刷新新闻
    refreshNews: async () => {
      const state = get();
      set({ lastFetchTime: 0 }); // 强制刷新缓存
      
      // 重新获取当前搜索结果
      await state.searchNews({ ...state.searchParams, page: 1 });
      
      // 重新获取热门新闻
      await state.getTrendingNews(true);
    },
    
    // 清空新闻数据
    clearNews: () => {
      set({
        articles: [],
        trendingNews: [],
        locationNews: {},
        currentArticle: null,
        currentPage: 1,
        totalResults: 0,
        hasMore: false,
        lastSearchQuery: '',
        error: null,
        lastFetchTime: 0
      });
    },
    
    // 清除错误
    clearError: () => {
      set({ error: null });
    },
    
    // 设置搜索参数
    setSearchParams: (params: NewsSearchParams) => {
      set({ searchParams: { ...get().searchParams, ...params } });
    },
    
    // 检查数据是否新鲜
    isDataFresh: () => {
      const state = get();
      return Date.now() - state.lastFetchTime < state.cacheExpiry;
    },
    
    // 根据ID获取文章
    getArticleById: (id: string) => {
      const state = get();
      return state.articles.find(article => article.id === id) ||
             state.trendingNews.find(article => article.id === id) ||
             Object.values(state.locationNews)
               .flat()
               .find(article => article.id === id);
    },
    
    // 根据地理位置获取文章
    getArticlesByLocation: (location: string) => {
      const state = get();
      return state.locationNews[location] || [];
    }
  }),
  {
    name: 'news-store',
    // 只持久化部分状态，避免存储过多数据
    partialize: (state) => ({
      searchParams: state.searchParams,
      lastSearchQuery: state.lastSearchQuery,
      cacheExpiry: state.cacheExpiry
    })
  }
));

// 导出类型
export type { NewsState };

// 导出默认实例
export default useNewsStore;