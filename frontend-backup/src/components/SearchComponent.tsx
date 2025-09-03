import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, X, Filter, MapPin, Clock, Star } from 'lucide-react';
import { NoSearchResults, LoadingState } from './EmptyState';
import { MicroInteraction } from './InteractionFeedback';

import { useNetworkStatus } from '../hooks/useNetworkStatus';

interface SearchResult {
  id: string;
  title: string;
  description: string;
  type: 'location' | 'user' | 'post';
  location?: {
    lat: number;
    lng: number;
    address: string;
  };
  rating?: number;
  timestamp?: Date;
  image?: string;
}

interface SearchComponentProps {
  onResultSelect?: (result: SearchResult) => void;
  placeholder?: string;
  showFilters?: boolean;
  maxResults?: number;
}

const SearchComponent: React.FC<SearchComponentProps> = ({
  onResultSelect,
  placeholder = "搜索地点、用户或内容...",
  showFilters = true,
  maxResults = 10
}) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [selectedFilter, setSelectedFilter] = useState<'all' | 'location' | 'user' | 'post'>('all');
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  
  const { isOnline } = useNetworkStatus();

  // 模拟搜索API
  const performSearch = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim() || !isOnline) return;
    
    setIsLoading(true);
    
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 800));
      
      // 模拟搜索结果
      const mockResults: SearchResult[] = [
        {
          id: '1',
          title: '中央公园',
          description: '城市中心的大型公园，空气清新',
          type: 'location' as const,
          location: { lat: 40.7829, lng: -73.9654, address: '纽约中央公园' },
          rating: 4.5,
          timestamp: new Date()
        },
        {
          id: '2',
          title: '张三',
          description: '活跃的气味探索者，已分享50+地点',
          type: 'user' as const,
          rating: 4.8
        },
        {
          id: '3',
          title: '咖啡店的香气',
          description: '这家咖啡店的烘焙香气真的很棒！',
          type: 'post' as const,
          location: { lat: 40.7589, lng: -73.9851, address: '时代广场咖啡店' },
          timestamp: new Date(Date.now() - 3600000)
        }
      ].filter(result => {
        const matchesQuery = result.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           result.description.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesFilter = selectedFilter === 'all' || result.type === selectedFilter;
        return matchesQuery && matchesFilter;
      }).slice(0, maxResults);
      
      setResults(mockResults);
      
      // 保存搜索历史
      if (searchQuery.trim() && !recentSearches.includes(searchQuery)) {
        setRecentSearches(prev => [searchQuery, ...prev.slice(0, 4)]);
      }
    } catch (error) {
      console.error('搜索失败:', error);
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  }, [selectedFilter, maxResults, recentSearches, isOnline]);

  // 防抖搜索
  useEffect(() => {
    const timer = setTimeout(() => {
      if (query.length >= 2) {
        performSearch(query);
      } else {
        setResults([]);
      }
    }, 300);

    return () => clearTimeout(timer);
  }, [query, performSearch]);

  const handleResultClick = (result: SearchResult) => {
    onResultSelect?.(result);
    setIsExpanded(false);
    setQuery('');
  };

  const clearSearch = () => {
    setQuery('');
    setResults([]);
    setIsExpanded(false);
  };

  const getResultIcon = (type: SearchResult['type']) => {
    switch (type) {
      case 'location': return <MapPin className="w-4 h-4 text-blue-500" />;
      case 'user': return <div className="w-4 h-4 bg-green-500 rounded-full" />;
      case 'post': return <Star className="w-4 h-4 text-yellow-500" />;
      default: return <Search className="w-4 h-4 text-gray-500" />;
    }
  };

  const formatTimestamp = (timestamp?: Date) => {
    if (!timestamp) return '';
    const now = new Date();
    const diff = now.getTime() - timestamp.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    if (hours < 1) return '刚刚';
    if (hours < 24) return `${hours}小时前`;
    return `${Math.floor(hours / 24)}天前`;
  };

  return (
    <div className="relative w-full max-w-2xl mx-auto">
      {/* 搜索输入框 */}
      <motion.div
        className={`relative bg-white rounded-xl shadow-lg border-2 transition-all duration-300 ${
          isExpanded ? 'border-blue-500 shadow-xl' : 'border-gray-200'
        }`}
        layout
      >
        <div className="flex items-center p-4">
          <Search className="w-5 h-5 text-gray-400 mr-3" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onFocus={() => setIsExpanded(true)}
            placeholder={placeholder}
            className="flex-1 outline-none text-gray-700 placeholder-gray-400"
            disabled={!isOnline}
          />
          
          {query && (
            <MicroInteraction type="hover">
              <button
                onClick={clearSearch}
                className="p-1 hover:bg-gray-100 rounded-full transition-colors"
                aria-label="清除搜索"
              >
                <X className="w-4 h-4 text-gray-400" />
              </button>
            </MicroInteraction>
          )}
          
          {showFilters && (
            <MicroInteraction type="hover">
              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="p-2 hover:bg-gray-100 rounded-full transition-colors ml-2"
                aria-label="筛选选项"
              >
                <Filter className="w-4 h-4 text-gray-400" />
              </button>
            </MicroInteraction>
          )}
        </div>

        {/* 筛选器 */}
        <AnimatePresence>
          {isExpanded && showFilters && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="border-t border-gray-100 p-4"
            >
              <div className="flex flex-wrap gap-2">
                {[
                  { key: 'all', label: '全部' },
                  { key: 'location', label: '地点' },
                  { key: 'user', label: '用户' },
                  { key: 'post', label: '内容' }
                ].map(filter => (
                  <button
                    key={filter.key}
                    onClick={() => setSelectedFilter(filter.key as 'all' | 'location' | 'user' | 'post')}
                    className={`px-3 py-1 rounded-full text-sm transition-colors ${
                      selectedFilter === filter.key
                        ? 'bg-blue-500 text-white'
                        : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                    }`}
                  >
                    {filter.label}
                  </button>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* 搜索结果 */}
      <AnimatePresence>
        {isExpanded && (query.length >= 2 || recentSearches.length > 0) && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl shadow-xl border border-gray-200 max-h-96 overflow-y-auto z-50"
          >
            {!isOnline ? (
              <div className="p-4 text-center text-gray-500">
                <div className="text-sm">网络连接已断开</div>
                <div className="text-xs text-gray-400 mt-1">请检查网络连接后重试</div>
              </div>
            ) : isLoading ? (
              <div className="p-4">
                <LoadingState message="搜索中..." />
              </div>
            ) : query.length >= 2 ? (
              results.length > 0 ? (
                <div className="py-2">
                  {results.map((result, index) => (
                    <motion.button
                      key={result.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      onClick={() => handleResultClick(result)}
                      className="w-full p-4 hover:bg-gray-50 transition-colors text-left border-b border-gray-100 last:border-b-0"
                    >
                      <div className="flex items-start gap-3">
                        {getResultIcon(result.type)}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <h3 className="font-medium text-gray-800 truncate">
                              {result.title}
                            </h3>
                            {result.rating && (
                              <div className="flex items-center gap-1 text-xs text-yellow-600">
                                <Star className="w-3 h-3 fill-current" />
                                <span>{result.rating}</span>
                              </div>
                            )}
                          </div>
                          <p className="text-sm text-gray-600 line-clamp-2">
                            {result.description}
                          </p>
                          {result.location && (
                            <p className="text-xs text-gray-400 mt-1">
                              {result.location.address}
                            </p>
                          )}
                          {result.timestamp && (
                            <div className="flex items-center gap-1 text-xs text-gray-400 mt-1">
                              <Clock className="w-3 h-3" />
                              <span>{formatTimestamp(result.timestamp)}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.button>
                  ))}
                </div>
              ) : (
                <div className="p-4">
                  <NoSearchResults
                    query={query}
                    onClear={clearSearch}
                  />
                </div>
              )
            ) : recentSearches.length > 0 ? (
              <div className="py-2">
                <div className="px-4 py-2 text-xs font-medium text-gray-500 border-b border-gray-100">
                  最近搜索
                </div>
                {recentSearches.map((search, index) => (
                  <button
                    key={`item-${index}`}
                    onClick={() => setQuery(search)}
                    className="w-full p-3 hover:bg-gray-50 transition-colors text-left flex items-center gap-3"
                  >
                    <Clock className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-700">{search}</span>
                  </button>
                ))}
              </div>
            ) : null}
          </motion.div>
        )}
      </AnimatePresence>

      {/* 点击外部关闭 */}
      {isExpanded && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setIsExpanded(false)}
        />
      )}
    </div>
  );
};

export default SearchComponent;