import React, { useState, useEffect, useCallback } from 'react';
import { Trophy, Calendar, MapPin, Coins, Search, ChevronDown, Star, Gift, Zap } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import useNotificationStore from '../../stores/notificationStore';

interface RewardRecord {
  id: string;
  annotationId: string;
  annotationTitle: string;
  annotationType: 'prank' | 'funny' | 'weird';
  reward: number;
  location: {
    latitude: number;
    longitude: number;
    address?: string;
  };
  claimedAt: string;
  distance: number;
  isFirstDiscovery: boolean;
  multiplier: number;
}

interface RewardStats {
  totalRewards: number;
  totalClaimed: number;
  firstDiscoveries: number;
  averageReward: number;
  bestDay: {
    date: string;
    rewards: number;
  };
}

interface RewardHistoryProps {
  className?: string;
}

const RewardHistory: React.FC<RewardHistoryProps> = ({ className = '' }) => {
  const { user } = useAuthStore();
  const { addNotification } = useNotificationStore();
  const [records, setRecords] = useState<RewardRecord[]>([]);
  const [stats, setStats] = useState<RewardStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'prank' | 'funny' | 'weird'>('all');
  const [sortBy, setSortBy] = useState<'date' | 'reward' | 'distance'>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const pageSize = 10;

  // 加载奖励历史
  const loadRewardHistory = useCallback(async (page = 1) => {
    if (!user) return;

    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: pageSize.toString(),
        search: searchTerm,
        type: filterType === 'all' ? '' : filterType,
        sortBy,
        sortOrder
      });

      const response = await fetch(`/api/v1/lbs/reward-history?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });

      if (!response.ok) {
        throw new Error('加载奖励历史失败');
      }

      const data = await response.json();
      setRecords(data.data.records || []);
      setStats(data.data.stats || null);
      setTotalPages(Math.ceil((data.data.total || 0) / pageSize));
      setCurrentPage(page);

    } catch (error) {
      console.error('加载奖励历史失败:', error);
      addNotification({
        type: 'error',
        title: '加载失败',
        message: '无法加载奖励历史记录'
      });
    } finally {
      setIsLoading(false);
    }
  }, [user, searchTerm, filterType, sortBy, sortOrder, addNotification]);

  // 格式化日期
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
      return '今天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    } else if (diffDays === 1) {
      return '昨天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    } else if (diffDays < 7) {
      return `${diffDays}天前`;
    } else {
      return date.toLocaleDateString('zh-CN');
    }
  };

  // 获取奖励类型图标
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'prank': return '😈';
      case 'funny': return '😂';
      case 'weird': return '🤔';
      default: return '📍';
    }
  };

  // 获取奖励类型颜色
  const getTypeColor = (type: string) => {
    switch (type) {
      case 'prank': return 'text-red-600 bg-red-100';
      case 'funny': return 'text-yellow-600 bg-yellow-100';
      case 'weird': return 'text-purple-600 bg-purple-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  // 获取奖励类型名称
  const getTypeName = (type: string) => {
    switch (type) {
      case 'prank': return '恶搞';
      case 'funny': return '搞笑';
      case 'weird': return '奇怪';
      default: return '未知';
    }
  };

  // 处理搜索
  const handleSearch = useCallback(() => {
    setCurrentPage(1);
    loadRewardHistory(1);
  }, [loadRewardHistory]);

  // 处理排序
  const handleSort = (field: 'date' | 'reward' | 'distance') => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  // 初始化加载
  useEffect(() => {
    loadRewardHistory();
  }, [user, filterType, sortBy, sortOrder, loadRewardHistory]);

  // 搜索防抖
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchTerm !== '') {
        handleSearch();
      } else {
        loadRewardHistory(1);
      }
    }, 500);

    return () => clearTimeout(timer);
  }, [searchTerm, handleSearch, loadRewardHistory]);

  if (!user) {
    return (
      <div className={`bg-white rounded-xl shadow-lg p-8 text-center ${className}`}>
        <Trophy className="w-16 h-16 mx-auto text-gray-300 mb-4" />
        <h3 className="text-xl font-semibold text-gray-900 mb-2">请先登录</h3>
        <p className="text-gray-500">登录后查看您的奖励历史记录</p>
      </div>
    );
  }

  return (
    <div className={`bg-white rounded-xl shadow-lg overflow-hidden ${className}`}>
      {/* 头部统计 */}
      {stats && (
        <div className="p-6 bg-gradient-to-r from-blue-500 to-purple-600 text-white">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-white/20 rounded-lg">
                <Trophy className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-2xl font-bold">奖励历史</h2>
                <p className="text-blue-100">您的LBS奖励记录</p>
              </div>
            </div>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-white/10 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-1">
                <Coins className="w-5 h-5 text-yellow-300" />
                <span className="text-sm text-blue-100">总奖励</span>
              </div>
              <p className="text-2xl font-bold">{stats.totalRewards}</p>
            </div>
            
            <div className="bg-white/10 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-1">
                <Gift className="w-5 h-5 text-green-300" />
                <span className="text-sm text-blue-100">已领取</span>
              </div>
              <p className="text-2xl font-bold">{stats.totalClaimed}</p>
            </div>
            
            <div className="bg-white/10 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-1">
                <Star className="w-5 h-5 text-orange-300" />
                <span className="text-sm text-blue-100">首次发现</span>
              </div>
              <p className="text-2xl font-bold">{stats.firstDiscoveries}</p>
            </div>
            
            <div className="bg-white/10 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-1">
                <Zap className="w-5 h-5 text-pink-300" />
                <span className="text-sm text-blue-100">平均奖励</span>
              </div>
              <p className="text-2xl font-bold">{stats.averageReward.toFixed(1)}</p>
            </div>
          </div>
        </div>
      )}
      
      {/* 筛选和搜索 */}
      <div className="p-6 border-b bg-gray-50">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
          {/* 搜索框 */}
          <div className="flex-1 max-w-md">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="搜索标注标题..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            {/* 类型筛选 */}
            <div className="relative">
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value as 'all' | 'prank' | 'funny' | 'weird')}
                className="appearance-none bg-white border border-gray-300 rounded-lg px-4 py-2 pr-8 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">所有类型</option>
                <option value="prank">😈 恶搞</option>
                <option value="funny">😂 搞笑</option>
                <option value="weird">🤔 奇怪</option>
              </select>
              <ChevronDown className="absolute right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
            </div>
            
            {/* 排序 */}
            <div className="flex items-center space-x-1">
              <button
                onClick={() => handleSort('date')}
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  sortBy === 'date' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'bg-white text-gray-600 hover:bg-gray-100'
                }`}
              >
                时间 {sortBy === 'date' && (sortOrder === 'desc' ? '↓' : '↑')}
              </button>
              <button
                onClick={() => handleSort('reward')}
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  sortBy === 'reward' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'bg-white text-gray-600 hover:bg-gray-100'
                }`}
              >
                奖励 {sortBy === 'reward' && (sortOrder === 'desc' ? '↓' : '↑')}
              </button>
              <button
                onClick={() => handleSort('distance')}
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  sortBy === 'distance' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'bg-white text-gray-600 hover:bg-gray-100'
                }`}
              >
                距离 {sortBy === 'distance' && (sortOrder === 'desc' ? '↓' : '↑')}
              </button>
            </div>
          </div>
        </div>
      </div>
      
      {/* 奖励记录列表 */}
      <div className="divide-y divide-gray-200">
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full mx-auto mb-4"></div>
            <p className="text-gray-500">加载中...</p>
          </div>
        ) : records.length === 0 ? (
          <div className="p-8 text-center">
            <Trophy className="w-16 h-16 mx-auto text-gray-300 mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">暂无奖励记录</h3>
            <p className="text-gray-500">快去探索附近的标注点获得奖励吧！</p>
          </div>
        ) : (
          records.map((record) => (
            <div key={record.id} className="p-6 hover:bg-gray-50 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4 flex-1">
                  {/* 类型图标 */}
                  <div className={`p-3 rounded-lg ${getTypeColor(record.annotationType)}`}>
                    <span className="text-xl">{getTypeIcon(record.annotationType)}</span>
                  </div>
                  
                  {/* 内容 */}
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <h4 className="font-semibold text-gray-900">{record.annotationTitle}</h4>
                      {record.isFirstDiscovery && (
                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                          <Star className="w-3 h-3 mr-1" />
                          首次发现
                        </span>
                      )}
                      {record.multiplier > 1 && (
                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                          <Zap className="w-3 h-3 mr-1" />
                          {record.multiplier}x
                        </span>
                      )}
                    </div>
                    
                    <div className="flex items-center space-x-4 text-sm text-gray-500 mb-2">
                      <span className={`px-2 py-1 rounded-full text-xs ${getTypeColor(record.annotationType)}`}>
                        {getTypeName(record.annotationType)}
                      </span>
                      <div className="flex items-center space-x-1">
                        <MapPin className="w-4 h-4" />
                        <span>{record.distance}m</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Calendar className="w-4 h-4" />
                        <span>{formatDate(record.claimedAt)}</span>
                      </div>
                    </div>
                    
                    {record.location.address && (
                      <p className="text-sm text-gray-600">{record.location.address}</p>
                    )}
                  </div>
                </div>
                
                {/* 奖励金额 */}
                <div className="text-right">
                  <div className="flex items-center space-x-1 text-green-600 font-semibold">
                    <Coins className="w-5 h-5" />
                    <span className="text-lg">+{record.reward}</span>
                  </div>
                  <p className="text-xs text-gray-500">积分</p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
      
      {/* 分页 */}
      {totalPages > 1 && (
        <div className="p-6 border-t bg-gray-50">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-700">
              第 {currentPage} 页，共 {totalPages} 页
            </p>
            
            <div className="flex items-center space-x-2">
              <button
                onClick={() => loadRewardHistory(currentPage - 1)}
                disabled={currentPage === 1 || isLoading}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                上一页
              </button>
              
              <div className="flex items-center space-x-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  const page = i + 1;
                  return (
                    <button
                      key={page}
                      onClick={() => loadRewardHistory(page)}
                      disabled={isLoading}
                      className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        currentPage === page
                          ? 'bg-blue-600 text-white'
                          : 'text-gray-700 hover:bg-gray-100 disabled:opacity-50'
                      }`}
                    >
                      {page}
                    </button>
                  );
                })}
              </div>
              
              <button
                onClick={() => loadRewardHistory(currentPage + 1)}
                disabled={currentPage === totalPages || isLoading}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                下一页
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RewardHistory;