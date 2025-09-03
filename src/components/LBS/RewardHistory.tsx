/**
 * 奖励历史组件
 * 显示用户的LBS奖励历史记录和统计信息
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect } from 'react';
import { Award, MapPin, Filter, ChevronDown, ChevronUp } from 'lucide-react';

interface RewardRecord {
  id: string;
  userId: string;
  geofenceId: string;
  geofenceName: string;
  rewardType: 'discovery' | 'checkin' | 'stay' | 'social';
  baseReward: number;
  timeDecay: number;
  firstDiscoveryBonus: number;
  finalPoints: number;
  longitude: number;
  latitude: number;
  timestamp: string;
  metadata?: any;
}

interface RewardStats {
  totalRewards: number;
  totalAmount: number;
  todayAmount: number;
  weekAmount: number;
  monthAmount: number;
  averagePerDay: number;
  streakDays: number;
  rank: number;
  totalUsers: number;
  rewardsByType: {
    discovery: { count: number; amount: number };
    checkin: { count: number; amount: number };
    stay: { count: number; amount: number };
    social: { count: number; amount: number };
  };
}

interface RewardHistoryProps {
  className?: string;
  onRewardSelect?: (reward: RewardRecord) => void;
}

const RewardHistory: React.FC<RewardHistoryProps> = ({
  className = ''
}) => {
  const [rewards, setRewards] = useState<RewardRecord[]>([]);
  const [stats, setStats] = useState<RewardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filters, setFilters] = useState({
    rewardType: '',
    dateRange: '7d', // 7d, 30d, 90d, all
    sortBy: 'timestamp', // timestamp, amount
    sortOrder: 'desc' // asc, desc
  });
  const [showFilters, setShowFilters] = useState(false);
  const [selectedPeriod, setSelectedPeriod] = useState<'today' | 'week' | 'month' | 'all'>('week');

  const pageSize = 20;

  // 获取奖励历史
  const fetchRewards = async () => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams({
        page: currentPage.toString(),
        limit: pageSize.toString(),
        ...(filters.rewardType && { type: filters.rewardType }),
        ...(filters.dateRange !== 'all' && { dateRange: filters.dateRange }),
        sortBy: filters.sortBy,
        sortOrder: filters.sortOrder
      });

      const response = await fetch(`/api/lbs/rewards/history?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`获取奖励历史失败: ${response.status}`);
      }

      const data = await response.json();
      setRewards(data.rewards || []);
      setTotalPages(Math.ceil((data.total || 0) / pageSize));
    } catch (err) {
      console.error('获取奖励历史失败:', err);
      setError(err instanceof Error ? err.message : '获取奖励历史失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取奖励统计
  const fetchStats = async () => {
    try {
      const response = await fetch(`/api/lbs/rewards/stats?period=${selectedPeriod}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`获取奖励统计失败: ${response.status}`);
      }

      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('获取奖励统计失败:', err);
    }
  };

  // 格式化奖励类型
  const formatRewardType = (type: string) => {
    const typeMap = {
      discovery: '发现奖励',
      checkin: '签到奖励',
      stay: '停留奖励',
      social: '社交奖励'
    };
    return typeMap[type as keyof typeof typeMap] || type;
  };

  // 格式化日期
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffHours < 1) {
      const diffMinutes = Math.floor(diffMs / (1000 * 60));
      return `${diffMinutes}分钟前`;
    } else if (diffHours < 24) {
      return `${diffHours}小时前`;
    } else if (diffDays < 7) {
      return `${diffDays}天前`;
    } else {
      return date.toLocaleDateString('zh-CN', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    }
  };

  // 获取奖励类型颜色
  const getRewardTypeColor = (type: string) => {
    const colorMap = {
      discovery: 'text-yellow-600 bg-yellow-100',
      checkin: 'text-blue-600 bg-blue-100',
      stay: 'text-green-600 bg-green-100',
      social: 'text-purple-600 bg-purple-100'
    };
    return colorMap[type as keyof typeof colorMap] || 'text-gray-600 bg-gray-100';
  };

  // 处理筛选变化
  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  // 重置筛选
  const resetFilters = () => {
    setFilters({
      rewardType: '',
      dateRange: '7d',
      sortBy: 'timestamp',
      sortOrder: 'desc'
    });
    setCurrentPage(1);
  };

  useEffect(() => {
    fetchRewards();
  }, [currentPage, filters]);

  useEffect(() => {
    fetchStats();
  }, [selectedPeriod]);

  if (loading && rewards.length === 0) {
    return (
      <div className={`bg-white rounded-lg shadow-sm p-6 ${className}`}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-gray-200 rounded w-1/3"></div>
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-16 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white rounded-lg shadow-sm ${className}`}>
      {/* 统计卡片 */}
      {stats && (
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">奖励统计</h2>
            <select
              value={selectedPeriod}
              onChange={(e) => setSelectedPeriod(e.target.value as any)}
              className="text-sm border border-gray-300 rounded px-3 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="today">今日</option>
              <option value="week">本周</option>
              <option value="month">本月</option>
              <option value="all">全部</option>
            </select>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{stats.totalRewards}</div>
              <div className="text-sm text-gray-600">总奖励次数</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{stats.totalAmount}</div>
              <div className="text-sm text-gray-600">总奖励积分</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600">{stats.averagePerDay.toFixed(1)}</div>
              <div className="text-sm text-gray-600">日均积分</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">#{stats.rank}</div>
              <div className="text-sm text-gray-600">排名</div>
            </div>
          </div>

          {/* 奖励类型分布 */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {Object.entries(stats.rewardsByType).map(([type, data]) => (
              <div key={type} className={`p-2 rounded-lg ${getRewardTypeColor(type)}`}>
                <div className="text-xs font-medium">{formatRewardType(type)}</div>
                <div className="text-sm font-bold">{data.count}次 · {data.amount}分</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 筛选器 */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">奖励历史</h3>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center space-x-1 text-sm text-gray-600 hover:text-gray-900"
          >
            <Filter className="h-4 w-4" />
            <span>筛选</span>
            {showFilters ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>

        {showFilters && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">奖励类型</label>
              <select
                value={filters.rewardType}
                onChange={(e) => handleFilterChange('rewardType', e.target.value)}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">全部类型</option>
                <option value="discovery">发现奖励</option>
                <option value="checkin">签到奖励</option>
                <option value="duration">停留奖励</option>
                <option value="social">社交奖励</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">时间范围</label>
              <select
                value={filters.dateRange}
                onChange={(e) => handleFilterChange('dateRange', e.target.value)}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="7d">最近7天</option>
                <option value="30d">最近30天</option>
                <option value="90d">最近90天</option>
                <option value="all">全部时间</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">排序方式</label>
              <select
                value={filters.sortBy}
                onChange={(e) => handleFilterChange('sortBy', e.target.value)}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="timestamp">时间</option>
                <option value="amount">奖励金额</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={resetFilters}
                className="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded text-sm font-medium transition-colors"
              >
                重置筛选
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 奖励列表 */}
      <div className="divide-y divide-gray-200">
        {error && (
          <div className="p-4 bg-red-50 border-l-4 border-red-400">
            <div className="text-red-700">{error}</div>
          </div>
        )}

        {rewards.length === 0 && !loading ? (
          <div className="p-8 text-center text-gray-500">
            <Award className="h-12 w-12 mx-auto mb-4 text-gray-300" />
            <p>暂无奖励记录</p>
            <p className="text-sm mt-1">开始探索附近的地理围栏来获得奖励吧！</p>
          </div>
        ) : (
          rewards.map((reward) => (
            <div
              key={reward.id}
              className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
              onClick={() => {}}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-1">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRewardTypeColor(reward.rewardType)}`}>
                      {formatRewardType(reward.rewardType)}
                    </span>
                    <span className="text-sm text-gray-600">{formatDate(reward.timestamp)}</span>
                  </div>
                  
                  <div className="flex items-center space-x-2 mb-2">
                    <MapPin className="h-4 w-4 text-gray-400" />
                    <span className="font-medium text-gray-900">{reward.geofenceName}</span>
                  </div>

                  <div className="text-sm text-gray-600 space-y-1">
                    <div className="flex justify-between">
                      <span>基础奖励:</span>
                      <span>{reward.baseReward} 分</span>
                    </div>
                    {reward.timeDecay !== 1 && (
                      <div className="flex justify-between">
                        <span>时间衰减:</span>
                        <span>×{reward.timeDecay.toFixed(2)}</span>
                      </div>
                    )}
                    {reward.firstDiscoveryBonus > 0 && (
                      <div className="flex justify-between text-yellow-600">
                        <span>首次发现奖励:</span>
                        <span>+{reward.firstDiscoveryBonus} 分</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-lg font-bold text-green-600">
                    +{reward.finalPoints || 0}
                  </div>
                  <div className="text-sm text-gray-500">积分</div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* 分页 */}
      {totalPages > 1 && (
        <div className="p-4 border-t border-gray-200">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              第 {currentPage} 页，共 {totalPages} 页
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
                className="px-3 py-1 border border-gray-300 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
              >
                上一页
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                disabled={currentPage === totalPages}
                className="px-3 py-1 border border-gray-300 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
              >
                下一页
              </button>
            </div>
          </div>
        </div>
      )}

      {loading && rewards.length > 0 && (
        <div className="p-4 text-center">
          <div className="inline-flex items-center space-x-2 text-gray-600">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
            <span className="text-sm">加载中...</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default RewardHistory;