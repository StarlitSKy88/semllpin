import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  // User, // 暂时注释掉，因为未使用
  MapPin,
  Heart,
  MessageCircle,
  Star,
  Trophy,
  Calendar as CalendarIcon,
  TrendingUp,
  // Award,
  // Target,
  // Clock,
  // Camera, // 暂时注释掉，因为未使用
  Share2,
  Settings,
  // Edit3, // 暂时注释掉，因为未使用
  Plus,
  Filter,
  Download,
  BarChart3,
  PieChart,
  Activity,
  Zap,
  // Crown,
  // Gift // 暂时注释掉，因为未使用
} from 'lucide-react';
import { LazyImage } from './LazyImage';
import { MicroInteraction, LoadingButton } from './InteractionFeedback';

// import { useMobile } from './MobileOptimization'; // 暂时注释掉，因为未使用
import { useNetworkStatus } from '../hooks/useNetworkStatus';
import { toast } from 'sonner';
import EmptyState, { LoadingState } from './EmptyState';
// import LazyContainer from './LazyLoad'; // 暂时注释掉，因为未使用

interface UserStats {
  totalPins: number;
  totalLikes: number;
  totalComments: number;
  totalViews: number;
  points: number;
  level: number;
  rank: string;
  joinDate: Date;
  streakDays: number;
  achievements: number;
}

interface Achievement {
  id: string;
  title: string;
  description: string;
  icon: string;
  rarity: 'common' | 'rare' | 'epic' | 'legendary';
  unlockedAt: Date;
  progress?: {
    current: number;
    total: number;
  };
}

interface Activity {
  id: string;
  type: 'pin_created' | 'pin_liked' | 'comment_added' | 'achievement_unlocked' | 'level_up';
  title: string;
  description: string;
  timestamp: Date;
  data?: Record<string, unknown>;
}

interface UserDashboardProps {
  userId?: string;
  className?: string;
}

const UserDashboard: React.FC<UserDashboardProps> = ({
  userId = 'current-user',
  className = ''
}) => {
  const [userStats, setUserStats] = useState<UserStats | null>(null);
  const [achievements, setAchievements] = useState<Achievement[]>([]);
  const [recentActivities, setRecentActivities] = useState<Activity[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'achievements' | 'activities' | 'analytics'>('overview');
  const [timeRange, setTimeRange] = useState<'week' | 'month' | 'year'>('month');
  const [showAchievementDetails, setShowAchievementDetails] = useState<Achievement | null>(null);
  
  // const { isMobile } = useMobile(); // 暂时注释掉，因为未使用
  const { isOnline } = useNetworkStatus();

  // 模拟用户数据
  const mockUserStats: UserStats = useMemo(() => ({
    totalPins: 42,
    totalLikes: 328,
    totalComments: 156,
    totalViews: 2847,
    points: 8650,
    level: 12,
    rank: '气味探索者',
    joinDate: new Date('2023-06-15'),
    streakDays: 15,
    achievements: 8
  }), []);

  const mockAchievements: Achievement[] = useMemo(() => [
    {
      id: '1',
      title: '初次标注',
      description: '创建你的第一个气味标注',
      icon: '🎯',
      rarity: 'common',
      unlockedAt: new Date('2023-06-16')
    },
    {
      id: '2',
      title: '人气王',
      description: '单个标注获得100个赞',
      icon: '👑',
      rarity: 'rare',
      unlockedAt: new Date('2023-08-22')
    },
    {
      id: '3',
      title: '咖啡专家',
      description: '标注20个咖啡相关气味',
      icon: '☕',
      rarity: 'epic',
      unlockedAt: new Date('2023-09-15'),
      progress: { current: 18, total: 20 }
    },
    {
      id: '4',
      title: '传奇探索者',
      description: '连续30天活跃',
      icon: '🏆',
      rarity: 'legendary',
      unlockedAt: new Date('2023-10-01')
    }
  ], []);

  const mockActivities: Activity[] = useMemo(() => [
    {
      id: '1',
      type: 'pin_created',
      title: '创建了新标注',
      description: '在星巴克标注了浓郁的咖啡香',
      timestamp: new Date(Date.now() - 3600000)
    },
    {
      id: '2',
      type: 'achievement_unlocked',
      title: '解锁成就',
      description: '获得了"咖啡专家"成就',
      timestamp: new Date(Date.now() - 7200000)
    },
    {
      id: '3',
      type: 'pin_liked',
      title: '标注获赞',
      description: '你的"樱花飘香"标注获得了5个新赞',
      timestamp: new Date(Date.now() - 10800000)
    },
    {
      id: '4',
      type: 'level_up',
      title: '等级提升',
      description: '恭喜升级到12级！',
      timestamp: new Date(Date.now() - 86400000)
    }
  ], []);

  useEffect(() => {
    const loadUserData = async () => {
      setIsLoading(true);
      try {
        // 模拟API调用
        await new Promise(resolve => setTimeout(resolve, 1000));
        setUserStats(mockUserStats);
        setAchievements(mockAchievements);
        setRecentActivities(mockActivities);
      } catch (_error) {
        toast.error('加载用户数据失败');
      } finally {
        setIsLoading(false);
      }
    };

    loadUserData();
  }, [userId, mockUserStats, mockAchievements, mockActivities]);

  const getRarityColor = (rarity: Achievement['rarity']) => {
    switch (rarity) {
      case 'common': return 'bg-gray-100 text-gray-700 border-gray-300';
      case 'rare': return 'bg-blue-100 text-blue-700 border-blue-300';
      case 'epic': return 'bg-purple-100 text-purple-700 border-purple-300';
      case 'legendary': return 'bg-yellow-100 text-yellow-700 border-yellow-300';
      default: return 'bg-gray-100 text-gray-700 border-gray-300';
    }
  };

  const getActivityIcon = (type: Activity['type']) => {
    switch (type) {
      case 'pin_created': return <MapPin className="w-4 h-4" />;
      case 'pin_liked': return <Heart className="w-4 h-4" />;
      case 'comment_added': return <MessageCircle className="w-4 h-4" />;
      case 'achievement_unlocked': return <Trophy className="w-4 h-4" />;
      case 'level_up': return <Star className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) return '刚刚';
    if (hours < 24) return `${hours}小时前`;
    return `${Math.floor(hours / 24)}天前`;
  };

  const calculateLevelProgress = (points: number, level: number) => {
    const pointsForCurrentLevel = level * 1000;
    const pointsForNextLevel = (level + 1) * 1000;
    const progress = ((points - pointsForCurrentLevel) / (pointsForNextLevel - pointsForCurrentLevel)) * 100;
    return Math.max(0, Math.min(100, progress));
  };

  if (isLoading) {
    return (
      <div className={`w-full ${className}`}>
        <LoadingState message="加载用户数据中..." />
      </div>
    );
  }

  if (!userStats) {
    return (
      <div className={`w-full ${className}`}>
        <EmptyState
          type="error"
          title="加载失败"
          description="无法加载用户数据，请稍后重试"
        />
      </div>
    );
  }

  return (
    <div className={`w-full space-y-6 ${className}`}>
      {/* 用户概览卡片 */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl p-6 text-white"
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <LazyImage
                src="https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=friendly%20user%20avatar%20smiling%20profile&image_size=square"
                alt="用户头像"
                className="w-16 h-16 rounded-full border-4 border-white/20"
              />
              <div className="absolute -bottom-1 -right-1 bg-green-400 w-6 h-6 rounded-full border-2 border-white flex items-center justify-center">
                <span className="text-xs font-bold text-white">{userStats.level}</span>
              </div>
            </div>
            <div>
              <h2 className="text-xl font-bold">气味探索者</h2>
              <p className="text-white/80">{userStats.rank}</p>
              <div className="flex items-center gap-2 mt-1">
                <Zap className="w-4 h-4 text-yellow-300" />
                <span className="text-sm">{userStats.streakDays}天连续活跃</span>
              </div>
            </div>
          </div>
          
          <div className="text-right">
            <div className="text-2xl font-bold">{userStats.points.toLocaleString()}</div>
            <div className="text-white/80 text-sm">积分</div>
          </div>
        </div>

        {/* 等级进度条 */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span>等级 {userStats.level}</span>
            <span>等级 {userStats.level + 1}</span>
          </div>
          <div className="w-full bg-white/20 rounded-full h-2">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${calculateLevelProgress(userStats.points, userStats.level)}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className="bg-white h-2 rounded-full"
            />
          </div>
        </div>
      </motion.div>

      {/* 统计数据网格 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: '标注数', value: userStats.totalPins, icon: MapPin, color: 'text-blue-600' },
          { label: '获赞数', value: userStats.totalLikes, icon: Heart, color: 'text-red-600' },
          { label: '评论数', value: userStats.totalComments, icon: MessageCircle, color: 'text-green-600' },
          { label: '浏览量', value: userStats.totalViews, icon: TrendingUp, color: 'text-purple-600' }
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="bg-white rounded-lg p-4 shadow-sm border border-gray-200"
          >
            <div className="flex items-center justify-between mb-2">
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
              <span className="text-2xl font-bold text-gray-800">
                {stat.value.toLocaleString()}
              </span>
            </div>
            <p className="text-sm text-gray-600">{stat.label}</p>
          </motion.div>
        ))}
      </div>

      {/* 标签页导航 */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8">
          {[
            { key: 'overview', label: '概览', icon: BarChart3 },
            { key: 'achievements', label: '成就', icon: Trophy },
            { key: 'activities', label: '动态', icon: Activity },
            { key: 'analytics', label: '分析', icon: PieChart }
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as 'overview' | 'achievements' | 'activities' | 'analytics')}
              className={`flex items-center gap-2 py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === tab.key
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* 标签页内容 */}
      <AnimatePresence mode="wait">
        {activeTab === 'overview' && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            className="space-y-6"
          >
            {/* 最近活动 */}
            <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-800">最近活动</h3>
                <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                  查看全部
                </button>
              </div>
              
              <div className="space-y-3">
                {recentActivities.slice(0, 5).map((activity, index) => (
                  <motion.div
                    key={activity.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-start gap-3 p-3 rounded-lg hover:bg-gray-50 transition-colors"
                  >
                    <div className="flex-shrink-0 w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-600">
                      {getActivityIcon(activity.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-800">{activity.title}</p>
                      <p className="text-sm text-gray-600">{activity.description}</p>
                      <p className="text-xs text-gray-500 mt-1">{formatTimeAgo(activity.timestamp)}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* 快速操作 */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: '添加标注', icon: Plus, action: () => toast.info('跳转到地图页面') },
                { label: '查看地图', icon: MapPin, action: () => toast.info('跳转到地图页面') },
                { label: '分享成就', icon: Share2, action: () => toast.info('分享功能开发中') },
                { label: '设置', icon: Settings, action: () => toast.info('跳转到设置页面') }
              ].map((action, _index) => (
                <MicroInteraction key={action.label} type="hover">
                  <button
                    onClick={action.action}
                    className="flex flex-col items-center gap-2 p-4 bg-white rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
                  >
                    <action.icon className="w-6 h-6 text-gray-600" />
                    <span className="text-sm font-medium text-gray-700">{action.label}</span>
                  </button>
                </MicroInteraction>
              ))}
            </div>
          </motion.div>
        )}

        {activeTab === 'achievements' && (
          <motion.div
            key="achievements"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            className="space-y-6"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-800">
                成就收集 ({achievements.filter(a => !a.progress).length}/{achievements.length})
              </h3>
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-gray-500" />
                <select className="text-sm border border-gray-300 rounded-md px-2 py-1">
                  <option value="all">全部成就</option>
                  <option value="unlocked">已解锁</option>
                  <option value="locked">未解锁</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {achievements.map((achievement, index) => (
                <motion.div
                  key={achievement.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className={`p-4 rounded-lg border-2 cursor-pointer transition-all hover:shadow-md ${
                    getRarityColor(achievement.rarity)
                  } ${achievement.progress ? 'opacity-60' : ''}`}
                  onClick={() => setShowAchievementDetails(achievement)}
                >
                  <div className="flex items-start gap-3">
                    <div className="text-3xl">{achievement.icon}</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">{achievement.title}</h4>
                      <p className="text-sm opacity-80 mt-1">{achievement.description}</p>
                      
                      {achievement.progress ? (
                        <div className="mt-3">
                          <div className="flex justify-between text-xs mb-1">
                            <span>进度</span>
                            <span>{achievement.progress.current}/{achievement.progress.total}</span>
                          </div>
                          <div className="w-full bg-white/50 rounded-full h-2">
                            <div
                              className="bg-current h-2 rounded-full transition-all"
                              style={{ width: `${(achievement.progress.current / achievement.progress.total) * 100}%` }}
                            />
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 mt-2 text-xs">
                          <CalendarIcon className="w-3 h-3" />
                          <span>{achievement.unlockedAt.toLocaleDateString()}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

        {activeTab === 'activities' && (
          <motion.div
            key="activities"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            className="space-y-6"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-800">活动历史</h3>
              <div className="flex items-center gap-2">
                <select 
                  value={timeRange}
                  onChange={(e) => setTimeRange(e.target.value as 'week' | 'month' | 'year')}
                  className="text-sm border border-gray-300 rounded-md px-2 py-1"
                >
                  <option value="week">本周</option>
                  <option value="month">本月</option>
                  <option value="year">本年</option>
                </select>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200">
              {recentActivities.length > 0 ? (
                <div className="divide-y divide-gray-200">
                  {recentActivities.map((activity, index) => (
                    <motion.div
                      key={activity.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="p-4 hover:bg-gray-50 transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <div className="flex-shrink-0 w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center text-blue-600">
                          {getActivityIcon(activity.type)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-start justify-between">
                            <div>
                              <p className="font-medium text-gray-800">{activity.title}</p>
                              <p className="text-gray-600 text-sm mt-1">{activity.description}</p>
                            </div>
                            <span className="text-xs text-gray-500 whitespace-nowrap ml-4">
                              {formatTimeAgo(activity.timestamp)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              ) : (
                <div className="p-8">
                  <EmptyState
                    type="no-data"
                    title="暂无活动记录"
                    description="开始探索气味世界，记录你的第一个标注吧！"
                  />
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'analytics' && (
          <motion.div
            key="analytics"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            className="space-y-6"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* 活跃度图表 */}
              <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
                <h4 className="font-semibold text-gray-800 mb-4">活跃度趋势</h4>
                <div className="h-40 bg-gray-50 rounded-lg flex items-center justify-center">
                  <div className="text-center text-gray-500">
                    <BarChart3 className="w-8 h-8 mx-auto mb-2" />
                    <p className="text-sm">图表功能开发中</p>
                  </div>
                </div>
              </div>

              {/* 分类分布 */}
              <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
                <h4 className="font-semibold text-gray-800 mb-4">标注分类分布</h4>
                <div className="h-40 bg-gray-50 rounded-lg flex items-center justify-center">
                  <div className="text-center text-gray-500">
                    <PieChart className="w-8 h-8 mx-auto mb-2" />
                    <p className="text-sm">图表功能开发中</p>
                  </div>
                </div>
              </div>
            </div>

            {/* 数据导出 */}
            <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h4 className="font-semibold text-gray-800">数据导出</h4>
                <LoadingButton
                  onClick={() => toast.info('导出功能开发中')}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  导出数据
                </LoadingButton>
              </div>
              <p className="text-gray-600 text-sm">
                导出你的所有标注数据、统计信息和成就记录，支持JSON和CSV格式。
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 成就详情弹窗 */}
      <AnimatePresence>
        {showAchievementDetails && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
            onClick={() => setShowAchievementDetails(null)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white rounded-xl p-6 max-w-md w-full"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="text-center">
                <div className="text-6xl mb-4">{showAchievementDetails.icon}</div>
                <h3 className="text-xl font-bold text-gray-800 mb-2">
                  {showAchievementDetails.title}
                </h3>
                <p className="text-gray-600 mb-4">{showAchievementDetails.description}</p>
                
                <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
                  getRarityColor(showAchievementDetails.rarity)
                }`}>
                  {showAchievementDetails.rarity === 'common' && '普通'}
                  {showAchievementDetails.rarity === 'rare' && '稀有'}
                  {showAchievementDetails.rarity === 'epic' && '史诗'}
                  {showAchievementDetails.rarity === 'legendary' && '传说'}
                </div>
                
                {showAchievementDetails.progress ? (
                  <div className="mt-4">
                    <div className="flex justify-between text-sm mb-2">
                      <span>完成进度</span>
                      <span>{showAchievementDetails.progress.current}/{showAchievementDetails.progress.total}</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-3">
                      <div
                        className="bg-blue-500 h-3 rounded-full transition-all"
                        style={{ width: `${(showAchievementDetails.progress.current / showAchievementDetails.progress.total) * 100}%` }}
                      />
                    </div>
                  </div>
                ) : (
                  <div className="mt-4 text-sm text-gray-500">
                    解锁时间：{showAchievementDetails.unlockedAt.toLocaleDateString()}
                  </div>
                )}
                
                <button
                  onClick={() => setShowAchievementDetails(null)}
                  className="mt-6 w-full py-2 px-4 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors"
                >
                  关闭
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 网络状态提示 */}
      {!isOnline && (
        <div className="fixed bottom-4 left-4 right-4 bg-yellow-100 border border-yellow-300 rounded-lg p-3 z-40">
          <p className="text-yellow-800 text-sm text-center">
            网络连接断开，部分功能可能受限
          </p>
        </div>
      )}
    </div>
  );
};

export default UserDashboard;