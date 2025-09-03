import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  MapPin,
  Star,
  Award,
  Calendar as CalendarIcon,
  Edit3,
  Camera,
  Settings,
  Share2,
  Heart,
  MessageCircle,
  TrendingUp
} from 'lucide-react';
import { LazyImage } from './LazyImage';
import { MicroInteraction, LoadingButton } from './InteractionFeedback';
// import { useMobile } from './MobileOptimization'; // 暂时注释掉，因为未使用
import EmptyState from './EmptyState';

interface UserStats {
  totalPins: number;
  totalLikes: number;
  totalComments: number;
  joinDate: Date;
  level: number;
  points: number;
  badges: string[];
}

interface UserActivity {
  id: string;
  type: 'pin' | 'like' | 'comment' | 'badge';
  title: string;
  description: string;
  timestamp: Date;
  location?: string;
  image?: string;
}

interface UserProfileProps {
  userId?: string;
  isOwnProfile?: boolean;
  onEdit?: () => void;
  onShare?: () => void;
}

const UserProfile: React.FC<UserProfileProps> = ({
  userId,
  isOwnProfile = false,
  onEdit,
  onShare
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'activity' | 'achievements'>('overview');
  const [isLoading, setIsLoading] = useState(false);
  // const { isMobile } = useMobile(); // 暂时注释掉，因为未使用

  // 模拟用户数据
  const userData = {
    id: userId || '1',
    name: '张小明',
    username: '@zhangxiaoming',
    bio: '热爱探索城市中的各种气味，分享生活中的美好发现。喜欢咖啡香气和花香。',
    avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=friendly%20asian%20person%20avatar%20profile%20photo%20smiling&image_size=square',
    coverImage: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=beautiful%20city%20landscape%20with%20flowers%20and%20coffee%20shops&image_size=landscape_16_9',
    location: '北京市朝阳区',
    website: 'https://example.com',
    isVerified: true,
    isFollowing: false
  };

  const userStats: UserStats = {
    totalPins: 156,
    totalLikes: 2340,
    totalComments: 890,
    joinDate: new Date('2023-01-15'),
    level: 8,
    points: 12450,
    badges: ['探索者', '咖啡爱好者', '摄影师', '活跃用户']
  };

  const recentActivity: UserActivity[] = [
    {
      id: '1',
      type: 'pin',
      title: '发现了新的咖啡店',
      description: '这家咖啡店的烘焙香气真的很棒！',
      timestamp: new Date(Date.now() - 3600000),
      location: '三里屯咖啡街',
      image: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=cozy%20coffee%20shop%20interior%20with%20warm%20lighting&image_size=square'
    },
    {
      id: '2',
      type: 'badge',
      title: '获得新徽章',
      description: '恭喜获得"咖啡爱好者"徽章！',
      timestamp: new Date(Date.now() - 7200000)
    },
    {
      id: '3',
      type: 'like',
      title: '点赞了气味标注',
      description: '"春天的花香"',
      timestamp: new Date(Date.now() - 10800000),
      location: '中央公园'
    }
  ];

  const handleFollow = async () => {
    setIsLoading(true);
    // 模拟API调用
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsLoading(false);
  };

  const getActivityIcon = (type: UserActivity['type']) => {
    switch (type) {
      case 'pin': return <MapPin className="w-4 h-4 text-blue-500" />;
      case 'like': return <Heart className="w-4 h-4 text-red-500" />;
      case 'comment': return <MessageCircle className="w-4 h-4 text-green-500" />;
      case 'badge': return <Award className="w-4 h-4 text-yellow-500" />;
      default: return <Star className="w-4 h-4 text-gray-500" />;
    }
  };

  const formatDate = (date: Date) => {
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    }).format(date);
  };

  const formatRelativeTime = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) return '刚刚';
    if (hours < 24) return `${hours}小时前`;
    return `${Math.floor(hours / 24)}天前`;
  };

  return (
    <div className="max-w-4xl mx-auto bg-white rounded-xl shadow-lg overflow-hidden">
      {/* 封面图片 */}
      <div className="relative h-48 md:h-64">
        <LazyImage
          src={userData.coverImage}
          alt="用户封面"
          className="w-full h-full object-cover"
        />
        <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent" />
        
        {/* 操作按钮 */}
        <div className="absolute top-4 right-4 flex gap-2">
          {isOwnProfile ? (
            <>
              <MicroInteraction type="hover">
                <button
                  onClick={onEdit}
                  className="p-2 bg-white/90 hover:bg-white rounded-full transition-colors"
                  aria-label="编辑资料"
                >
                  <Edit3 className="w-4 h-4 text-gray-700" />
                </button>
              </MicroInteraction>
              <MicroInteraction type="hover">
                <button
                  className="p-2 bg-white/90 hover:bg-white rounded-full transition-colors"
                  aria-label="设置"
                >
                  <Settings className="w-4 h-4 text-gray-700" />
                </button>
              </MicroInteraction>
            </>
          ) : (
            <MicroInteraction type="hover">
              <button
                onClick={onShare}
                className="p-2 bg-white/90 hover:bg-white rounded-full transition-colors"
                aria-label="分享用户"
              >
                <Share2 className="w-4 h-4 text-gray-700" />
              </button>
            </MicroInteraction>
          )}
        </div>
      </div>

      {/* 用户信息 */}
      <div className="relative px-6 pb-6">
        {/* 头像 */}
        <div className="relative -mt-16 mb-4">
          <div className="relative inline-block">
            <LazyImage
              src={userData.avatar}
              alt={userData.name}
              className="w-32 h-32 rounded-full border-4 border-white shadow-lg"
            />
            {userData.isVerified && (
              <div className="absolute bottom-2 right-2 w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center border-2 border-white">
                <Star className="w-4 h-4 text-white fill-current" />
              </div>
            )}
            {isOwnProfile && (
              <button className="absolute bottom-0 right-0 w-8 h-8 bg-gray-800 rounded-full flex items-center justify-center border-2 border-white hover:bg-gray-700 transition-colors">
                <Camera className="w-4 h-4 text-white" />
              </button>
            )}
          </div>
        </div>

        {/* 基本信息 */}
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-2">
            <h1 className="text-2xl font-bold text-gray-800">{userData.name}</h1>
            {userData.isVerified && (
              <div className="w-5 h-5 bg-blue-500 rounded-full flex items-center justify-center">
                <Star className="w-3 h-3 text-white fill-current" />
              </div>
            )}
          </div>
          <p className="text-gray-600 mb-2">{userData.username}</p>
          <p className="text-gray-700 mb-4">{userData.bio}</p>
          
          <div className="flex flex-wrap items-center gap-4 text-sm text-gray-600">
            <div className="flex items-center gap-1">
              <MapPin className="w-4 h-4" />
              <span>{userData.location}</span>
            </div>
            <div className="flex items-center gap-1">
              <CalendarIcon className="w-4 h-4" />
              <span>加入于 {formatDate(userStats.joinDate)}</span>
            </div>
            <div className="flex items-center gap-1">
              <TrendingUp className="w-4 h-4" />
              <span>等级 {userStats.level}</span>
            </div>
          </div>
        </div>

        {/* 操作按钮 */}
        {!isOwnProfile && (
          <div className="flex gap-3 mb-6">
            <LoadingButton
              onClick={handleFollow}
              loading={isLoading}
              className="flex-1 bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-lg transition-colors"
            >
              {userData.isFollowing ? '已关注' : '关注'}
            </LoadingButton>
            <button className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors">
              发消息
            </button>
          </div>
        )}

        {/* 统计数据 */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <div className="text-2xl font-bold text-gray-800">{userStats.totalPins}</div>
            <div className="text-sm text-gray-600">标注</div>
          </div>
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <div className="text-2xl font-bold text-gray-800">{userStats.totalLikes}</div>
            <div className="text-sm text-gray-600">获赞</div>
          </div>
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <div className="text-2xl font-bold text-gray-800">{userStats.totalComments}</div>
            <div className="text-sm text-gray-600">评论</div>
          </div>
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <div className="text-2xl font-bold text-gray-800">{userStats.points}</div>
            <div className="text-sm text-gray-600">积分</div>
          </div>
        </div>

        {/* 标签页 */}
        <div className="border-b border-gray-200 mb-6">
          <nav className="flex space-x-8">
            {[
              { key: 'overview', label: '概览' },
              { key: 'activity', label: '动态' },
              { key: 'achievements', label: '成就' }
            ].map(tab => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as 'overview' | 'activity' | 'achievements')}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.key
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* 标签页内容 */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* 最近活动 */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-800 mb-4">最近活动</h3>
                  {recentActivity.length > 0 ? (
                    <div className="space-y-3">
                      {recentActivity.slice(0, 3).map(activity => (
                        <div key={activity.id} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                          {getActivityIcon(activity.type)}
                          <div className="flex-1 min-w-0">
                            <p className="font-medium text-gray-800">{activity.title}</p>
                            <p className="text-sm text-gray-600">{activity.description}</p>
                            {activity.location && (
                              <p className="text-xs text-gray-500 mt-1">{activity.location}</p>
                            )}
                            <p className="text-xs text-gray-400 mt-1">
                              {formatRelativeTime(activity.timestamp)}
                            </p>
                          </div>
                          {activity.image && (
                            <LazyImage
                              src={activity.image}
                              alt="活动图片"
                              className="w-12 h-12 rounded-lg object-cover"
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      type="no-data"
                      title="暂无活动"
                      description="用户还没有任何活动记录"
                    />
                  )}
                </div>
              </div>
            )}

            {activeTab === 'activity' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-800 mb-4">全部活动</h3>
                {recentActivity.length > 0 ? (
                  <div className="space-y-3">
                    {recentActivity.map(activity => (
                      <motion.div
                        key={activity.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="flex items-start gap-3 p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                      >
                        {getActivityIcon(activity.type)}
                        <div className="flex-1 min-w-0">
                          <p className="font-medium text-gray-800">{activity.title}</p>
                          <p className="text-sm text-gray-600">{activity.description}</p>
                          {activity.location && (
                            <p className="text-xs text-gray-500 mt-1">{activity.location}</p>
                          )}
                          <p className="text-xs text-gray-400 mt-1">
                            {formatRelativeTime(activity.timestamp)}
                          </p>
                        </div>
                        {activity.image && (
                          <LazyImage
                            src={activity.image}
                            alt="活动图片"
                            className="w-16 h-16 rounded-lg object-cover"
                          />
                        )}
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    type="no-data"
                    title="暂无活动"
                    description="用户还没有任何活动记录"
                  />
                )}
              </div>
            )}

            {activeTab === 'achievements' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-800 mb-4">成就徽章</h3>
                {userStats.badges.length > 0 ? (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    {userStats.badges.map((badge, index) => (
                      <motion.div
                        key={badge}
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: index * 0.1 }}
                        className="p-4 bg-gradient-to-br from-yellow-50 to-orange-50 border border-yellow-200 rounded-lg text-center"
                      >
                        <Award className="w-8 h-8 text-yellow-600 mx-auto mb-2" />
                        <p className="font-medium text-gray-800">{badge}</p>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    type="no-data"
                    title="暂无徽章"
                    description="继续活跃来获得更多成就徽章吧！"
                  />
                )}
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
};

export default UserProfile;