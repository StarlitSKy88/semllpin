import { Avatar, Button, Card, Empty, Rate, Space, Spin, Tag, Typography } from 'antd';

import React, { useState, useMemo } from 'react';

import { 
  Flame, 
  Eye, 
  Heart, 
  MessageCircle,
  Trophy,
  Clock,
  MapPin
} from 'lucide-react';
// import { useSelector } from 'react-redux'; // removed as unused
// import type { RootState } from '../../store'; // removed as unused

const { Text } = Typography; // Title removed as unused

interface Annotation {
  id: string;
  latitude: number;
  longitude: number;
  smell_intensity: number;
  description?: string;
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
  likes_count: number;
  views_count: number;
  created_at: string;
  media_files?: string[];
  comments_count?: number;
  category?: string;
}

interface ContentRecommendationProps {
  annotations: Annotation[];
  userLocation?: [number, number];
  onAnnotationSelect?: (annotation: Annotation) => void;
  visible?: boolean;
}

// 计算两点间距离（简化版）
const calculateDistance = (lat1: number, lon1: number, lat2: number, lon2: number): number => {
  const R = 6371; // 地球半径（公里）
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
};

// 推荐算法
const getRecommendations = (
  annotations: Annotation[], 
  userLocation?: [number, number]
): {
  trending: Annotation[];
  nearby: Annotation[];
  topRated: Annotation[];
  recent: Annotation[];
} => {
  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  // 热门内容（基于浏览量和点赞数）
  const trending = [...annotations]
    .filter(a => new Date(a.created_at) > oneWeekAgo)
    .sort((a, b) => {
      const scoreA = a.views_count * 0.3 + a.likes_count * 0.7;
      const scoreB = b.views_count * 0.3 + b.likes_count * 0.7;
      return scoreB - scoreA;
    })
    .slice(0, 5);

  // 附近内容
  const nearby = userLocation ? [...annotations]
    .map(a => ({
      ...a,
      distance: calculateDistance(userLocation[0], userLocation[1], a.latitude, a.longitude)
    }))
    .filter(a => a.distance <= 5) // 5公里内
    .sort((a, b) => a.distance - b.distance)
    .slice(0, 5) : [];

  // 高评分内容
  const topRated = [...annotations]
    .filter(a => a.likes_count > 0)
    .sort((a, b) => {
      const ratingA = a.smell_intensity + (a.likes_count / Math.max(a.views_count, 1)) * 5;
      const ratingB = b.smell_intensity + (b.likes_count / Math.max(b.views_count, 1)) * 5;
      return ratingB - ratingA;
    })
    .slice(0, 5);

  // 最新内容
  const recent = [...annotations]
    .filter(a => new Date(a.created_at) > oneDayAgo)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  return { trending, nearby, topRated, recent };
};

const ContentRecommendation: React.FC<ContentRecommendationProps> = ({
  annotations,
  userLocation,
  onAnnotationSelect,
  visible = true
}) => {
  const [activeTab, setActiveTab] = useState<'trending' | 'nearby' | 'topRated' | 'recent'>('trending');
  const [loading] = useState(false); // setLoading removed as unused
  // const { user } = useSelector((state: RootState) => state.auth); // removed as unused

  const recommendations = useMemo(() => {
    return getRecommendations(annotations, userLocation);
  }, [annotations, userLocation]);

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return '刚刚';
    if (diffInHours < 24) return `${diffInHours}小时前`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}天前`;
    return date.toLocaleDateString('zh-CN');
  };

  const formatDistance = (distance: number) => {
    if (distance < 1) return `${Math.round(distance * 1000)}m`;
    return `${distance.toFixed(1)}km`;
  };

  const renderAnnotationCard = (annotation: Annotation, showDistance = false) => {
    const distance = userLocation ? calculateDistance(
      userLocation[0], userLocation[1], 
      annotation.latitude, annotation.longitude
    ) : 0;

    return (
      <Card 
        key={annotation.id}
        size="small" 
        className="mb-3 hover:shadow-md transition-shadow cursor-pointer"
        onClick={() => onAnnotationSelect?.(annotation)}
        bodyStyle={{ padding: '12px' }}
      >
        <div className="space-y-2">
          {/* 用户信息 */}
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Avatar 
                size="small" 
                src={annotation.user.avatar}
                className="bg-primary-500"
              >
                {annotation.user.username[0]?.toUpperCase()}
              </Avatar>
              <div>
                <Text strong className="text-sm">{annotation.user.username}</Text>
                <div className="text-xs text-gray-500">
                  {formatTimeAgo(annotation.created_at)}
                </div>
              </div>
            </div>
            {showDistance && userLocation && (
              <Tag icon={<MapPin size={12} />} color="blue" className="text-xs">
                {formatDistance(distance)}
              </Tag>
            )}
          </div>

          {/* 臭味强度 */}
          <div className="flex items-center space-x-2">
            <Rate 
              disabled 
              value={annotation.smell_intensity} 
              count={10} 
              className="text-xs"
            />
            <Tag 
              color={annotation.smell_intensity >= 8 ? 'red' : 
                     annotation.smell_intensity >= 5 ? 'orange' : 'green'}
              className="text-xs"
            >
              {annotation.smell_intensity}/10
            </Tag>
          </div>

          {/* 描述 */}
          {annotation.description && (
            <Text className="text-sm text-gray-700 line-clamp-2">
              {annotation.description}
            </Text>
          )}

          {/* 分类 */}
          {annotation.category && (
            <Tag className="text-xs">{annotation.category}</Tag>
          )}

          {/* 统计信息 */}
          <div className="flex items-center justify-between text-xs text-gray-500">
            <Space size={8}>
              <span className="flex items-center space-x-1">
                <Eye size={12} />
                <span>{annotation.views_count}</span>
              </span>
              <span className="flex items-center space-x-1">
                <Heart size={12} />
                <span>{annotation.likes_count}</span>
              </span>
              {annotation.comments_count !== undefined && (
                <span className="flex items-center space-x-1">
                  <MessageCircle size={12} />
                  <span>{annotation.comments_count}</span>
                </span>
              )}
            </Space>
          </div>
        </div>
      </Card>
    );
  };

  const getCurrentData = () => {
    switch (activeTab) {
      case 'trending':
        return recommendations.trending;
      case 'nearby':
        return recommendations.nearby;
      case 'topRated':
        return recommendations.topRated;
      case 'recent':
        return recommendations.recent;
      default:
        return [];
    }
  };

  const getTabTitle = () => {
    switch (activeTab) {
      case 'trending':
        return '🔥 热门推荐';
      case 'nearby':
        return '📍 附近内容';
      case 'topRated':
        return '⭐ 高评分';
      case 'recent':
        return '🕒 最新发布';
      default:
        return '';
    }
  };

  if (!visible) return null;

  return (
    <div className="w-80">
      <Card 
        title={getTabTitle()}
        size="small"
        className="h-full"
        bodyStyle={{ padding: '12px', maxHeight: '500px', overflowY: 'auto' }}
        extra={
          <Space>
            <Button 
              size="small" 
              type={activeTab === 'trending' ? 'primary' : 'text'}
              icon={<Flame size={14} />}
              onClick={() => setActiveTab('trending')}
            />
            {userLocation && (
              <Button 
                size="small" 
                type={activeTab === 'nearby' ? 'primary' : 'text'}
                icon={<MapPin size={14} />}
                onClick={() => setActiveTab('nearby')}
              />
            )}
            <Button 
              size="small" 
              type={activeTab === 'topRated' ? 'primary' : 'text'}
              icon={<Trophy size={14} />}
              onClick={() => setActiveTab('topRated')}
            />
            <Button 
              size="small" 
              type={activeTab === 'recent' ? 'primary' : 'text'}
              icon={<Clock size={14} />}
              onClick={() => setActiveTab('recent')}
            />
          </Space>
        }
      >
        {loading ? (
          <div className="text-center py-8">
            <Spin size="large" />
          </div>
        ) : (
          <div>
            {getCurrentData().length > 0 ? (
              getCurrentData().map(annotation => 
                renderAnnotationCard(annotation, activeTab === 'nearby')
              )
            ) : (
              <Empty 
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description={
                  activeTab === 'nearby' && !userLocation 
                    ? '需要位置权限才能显示附近内容'
                    : '暂无相关内容'
                }
                className="py-8"
              />
            )}
          </div>
        )}
      </Card>
    </div>
  );
};

export default ContentRecommendation;