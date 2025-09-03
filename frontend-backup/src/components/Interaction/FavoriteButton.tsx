import React, { useState, useEffect, useCallback } from 'react';
import { Button, Space, Tooltip, Typography } from 'antd';
import { Star, Loader2 } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import interactionApi, { FavoriteType } from '../../services/interactionApi';

const { Text } = Typography;

interface FavoriteButtonProps {
  targetId: string;
  targetType: FavoriteType;
  size?: 'small' | 'middle' | 'large';
  showCount?: boolean;
  showText?: boolean;
  style?: React.CSSProperties;
  className?: string;
  onFavoriteChange?: (isFavorited: boolean, favoriteCount: number) => void;
}

const FavoriteButton: React.FC<FavoriteButtonProps> = ({
  targetId,
  targetType,
  size = 'middle',
  showCount = true,
  showText = false,
  style,
  className,
  onFavoriteChange
}) => {
  const { isAuthenticated } = useAuthStore();
  const [isFavorited, setIsFavorited] = useState(false);
  const [favoriteCount, setFavoriteCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);

  // 获取互动统计
  const fetchStats = useCallback(async () => {
    try {
      const stats = await interactionApi.getInteractionStats(targetId, targetType);
      setIsFavorited(stats.isFavorited);
      setFavoriteCount(stats.favoriteCount);
    } catch (error) {
      console.error('获取收藏状态失败:', error);
    } finally {
      setInitialLoading(false);
    }
  }, [targetId, targetType]);

  // 处理收藏/取消收藏
  const handleFavorite = async () => {
    if (!isAuthenticated) {
      // 可以在这里触发登录模态框
      return;
    }

    if (loading) return;

    setLoading(true);
    try {
      if (isFavorited) {
        await interactionApi.unfavoriteTarget(targetId, targetType);
        setIsFavorited(false);
        setFavoriteCount(prev => prev - 1);
        onFavoriteChange?.(false, favoriteCount - 1);
      } else {
        await interactionApi.favoriteTarget(targetId, targetType);
        setIsFavorited(true);
        setFavoriteCount(prev => prev + 1);
        onFavoriteChange?.(true, favoriteCount + 1);
      }
    } catch (error) {
      console.error('收藏操作失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  // 获取按钮文本
  const getButtonText = () => {
    if (!showText) return null;
    return isFavorited ? '已收藏' : '收藏';
  };

  // 获取工具提示文本
  const getTooltipText = () => {
    if (!isAuthenticated) {
      return '请先登录';
    }
    return isFavorited ? '取消收藏' : '收藏';
  };

  if (initialLoading) {
    return (
      <Button
        size={size}
        icon={<Loader2 size={16} className="animate-spin" />}
        style={style}
        className={className}
        disabled
      >
        {showText && '加载中'}
        {showCount && <Text type="secondary">--</Text>}
      </Button>
    );
  }

  return (
    <Tooltip title={getTooltipText()}>
      <Button
        type={isFavorited ? 'primary' : 'default'}
        size={size}
        icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Star size={16} fill={isFavorited ? 'currentColor' : 'none'} />}
        onClick={handleFavorite}
        style={{
          color: isFavorited ? '#faad14' : undefined,
          borderColor: isFavorited ? '#faad14' : undefined,
          ...style
        }}
        className={className}
        disabled={loading}
      >
        <Space size={4}>
          {getButtonText()}
          {showCount && (
            <Text 
              type={isFavorited ? undefined : 'secondary'}
              style={{ color: isFavorited ? 'inherit' : undefined }}
            >
              {interactionApi.formatCount(favoriteCount)}
            </Text>
          )}
        </Space>
      </Button>
    </Tooltip>
  );
};

export default FavoriteButton;