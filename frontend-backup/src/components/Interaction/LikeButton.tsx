import React, { useState, useEffect, useCallback } from 'react';
import { Button, Space, Tooltip, Typography } from 'antd';
import { Heart, Loader2 } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import interactionApi, { LikeType } from '../../services/interactionApi';

const { Text } = Typography;

interface LikeButtonProps {
  targetId: string;
  targetType: LikeType;
  size?: 'small' | 'middle' | 'large';
  showCount?: boolean;
  showText?: boolean;
  style?: React.CSSProperties;
  className?: string;
  onLikeChange?: (isLiked: boolean, likeCount: number) => void;
}

const LikeButton: React.FC<LikeButtonProps> = ({
  targetId,
  targetType,
  size = 'middle',
  showCount = true,
  showText = false,
  style,
  className,
  onLikeChange
}) => {
  const { isAuthenticated } = useAuthStore();
  const [isLiked, setIsLiked] = useState(false);
  const [likeCount, setLikeCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);

  // 获取互动统计
  const fetchStats = useCallback(async () => {
    try {
      const stats = await interactionApi.getInteractionStats(targetId, targetType);
      setIsLiked(stats.isLiked);
      setLikeCount(stats.likeCount);
    } catch (error) {
      console.error('获取点赞状态失败:', error);
    } finally {
      setInitialLoading(false);
    }
  }, [targetId, targetType]);

  // 处理点赞/取消点赞
  const handleLike = async () => {
    if (!isAuthenticated) {
      // 可以在这里触发登录模态框
      return;
    }

    if (loading) return;

    setLoading(true);
    try {
      if (isLiked) {
        await interactionApi.unlikeTarget(targetId, targetType);
        setIsLiked(false);
        setLikeCount(prev => prev - 1);
        onLikeChange?.(false, likeCount - 1);
      } else {
        await interactionApi.likeTarget(targetId, targetType);
        setIsLiked(true);
        setLikeCount(prev => prev + 1);
        onLikeChange?.(true, likeCount + 1);
      }
    } catch (error) {
      console.error('点赞操作失败:', error);
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
    return isLiked ? '已点赞' : '点赞';
  };

  // 获取工具提示文本
  const getTooltipText = () => {
    if (!isAuthenticated) {
      return '请先登录';
    }
    return isLiked ? '取消点赞' : '点赞';
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
        type={isLiked ? 'primary' : 'default'}
        size={size}
        icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Heart size={16} fill={isLiked ? 'currentColor' : 'none'} />}
        onClick={handleLike}
        style={{
          color: isLiked ? '#ff4d4f' : undefined,
          borderColor: isLiked ? '#ff4d4f' : undefined,
          ...style
        }}
        className={className}
        disabled={loading}
      >
        <Space size={4}>
          {getButtonText()}
          {showCount && (
            <Text 
              type={isLiked ? undefined : 'secondary'}
              style={{ color: isLiked ? 'inherit' : undefined }}
            >
              {interactionApi.formatCount(likeCount)}
            </Text>
          )}
        </Space>
      </Button>
    </Tooltip>
  );
};

export default LikeButton;