import React, { useState, useEffect } from 'react';
import { Button, message } from 'antd';
import { UserPlus, UserMinus, Loader2 } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

import { followUser, unfollowUser, checkFollowStatus } from '../../utils/api';

interface FollowButtonProps {
  userId: string;
  size?: 'small' | 'middle' | 'large';
  type?: 'primary' | 'default' | 'text' | 'link';
  block?: boolean;
  onFollowChange?: (userId: string, isFollowing: boolean) => void;
  className?: string;
}

const FollowButton: React.FC<FollowButtonProps> = ({
  userId,
  size = 'middle',
  type = 'primary',
  block = false,
  onFollowChange,
  className
}) => {
  const [loading, setLoading] = useState(false);
  const [isFollowing, setIsFollowing] = useState(false);
  const [statusLoading, setStatusLoading] = useState(true);
  const { user: currentUser } = useAuthStore();

  // 检查关注状态
  useEffect(() => {
    const fetchFollowStatus = async () => {
      if (!currentUser || currentUser.id === userId) {
        setStatusLoading(false);
        return;
      }

      try {
        const response = await checkFollowStatus(userId);
        setIsFollowing(response.isFollowing);
      } catch (error) {
        console.error('获取关注状态失败:', error);
      } finally {
        setStatusLoading(false);
      }
    };

    fetchFollowStatus();
  }, [userId, currentUser]);

  const handleFollowToggle = async () => {
    if (!currentUser) {
      message.warning('请先登录');
      return;
    }

    if (currentUser.id === userId) {
      message.warning('不能关注自己');
      return;
    }

    setLoading(true);
    try {
      if (isFollowing) {
        await unfollowUser(userId);
        message.success('已取消关注');
        setIsFollowing(false);
        onFollowChange?.(userId, false);
      } else {
        await followUser(userId);
        message.success('关注成功');
        setIsFollowing(true);
        onFollowChange?.(userId, true);
      }
    } catch (error: unknown) {
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as Error & { response?: { data?: { error?: string } } }).response?.data?.error || '操作失败'
        : '操作失败';
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // 如果是自己，不显示按钮
  if (!currentUser || currentUser.id === userId) {
    return null;
  }

  // 如果正在加载状态，显示加载按钮
  if (statusLoading) {
    return (
      <Button
        size={size}
        type="default"
        block={block}
        className={className}
        icon={<Loader2 size={16} className="animate-spin" />}
        disabled
      >
        加载中...
      </Button>
    );
  }

  return (
    <Button
      size={size}
      type={isFollowing ? 'default' : type}
      block={block}
      className={className}
      icon={isFollowing ? <UserMinus size={16} /> : <UserPlus size={16} />}
      loading={loading}
      onClick={handleFollowToggle}
    >
      {isFollowing ? '取消关注' : '关注'}
    </Button>
  );
};

export default FollowButton;