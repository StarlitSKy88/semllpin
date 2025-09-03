import React, { useState } from 'react';
import { Avatar, Button, Card, Space, Typography, message } from 'antd';;
import { UserOutlined, UserAddOutlined, UserDeleteOutlined } from '@ant-design/icons';
import { useAuthStore } from '../../stores/authStore';

import { followUser, unfollowUser } from '../../utils/api';

const { Text, Title } = Typography;

interface User {
  id: string;
  username: string;
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  followers_count: number;
  following_count: number;
  followed_at?: string;
}

interface UserCardProps {
  user: User;
  showFollowButton?: boolean;
  isFollowing?: boolean;
  onFollowChange?: (userId: string, isFollowing: boolean) => void;
  size?: 'small' | 'default' | 'large';
}

const UserCard: React.FC<UserCardProps> = ({
  user,
  showFollowButton = true,
  isFollowing = false,
  onFollowChange,
  size = 'default'
}) => {
  const [loading, setLoading] = useState(false);
  const [followState, setFollowState] = useState(isFollowing);
  const { user: currentUser } = useAuthStore();

  const handleFollowToggle = async () => {
    if (!currentUser) {
      message.warning('请先登录');
      return;
    }

    if (currentUser.id === user.id) {
      message.warning('不能关注自己');
      return;
    }

    setLoading(true);
    try {
      if (followState) {
        await unfollowUser(user.id);
        message.success('已取消关注');
        setFollowState(false);
        onFollowChange?.(user.id, false);
      } else {
        await followUser(user.id);
        message.success('关注成功');
        setFollowState(true);
        onFollowChange?.(user.id, true);
      }
    } catch (error: unknown) {
      const errorWithResponse = error as {
        response?: {
          data?: {
            error?: string;
          };
        };
      };
      const errorMessage = errorWithResponse.response?.data?.error || '操作失败';
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const cardSize = {
    small: { bodyStyle: { padding: '12px' } },
    default: { bodyStyle: { padding: '16px' } },
    large: { bodyStyle: { padding: '24px' } }
  }[size];

  const avatarSize = {
    small: 40,
    default: 64,
    large: 80
  }[size];

  return (
    <Card
      {...cardSize}
      hoverable
      className="user-card"
      actions={showFollowButton && currentUser?.id !== user.id ? [
        <Button
          key="follow"
          type={followState ? 'default' : 'primary'}
          icon={followState ? <UserDeleteOutlined /> : <UserAddOutlined />}
          loading={loading}
          onClick={handleFollowToggle}
          size={size === 'small' ? 'small' : 'middle'}
        >
          {followState ? '取消关注' : '关注'}
        </Button>
      ] : undefined}
    >
      <Card.Meta
        avatar={
          <Avatar
            size={avatarSize}
            src={user.avatar_url}
            icon={<UserOutlined />}
          />
        }
        title={
          <Space direction="vertical" size={0}>
            <Title level={size === 'small' ? 5 : 4} style={{ margin: 0 }}>
              {user.display_name || user.username}
            </Title>
            {user.display_name && (
              <Text type="secondary" style={{ fontSize: '12px' }}>
                @{user.username}
              </Text>
            )}
          </Space>
        }
        description={
          <Space direction="vertical" size={4}>
            {user.bio && (
              <Text
                ellipsis={{ tooltip: user.bio }}
                style={{ fontSize: '13px' }}
              >
                {user.bio}
              </Text>
            )}
            <Space size={16}>
              <Text style={{ fontSize: '12px' }}>
                <strong>{user.followers_count}</strong> 粉丝
              </Text>
              <Text style={{ fontSize: '12px' }}>
                <strong>{user.following_count}</strong> 关注
              </Text>
            </Space>
            {user.followed_at && (
              <Text type="secondary" style={{ fontSize: '11px' }}>
                关注于 {new Date(user.followed_at).toLocaleDateString()}
              </Text>
            )}
          </Space>
        }
      />
    </Card>
  );
};

export default UserCard;