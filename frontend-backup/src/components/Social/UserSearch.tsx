import React, { useState, useEffect } from 'react';
import { Avatar, Empty, Input, List, Space, Spin, Typography } from 'antd';
import { SearchOutlined, UserOutlined } from '@ant-design/icons';
import { useAuthStore } from '../../stores/authStore';

import FollowButton from './FollowButton';
import api from '../../utils/api';
// 简单的防抖函数
const debounce = <T extends (...args: unknown[]) => unknown>(
  func: T,
  wait: number
) => {
  let timeout: NodeJS.Timeout;
  const debouncedFunc = (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
  debouncedFunc.cancel = () => clearTimeout(timeout);
  return debouncedFunc;
};

const { Search } = Input;
const { Text } = Typography;

interface User {
  id: string;
  username: string;
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  followers_count: number;
  following_count: number;
}

interface UserSearchProps {
  onUserSelect?: (user: User) => void;
  placeholder?: string;
  size?: 'small' | 'middle' | 'large';
  showFollowButton?: boolean;
}

const UserSearch: React.FC<UserSearchProps> = ({
  onUserSelect,
  placeholder = '搜索用户...',
  size = 'middle',
  showFollowButton = true
}) => {
  const [searchValue, setSearchValue] = useState('');
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const { user: currentUser } = useAuthStore();

  // 防抖搜索函数
  const debouncedSearch = React.useMemo(() => debounce((...args: unknown[]) => {
    const query = args[0] as string;
    if (!query.trim()) {
      setUsers([]);
      setHasSearched(false);
      return;
    }

    setLoading(true);
    setHasSearched(true);
    
    (async () => {
      try {
        const response = await api.get('/users/search', {
          params: { q: query, limit: 20 }
        });
        setUsers(response.data.users || []);
      } catch (error) {
        console.error('搜索用户失败:', error);
        setUsers([]);
      } finally {
        setLoading(false);
      }
    })();
  }, 300), []);

  useEffect(() => {
    debouncedSearch(searchValue);
    return () => {
      debouncedSearch.cancel();
    };
  }, [searchValue, debouncedSearch]);

  const handleSearch = (value: string) => {
    setSearchValue(value);
  };

  const handleUserClick = (user: User) => {
    onUserSelect?.(user);
  };

  const handleFollowChange = (userId: string, isFollowing: boolean) => {
    // 更新本地用户列表中的关注状态
    setUsers(prevUsers => 
      prevUsers.map(user => {
        if (user.id === userId) {
          return {
            ...user,
            followers_count: isFollowing 
              ? user.followers_count + 1 
              : user.followers_count - 1
          };
        }
        return user;
      })
    );
  };

  return (
    <div className="user-search">
      <Search
        placeholder={placeholder}
        allowClear
        size={size}
        prefix={<SearchOutlined />}
        value={searchValue}
        onChange={(e) => handleSearch(e.target.value)}
        style={{ marginBottom: 16 }}
      />
      
      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        <Spin spinning={loading}>
          {hasSearched && users.length === 0 && !loading ? (
            <Empty
              description="未找到相关用户"
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          ) : (
            <List
              dataSource={users}
              renderItem={(user) => (
                <List.Item
                  actions={[
                    showFollowButton && (
                      <FollowButton
                        key="follow"
                        userId={user.id}
                        size="small"
                        onFollowChange={handleFollowChange}
                      />
                    )
                  ].filter(Boolean)}
                >
                  <List.Item.Meta
                    avatar={
                      <Avatar
                        src={user.avatar_url}
                        icon={<UserOutlined />}
                        size={40}
                        style={{ cursor: 'pointer' }}
                        onClick={() => handleUserClick(user)}
                      />
                    }
                    title={
                      <div
                        style={{ cursor: 'pointer' }}
                        onClick={() => handleUserClick(user)}
                      >
                        <Space direction="vertical" size={0}>
                          <Text strong>
                            {user.display_name || user.username}
                            {currentUser?.id === user.id && (
                              <Text type="secondary" style={{ marginLeft: 4 }}>
                                (我)
                              </Text>
                            )}
                          </Text>
                          {user.display_name && (
                            <Text type="secondary" style={{ fontSize: '12px' }}>
                              @{user.username}
                            </Text>
                          )}
                        </Space>
                      </div>
                    }
                    description={
                      <Space direction="vertical" size={2}>
                        {user.bio && (
                          <Text
                            ellipsis={{ tooltip: user.bio }}
                            style={{ fontSize: '12px' }}
                          >
                            {user.bio}
                          </Text>
                        )}
                        <Space size={12}>
                          <Text style={{ fontSize: '11px' }}>
                            <strong>{user.followers_count}</strong> 粉丝
                          </Text>
                          <Text style={{ fontSize: '11px' }}>
                            <strong>{user.following_count}</strong> 关注
                          </Text>
                        </Space>
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          )}
        </Spin>
      </div>
    </div>
  );
};

export default UserSearch;