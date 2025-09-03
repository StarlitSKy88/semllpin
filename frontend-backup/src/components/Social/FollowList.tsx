import { Empty, List, Pagination, Space, Spin, Tabs } from 'antd';

import React, { useState, useEffect, useCallback } from 'react';
 // Typography removed as unused
import { UserOutlined, HeartOutlined } from '@ant-design/icons';
import UserCard from './UserCard';
import { getUserFollowing, getUserFollowers, getMutualFollows } from '../../utils/api';
import { useAuthStore } from '../../stores/authStore';


// const { Title } = Typography; // removed as unused
// const { TabPane } = Tabs; // removed as unused

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

interface FollowListProps {
  userId: string;
  defaultTab?: 'following' | 'followers' | 'mutual';
  showTabs?: boolean;
}

const FollowList: React.FC<FollowListProps> = ({
  userId,
  defaultTab = 'following',
  showTabs = true
}) => {
  const [activeTab, setActiveTab] = useState(defaultTab);
  const [loading, setLoading] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0
  });
  const { user: currentUser } = useAuthStore();

  const fetchUsers = useCallback(async (tab: string, page: number = 1, limit: number = 20) => {
    setLoading(true);
    try {
      let response;
      switch (tab) {
        case 'following':
          response = await getUserFollowing(userId, page, limit);
          setUsers(response.following || []);
          break;
        case 'followers':
          response = await getUserFollowers(userId, page, limit);
          setUsers(response.followers || []);
          break;
        case 'mutual':
          response = await getMutualFollows(userId, page, limit);
          setUsers(response.mutualFollows || []);
          break;
        default:
          setUsers([]);
      }
      
      if (response?.pagination) {
        setPagination({
          page: response.pagination.page,
          limit: response.pagination.limit,
          total: response.pagination.total,
          totalPages: response.pagination.totalPages
        });
      }
    } catch (error) {
      console.error('获取用户列表失败:', error);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }, [userId, setUsers, setLoading, setPagination]);

  useEffect(() => {
    fetchUsers(activeTab, 1, pagination.limit);
  }, [activeTab, fetchUsers, pagination.limit]);

  const handleTabChange = (key: string) => {
    setActiveTab(key as 'following' | 'followers' | 'mutual');
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handlePageChange = (page: number) => {
    setPagination(prev => ({ ...prev, page }));
    fetchUsers(activeTab, page, pagination.limit);
  };

  const handleFollowChange = (targetUserId: string, isFollowing: boolean) => {
    // 更新本地状态
    setUsers(prevUsers => 
      prevUsers.map(user => {
        if (user.id === targetUserId) {
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

  const getTabTitle = (tab: string, count: number) => {
    const titles = {
      following: `关注 (${count})`,
      followers: `粉丝 (${count})`,
      mutual: `互相关注 (${count})`
    };
    return titles[tab as keyof typeof titles] || tab;
  };

  const renderContent = () => (
    <div>
      <Spin spinning={loading}>
        {users.length === 0 && !loading ? (
          <Empty
            description={
              activeTab === 'following' ? '暂无关注的用户' :
              activeTab === 'followers' ? '暂无粉丝' :
              '暂无互相关注的用户'
            }
          />
        ) : (
          <List
            grid={{
              gutter: 16,
              xs: 1,
              sm: 2,
              md: 2,
              lg: 3,
              xl: 3,
              xxl: 4
            }}
            dataSource={users}
            renderItem={(user) => (
              <List.Item>
                <UserCard
                  user={user}
                  showFollowButton={currentUser?.id !== user.id}
                  onFollowChange={handleFollowChange}
                  size="default"
                />
              </List.Item>
            )}
          />
        )}
      </Spin>
      
      {pagination.total > pagination.limit && (
        <div style={{ textAlign: 'center', marginTop: 24 }}>
          <Pagination
            current={pagination.page}
            total={pagination.total}
            pageSize={pagination.limit}
            onChange={handlePageChange}
            showSizeChanger={false}
            showQuickJumper
            showTotal={(total, range) => 
              `第 ${range[0]}-${range[1]} 条，共 ${total} 条`
            }
          />
        </div>
      )}
    </div>
  );

  if (!showTabs) {
    return renderContent();
  }

  return (
    <div className="follow-list">
      <Tabs
        activeKey={activeTab}
        onChange={handleTabChange}
        centered
        items={[
          {
            key: 'following',
            label: (
              <Space>
                <UserOutlined />
                {getTabTitle('following', pagination.total)}
              </Space>
            ),
            children: renderContent()
          },
          {
            key: 'followers',
            label: (
              <Space>
                <UserOutlined />
                {getTabTitle('followers', pagination.total)}
              </Space>
            ),
            children: renderContent()
          },
          {
            key: 'mutual',
            label: (
              <Space>
                <HeartOutlined />
                {getTabTitle('mutual', pagination.total)}
              </Space>
            ),
            children: renderContent()
          }
        ]}
      />
    </div>
  );
};

export default FollowList;