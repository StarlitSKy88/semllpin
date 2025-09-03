import { Avatar, Button, Card, Empty, Input, List, Space, Spin, Tabs, Typography, message } from 'antd';

import React, { useState, useEffect, useCallback, useMemo, memo } from 'react';

import { User, Search as SearchIcon, Users, Heart } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';

import FollowList from '../components/Social/FollowList';
import UserSearch from '../components/Social/UserSearch';
import socialApi, { type UserInfo } from '../services/socialApi';
import { DecorativeElements } from '../components/UI/DecorativeElements';

const { Title, Text } = Typography;
// const { TabPane } = Tabs; // Removed as unused
const { Search } = Input;

interface SocialStats {
  followersCount: number;
  followingCount: number;
  mutualFollowsCount: number;
}

// 优化的SocialPage组件，添加性能防护措施
const SocialPage: React.FC = memo(() => {
  const { user, isAuthenticated } = useAuthStore();
  const [activeTab, setActiveTab] = useState('discover');
  const [stats, setStats] = useState<SocialStats>({
    followersCount: 0,
    followingCount: 0,
    mutualFollowsCount: 0
  });
  const [recommendedUsers, setRecommendedUsers] = useState<UserInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // 获取用户社交统计 - 添加防抖和条件检查
  const fetchSocialStats = useCallback(async () => {
    if (!user?.id || loading) return;
    
    try {
      setLoading(true);
      const statsData = await socialApi.getFollowStats(user.id);
      setStats(statsData);
    } catch (_error: unknown) {
      console.error('获取社交统计失败:', _error);
    } finally {
      setLoading(false);
    }
  }, [user?.id, loading]);

  // 获取推荐用户 - 添加防抖机制
  const fetchRecommendedUsers = useCallback(async () => {
    if (loading) return;
    
    setLoading(true);
    try {
      const data = await socialApi.getRecommendedUsers({ limit: 10 });
      setRecommendedUsers(data.following || []);
    } catch (_error: unknown) {
      console.error('获取推荐用户失败:', _error);
      message.error('获取推荐用户失败');
    } finally {
      setLoading(false);
    }
  }, [loading]);

  // 处理关注状态变化 - 优化状态更新
  const handleFollowChange = useCallback((userId: string, isFollowing: boolean) => {
    if (!userId || loading) return;
    
    // 更新推荐用户列表中的关注状态
    setRecommendedUsers(prevUsers => 
      prevUsers.map(user => 
        user.id === userId 
          ? { 
              ...user, 
              isFollowing,
              followersCount: isFollowing 
                ? user.followersCount + 1 
                : Math.max(0, user.followersCount - 1)
            }
          : user
      )
    );
    
    // 更新统计数据
    if (isFollowing) {
      setStats(prev => ({
        ...prev,
        followingCount: prev.followingCount + 1
      }));
    } else {
      setStats(prev => ({
        ...prev,
        followingCount: Math.max(0, prev.followingCount - 1)
      }));
    }
  }, [loading]);

  // 处理搜索
  const handleSearch = (value: string) => {
    setSearchQuery(value);
    if (value.trim()) {
      setActiveTab('search');
    }
  };

  // 优化useEffect依赖项
  useEffect(() => {
    if (isAuthenticated && user?.id) {
      fetchSocialStats();
      fetchRecommendedUsers();
    }
  }, [isAuthenticated, user?.id, fetchSocialStats, fetchRecommendedUsers]); // 添加具体依赖项
  
  // 防止内存泄漏
  useEffect(() => {
    return () => {
      setLoading(false);
    };
  }, []);

  // 使用useMemo优化条件渲染
  const loginPrompt = useMemo(() => {
    if (isAuthenticated) return null;
    
    return (
      <div style={{ padding: '24px', textAlign: 'center' }}>
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="请先登录以查看社交功能"
        >
          <Button type="primary" href="/login">
            立即登录
          </Button>
        </Empty>
      </div>
    );
  }, [isAuthenticated]);
  
  if (loginPrompt) return loginPrompt;

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      <div className="relative" style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <DecorativeElements variant="background" animate />
      <DecorativeElements variant="floating" position="top-left" animate />
      <DecorativeElements variant="floating" position="top-right" animate />
      <DecorativeElements variant="floating" position="bottom-left" animate />
      <DecorativeElements variant="floating" position="bottom-right" animate />
      <div className="relative z-10">
      {/* 页面标题和搜索 */}
      <div style={{ marginBottom: '24px' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Title level={2} style={{ margin: 0, color: '#7f1d1d' }}>
            社交中心
          </Title>
          <Search
            placeholder="搜索用户..."
            allowClear
            enterButton={<SearchIcon size={16} />}
            size="large"
            onSearch={handleSearch}
            style={{ maxWidth: '400px' }}
          />
        </Space>
      </div>

      {/* 社交统计卡片 */}
      <Card style={{ marginBottom: '24px' }}>
        <Space size="large">
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#7f1d1d' }}>
              {stats.followersCount.toLocaleString()}
            </div>
            <Text type="secondary">粉丝</Text>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f59e0b' }}>
              {stats.followingCount.toLocaleString()}
            </div>
            <Text type="secondary">关注</Text>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#059669' }}>
              {stats.mutualFollowsCount.toLocaleString()}
            </div>
            <Text type="secondary">互相关注</Text>
          </div>
        </Space>
      </Card>

      {/* 标签页内容 */}
      <Tabs 
        activeKey={activeTab} 
        onChange={setActiveTab}
        items={[
          {
            key: 'discover',
            label: (
              <span>
                <Heart size={16} style={{ marginRight: '8px' }} />
                发现
              </span>
            ),
            children: (
              <Card>
                <Title level={4} style={{ marginBottom: '16px' }}>
                  推荐关注
                </Title>
                <Spin spinning={loading}>
                  {recommendedUsers.length > 0 ? (
                    <List
                      itemLayout="horizontal"
                      dataSource={recommendedUsers}
                      renderItem={(user) => (
                        <List.Item
                          key={user.id}
                          actions={[
                            <Button
                              key="follow"
                              type={user.isFollowing ? 'default' : 'primary'}
                              size="small"
                              onClick={() => {
                                // 这里应该调用关注/取消关注API
                                const newStatus = !user.isFollowing;
                                handleFollowChange(user.id, newStatus);
                              }}
                            >
                              {user.isFollowing ? '已关注' : '关注'}
                            </Button>
                          ]}
                        >
                          <List.Item.Meta
                            avatar={
                              <Avatar 
                                size={48} 
                                src={user.avatar} 
                                icon={<User size={20} />}
                              />
                            }
                            title={user.username}
                            description={
                              <Space direction="vertical" size={4}>
                                <Text type="secondary">{user.email}</Text>
                                <Space size={16}>
                                  <Text type="secondary">
                                    粉丝 {user.followersCount.toLocaleString()}
                                  </Text>
                                  <Text type="secondary">
                                    关注 {user.followingCount.toLocaleString()}
                                  </Text>
                                </Space>
                              </Space>
                            }
                          />
                        </List.Item>
                      )}
                    />
                  ) : (
                    <Empty
                      image={Empty.PRESENTED_IMAGE_SIMPLE}
                      description="暂无推荐用户"
                    />
                  )}
                </Spin>
              </Card>
            )
          },
          {
            key: 'followers',
            label: (
              <span>
                <Users size={16} style={{ marginRight: '8px' }} />
                粉丝 ({stats.followersCount})
              </span>
            ),
            children: user?.id ? (
              <FollowList
                userId={user.id}
                defaultTab="followers"
                showTabs={false}
              />
            ) : null
          },
          {
            key: 'following',
            label: (
              <span>
                <User size={16} style={{ marginRight: '8px' }} />
                关注 ({stats.followingCount})
              </span>
            ),
            children: user?.id ? (
              <FollowList
                userId={user.id}
                defaultTab="following"
                showTabs={false}
              />
            ) : null
          },
          {
            key: 'search',
            label: (
              <span>
                <SearchIcon size={16} style={{ marginRight: '8px' }} />
                搜索结果
              </span>
            ),
            children: (
              <UserSearch
                placeholder={`搜索"${searchQuery}"...`}
                showFollowButton={true}
              />
            )
          }
        ]}
      />      </div>
      </div>
    </div>
  );
});

export default SocialPage;