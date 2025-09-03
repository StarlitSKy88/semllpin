import { Avatar, Button, Card, Col, Divider, Row, Space, Statistic, Tabs, Typography } from 'antd';


import React, { useState, useEffect } from 'react';

import { User, Wallet, History, Trophy, Settings, Plus } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { useUIStore } from '../stores/uiStore';
import WalletCard from '../components/Wallet/WalletCard';
import TransactionHistory from '../components/Wallet/TransactionHistory';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { PageLoading } from '../components/LoadingSkeleton';
import { FadeIn, SlideUp } from '../components/OptimizedMotion';
import { DecorativeElements } from '../components/UI/DecorativeElements';


const { Title, Text } = Typography;

interface UserProfile {
  id: string;
  username: string;
  email: string;
  avatar?: string;
  createdAt: string;
  stats: {
    totalPranks: number;
    totalLikes: number;
    totalComments: number;
    totalSpent: number;
    totalEarned: number;
  };
}

const ProfilePage: React.FC = () => {
  
  const [searchParams] = useSearchParams();
  const { user } = useAuthStore();
  const { openModal } = useUIStore();
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') || 'profile');
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);

  // 处理充值按钮点击
  const handleTopUp = () => {
    openModal({ type: 'topup' });
  };

  useEffect(() => {
    const tab = searchParams.get('tab');
    if (tab) {
      setActiveTab(tab);
    }
  }, [searchParams]);

  useEffect(() => {
    // 模拟用户资料数据
    if (user) {
      setUserProfile({
        id: user.id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        createdAt: (user as { createdAt?: string }).createdAt || new Date().toISOString(),
        stats: {
          totalPranks: 12,
          totalLikes: 156,
          totalComments: 89,
          totalSpent: 45.50,
          totalEarned: 23.75
        }
      });
    }
  }, [user]);

  const handleViewTransactionHistory = () => {
    setActiveTab('payments');
  };

  if (!userProfile) {
    return <PageLoading />;
  }

  return (
    <ErrorBoundary>
      <div className="relative p-6 bg-gradient-to-br from-pomegranate-50 to-floral-50">
        <DecorativeElements variant="background" animate />
        <DecorativeElements variant="floating" position="top-left" animate />
        <DecorativeElements variant="floating" position="top-right" animate />
        <DecorativeElements variant="floating" position="bottom-left" animate />
        <DecorativeElements variant="floating" position="bottom-right" animate />
      <Row gutter={[24, 24]} className="relative z-10">
        {/* 用户基本信息 */}
        <Col span={24}>
          <FadeIn>
            <Card>
            <Row align="middle" gutter={24}>
              <Col>
                <Avatar 
                  size={80} 
                  src={userProfile.avatar} 
                  icon={<User size={32} />}
                />
              </Col>
              <Col flex={1}>
                <Space direction="vertical" size="small">
                  <Title level={2} style={{ margin: 0, color: '#7f1d1d' }}>
                    {userProfile.username}
                  </Title>
                  <Text type="secondary">{userProfile.email}</Text>
                  <Text type="secondary">
                    加入时间: {new Date(userProfile.createdAt).toLocaleDateString('zh-CN')}
                  </Text>
                </Space>
              </Col>
            </Row>
            
            <Divider />
            
            {/* 用户统计 */}
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="发布恶搞"
                  value={userProfile.stats.totalPranks}
                  prefix={<Trophy size={16} color="#7f1d1d" />}
                  valueStyle={{ color: '#7f1d1d' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="获得点赞"
                  value={userProfile.stats.totalLikes}
                  prefix={<Trophy size={16} color="#f59e0b" />}
                  valueStyle={{ color: '#f59e0b' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="总支出"
                  value={userProfile.stats.totalSpent}
                  precision={2}
                  prefix="$"
                  valueStyle={{ color: '#7f1d1d' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="总收入"
                  value={userProfile.stats.totalEarned}
                  precision={2}
                  prefix="$"
                  valueStyle={{ color: '#059669' }}
                />
              </Col>
            </Row>
            </Card>
          </FadeIn>
        </Col>
        
        {/* 标签页内容 */}
        <Col span={24}>
          <SlideUp>
            <Card>
            <Tabs 
              activeKey={activeTab} 
              onChange={setActiveTab}
              items={[
                {
                  key: 'profile',
                  label: (
                    <span>
                      <User size={16} />
                      个人资料
                    </span>
                  ),
                  children: (
                    <div style={{ padding: '20px 0' }}>
                      <Title level={4} style={{ color: '#7f1d1d' }}>个人信息</Title>
                      <Row gutter={[16, 16]}>
                        <Col span={12}>
                          <Text strong>用户名: </Text>
                          <Text>{userProfile.username}</Text>
                        </Col>
                        <Col span={12}>
                          <Text strong>邮箱: </Text>
                          <Text>{userProfile.email}</Text>
                        </Col>
                        <Col span={12}>
                          <Text strong>注册时间: </Text>
                          <Text>{new Date(userProfile.createdAt).toLocaleString('zh-CN')}</Text>
                        </Col>
                        <Col span={12}>
                          <Text strong>用户ID: </Text>
                          <Text code>{userProfile.id}</Text>
                        </Col>
                      </Row>
                    </div>
                  )
                },
                {
                  key: 'wallet',
                  label: (
                    <span>
                      <Wallet size={16} />
                      我的钱包
                    </span>
                  ),
                  children: (
                    <Space direction="vertical" style={{ width: '100%' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                        <Typography.Title level={4} style={{ margin: 0, color: '#7f1d1d' }}>我的钱包</Typography.Title>
                        <Button 
                          type="primary" 
                          icon={<Plus size={16} />}
                          onClick={handleTopUp}
                        >
                          充值
                        </Button>
                      </div>
                      <WalletCard onViewHistory={handleViewTransactionHistory} />
                    </Space>
                  )
                },
                {
                  key: 'payments',
                  label: (
                    <span>
                      <History size={16} />
                      交易记录
                    </span>
                  ),
                  children: (
                    <TransactionHistory />
                  )
                },
                {
                  key: 'settings',
                  label: (
                    <span>
                      <Settings size={16} />
                      账户设置
                    </span>
                  ),
                  children: (
                    <div style={{ padding: '20px 0' }}>
                      <Title level={4} style={{ color: '#7f1d1d' }}>账户设置</Title>
                      <Text type="secondary">
                        账户设置功能正在开发中...
                      </Text>
                    </div>
                  )
                }
              ]}
            />
            </Card>
          </SlideUp>
        </Col>
      </Row>
    </div>
    </ErrorBoundary>
  );
};

export default ProfilePage;