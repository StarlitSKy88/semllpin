import { Avatar, Button, Card, Space, Spin, Typography, message } from 'antd';

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

import { ArrowLeftOutlined, UserOutlined } from '@ant-design/icons';
import { useAuthStore } from '../stores/authStore';
import { DecorativeElements } from '../components/UI/DecorativeElements';

import FollowList from '../components/Social/FollowList';
import api from '../utils/api';

const { Title, Text } = Typography;

interface UserProfile {
  id: string;
  username: string;
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  followers_count: number;
  following_count: number;
}

const FollowPage: React.FC = () => {
  const { userId, tab } = useParams<{ userId: string; tab?: string }>();
  const navigate = useNavigate();
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const { user: currentUser } = useAuthStore();

  useEffect(() => {
    const fetchUserProfile = async () => {
      if (!userId) return;
      
      setLoading(true);
      try {
        const response = await api.get(`/users/${userId}`);
        setUserProfile(response.data.user);
      } catch (error: unknown) {
        message.error('获取用户信息失败');
        console.error('获取用户信息失败:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchUserProfile();
  }, [userId]);

  const handleBack = () => {
    navigate(-1);
  };

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '400px' 
      }}>
        <Spin size="large" />
      </div>
    );
  }

  if (!userProfile) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <Text type="secondary">用户不存在</Text>
      </div>
    );
  }

  const defaultTab = (tab as 'following' | 'followers' | 'mutual') || 'following';
  const isOwnProfile = currentUser?.id === userId;

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      {/* Background decorative elements */}
      <DecorativeElements variant="background" animate={true} />
      
      {/* Floating decorative elements */}
      <DecorativeElements variant="floating" position="top-left" animate={true} />
      <DecorativeElements variant="floating" position="top-right" animate={true} />
      <DecorativeElements variant="floating" position="bottom-left" animate={true} />
      <DecorativeElements variant="floating" position="bottom-right" animate={true} />
      
      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px' }}>
      {/* 头部导航 */}
      <div style={{ marginBottom: '20px' }}>
        <Button 
          type="text" 
          icon={<ArrowLeftOutlined />} 
          onClick={handleBack}
          style={{ marginBottom: '16px', color: '#7f1d1d' }}
        >
          返回
        </Button>
      </div>

      {/* 用户信息卡片 */}
      <Card style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <Avatar
            size={80}
            src={userProfile.avatar_url}
            icon={<UserOutlined />}
          />
          <div style={{ flex: 1 }}>
            <Space direction="vertical" size={4}>
              <Title level={3} style={{ margin: 0, color: '#7f1d1d' }}>
                {userProfile.display_name || userProfile.username}
                {isOwnProfile && (
                  <Text type="secondary" style={{ marginLeft: '8px', fontSize: '14px' }}>
                    (我)
                  </Text>
                )}
              </Title>
              {userProfile.display_name && (
                <Text type="secondary">@{userProfile.username}</Text>
              )}
              {userProfile.bio && (
                <Text style={{ color: '#666' }}>{userProfile.bio}</Text>
              )}
              <Space size={24}>
                <Text style={{ color: '#dc2626' }}>
                  <strong>{userProfile.followers_count}</strong> 粉丝
                </Text>
                <Text style={{ color: '#059669' }}>
                  <strong>{userProfile.following_count}</strong> 关注
                </Text>
              </Space>
            </Space>
          </div>
        </div>
      </Card>

      {/* 关注列表 */}
      <Card>
        <FollowList 
          userId={userId!} 
          defaultTab={defaultTab}
          showTabs={true}
        />
      </Card>
      </div>
    </div>
  );
};

export default FollowPage;