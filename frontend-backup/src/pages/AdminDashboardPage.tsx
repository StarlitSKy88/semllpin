import { Alert, Avatar, Badge, Button, Card, Col, List, Progress, Row, Space, Statistic, Table, Tag, Tooltip, Typography, message } from 'antd';


import React, { useState, useEffect } from 'react';

import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { PageLoading } from '../components/LoadingSkeleton';
import { FadeIn, SlideUp } from '../components/OptimizedMotion';
import { DecorativeElements } from '../components/UI/DecorativeElements';

import { BellOutlined, DollarOutlined, EyeOutlined, FileTextOutlined, RiseOutlined, SettingOutlined, UserOutlined, WarningOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { useTranslation } from 'react-i18next';

import adminApi, {
  type AdminStats,
  type UserManagement,
  type ContentReview
} from '../services/adminApi';
import {
  getUserStatusColor,
  getReviewStatusColor,
  // isAdmin, // removed as unused
  isModerator,
  formatCurrency,
  formatRelativeTime
} from '../services/adminApi';
import type { UserStatusType } from '../services/adminApi';
// formatCurrency and formatRelativeTime are imported from adminApi

const { Title, Text } = Typography;

interface QuickAction {
  title: string;
  description: string;
  icon: React.ReactNode;
  action: () => void;
  color: string;
  permission: string[];
}

const AdminDashboardPage: React.FC = () => {
  
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [recentUsers, setRecentUsers] = useState<UserManagement[]>([]);
  const [pendingReviews, setPendingReviews] = useState<ContentReview[]>([]);
  const [error, setError] = useState<string | null>(null);

  // 检查权限
  const hasPermission = (requiredRoles: string[]) => {
    return user && user.role && requiredRoles.includes(user.role);
  };

  // 快速操作配置
  const quickActions: QuickAction[] = [
    {
      title: '用户管理',
      description: '管理用户账户和权限',
      icon: <UserOutlined />,
      action: () => navigate('/admin/users'),
      color: '#1890ff',
      permission: ['admin', 'super_admin', 'moderator']
    },
    {
      title: '内容审核',
      description: '审核待处理的内容',
      icon: <EyeOutlined />,
      action: () => navigate('/admin/content'),
      color: '#52c41a',
      permission: ['admin', 'super_admin', 'moderator']
    },
    {
      title: '财务管理',
      description: '交易记录和提现审核',
      icon: <DollarOutlined />,
      action: () => navigate('/admin/financial'),
      color: '#13c2c2',
      permission: ['admin', 'super_admin']
    },
    {
      title: '数据分析',
      description: '用户行为和收入分析',
      icon: <RiseOutlined />,
      action: () => navigate('/admin/analytics'),
      color: '#eb2f96',
      permission: ['admin', 'super_admin']
    },
    {
      title: '系统设置',
      description: '配置系统参数',
      icon: <SettingOutlined />,
      action: () => navigate('/admin/system'),
      color: '#722ed1',
      permission: ['admin', 'super_admin']
    },
    {
      title: '操作日志',
      description: '查看管理员操作记录',
      icon: <FileTextOutlined />,
      action: () => navigate('/admin/logs'),
      color: '#fa8c16',
      permission: ['admin', 'super_admin']
    }
  ];

  // 加载数据
  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      // 并行加载数据
      const [statsData, usersData, reviewsData] = await Promise.all([
        adminApi.getAdminStats(),
        adminApi.getUserManagement({ page: 1, limit: 5, sortBy: 'created_at', sortOrder: 'desc' }),
        adminApi.getContentReviews({ page: 1, limit: 5, status: 'pending' })
      ]);

      setStats(statsData);
      setRecentUsers(usersData.data);
      setPendingReviews(reviewsData.data);
    } catch (err: unknown) {
      console.error('加载管理员数据失败:', err);
      const errorMessage = err instanceof Error && 'response' in err 
        ? (err as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '加载数据失败';
      setError(errorMessage || '加载数据失败');
      message.error('加载数据失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // 检查权限
    if (!user || !user.role || !isModerator(user.role)) {
      navigate('/');
      return;
    }

    loadData();
  }, [user, navigate]);

  // 处理快速审核
  const handleQuickReview = async (reviewId: string, action: 'approve' | 'reject') => {
    try {
      await adminApi.handleContentReview(reviewId, action);
      message.success(`内容${action === 'approve' ? '通过' : '拒绝'}成功`);
      loadData(); // 重新加载数据
    } catch (err: unknown) {
      const errorMessage = err instanceof Error && 'response' in err 
        ? (err as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '操作失败';
      message.error(errorMessage || '操作失败');
    }
  };

  // 渲染统计卡片
  const renderStatsCards = () => {
    if (!stats) return null;

    const statsConfig = [
      {
        title: '总用户数',
        value: stats.totalUsers,
        icon: <UserOutlined style={{ color: '#7f1d1d' }} />,
        color: '#7f1d1d',
        suffix: '人'
      },
      {
        title: '活跃用户',
        value: stats.activeUsers,
        icon: <UserOutlined style={{ color: '#059669' }} />,
        color: '#059669',
        suffix: '人',
        precision: 0
      },
      {
        title: '总标注数',
        value: stats.totalAnnotations,
        icon: <FileTextOutlined style={{ color: '#7f1d1d' }} />,
        color: '#7f1d1d',
        suffix: '条'
      },
      {
        title: '月收入',
        value: stats.monthlyRevenue,
        icon: <DollarOutlined style={{ color: '#f59e0b' }} />,
        color: '#f59e0b',
        formatter: (value: number | string) => formatCurrency(Number(value))
      },
      {
        title: '待审核',
        value: stats.pendingAnnotations,
        icon: <WarningOutlined style={{ color: '#dc2626' }} />,
        color: '#dc2626',
        suffix: '条'
      },
      {
        title: '待处理举报',
        value: stats.pendingReports,
        icon: <BellOutlined style={{ color: '#dc2626' }} />,
        color: '#dc2626',
        suffix: '条'
      }
    ];

    return (
      <Row gutter={[16, 16]}>
        {statsConfig.map((stat, index) => (
          <Col xs={24} sm={12} lg={8} xl={4} key={`item-${index}`}>
            <Card>
              <Statistic
                title={stat.title}
                value={stat.value}
                prefix={stat.icon}
                suffix={stat.suffix}
                formatter={stat.formatter}
                precision={stat.precision}
                valueStyle={{ color: stat.color }}
              />
            </Card>
          </Col>
        ))}
      </Row>
    );
  };

  // 渲染快速操作
  const renderQuickActions = () => {
    const availableActions = quickActions.filter(action => 
      hasPermission(action.permission)
    );

    return (
      <Card title="快速操作" extra={<RiseOutlined />}>
        <Row gutter={[16, 16]}>
          {availableActions.map((action, index) => (
            <Col xs={24} sm={12} lg={6} key={`item-${index}`}>
              <Card
                hoverable
                onClick={action.action}
                style={{ 
                  borderLeft: `4px solid ${action.color}`,
                  cursor: 'pointer'
                }}
              >
                <Space direction="vertical" size="small">
                  <Space>
                    <span style={{ color: action.color, fontSize: '20px' }}>
                      {action.icon}
                    </span>
                    <Text strong>{action.title}</Text>
                  </Space>
                  <Text type="secondary" style={{ fontSize: '12px' }}>
                    {action.description}
                  </Text>
                </Space>
              </Card>
            </Col>
          ))}
        </Row>
      </Card>
    );
  };

  // 渲染最近用户
  const renderRecentUsers = () => {
    const columns = [
      {
        title: '用户名',
        dataIndex: 'username',
        key: 'username',
        render: (text: string) => (
          <Space>
            <Avatar icon={<UserOutlined />} size="small" />
            <span>{text}</span>
          </Space>
        )
      },
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        render: (status: string) => (
          <Tag color={getUserStatusColor(status as UserStatusType)}>
            {status}
          </Tag>
        )
      },
      {
        title: '注册时间',
        dataIndex: 'created_at',
        key: 'created_at',
        render: (date: string) => (
          <Tooltip title={new Date(date).toLocaleString()}>
            {formatRelativeTime(date)}
          </Tooltip>
        )
      },
      {
        title: '操作',
        key: 'action',
        render: (record: UserManagement) => (
          <Button 
            type="link" 
            size="small"
            onClick={() => navigate(`/admin/users?userId=${record.id}`)}
          >
            查看详情
          </Button>
        )
      }
    ];

    return (
      <Card 
        title="最近注册用户" 
        extra={
          <Button 
            type="link" 
            onClick={() => navigate('/admin/users')}
          >
            查看全部
          </Button>
        }
      >
        <Table
          dataSource={recentUsers}
          columns={columns}
          pagination={false}
          size="small"
          rowKey="id"
        />
      </Card>
    );
  };

  // 渲染待审核内容
  const renderPendingReviews = () => {
    return (
      <Card 
        title="待审核内容" 
        extra={
          <Badge count={pendingReviews.length} showZero>
            <Button 
              type="link" 
              onClick={() => navigate('/admin/content-reviews')}
            >
              查看全部
            </Button>
          </Badge>
        }
      >
        <List
          dataSource={pendingReviews}
          renderItem={(item) => (
            <List.Item
              actions={[
                <Button
                  key="approve"
                  type="primary"
                  size="small"
                  onClick={() => handleQuickReview(item.id, 'approve')}
                >
                  通过
                </Button>,
                <Button
                  key="reject"
                  danger
                  size="small"
                  onClick={() => handleQuickReview(item.id, 'reject')}
                >
                  拒绝
                </Button>
              ]}
            >
              <List.Item.Meta
                avatar={
                  <Badge 
                    status={getReviewStatusColor(item.status) as 'success' | 'processing' | 'default' | 'error' | 'warning'} 
                    text={item.type}
                  />
                }
                title={
                  <Space>
                    <Text>{item.content_preview || '内容预览'}</Text>
                    <Tag color="orange">{item.reason}</Tag>
                  </Space>
                }
                description={
                  <Text type="secondary">
                    举报者: {item.reporter_username} • {formatRelativeTime(item.created_at)}
                  </Text>
                }
              />
            </List.Item>
          )}
          locale={{ emptyText: '暂无待审核内容' }}
        />
      </Card>
    );
  };

  // 渲染系统健康度
  const renderSystemHealth = () => {
    if (!stats) return null;

    const userActiveRate = stats.totalUsers > 0 ? (stats.activeUsers / stats.totalUsers) * 100 : 0;
    const contentApprovalRate = stats.totalAnnotations > 0 ? 
      (stats.approvedAnnotations / stats.totalAnnotations) * 100 : 0;

    return (
      <Card title="系统健康度">
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <div>
            <Text>用户活跃度</Text>
            <Progress 
              percent={Math.round(userActiveRate)} 
              status={userActiveRate > 80 ? 'success' : userActiveRate > 60 ? 'normal' : 'exception'}
              format={(percent) => `${percent}%`}
            />
          </div>
          <div>
            <Text>内容通过率</Text>
            <Progress 
              percent={Math.round(contentApprovalRate)} 
              status={contentApprovalRate > 90 ? 'success' : contentApprovalRate > 70 ? 'normal' : 'exception'}
              format={(percent) => `${percent}%`}
            />
          </div>
          <div>
            <Text>待处理事项</Text>
            <Progress 
              percent={stats.pendingReports > 10 ? 100 : (stats.pendingReports / 10) * 100}
              status={stats.pendingReports > 10 ? 'exception' : stats.pendingReports > 5 ? 'normal' : 'success'}
              format={() => `${stats.pendingReports} 项`}
            />
          </div>
        </Space>
      </Card>
    );
  };

  if (loading) {
    return <PageLoading />;
  }

  if (error) {
    return (
      <Alert
        message="加载失败"
        description={error}
        type="error"
        showIcon
        action={
          <Button size="small" onClick={loadData}>
            重试
          </Button>
        }
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      <DecorativeElements variant="background" />
      <DecorativeElements variant="floating" position="top-left" />
      <DecorativeElements variant="floating" position="top-right" />
      <DecorativeElements variant="floating" position="bottom-left" />
      <DecorativeElements variant="floating" position="bottom-right" />
      
      <ErrorBoundary>
        <div className="relative z-10" style={{ padding: '24px' }}>
          <FadeIn>
            <div style={{ marginBottom: '24px' }}>
              <Title level={2} style={{ color: '#7f1d1d' }}>{t('navigation.dashboard')}</Title>
              <Text type="secondary">
                {t('dashboard.welcome', { username: user?.username })}
              </Text>
            </div>
          </FadeIn>

        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          {/* 统计卡片 */}
          <SlideUp>
            {renderStatsCards()}
          </SlideUp>

          {/* 快速操作 */}
          <FadeIn>
            {renderQuickActions()}
          </FadeIn>

          {/* 详细信息 */}
          <SlideUp>
            <Row gutter={[16, 16]}>
              <Col xs={24} lg={12}>
                {renderRecentUsers()}
              </Col>
              <Col xs={24} lg={12}>
                {renderPendingReviews()}
              </Col>
            </Row>
          </SlideUp>

          {/* 系统健康度 */}
          <FadeIn>
            <Row gutter={[16, 16]}>
              <Col xs={24} lg={12}>
                {renderSystemHealth()}
              </Col>
              <Col xs={24} lg={12}>
                <Card title="快速统计">
                  <Row gutter={16}>
                    <Col span={12}>
                      <Statistic
                        title="今日新增用户"
                        value={Math.floor(Math.random() * 20) + 5}
                        suffix="人"
                        valueStyle={{ color: '#3f8600' }}
                      />
                    </Col>
                    <Col span={12}>
                      <Statistic
                        title="今日新增标注"
                        value={Math.floor(Math.random() * 100) + 50}
                        suffix="条"
                        valueStyle={{ color: '#cf1322' }}
                      />
                    </Col>
                  </Row>
                </Card>
              </Col>
            </Row>
          </FadeIn>
        </Space>
        </div>
      </ErrorBoundary>
    </div>
  );
};

export default AdminDashboardPage;