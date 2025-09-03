import { Avatar, Button, Card, Col, Empty, List, Row, Select, Space, Spin, Statistic, Tag, Typography } from 'antd';
import React, { useState, useEffect } from 'react';
import { CalendarOutlined, EnvironmentOutlined, EyeOutlined, FireOutlined, ShareAltOutlined, TrophyOutlined } from '@ant-design/icons';
import { DecorativeElements } from '../components/UI/DecorativeElements';
import { getPopularShares } from '../utils/api';
import { useNavigate } from 'react-router-dom';

const { Title, Text } = Typography;

interface PopularShare {
  id: string;
  platform: string;
  platformName: string;
  shareUrl: string;
  createdAt: string;
  shareCount: number;
  annotation: {
    id: string;
    description: string;
    smellIntensity: number;
    latitude: number;
    longitude: number;
    viewCount: number;
    likeCount: number;
  };
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
}

interface PopularSharesData {
  shares: PopularShare[];
  stats: {
    totalShares: number;
    totalPlatforms: number;
    mostPopularPlatform: string;
    todayShares: number;
  };
}

const PLATFORM_COLORS: Record<string, string> = {
  twitter: '#1DA1F2',
  wechat: '#07C160',
  weibo: '#E6162D',
  facebook: '#1877F2',
  linkedin: '#0A66C2',
  instagram: '#E4405F',
  other: '#666666'
};

const TIME_RANGES = [
  { label: '今日热门', value: 'today' },
  { label: '本周热门', value: 'week' },
  { label: '本月热门', value: 'month' },
  { label: '全部时间', value: 'all' }
];

const PopularSharesPage: React.FC = () => {
  const navigate = useNavigate();
  const [data, setData] = useState<PopularSharesData | null>(null);
  const [loading, setLoading] = useState(false);
  const [timeRange, setTimeRange] = useState('week');
  const [selectedPlatform, setSelectedPlatform] = useState<string | undefined>(undefined);

  // 加载热门分享
  const loadPopularShares = async (range = 'week', platform?: string) => {
    try {
      setLoading(true);
      const response = await getPopularShares(range, platform, 20);
      setData(response.data);
    } catch (error) {
      console.error('加载热门分享失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPopularShares(timeRange, selectedPlatform);
  }, [timeRange, selectedPlatform]);

  // 处理时间范围变化
  const handleTimeRangeChange = (range: string) => {
    setTimeRange(range);
  };

  // 处理平台筛选
  const handlePlatformChange = (platform: string | undefined) => {
    setSelectedPlatform(platform);
  };

  // 查看标注详情
  const handleViewAnnotation = (annotationId: string) => {
    navigate(`/map?annotation=${annotationId}`);
  };

  // 查看用户资料
  const handleViewUser = (userId: string) => {
    navigate(`/users/${userId}`);
  };

  // 复制分享链接
  const handleCopyLink = async (shareUrl: string) => {
    try {
      await navigator.clipboard.writeText(shareUrl);
      // message.success('链接已复制到剪贴板');
    } catch (error) {
      console.error('复制失败:', error);
    }
  };

  // 格式化时间
  const formatTime = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return '刚刚';
    if (diffInHours < 24) return `${diffInHours}小时前`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}天前`;
    return date.toLocaleDateString('zh-CN');
  };

  // 获取排名图标
  const getRankIcon = (index: number) => {
    if (index === 0) return <TrophyOutlined style={{ color: '#FFD700' }} />;
    if (index === 1) return <TrophyOutlined style={{ color: '#C0C0C0' }} />;
    if (index === 2) return <TrophyOutlined style={{ color: '#CD7F32' }} />;
    return <span style={{ color: '#999', fontWeight: 'bold' }}>#{index + 1}</span>;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      {/* Background decorative elements */}
      <DecorativeElements variant="background" animate={true} />
      
      {/* Floating decorative elements */}
      <DecorativeElements variant="floating" position="top-left" animate={true} />
      <DecorativeElements variant="floating" position="top-right" animate={true} />
      <DecorativeElements variant="floating" position="bottom-left" animate={true} />
      <DecorativeElements variant="floating" position="bottom-right" animate={true} />
      
      <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
        {/* 页面标题 */}
        <div style={{ marginBottom: 24 }}>
          <Title level={2}>
            <FireOutlined style={{ marginRight: 8, color: '#7f1d1d' }} />
            热门分享
          </Title>
        <Text type="secondary">
          发现最受欢迎的臭味标注分享
        </Text>
      </div>

      {/* 统计数据 */}
      {data?.stats && (
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={6}>
            <Card>
              <Statistic
                title="总分享数"
                value={data.stats.totalShares}
                prefix={<ShareAltOutlined />}
                valueStyle={{ color: '#3f8600' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="平台数量"
                value={data.stats.totalPlatforms}
                valueStyle={{ color: '#1890ff' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="今日分享"
                value={data.stats.todayShares}
                prefix={<CalendarOutlined />}
                valueStyle={{ color: '#cf1322' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="热门平台"
                value={data.stats.mostPopularPlatform}
                valueStyle={{ color: '#722ed1' }}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* 筛选器 */}
      <Card style={{ marginBottom: 24 }}>
        <Space size={16}>
          <div>
            <Text strong>时间范围：</Text>
            <Select
              style={{ width: 120, marginLeft: 8 }}
              value={timeRange}
              onChange={handleTimeRangeChange}
            >
              {TIME_RANGES.map(range => (
                <Select.Option key={range.value} value={range.value}>
                  {range.label}
                </Select.Option>
              ))}
            </Select>
          </div>
          <div>
            <Text strong>平台筛选：</Text>
            <Select
              style={{ width: 120, marginLeft: 8 }}
              placeholder="全部平台"
              allowClear
              value={selectedPlatform}
              onChange={handlePlatformChange}
            >
              <Select.Option value="twitter">Twitter</Select.Option>
              <Select.Option value="wechat">微信</Select.Option>
              <Select.Option value="weibo">微博</Select.Option>
              <Select.Option value="facebook">Facebook</Select.Option>
              <Select.Option value="linkedin">LinkedIn</Select.Option>
              <Select.Option value="instagram">Instagram</Select.Option>
            </Select>
          </div>
        </Space>
      </Card>

      {/* 热门分享列表 */}
      <Card>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <Spin size="large" />
            <div style={{ marginTop: 16 }}>加载中...</div>
          </div>
        ) : data?.shares.length === 0 ? (
          <Empty
            description="暂无热门分享"
            style={{ padding: '40px 0' }}
          >
            <Button type="primary" onClick={() => navigate('/map')}>
              去地图分享标注
            </Button>
          </Empty>
        ) : (
          <List
            itemLayout="vertical"
            dataSource={data?.shares || []}
            renderItem={(share, index) => (
              <List.Item
                key={share.id}
                actions={[
                  <Button
                    key="user"
                    type="link"
                    icon={<EyeOutlined />}
                    onClick={() => handleViewUser(share.user.id)}
                  >
                    查看用户
                  </Button>,
                  <Button
                    key="view"
                    type="link"
                    icon={<EnvironmentOutlined />}
                    onClick={() => handleViewAnnotation(share.annotation.id)}
                  >
                    查看标注
                  </Button>,
                  <Button
                    key="copy"
                    type="link"
                    icon={<ShareAltOutlined />}
                    onClick={() => handleCopyLink(share.shareUrl)}
                  >
                    复制链接
                  </Button>
                ]}
                extra={
                  <div style={{ textAlign: 'center', minWidth: 80 }}>
                    <div style={{ fontSize: 24, marginBottom: 4 }}>
                      {getRankIcon(index)}
                    </div>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {share.shareCount} 次分享
                    </Text>
                  </div>
                }
              >
                <List.Item.Meta
                  avatar={
                    <Avatar
                      src={share.user.avatar}
                      style={{ 
                        backgroundColor: share.user.avatar ? undefined : '#1890ff'
                      }}
                      size="large"
                    >
                      {!share.user.avatar && share.user.username.charAt(0).toUpperCase()}
                    </Avatar>
                  }
                  title={
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span>{share.annotation.description || '臭味标注'}</span>
                      <Tag 
                        color={PLATFORM_COLORS[share.platform]}
                        style={{ margin: 0 }}
                      >
                        {share.platformName}
                      </Tag>
                      {index < 3 && (
                        <Tag color="gold" style={{ margin: 0 }}>
                          <FireOutlined /> 热门
                        </Tag>
                      )}
                    </div>
                  }
                  description={
                    <Space direction="vertical" size={4}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Text type="secondary">分享者: {share.user.username}</Text>
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <CalendarOutlined />
                          <Text type="secondary">{formatTime(share.createdAt)}</Text>
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Text type="secondary">臭味强度: {share.annotation.smellIntensity}/10</Text>
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <EyeOutlined />
                          <Text type="secondary">{share.annotation.viewCount} 浏览</Text>
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Text type="secondary">{share.annotation.likeCount} 点赞</Text>
                        </span>
                      </div>
                      <div>
                        <Text type="secondary" style={{ fontSize: '12px' }}>
                          位置: {share.annotation.latitude.toFixed(4)}, {share.annotation.longitude.toFixed(4)}
                        </Text>
                      </div>
                    </Space>
                  }
                />
              </List.Item>
            )}
          />
        )}
      </Card>
      </div>
    </div>
  );
};

export default PopularSharesPage;