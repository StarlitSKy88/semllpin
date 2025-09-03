import { Avatar, Button, Card, Empty, List, Pagination, Select, Space, Spin, Tag, Typography } from 'antd';
import React, { useState, useEffect } from 'react';
import { ShareAltOutlined, EnvironmentOutlined, CalendarOutlined } from '@ant-design/icons';
import { DecorativeElements } from '../components/UI/DecorativeElements';
import { getUserShareHistory } from '../utils/api';
import { useNavigate } from 'react-router-dom';

const { Title, Text } = Typography;

interface ShareRecord {
  id: string;
  platform: string;
  platformName: string;
  shareUrl: string;
  createdAt: string;
  annotation: {
    id: string;
    description: string;
    smellIntensity: number;
    latitude: number;
    longitude: number;
  };
}

interface ShareHistoryData {
  shares: ShareRecord[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
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

const ShareHistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [data, setData] = useState<ShareHistoryData | null>(null);
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedPlatform, setSelectedPlatform] = useState<string | undefined>(undefined);
  const pageSize = 10;

  // 加载分享历史
  const loadShareHistory = async (page = 1, platform?: string) => {
    try {
      setLoading(true);
      const response = await getUserShareHistory(page, pageSize, platform);
      setData(response.data);
    } catch (error) {
      console.error('加载分享历史失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadShareHistory(currentPage, selectedPlatform);
  }, [currentPage, selectedPlatform]);

  // 处理页码变化
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  // 处理平台筛选
  const handlePlatformChange = (platform: string | undefined) => {
    setSelectedPlatform(platform);
    setCurrentPage(1);
  };

  // 查看标注详情
  const handleViewAnnotation = (annotationId: string) => {
    // 这里可以导航到标注详情页面或在地图上显示
    navigate(`/map?annotation=${annotationId}`);
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
            <ShareAltOutlined style={{ marginRight: 8, color: '#7f1d1d' }} />
            分享历史
          </Title>
        <Text type="secondary">
          查看你的所有分享记录和统计数据
        </Text>
      </div>

      {/* 筛选器 */}
      <Card style={{ marginBottom: 24 }}>
        <Space size={16}>
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

      {/* 分享记录列表 */}
      <Card>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <Spin size="large" />
            <div style={{ marginTop: 16 }}>加载中...</div>
          </div>
        ) : data?.shares.length === 0 ? (
          <Empty
            description="还没有分享记录"
            style={{ padding: '40px 0' }}
          >
            <Button type="primary" onClick={() => navigate('/map')}>
              去地图分享标注
            </Button>
          </Empty>
        ) : (
          <>
            <List
              itemLayout="vertical"
              dataSource={data?.shares || []}
              renderItem={(share) => (
                <List.Item
                  key={share.id}
                  actions={[
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
                >
                  <List.Item.Meta
                    avatar={
                      <Avatar
                        style={{ 
                          backgroundColor: PLATFORM_COLORS[share.platform] || '#666666',
                          color: 'white'
                        }}
                        size="large"
                      >
                        {share.platformName.charAt(0)}
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
                      </div>
                    }
                    description={
                      <Space direction="vertical" size={4}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <CalendarOutlined />
                            <Text type="secondary">{formatTime(share.createdAt)}</Text>
                          </span>
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <Text type="secondary">臭味强度: {share.annotation.smellIntensity}/10</Text>
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
            
            {/* 分页 */}
            {data && data.pagination.totalPages > 1 && (
              <div style={{ textAlign: 'center', marginTop: 24 }}>
                <Pagination
                  current={data.pagination.page}
                  total={data.pagination.total}
                  pageSize={data.pagination.limit}
                  onChange={handlePageChange}
                  showSizeChanger={false}
                  showQuickJumper
                  showTotal={(total, range) => 
                    `第 ${range[0]}-${range[1]} 条，共 ${total} 条记录`
                  }
                />
              </div>
            )}
          </>
        )}
      </Card>
      </div>
    </div>
  );
};

export default ShareHistoryPage;