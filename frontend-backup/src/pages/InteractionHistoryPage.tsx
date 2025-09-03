import { Avatar, Button, Card, Col, Empty, List, Row, Select, Space, Spin, Statistic, Tabs, Tag, Typography } from 'antd';
import React, { useState, useEffect, useCallback } from 'react';
import { EnvironmentOutlined, EyeOutlined, LikeOutlined, MessageOutlined, StarOutlined, UserOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { DecorativeElements } from '../components/UI/DecorativeElements';
import interactionApi, { LikeType, FavoriteType, type Like, type Favorite, type PaginatedResponse } from '../services/interactionApi';
// import { formatDistanceToNow } from 'date-fns'; // Removed as module not found
// import { zhCN } from 'date-fns/locale'; // Removed as module not found

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;
const { Option } = Select;

interface InteractionHistoryData {
  likes: PaginatedResponse<Like>;
  favorites: PaginatedResponse<Favorite>;
}

const InteractionHistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'likes' | 'favorites'>('likes');
  const [data, setData] = useState<InteractionHistoryData>({
    likes: { data: [], pagination: { page: 1, limit: 20, total: 0, totalPages: 0 } },
    favorites: { data: [], pagination: { page: 1, limit: 20, total: 0, totalPages: 0 } }
  });
  const [loading, setLoading] = useState(false);
  const [likeTypeFilter, setLikeTypeFilter] = useState<LikeType | undefined>(undefined);
  const [favoriteTypeFilter, setFavoriteTypeFilter] = useState<FavoriteType | undefined>(undefined);

  // 获取点赞历史
  const fetchLikes = useCallback(async (page = 1) => {
    setLoading(true);
    try {
      const response = await interactionApi.getUserLikes({
        page,
        limit: data.likes.pagination.limit,
        targetType: likeTypeFilter
      });
      setData(prev => ({ ...prev, likes: response }));
    } catch (error: unknown) {
      console.error('获取点赞历史失败:', error);
    } finally {
      setLoading(false);
    }
  }, [data.likes.pagination.limit, likeTypeFilter]);

  // 获取收藏列表
  const fetchFavorites = useCallback(async (page = 1) => {
    setLoading(true);
    try {
      const response = await interactionApi.getUserFavorites({
        page,
        limit: data.favorites.pagination.limit,
        targetType: favoriteTypeFilter
      });
      setData(prev => ({ ...prev, favorites: response }));
    } catch (error: unknown) {
      console.error('获取收藏列表失败:', error);
    } finally {
      setLoading(false);
    }
  }, [data.favorites.pagination.limit, favoriteTypeFilter]);

  // 处理标签页切换
  const handleTabChange = (key: string) => {
    setActiveTab(key as 'likes' | 'favorites');
  };

  // 处理点赞类型过滤
  const handleLikeTypeFilter = (value: LikeType | undefined) => {
    setLikeTypeFilter(value);
  };

  // 处理收藏类型过滤
  const handleFavoriteTypeFilter = (value: FavoriteType | undefined) => {
    setFavoriteTypeFilter(value);
  };

  // 查看详情
  const handleViewDetail = (targetId: string, targetType: string) => {
    if (targetType === 'annotation') {
      navigate(`/map?annotation=${targetId}`);
    } else if (targetType === 'user') {
      navigate(`/profile/${targetId}`);
    }
  };

  useEffect(() => {
    if (activeTab === 'likes') {
      fetchLikes(1);
    } else {
      fetchFavorites(1);
    }
  }, [activeTab, likeTypeFilter, favoriteTypeFilter, fetchLikes, fetchFavorites]);

  // 渲染点赞项
  const renderLikeItem = (like: Like) => {
    return (
      <List.Item
        key={like.id}
        actions={[
          <Button
            key="view"
            type="link"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetail(like.targetId, like.targetType)}
          >
            查看
          </Button>
        ]}
      >
        <List.Item.Meta
          avatar={
            <Avatar 
              size={48} 
              icon={<LikeOutlined />}
              style={{ backgroundColor: '#ff4d4f' }}
            />
          }
          title={
            <Space>
              <Text strong>
                点赞了{interactionApi.getLikeTypeText(like.targetType)}
              </Text>
              <Tag color="red">{interactionApi.getLikeTypeText(like.targetType)}</Tag>
            </Space>
          }
          description={
            <Space direction="vertical" size={4}>
              <Text type="secondary">
                目标ID: {like.targetId}
              </Text>
              <Text type="secondary" style={{ fontSize: '12px' }}>
                {new Date(like.createdAt).toLocaleDateString('zh-CN')}
              </Text>
            </Space>
          }
        />
      </List.Item>
    );
  };

  // 渲染收藏项
  const renderFavoriteItem = (favorite: Favorite) => {
    return (
      <List.Item
        key={favorite.id}
        actions={[
          <Button
            key="view"
            type="link"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetail(favorite.targetId, favorite.targetType)}
          >
            查看
          </Button>
        ]}
      >
        <List.Item.Meta
          avatar={
            favorite.annotation?.imageUrl ? (
              <Avatar 
                size={48} 
                src={favorite.annotation.imageUrl}
                style={{ borderRadius: '8px' }}
              />
            ) : (
              <Avatar 
                size={48} 
                icon={<StarOutlined />}
                style={{ backgroundColor: '#faad14' }}
              />
            )
          }
          title={
            <Space>
              <Text strong>
                {favorite.annotation?.title || favorite.user?.username || `收藏的${interactionApi.getFavoriteTypeText(favorite.targetType)}`}
              </Text>
              <Tag color="gold">{interactionApi.getFavoriteTypeText(favorite.targetType)}</Tag>
            </Space>
          }
          description={
            <Space direction="vertical" size={4}>
              {favorite.annotation && (
                <>
                  <Paragraph 
                    ellipsis={{ rows: 2 }}
                    style={{ margin: 0, color: '#666' }}
                  >
                    {favorite.annotation.description}
                  </Paragraph>
                  <Space size={4}>
                    <EnvironmentOutlined style={{ color: '#1890ff' }} />
                    <Text type="secondary" style={{ fontSize: '12px' }}>
                      {favorite.annotation.location}
                    </Text>
                  </Space>
                </>
              )}
              {favorite.user && (
                <Space size={4}>
                  <UserOutlined style={{ color: '#52c41a' }} />
                  <Text type="secondary" style={{ fontSize: '12px' }}>
                    用户: {favorite.user.username}
                  </Text>
                </Space>
              )}
              <Text type="secondary" style={{ fontSize: '12px' }}>
                收藏于 {new Date(favorite.createdAt).toLocaleDateString('zh-CN')}
              </Text>
            </Space>
          }
        />
      </List.Item>
    );
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
        <div style={{ marginBottom: '24px' }}>
          <Title level={2}>
            <MessageOutlined style={{ marginRight: '8px', color: '#7f1d1d' }} />
            互动历史
          </Title>
        <Text type="secondary">
          查看您的点赞和收藏记录
        </Text>
      </div>

      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: '24px' }}>
        <Col span={12}>
          <Card>
            <Statistic
              title="总点赞数"
              value={data.likes.pagination.total}
              prefix={<LikeOutlined style={{ color: '#ff4d4f' }} />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={12}>
          <Card>
            <Statistic
              title="总收藏数"
              value={data.favorites.pagination.total}
              prefix={<StarOutlined style={{ color: '#faad14' }} />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 主要内容 */}
      <Card>
        <Tabs activeKey={activeTab} onChange={handleTabChange}>
          <TabPane
            tab={
              <Space>
                <LikeOutlined />
                点赞历史
                <Tag color="red">{data.likes.pagination.total}</Tag>
              </Space>
            }
            key="likes"
          >
            {/* 过滤器 */}
            <div style={{ marginBottom: '16px' }}>
              <Space>
                <Text>类型筛选：</Text>
                <Select
                  value={likeTypeFilter}
                  onChange={handleLikeTypeFilter}
                  style={{ width: 120 }}
                  allowClear
                  placeholder="全部类型"
                >
                  <Option value={LikeType.ANNOTATION}>标注</Option>
                  <Option value={LikeType.COMMENT}>评论</Option>
                  <Option value={LikeType.USER}>用户</Option>
                </Select>
              </Space>
            </div>

            {/* 点赞列表 */}
            <Spin spinning={loading}>
              {data.likes.data.length > 0 ? (
                <List
                  itemLayout="horizontal"
                  dataSource={data.likes.data}
                  renderItem={renderLikeItem}
                  pagination={{
                    current: data.likes.pagination.page,
                    total: data.likes.pagination.total,
                    pageSize: data.likes.pagination.limit,
                    showSizeChanger: true,
                    showQuickJumper: true,
                    showTotal: (total, range) => 
                      `第 ${range[0]}-${range[1]} 条，共 ${total} 条点赞记录`,
                    onChange: fetchLikes,
                    onShowSizeChange: (_current, size) => {
                      setData(prev => ({
                        ...prev,
                        likes: {
                          ...prev.likes,
                          pagination: {
                            ...prev.likes.pagination,
                            limit: size
                          }
                        }
                      }));
                      fetchLikes(1);
                    }
                  }}
                />
              ) : (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="暂无点赞记录"
                >
                  <Button type="primary" onClick={() => navigate('/map')}>
                    去发现有趣内容
                  </Button>
                </Empty>
              )}
            </Spin>
          </TabPane>

          <TabPane
            tab={
              <Space>
                <StarOutlined />
                收藏列表
                <Tag color="gold">{data.favorites.pagination.total}</Tag>
              </Space>
            }
            key="favorites"
          >
            {/* 过滤器 */}
            <div style={{ marginBottom: '16px' }}>
              <Space>
                <Text>类型筛选：</Text>
                <Select
                  value={favoriteTypeFilter}
                  onChange={handleFavoriteTypeFilter}
                  style={{ width: 120 }}
                  allowClear
                  placeholder="全部类型"
                >
                  <Option value={FavoriteType.ANNOTATION}>标注</Option>
                  <Option value={FavoriteType.USER}>用户</Option>
                </Select>
              </Space>
            </div>

            {/* 收藏列表 */}
            <Spin spinning={loading}>
              {data.favorites.data.length > 0 ? (
                <List
                  itemLayout="horizontal"
                  dataSource={data.favorites.data}
                  renderItem={renderFavoriteItem}
                  pagination={{
                    current: data.favorites.pagination.page,
                    total: data.favorites.pagination.total,
                    pageSize: data.favorites.pagination.limit,
                    showSizeChanger: true,
                    showQuickJumper: true,
                    showTotal: (total, range) => 
                      `第 ${range[0]}-${range[1]} 条，共 ${total} 条收藏记录`,
                    onChange: fetchFavorites,
                    onShowSizeChange: (_current, size) => {
                      setData(prev => ({
                        ...prev,
                        favorites: {
                          ...prev.favorites,
                          pagination: {
                            ...prev.favorites.pagination,
                            limit: size
                          }
                        }
                      }));
                      fetchFavorites(1);
                    }
                  }}
                />
              ) : (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="暂无收藏记录"
                >
                  <Button type="primary" onClick={() => navigate('/map')}>
                    去发现有趣内容
                  </Button>
                </Empty>
              )}
            </Spin>
          </TabPane>
        </Tabs>
      </Card>

      {/* 提示信息 */}
      <Card style={{ marginTop: '24px', backgroundColor: '#f6f8fa' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Title level={5} style={{ margin: 0 }}>
            💡 互动记录说明
          </Title>
          <Text type="secondary">
            这里记录了您在平台上的所有互动行为，包括点赞的内容和收藏的项目。
            您可以通过筛选功能快速找到特定类型的记录。
          </Text>
          <Space wrap>
            <Tag color="red">点赞记录</Tag>
            <Tag color="gold">收藏记录</Tag>
            <Tag color="blue">快速查看</Tag>
            <Tag color="green">类型筛选</Tag>
          </Space>
        </Space>
      </Card>
      </div>
    </div>
  );
};

export default InteractionHistoryPage;