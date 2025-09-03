import { Avatar, Badge, Button, Card, Col, Divider, Drawer, Modal, Row, Select, Space, Statistic, Table, Tag, Tooltip, Typography, message } from 'antd';


import React, { useState, useEffect, useCallback } from 'react';

import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { PageLoading } from '../components/LoadingSkeleton';
import { FadeIn, SlideUp } from '../components/OptimizedMotion';
import { DecorativeElements } from '../components/UI/DecorativeElements';

import { CheckOutlined, CloseOutlined, ExclamationCircleOutlined, EyeOutlined, FlagOutlined, UserOutlined } from '@ant-design/icons';
import adminApi, { 
  type ContentReview, 
  type ReviewStatusType
} from '../services/adminApi';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import 'dayjs/locale/zh-cn';

dayjs.extend(relativeTime);
dayjs.locale('zh-cn');

const { Title, Text, Paragraph } = Typography;
const { confirm } = Modal;

interface ContentReviewPageState {
  reviews: ContentReview[];
  loading: boolean;
  selectedReview: ContentReview | null;
  drawerVisible: boolean;
  stats: {
    pending: number;
    approved: number;
    rejected: number;
    total: number;
  };
  filters: {
    status: ReviewStatusType | 'all';
    type: 'annotation' | 'comment' | 'media' | 'all';
    contentType: string;
  };
  pagination: {
    current: number;
    pageSize: number;
    total: number;
  };
}

const AdminContentReviewPage: React.FC = () => {
  
  const [state, setState] = useState<ContentReviewPageState>({
    reviews: [],
    loading: false,
    selectedReview: null,
    drawerVisible: false,
    stats: {
      pending: 0,
      approved: 0,
      rejected: 0,
      total: 0
    },
    filters: {
      status: 'all',
      type: 'all',
      contentType: 'all'
    },
    pagination: {
      current: 1,
      pageSize: 10,
      total: 0
    }
  });



  // 解构状态
  const { reviews, loading, selectedReview, drawerVisible, stats, filters, pagination } = state;

  // 更新状态的辅助函数
  const setReviews = useCallback((reviews: ContentReview[]) => setState(prev => ({ ...prev, reviews })), []);
  const setLoading = useCallback((loading: boolean) => setState(prev => ({ ...prev, loading })), []);
  const setSelectedReview = useCallback((selectedReview: ContentReview | null) => setState(prev => ({ ...prev, selectedReview })), []);
  const setDrawerVisible = useCallback((drawerVisible: boolean) => setState(prev => ({ ...prev, drawerVisible })), []);
  const setStats = useCallback((stats: typeof state.stats) => setState(prev => ({ ...prev, stats })), [state]);
  const setFilters = useCallback((filters: typeof state.filters) => setState(prev => ({ ...prev, filters })), [state]);
  const setPagination = useCallback((pagination: Partial<typeof state.pagination>) => setState(prev => ({ ...prev, pagination: { ...prev.pagination, ...pagination } })), [state]);

  // 加载内容审核列表
  const loadReviews = useCallback(async () => {
    setLoading(true);
    try {
      const response = await adminApi.getContentReviews({
        page: pagination.current,
        limit: pagination.pageSize,
        status: filters.status === 'all' ? undefined : filters.status,
        type: filters.type === 'all' ? undefined : filters.type
      });
      
      setReviews(response.data || []);
      // Calculate stats from the data
      const calculatedStats = {
        pending: response.data?.filter(r => r.status === 'pending').length || 0,
        approved: response.data?.filter(r => r.status === 'approved').length || 0,
        rejected: response.data?.filter(r => r.status === 'rejected').length || 0,
        total: response.pagination?.total || 0
      };
      setStats(calculatedStats);
      setPagination({
        total: response.pagination?.total || 0
      });
    } catch {
      message.error('加载审核列表失败');
    } finally {
      setLoading(false);
    }
  }, [pagination, filters.status, filters.type, setReviews, setLoading, setStats, setPagination]);

  // 处理审核
  const handleReview = async (reviewId: string, action: 'approve' | 'reject', reason?: string) => {
    try {
      await adminApi.handleContentReview(reviewId, action, reason);
      message.success(`${action === 'approve' ? '通过' : '拒绝'}审核成功`);
      loadReviews();
      setDrawerVisible(false);
    } catch {
      message.error('处理审核失败');
    }
  };

  // 批量审核
  const handleBatchReview = (action: 'approve' | 'reject') => {
    // 实现批量审核逻辑
    message.info(`批量${action === 'approve' ? '通过' : '拒绝'}功能开发中`);
  };

  // 查看详情
  const viewDetails = (review: ContentReview) => {
    setSelectedReview(review);
    setDrawerVisible(true);
  };

  // 获取状态标签
  const getStatusBadge = (status: ReviewStatusType) => {
    const statusConfig: Record<ReviewStatusType, { color: string; text: string }> = {
      pending: { color: 'orange', text: '待审核' },
      approved: { color: 'green', text: '已通过' },
      rejected: { color: 'red', text: '已拒绝' }
    };
    return statusConfig[status] || { color: 'default', text: status };
  };

  // 获取举报原因标签
  const getReasonBadge = (reason: string | undefined) => {
    if (!reason) return { color: 'default', text: '无原因' };
    
    const reasonConfig: Record<string, { color: string; text: string }> = {
      spam: { color: 'red', text: '垃圾信息' },
      inappropriate: { color: 'orange', text: '不当内容' },
      harassment: { color: 'red', text: '骚扰' },
      fake: { color: 'purple', text: '虚假信息' },
      copyright: { color: 'blue', text: '版权问题' },
      other: { color: 'default', text: '其他' }
    };
    return reasonConfig[reason] || { color: 'default', text: reason };
  };

  // 处理状态变更
  const handleStatusChange = (reviewId: string, status: ReviewStatusType) => {
    confirm({
      title: `确认${status === 'approved' ? '通过' : '拒绝'}审核？`,
      icon: <ExclamationCircleOutlined />,
      onOk() {
        handleReview(reviewId, status === 'approved' ? 'approve' : 'reject');
      }
    });
  };

  // 表格列定义
  const columns: ColumnsType<ContentReview> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 100,
      render: (id: string) => (
        <Text code style={{ fontSize: '12px' }}>
          {id.slice(0, 8)}...
        </Text>
      )
    },
    {
      title: '内容类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (type: string) => {
        const typeConfig: Record<string, { color: string; text: string }> = {
          annotation: { color: 'blue', text: '标注' },
          comment: { color: 'green', text: '评论' },
          media: { color: 'purple', text: '媒体' }
        };
        const config = typeConfig[type] || { color: 'default', text: type };
        return <Tag color={config.color}>{config.text}</Tag>;
      }
    },
    {
      title: '内容预览',
      dataIndex: 'content_preview',
      key: 'content_preview',
      width: 200,
      render: (preview: string) => (
        <Paragraph ellipsis={{ rows: 2, tooltip: preview }}>
          {preview || '无预览内容'}
        </Paragraph>
      )
    },
    {
      title: '举报原因',
      dataIndex: 'reason',
      key: 'reason',
      width: 120,
      render: (reason: string) => {
        const config = getReasonBadge(reason);
        return <Tag color={config.color}>{config.text}</Tag>;
      }
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: ReviewStatusType) => {
        const config = getStatusBadge(status);
        return <Badge color={config.color} text={config.text} />;
      }
    },
    {
      title: '举报人',
      dataIndex: 'reporter_username',
      key: 'reporter_username',
      width: 120,
      render: (username: string) => (
        <Space>
          <Avatar size="small" icon={<UserOutlined />} />
          <Text>{username || '匿名'}</Text>
        </Space>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (date: string) => (
        <Tooltip title={dayjs(date).format('YYYY-MM-DD HH:mm:ss')}>
          <Text type="secondary">
            {dayjs(date).fromNow()}
          </Text>
        </Tooltip>
      )
    },
    {
      title: '操作',
      key: 'actions',
      width: 200,
      render: (_, record: ContentReview) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => viewDetails(record)}
          >
            查看
          </Button>
          {record.status === 'pending' && (
            <>
              <Button
                type="link"
                size="small"
                icon={<CheckOutlined />}
                style={{ color: '#52c41a' }}
                onClick={() => handleStatusChange(record.id, 'approved')}
              >
                通过
              </Button>
              <Button
                type="link"
                size="small"
                icon={<CloseOutlined />}
                danger
                onClick={() => handleStatusChange(record.id, 'rejected')}
              >
                拒绝
              </Button>
            </>
          )}
        </Space>
      )
    }
  ];

  useEffect(() => {
    loadReviews();
  }, [pagination.pageSize, filters, loadReviews]);

  if (loading && reviews.length === 0) {
    return <PageLoading />;
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50 relative">
        {/* 装饰元素 */}
        <DecorativeElements variant="background" />
        <DecorativeElements variant="floating" position="top-left" />
        <DecorativeElements variant="floating" position="top-right" />
        <DecorativeElements variant="floating" position="bottom-left" />
        <DecorativeElements variant="floating" position="bottom-right" />
        
        <div className="relative z-10" style={{ padding: '24px' }}>
        <FadeIn>
          <Title level={2} style={{ color: '#7f1d1d' }}>内容审核管理</Title>
        </FadeIn>
        
        {/* 统计卡片 */}
        <SlideUp>
          <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="待审核"
              value={stats.pending}
              valueStyle={{ color: '#dc2626' }}
              prefix={<ExclamationCircleOutlined style={{ color: '#dc2626' }} />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="已通过"
              value={stats.approved}
              valueStyle={{ color: '#059669' }}
              prefix={<CheckOutlined style={{ color: '#059669' }} />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="已拒绝"
              value={stats.rejected}
              valueStyle={{ color: '#7f1d1d' }}
              prefix={<CloseOutlined style={{ color: '#7f1d1d' }} />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="总计"
              value={stats.total}
              valueStyle={{ color: '#7f1d1d' }}
              prefix={<FlagOutlined style={{ color: '#7f1d1d' }} />}
            />
          </Card>
        </Col>
          </Row>
        </SlideUp>

        {/* 筛选器 */}
        <FadeIn>
          <Card style={{ marginBottom: 24 }}>
        <Space wrap>
          <Select
            value={filters.status}
            onChange={(value: ReviewStatusType | 'all') => setFilters({ ...filters, status: value })}
            style={{ width: 120 }}
          >
            <Select.Option value="all">全部状态</Select.Option>
            <Select.Option value="pending">待审核</Select.Option>
            <Select.Option value="approved">已通过</Select.Option>
            <Select.Option value="rejected">已拒绝</Select.Option>
          </Select>
          
          <Select
            value={filters.type}
            onChange={(value: 'annotation' | 'comment' | 'media' | 'all') => setFilters({ ...filters, type: value })}
            style={{ width: 120 }}
          >
            <Select.Option value="all">全部类型</Select.Option>
            <Select.Option value="annotation">标注</Select.Option>
            <Select.Option value="comment">评论</Select.Option>
            <Select.Option value="media">媒体</Select.Option>
          </Select>
          
          <Button onClick={loadReviews}>刷新</Button>
          
          <Button
            type="primary"
            onClick={() => handleBatchReview('approve')}
            disabled={!reviews.some(r => r.status === 'pending')}
          >
            批量通过
          </Button>
          
          <Button
            danger
            onClick={() => handleBatchReview('reject')}
            disabled={!reviews.some(r => r.status === 'pending')}
          >
            批量拒绝
          </Button>
        </Space>
          </Card>
        </FadeIn>

        {/* 审核列表 */}
        <SlideUp>
          <Card>
        <Table
          columns={columns}
          dataSource={reviews}
          rowKey="id"
          loading={loading}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
            onChange: (page, pageSize) => {
              setPagination({ ...pagination, current: page, pageSize: pageSize || 10 });
            }
          }}
        />
          </Card>
        </SlideUp>

        {/* 详情抽屉 */}
      <Drawer
        title="审核详情"
        width={600}
        open={drawerVisible}
        onClose={() => setDrawerVisible(false)}
        extra={
          selectedReview?.status === 'pending' && (
            <Space>
              <Button
                type="primary"
                icon={<CheckOutlined />}
                onClick={() => selectedReview && handleReview(selectedReview.id, 'approve')}
              >
                通过
              </Button>
              <Button
                danger
                icon={<CloseOutlined />}
                onClick={() => selectedReview && handleReview(selectedReview.id, 'reject')}
              >
                拒绝
              </Button>
            </Space>
          )
        }
      >
        {selectedReview && (
          <div>
            <Title level={4}>基本信息</Title>
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <Text strong>内容ID: </Text>
                <Text code>{selectedReview.content_id}</Text>
              </div>
              <div>
                <Text strong>类型: </Text>
                {selectedReview.type && (
                  <Tag color="blue">{selectedReview.type}</Tag>
                )}
              </div>
              <div>
                <Text strong>状态: </Text>
                <Badge
                  color={getStatusBadge(selectedReview.status as ReviewStatusType).color}
                  text={getStatusBadge(selectedReview.status as ReviewStatusType).text}
                />
              </div>
              <div>
                <Text strong>创建时间: </Text>
                <Text type="secondary">
                  {dayjs(selectedReview.created_at).format('YYYY-MM-DD HH:mm')}
                </Text>
              </div>
            </Space>

            <Divider />

            <Title level={4}>举报信息</Title>
            <Space direction="vertical" style={{ width: '100%' }}>
              <Space>
                <Avatar
                  icon={<UserOutlined />}
                />
                <Text>{selectedReview.reporter_username || '匿名用户'}</Text>
              </Space>
              <Text type="secondary" style={{ fontSize: '12px' }}>
                举报人: {selectedReview.reporter_username || '匿名'} (ID: {selectedReview.reported_by || 'N/A'})
              </Text>
            </Space>

            <Divider />

            <Title level={4}>内容预览</Title>
            <Paragraph ellipsis={{ rows: 3, expandable: true }}>
              {selectedReview.content_preview || '无预览内容'}
            </Paragraph>

            <Divider />

            <Title level={4}>举报详情</Title>
            <Paragraph>
              <Text strong>举报原因: </Text>
              {selectedReview.reason || '无原因'}
            </Paragraph>

            {selectedReview.reviewed_at && (
              <>
                <Divider />
                <Title level={4}>审核信息</Title>
                <Space direction="vertical" style={{ width: '100%' }}>
                  <div>
                    <Text strong>审核时间: </Text>
                    <Text>{dayjs(selectedReview.reviewed_at).format('YYYY-MM-DD HH:mm:ss')}</Text>
                  </div>
                  <div>
                    <Text strong>审核人: </Text>
                    <Text>{selectedReview.reviewed_by || '系统'}</Text>
                  </div>
                </Space>
              </>
            )}
          </div>
        )}
        </Drawer>
        </div>
      </div>
    </ErrorBoundary>
  );
};

export default AdminContentReviewPage;