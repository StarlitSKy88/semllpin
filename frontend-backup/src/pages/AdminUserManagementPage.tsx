import { Alert, Avatar, Badge, Button, Card, Col, Descriptions, Drawer, Form, Input, Modal, Popconfirm, Row, Select, Space, Statistic, Table, Tag, Tooltip, Typography, message } from 'antd';
import { DecorativeElements } from '../components/UI/DecorativeElements';



import React, { useState, useEffect, useCallback } from 'react';

import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { PageLoading } from '../components/LoadingSkeleton';
import { FadeIn, SlideUp } from '../components/OptimizedMotion';

import { CheckCircleOutlined, EditOutlined, ExportOutlined, EyeOutlined, ReloadOutlined, StopOutlined, UserOutlined, WarningOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';

import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { FilterValue, SorterResult } from 'antd/es/table/interface';
import adminApi, {
  type UserManagement,
  type UserStatusType,
  type UserManagementParams,
  UserStatus,
  getUserStatusText,
  getUserStatusColor,
  getAdminRoleText,
  formatDate,
  formatRelativeTime,
  formatCurrency,
  isAdmin
} from '../services/adminApi';

const { Search } = Input;
const { Option } = Select;
const { Title, Text } = Typography;

interface UserDetailDrawerProps {
  visible: boolean;
  user: UserManagement | null;
  onClose: () => void;
  onStatusUpdate: (userId: string, status: UserStatusType, reason?: string) => void;
}

const UserDetailDrawer: React.FC<UserDetailDrawerProps> = ({
  visible,
  user,
  onClose,
  onStatusUpdate
}) => {
  const [form] = Form.useForm();
  // const [, setLoading] = useState(false); // loading removed as unused

  const handleStatusUpdate = async (values: { status: UserStatusType; reason?: string }) => {
    if (!user) return;
    
    // setLoading(true);
    try {
      await onStatusUpdate(user.id, values.status, values.reason);
      message.success('用户状态更新成功');
      onClose();
    } catch {
      message.error('更新失败');
    } finally {
      // setLoading(false);
    }
  };

  if (!user) return null;

  return (
    <Drawer
      title="用户详情"
      width={600}
      open={visible}
      onClose={onClose}
      extra={
        <Space>
          <Button icon={<EditOutlined />} onClick={() => form.submit()}>
            更新状态
          </Button>
        </Space>
      }
    >
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {/* 基本信息 */}
        <Card title="基本信息" size="small">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="用户名">{user.username}</Descriptions.Item>
            <Descriptions.Item label="邮箱">{user.email}</Descriptions.Item>
            <Descriptions.Item label="角色">
              <Tag color="blue">{getAdminRoleText(user.role)}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={getUserStatusColor(user.status)}>
                {getUserStatusText(user.status)}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="注册时间">
              {formatDate(user.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label="最后登录">
              {user.last_login ? formatDate(user.last_login) : '从未登录'}
            </Descriptions.Item>
          </Descriptions>
        </Card>

        {/* 统计信息 */}
        <Card title="活动统计" size="small">
          <Row gutter={16}>
            <Col span={8}>
              <Statistic
                title="标注数量"
                value={user.total_annotations}
                suffix="条"
              />
            </Col>
            <Col span={8}>
              <Statistic
                title="总消费"
                value={user.total_spent}
                formatter={(value: unknown) => formatCurrency(value as number)}
              />
            </Col>
            <Col span={8}>
              <Statistic
                title="总收入"
                value={user.total_earned}
                formatter={(value: unknown) => formatCurrency(value as number)}
              />
            </Col>
          </Row>
        </Card>

        {/* 举报信息 */}
        {user.reports_count > 0 && (
          <Alert
            message={`该用户被举报 ${user.reports_count} 次`}
            type="warning"
            showIcon
            icon={<WarningOutlined />}
          />
        )}

        {/* 状态更新表单 */}
        <Card title="更新用户状态" size="small">
          <Form
            form={form}
            layout="vertical"
            initialValues={{ status: user.status }}
            onFinish={handleStatusUpdate}
          >
            <Form.Item
              name="status"
              label="用户状态"
              rules={[{ required: true, message: '请选择用户状态' }]}
            >
              <Select>
                <Option value={UserStatus.ACTIVE}>
                  <Space>
                    <CheckCircleOutlined style={{ color: '#52c41a' }} />
                    {getUserStatusText(UserStatus.ACTIVE)}
                  </Space>
                </Option>
                <Option value={UserStatus.SUSPENDED}>
                  <Space>
                    <StopOutlined style={{ color: '#faad14' }} />
                    {getUserStatusText(UserStatus.SUSPENDED)}
                  </Space>
                </Option>
                <Option value={UserStatus.BANNED}>
                  <Space>
                    <WarningOutlined style={{ color: '#f5222d' }} />
                    {getUserStatusText(UserStatus.BANNED)}
                  </Space>
                </Option>
              </Select>
            </Form.Item>
            <Form.Item
              name="reason"
              label="操作原因"
              rules={[{ max: 500, message: '原因不能超过500字符' }]}
            >
              <Input.TextArea
                rows={3}
                placeholder="请输入操作原因（可选）"
              />
            </Form.Item>
          </Form>
        </Card>
      </Space>
    </Drawer>
  );
};

const AdminUserManagementPage: React.FC = () => {
  
  const navigate = useNavigate();
  const { user: currentUser } = useAuthStore();
  const [loading, setLoading] = useState(false);
  const [users, setUsers] = useState<UserManagement[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  // const [selectedUsers, setSelectedUsers] = useState<UserManagement[]>([]); // Removed as unused
  const [detailVisible, setDetailVisible] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserManagement | null>(null);
  const [batchModalVisible, setBatchModalVisible] = useState(false);
  const [batchForm] = Form.useForm();

  // 查询参数
  const [params, setParams] = useState<UserManagementParams>({
    page: 1,
    limit: 20,
    sortBy: 'created_at',
    sortOrder: 'desc'
  });

  // 检查权限
  useEffect(() => {
    if (!currentUser || !isAdmin(currentUser.role)) {
      navigate('/');
      return;
    }
  }, [currentUser, navigate]);

  // 加载用户列表
  const loadUsers = useCallback(async () => {
    try {
      setLoading(true);
      const response = await adminApi.getUserManagement(params);
      setUsers(response.data);
      setTotal(response.pagination.total);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '加载用户列表失败';
      message.error(errorMessage || '加载用户列表失败');
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  // 处理搜索
  const handleSearch = (value: string) => {
    setParams(prev => ({ ...prev, search: value || undefined, page: 1 }));
  };

  // 处理筛选
  const handleFilter = (field: string, value: string | number | boolean | null) => {
    setParams(prev => ({ ...prev, [field]: value || undefined, page: 1 }));
  };

  // 处理排序
  const handleTableChange = (
    pagination: TablePaginationConfig,
    _filters: Record<string, FilterValue | null>,
    sorter: SorterResult<UserManagement> | SorterResult<UserManagement>[]
  ) => {
    const sortConfig = Array.isArray(sorter) ? sorter[0] : sorter;
    setParams(prev => ({
      ...prev,
      page: pagination.current || 1,
      limit: pagination.pageSize || 10,
      sortBy: (sortConfig?.field as 'email' | 'username' | 'created_at' | 'total_annotations' | 'total_spent' | 'reports_count') || 'created_at',
      sortOrder: sortConfig?.order === 'ascend' ? 'asc' : 'desc'
    }));
  };

  // 处理用户状态更新
  const handleStatusUpdate = async (userId: string, status: UserStatusType, reason?: string) => {
    try {
      await adminApi.updateUserStatus(userId, status, reason);
      message.success('用户状态更新成功');
      loadUsers();
    } catch (error: unknown) {
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '更新失败';
      message.error(errorMessage || '更新失败');
    }
  };

  // 处理批量操作
  const handleBatchOperation = async (values: { operation: 'suspend' | 'activate' | 'ban' | 'delete'; reason?: string }) => {
    try {
      const userIds = selectedRowKeys as string[];
      await adminApi.batchUserOperation(userIds, values.operation, values.reason);
      message.success(`批量${values.operation}操作成功`);
      setSelectedRowKeys([]);
      // setSelectedUsers([]); // Removed as unused
      setBatchModalVisible(false);
      batchForm.resetFields();
      loadUsers();
    } catch (error: unknown) {
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '批量操作失败';
      message.error(errorMessage || '批量操作失败');
    }
  };

  // 表格列配置
  const columns: ColumnsType<UserManagement> = [
    {
      title: '用户',
      dataIndex: 'username',
      key: 'username',
      sorter: true,
      render: (text: string, record: UserManagement) => (
        <Space>
          <Avatar icon={<UserOutlined />} size="small" />
          <div>
            <div>{text}</div>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {record.email}
            </Text>
          </div>
        </Space>
      )
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      render: (role: string) => (
        <Tag color="blue">{getAdminRoleText(role)}</Tag>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: UserStatusType) => (
        <Tag color={getUserStatusColor(status)}>
          {getUserStatusText(status)}
        </Tag>
      )
    },
    {
      title: '标注数',
      dataIndex: 'total_annotations',
      key: 'total_annotations',
      sorter: true,
      render: (value: number) => value.toLocaleString()
    },
    {
      title: '消费金额',
      dataIndex: 'total_spent',
      key: 'total_spent',
      sorter: true,
      render: (value: number) => formatCurrency(value)
    },
    {
      title: '举报次数',
      dataIndex: 'reports_count',
      key: 'reports_count',
      sorter: true,
      render: (count: number) => (
        count > 0 ? (
          <Badge count={count} style={{ backgroundColor: '#f5222d' }} />
        ) : (
          <span>0</span>
        )
      )
    },
    {
      title: '注册时间',
      dataIndex: 'created_at',
      key: 'created_at',
      sorter: true,
      render: (date: string) => (
        <Tooltip title={formatDate(date)}>
          {formatRelativeTime(date)}
        </Tooltip>
      )
    },
    {
      title: '操作',
      key: 'action',
      width: 200,
      render: (record: UserManagement) => (
        <Space size="small">
          <Tooltip title="查看详情">
            <Button
              type="text"
              icon={<EyeOutlined />}
              onClick={() => {
                setSelectedUser(record);
                setDetailVisible(true);
              }}
            />
          </Tooltip>
          <Tooltip title="快速暂停">
            <Popconfirm
              title="确定要暂停该用户吗？"
              onConfirm={() => handleStatusUpdate(record.id, UserStatus.SUSPENDED)}
              disabled={record.status === UserStatus.SUSPENDED}
            >
              <Button
                type="text"
                icon={<StopOutlined />}
                disabled={record.status === UserStatus.SUSPENDED}
              />
            </Popconfirm>
          </Tooltip>
          <Tooltip title="快速激活">
            <Popconfirm
              title="确定要激活该用户吗？"
              onConfirm={() => handleStatusUpdate(record.id, UserStatus.ACTIVE)}
              disabled={record.status === UserStatus.ACTIVE}
            >
              <Button
                type="text"
                icon={<CheckCircleOutlined />}
                disabled={record.status === UserStatus.ACTIVE}
              />
            </Popconfirm>
          </Tooltip>
        </Space>
      )
    }
  ];

  // 行选择配置
  const rowSelection = {
    selectedRowKeys,
    onChange: (keys: React.Key[]) => {
      setSelectedRowKeys(keys);
      // setSelectedUsers(rows); // Removed as unused
    },
    getCheckboxProps: (record: UserManagement) => ({
      disabled: record.role === 'super_admin' && currentUser?.role !== 'super_admin'
    })
  };

  if (loading && users.length === 0) {
    return <PageLoading />;
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
        <DecorativeElements variant="background" />
        <DecorativeElements variant="floating" position="top-left" />
        <DecorativeElements variant="floating" position="top-right" />
        <DecorativeElements variant="floating" position="bottom-left" />
        <DecorativeElements variant="floating" position="bottom-right" />
        
        <div className="relative z-10" style={{ padding: '24px' }}>
          <FadeIn>
            <Card>
              <div style={{ marginBottom: '16px' }}>
                <Title level={3} style={{ color: '#7f1d1d' }}>用户管理</Title>
              <Text type="secondary">管理平台用户账户和权限</Text>
            </div>

            {/* 搜索和筛选 */}
            <SlideUp>
              <Row gutter={[16, 16]} style={{ marginBottom: '16px' }}>
          <Col xs={24} sm={12} md={8}>
            <Search
              placeholder="搜索用户名或邮箱"
              allowClear
              onSearch={handleSearch}
              style={{ width: '100%' }}
            />
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Select
              placeholder="筛选状态"
              allowClear
              style={{ width: '100%' }}
              onChange={(value) => handleFilter('status', value)}
            >
              <Option value={UserStatus.ACTIVE}>{getUserStatusText(UserStatus.ACTIVE)}</Option>
              <Option value={UserStatus.SUSPENDED}>{getUserStatusText(UserStatus.SUSPENDED)}</Option>
              <Option value={UserStatus.BANNED}>{getUserStatusText(UserStatus.BANNED)}</Option>
              <Option value={UserStatus.PENDING}>{getUserStatusText(UserStatus.PENDING)}</Option>
            </Select>
          </Col>
          <Col xs={24} sm={24} md={10}>
            <Space>
              <Button
                icon={<ReloadOutlined />}
                onClick={loadUsers}
                loading={loading}
              >
                刷新
              </Button>
              <Button
                icon={<ExportOutlined />}
                onClick={() => message.info('导出功能开发中')}
              >
                导出
              </Button>
              {selectedRowKeys.length > 0 && (
                <Button
                  type="primary"
                  onClick={() => setBatchModalVisible(true)}
                >
                  批量操作 ({selectedRowKeys.length})
                </Button>
              )}
            </Space>
          </Col>
              </Row>
            </SlideUp>

            {/* 用户表格 */}
            <FadeIn>
              <Table
          rowSelection={rowSelection}
          columns={columns}
          dataSource={users}
          rowKey="id"
          loading={loading}
          pagination={{
            current: params.page,
            pageSize: params.limit,
            total,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`
          }}
          onChange={handleTableChange}
          scroll={{ x: 1200 }}
              />
            </FadeIn>
          </Card>
        </FadeIn>

        {/* 用户详情抽屉 */}
      <UserDetailDrawer
        visible={detailVisible}
        user={selectedUser}
        onClose={() => {
          setDetailVisible(false);
          setSelectedUser(null);
        }}
        onStatusUpdate={handleStatusUpdate}
      />

      {/* 批量操作模态框 */}
      <Modal
        title="批量操作"
        open={batchModalVisible}
        onCancel={() => {
          setBatchModalVisible(false);
          batchForm.resetFields();
        }}
        onOk={() => batchForm.submit()}
        confirmLoading={loading}
      >
        <Alert
          message={`已选择 ${selectedRowKeys.length} 个用户`}
          type="info"
          style={{ marginBottom: '16px' }}
        />
        <Form
          form={batchForm}
          layout="vertical"
          onFinish={handleBatchOperation}
        >
          <Form.Item
            name="operation"
            label="操作类型"
            rules={[{ required: true, message: '请选择操作类型' }]}
          >
            <Select placeholder="选择要执行的操作">
              <Option value="activate">激活用户</Option>
              <Option value="suspend">暂停用户</Option>
              <Option value="ban">封禁用户</Option>
              <Option value="delete">删除用户</Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="reason"
            label="操作原因"
            rules={[{ max: 500, message: '原因不能超过500字符' }]}
          >
            <Input.TextArea
              rows={3}
              placeholder="请输入操作原因（可选）"
            />
          </Form.Item>
        </Form>
        </Modal>
        </div>
      </div>
    </ErrorBoundary>
  );
};

export default AdminUserManagementPage;