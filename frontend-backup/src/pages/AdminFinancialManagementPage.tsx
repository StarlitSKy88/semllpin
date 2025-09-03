import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  Table,
  Button,
  Space,
  Tag,
  Statistic,
  Row,
  Col,
  DatePicker,
  Select,
  Input,
  Modal,
  Form,
  message,
  Tabs,
  Drawer,
  Descriptions,
  Tooltip,
  Badge
} from 'antd';
import { DecorativeElements } from '../components/UI/DecorativeElements';
import {
  ExportOutlined,
  EyeOutlined,
  CheckOutlined,
  CloseOutlined,
  DownloadOutlined,
  RiseOutlined
} from '@ant-design/icons';
import { Line, Pie } from '@ant-design/plots';
import dayjs from 'dayjs';
import adminApi from '../services/adminApi';
import type { FinancialOverview, TransactionRecord, FinancialParams, WithdrawalParams, WithdrawalRequest } from '../services/adminApi';

const { RangePicker } = DatePicker;
const { Option } = Select;
const { Search } = Input;
const { TabPane } = Tabs;

interface Transaction {
  id: string;
  type: 'annotation_payment' | 'reward_payout' | 'withdrawal' | 'refund';
  amount: number;
  fee: number;
  netAmount: number;
  status: 'pending' | 'completed' | 'failed' | 'cancelled';
  userId: string;
  userName: string;
  description: string;
  createdAt: string;
  completedAt?: string;
  paymentMethod: string;
  transactionId: string;
}

interface WithdrawalRequestDisplay {
  id: string;
  userId: string;
  userName: string;
  amount: number;
  fee: number;
  netAmount: number;
  status: 'pending' | 'approved' | 'rejected' | 'completed';
  paymentMethod: string;
  accountInfo: string;
  requestedAt: string;
  processedAt?: string;
  processedBy?: string;
  rejectReason?: string;
}

interface FinancialStats {
  totalRevenue: number;
  totalFees: number;
  totalPayouts: number;
  pendingWithdrawals: number;
  dailyRevenue: Array<{ date: string; revenue: number; fees: number }>;
  revenueByType: Array<{ type: string; amount: number }>;
  monthlyGrowth: number;
}

const AdminFinancialManagementPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [withdrawalRequests, setWithdrawalRequests] = useState<WithdrawalRequestDisplay[]>([]);
  const [financialStats, setFinancialStats] = useState<FinancialStats | null>(null);
  const [selectedTransaction, setSelectedTransaction] = useState<Transaction | null>(null);
  const [selectedWithdrawal, setSelectedWithdrawal] = useState<WithdrawalRequestDisplay | null>(null);
  const [transactionDrawerVisible, setTransactionDrawerVisible] = useState(false);
  const [withdrawalDrawerVisible, setWithdrawalDrawerVisible] = useState(false);
  const [withdrawalModalVisible, setWithdrawalModalVisible] = useState(false);
  const [dateRange, setDateRange] = useState<[dayjs.Dayjs, dayjs.Dayjs] | null>(null);
  const [transactionType, setTransactionType] = useState<string>('all');
  const [withdrawalStatus, setWithdrawalStatus] = useState<string>('all');
  const [searchKeyword, setSearchKeyword] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  
  const [form] = Form.useForm();
  // const dispatch = useAppDispatch();
  // const { user } = useAppSelector(state => state.auth);

  // 数据获取函数
  const fetchFinancialOverview = async (): Promise<FinancialOverview> => {
    try {
      return await adminApi.getFinancialOverview();
    } catch {
      message.error('获取财务概览失败');
      throw new Error('获取财务概览失败');
    }
  };

  const fetchTransactionRecords = async (params: FinancialParams): Promise<{ data: TransactionRecord[], total: number }> => {
    try {
      const response = await adminApi.getTransactionRecords(params);
      return {
        data: response.data,
        total: response.pagination.total
      };
    } catch {
      message.error('获取交易记录失败');
      throw new Error('获取交易记录失败');
    }
  };

  const fetchWithdrawalRequests = async (params: WithdrawalParams): Promise<{ data: WithdrawalRequestDisplay[], total: number }> => {
    try {
      const response = await adminApi.getWithdrawalRequests(params);
      return {
        data: response.data.map((item: WithdrawalRequest) => ({
          id: item.id,
          userId: item.user_id,
          userName: item.username,
          amount: item.amount,
          fee: item.fee,
          netAmount: item.net_amount,
          status: item.status as 'pending' | 'approved' | 'rejected' | 'completed',
          paymentMethod: item.payment_method,
          accountInfo: JSON.stringify(item.payment_details || {}),
          requestedAt: item.requested_at,
          processedAt: item.processed_at || undefined,
          processedBy: item.processed_by || undefined,
          rejectReason: item.rejection_reason || undefined
        })),
        total: response.pagination.total
      };
    } catch {
      message.error('获取提现申请失败');
      throw new Error('获取提现申请失败');
    }
  };

  const loadFinancialData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, transactionsRes, withdrawalsRes] = await Promise.all([
        fetchFinancialOverview(),
        fetchTransactionRecords({
          type: transactionType === 'all' ? undefined : transactionType as 'payment' | 'reward' | 'withdrawal' | 'refund',
          startDate: dateRange?.[0]?.format('YYYY-MM-DD'),
          endDate: dateRange?.[1]?.format('YYYY-MM-DD'),
          userId: searchKeyword || undefined
        }),
        fetchWithdrawalRequests({
            status: withdrawalStatus === 'all' ? undefined : withdrawalStatus as 'pending' | 'approved' | 'rejected' | 'completed'
          })
      ]);
      
      setFinancialStats({
        totalRevenue: statsRes.totalRevenue,
        totalFees: statsRes.platformFees,
        totalPayouts: statsRes.totalWithdrawals,
        pendingWithdrawals: statsRes.pendingWithdrawals,
        dailyRevenue: [],
        revenueByType: [],
        monthlyGrowth: 0
      });
      setTransactions(transactionsRes.data.map(item => ({
        id: item.id,
        type: item.type as 'annotation_payment' | 'reward_payout' | 'withdrawal' | 'refund',
        amount: item.amount,
        fee: item.fee,
        netAmount: item.amount - item.fee,
        status: item.status as 'pending' | 'completed' | 'failed' | 'cancelled',
        userId: item.user_id,
        userName: item.username || '',
        description: item.description || '',
        createdAt: item.created_at,
        completedAt: item.completed_at,
        paymentMethod: item.payment_method || '',
        transactionId: item.transaction_id || item.id
      })));
      setWithdrawalRequests(withdrawalsRes.data);
    } catch {
      message.error('加载财务数据失败');
    } finally {
      setLoading(false);
    }
  }, [dateRange, transactionType, withdrawalStatus, searchKeyword]);

  useEffect(() => {
    loadFinancialData();
  }, [loadFinancialData]);

  const handleWithdrawalAction = async (id: string, action: 'approve' | 'reject', rejectReason?: string) => {
    try {
      await adminApi.handleWithdrawalRequest(id, action, rejectReason);
      message.success(`提现申请已${action === 'approve' ? '批准' : '拒绝'}`);
      loadFinancialData();
      setWithdrawalModalVisible(false);
    } catch {
      message.error('操作失败');
    }
  };

  const exportTransactions = async () => {
    try {
      const response = await adminApi.exportFinancialData({
        type: transactionType === 'all' ? undefined : transactionType as 'payment' | 'reward' | 'withdrawal' | 'refund',
        startDate: dateRange?.[0]?.format('YYYY-MM-DD'),
        endDate: dateRange?.[1]?.format('YYYY-MM-DD')
      });
      
      // 创建下载链接
      const url = window.URL.createObjectURL(response);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `transactions_${dayjs().format('YYYY-MM-DD')}.xlsx`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      message.success('交易记录导出成功');
    } catch {
      message.error('导出失败');
    }
  };

  const getTransactionTypeTag = (type: string) => {
    const typeMap = {
      annotation_payment: { color: 'green', text: '标注付费' },
      reward_payout: { color: 'blue', text: '奖励发放' },
      withdrawal: { color: 'orange', text: '提现' },
      refund: { color: 'red', text: '退款' }
    };
    const config = typeMap[type as keyof typeof typeMap] || { color: 'default', text: type };
    return <Tag color={config.color}>{config.text}</Tag>;
  };

  const getStatusTag = (status: string) => {
    const statusMap = {
      pending: { color: 'processing', text: '处理中' },
      completed: { color: 'success', text: '已完成' },
      failed: { color: 'error', text: '失败' },
      cancelled: { color: 'default', text: '已取消' },
      approved: { color: 'success', text: '已批准' },
      rejected: { color: 'error', text: '已拒绝' }
    };
    const config = statusMap[status as keyof typeof statusMap] || { color: 'default', text: status };
    return <Tag color={config.color}>{config.text}</Tag>;
  };

  const transactionColumns = [
    {
      title: '交易ID',
      dataIndex: 'transactionId',
      key: 'transactionId',
      width: 120,
      render: (text: string) => (
        <Tooltip title={text}>
          <span style={{ fontFamily: 'monospace' }}>{text.slice(-8)}</span>
        </Tooltip>
      )
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: getTransactionTypeTag
    },
    {
      title: '用户',
      dataIndex: 'userName',
      key: 'userName',
      width: 120
    },
    {
      title: '金额',
      dataIndex: 'amount',
      key: 'amount',
      width: 100,
      render: (amount: number) => `¥${amount.toFixed(2)}`
    },
    {
      title: '手续费',
      dataIndex: 'fee',
      key: 'fee',
      width: 80,
      render: (fee: number) => `¥${fee.toFixed(2)}`
    },
    {
      title: '净额',
      dataIndex: 'netAmount',
      key: 'netAmount',
      width: 100,
      render: (netAmount: number) => `¥${netAmount.toFixed(2)}`
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: getStatusTag
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 150,
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm')
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      render: (_: unknown, record: Transaction) => (
        <Button
          type="link"
          icon={<EyeOutlined />}
          onClick={() => {
            setSelectedTransaction(record);
            setTransactionDrawerVisible(true);
          }}
        >
          详情
        </Button>
      )
    }
  ];

  const withdrawalColumns = [
    {
      title: '申请ID',
      dataIndex: 'id',
      key: 'id',
      width: 120,
      render: (text: string) => (
        <span style={{ fontFamily: 'monospace' }}>{text.slice(-8)}</span>
      )
    },
    {
      title: '用户',
      dataIndex: 'userName',
      key: 'userName',
      width: 120
    },
    {
      title: '提现金额',
      dataIndex: 'amount',
      key: 'amount',
      width: 100,
      render: (amount: number) => `¥${amount.toFixed(2)}`
    },
    {
      title: '手续费',
      dataIndex: 'fee',
      key: 'fee',
      width: 80,
      render: (fee: number) => `¥${fee.toFixed(2)}`
    },
    {
      title: '实际到账',
      dataIndex: 'netAmount',
      key: 'netAmount',
      width: 100,
      render: (netAmount: number) => `¥${netAmount.toFixed(2)}`
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: getStatusTag
    },
    {
      title: '申请时间',
      dataIndex: 'requestedAt',
      key: 'requestedAt',
      width: 150,
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm')
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      render: (_: unknown, record: WithdrawalRequestDisplay) => (
        <Space>
          <Button
            type="link"
            icon={<EyeOutlined />}
            onClick={() => {
              setSelectedWithdrawal(record);
              setWithdrawalDrawerVisible(true);
            }}
          >
            详情
          </Button>
          {record.status === 'pending' && (
            <>
              <Button
                type="link"
                icon={<CheckOutlined />}
                onClick={() => handleWithdrawalAction(record.id, 'approve')}
              >
                批准
              </Button>
              <Button
                type="link"
                danger
                icon={<CloseOutlined />}
                onClick={() => {
                  setSelectedWithdrawal(record);
                  setWithdrawalModalVisible(true);
                }}
              >
                拒绝
              </Button>
            </>
          )}
        </Space>
      )
    }
  ];

  const renderOverview = () => (
    <div>
      {/* 统计卡片 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="总收入"
              value={financialStats?.totalRevenue || 0}
              precision={2}
              prefix="¥"
              valueStyle={{ color: '#3f8600' }}
              suffix={
                <span style={{ fontSize: 14, color: '#666' }}>
                  <RiseOutlined /> {financialStats?.monthlyGrowth || 0}%
                </span>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="手续费收入"
              value={financialStats?.totalFees || 0}
              precision={2}
              prefix="¥"
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="奖励支出"
              value={financialStats?.totalPayouts || 0}
              precision={2}
              prefix="¥"
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="待处理提现"
              value={financialStats?.pendingWithdrawals || 0}
              precision={2}
              prefix="¥"
              valueStyle={{ color: '#fa8c16' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 图表 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={16}>
          <Card title="收入趋势" extra={<Button icon={<ExportOutlined />}>导出</Button>}>
            {financialStats?.dailyRevenue && (
              <Line
                data={financialStats.dailyRevenue}
                xField="date"
                yField="revenue"
                seriesField="type"
                height={300}
                smooth
                point={{
                  size: 3,
                  shape: 'circle'
                }}
              />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={8}>
          <Card title="收入构成">
            {financialStats?.revenueByType && (
              <Pie
                data={financialStats.revenueByType}
                angleField="amount"
                colorField="type"
                radius={0.8}
                height={300}
                label={{
                  type: 'outer',
                  content: '{name} {percentage}'
                }}
              />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      <DecorativeElements variant="background" />
      <DecorativeElements variant="floating" position="top-left" />
      <DecorativeElements variant="floating" position="top-right" />
      <DecorativeElements variant="floating" position="bottom-left" />
      <DecorativeElements variant="floating" position="bottom-right" />
      
      <div className="relative z-10" style={{ padding: 24 }}>
        <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h1 style={{ color: '#7f1d1d' }}>财务管理</h1>
        <Space>
          <Button icon={<DownloadOutlined />} onClick={exportTransactions}>
            导出数据
          </Button>
        </Space>
      </div>

      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        <TabPane tab="财务概览" key="overview">
          {renderOverview()}
        </TabPane>
        
        <TabPane tab="交易记录" key="transactions">
          <Card>
            <div style={{ marginBottom: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              <RangePicker
                value={dateRange}
                onChange={(dates) => setDateRange(dates as [dayjs.Dayjs, dayjs.Dayjs] | null)}
                placeholder={['开始日期', '结束日期']}
              />
              <Select
                value={transactionType}
                onChange={setTransactionType}
                style={{ width: 120 }}
                placeholder="交易类型"
              >
                <Option value="all">全部类型</Option>
                <Option value="annotation_payment">标注付费</Option>
                <Option value="reward_payout">奖励发放</Option>
                <Option value="withdrawal">提现</Option>
                <Option value="refund">退款</Option>
              </Select>
              <Search
                placeholder="搜索用户名或交易ID"
                value={searchKeyword}
                onChange={(e) => setSearchKeyword(e.target.value)}
                style={{ width: 200 }}
                allowClear
              />
            </div>
            
            <Table
              columns={transactionColumns}
              dataSource={transactions}
              rowKey="id"
              loading={loading}
              pagination={{
                total: transactions.length,
                pageSize: 20,
                showSizeChanger: true,
                showQuickJumper: true,
                showTotal: (total) => `共 ${total} 条记录`
              }}
              scroll={{ x: 1000 }}
            />
          </Card>
        </TabPane>
        
        <TabPane tab={<Badge count={withdrawalRequests.filter(w => w.status === 'pending').length}>提现审核</Badge>} key="withdrawals">
          <Card>
            <div style={{ marginBottom: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              <Select
                value={withdrawalStatus}
                onChange={setWithdrawalStatus}
                style={{ width: 120 }}
                placeholder="状态"
              >
                <Option value="all">全部状态</Option>
                <Option value="pending">待审核</Option>
                <Option value="approved">已批准</Option>
                <Option value="rejected">已拒绝</Option>
                <Option value="completed">已完成</Option>
              </Select>
              <Search
                placeholder="搜索用户名"
                value={searchKeyword}
                onChange={(e) => setSearchKeyword(e.target.value)}
                style={{ width: 200 }}
                allowClear
              />
            </div>
            
            <Table
              columns={withdrawalColumns}
              dataSource={withdrawalRequests}
              rowKey="id"
              loading={loading}
              pagination={{
                total: withdrawalRequests.length,
                pageSize: 20,
                showSizeChanger: true,
                showQuickJumper: true,
                showTotal: (total) => `共 ${total} 条记录`
              }}
              scroll={{ x: 1000 }}
            />
          </Card>
        </TabPane>
      </Tabs>

      {/* 交易详情抽屉 */}
      <Drawer
        title="交易详情"
        width={600}
        open={transactionDrawerVisible}
        onClose={() => setTransactionDrawerVisible(false)}
      >
        {selectedTransaction && (
          <Descriptions column={1} bordered>
            <Descriptions.Item label="交易ID">{selectedTransaction.transactionId}</Descriptions.Item>
            <Descriptions.Item label="类型">{getTransactionTypeTag(selectedTransaction.type)}</Descriptions.Item>
            <Descriptions.Item label="用户">{selectedTransaction.userName}</Descriptions.Item>
            <Descriptions.Item label="描述">{selectedTransaction.description}</Descriptions.Item>
            <Descriptions.Item label="金额">¥{selectedTransaction.amount.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="手续费">¥{selectedTransaction.fee.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="净额">¥{selectedTransaction.netAmount.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="支付方式">{selectedTransaction.paymentMethod}</Descriptions.Item>
            <Descriptions.Item label="状态">{getStatusTag(selectedTransaction.status)}</Descriptions.Item>
            <Descriptions.Item label="创建时间">
              {dayjs(selectedTransaction.createdAt).format('YYYY-MM-DD HH:mm:ss')}
            </Descriptions.Item>
            {selectedTransaction.completedAt && (
              <Descriptions.Item label="完成时间">
                {dayjs(selectedTransaction.completedAt).format('YYYY-MM-DD HH:mm:ss')}
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
      </Drawer>

      {/* 提现详情抽屉 */}
      <Drawer
        title="提现详情"
        width={600}
        open={withdrawalDrawerVisible}
        onClose={() => setWithdrawalDrawerVisible(false)}
      >
        {selectedWithdrawal && (
          <Descriptions column={1} bordered>
            <Descriptions.Item label="申请ID">{selectedWithdrawal.id}</Descriptions.Item>
            <Descriptions.Item label="用户">{selectedWithdrawal.userName}</Descriptions.Item>
            <Descriptions.Item label="提现金额">¥{selectedWithdrawal.amount.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="手续费">¥{selectedWithdrawal.fee.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="实际到账">¥{selectedWithdrawal.netAmount.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="支付方式">{selectedWithdrawal.paymentMethod}</Descriptions.Item>
            <Descriptions.Item label="账户信息">{selectedWithdrawal.accountInfo}</Descriptions.Item>
            <Descriptions.Item label="状态">{getStatusTag(selectedWithdrawal.status)}</Descriptions.Item>
            <Descriptions.Item label="申请时间">
              {dayjs(selectedWithdrawal.requestedAt).format('YYYY-MM-DD HH:mm:ss')}
            </Descriptions.Item>
            {selectedWithdrawal.processedAt && (
              <Descriptions.Item label="处理时间">
                {dayjs(selectedWithdrawal.processedAt).format('YYYY-MM-DD HH:mm:ss')}
              </Descriptions.Item>
            )}
            {selectedWithdrawal.processedBy && (
              <Descriptions.Item label="处理人">{selectedWithdrawal.processedBy}</Descriptions.Item>
            )}
            {selectedWithdrawal.rejectReason && (
              <Descriptions.Item label="拒绝原因">{selectedWithdrawal.rejectReason}</Descriptions.Item>
            )}
          </Descriptions>
        )}
      </Drawer>

      {/* 拒绝提现模态框 */}
      <Modal
        title="拒绝提现申请"
        open={withdrawalModalVisible}
        onCancel={() => setWithdrawalModalVisible(false)}
        footer={null}
      >
        <Form
          form={form}
          onFinish={(values) => {
            if (selectedWithdrawal) {
              handleWithdrawalAction(selectedWithdrawal.id, 'reject', values.reason);
            }
          }}
          layout="vertical"
        >
          <Form.Item
            name="reason"
            label="拒绝原因"
            rules={[{ required: true, message: '请输入拒绝原因' }]}
          >
            <Input.TextArea rows={4} placeholder="请详细说明拒绝原因..." />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                确认拒绝
              </Button>
              <Button onClick={() => setWithdrawalModalVisible(false)}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
      </div>
    </div>
  );
};

export default AdminFinancialManagementPage;