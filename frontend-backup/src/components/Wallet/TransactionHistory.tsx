import { Button, Card, Col, DatePicker, Empty, Input, Row, Select, Space, Statistic, Table, Tag, Typography } from 'antd';

import React, { useState, useEffect, useCallback } from 'react';

import { SearchOutlined, DownloadOutlined, FilterOutlined, DollarOutlined } from '@ant-design/icons';
import { useUIStore } from '../../stores/uiStore';
import api from '../../utils/api';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';

const { Text } = Typography; // Title removed as unused
const { RangePicker } = DatePicker;
const { Option } = Select;

interface Transaction {
  id: string;
  type: 'payment' | 'refund' | 'reward' | 'topup';
  amount: number;
  currency: string;
  description: string;
  status: 'completed' | 'pending' | 'failed' | 'cancelled';
  prankId?: string;
  sessionId?: string;
  createdAt: string;
  updatedAt: string;
}

interface TransactionFilters {
  type?: string;
  status?: string;
  dateRange?: [string, string];
  search?: string;
}

interface TransactionSummary {
  totalTransactions: number;
  totalAmount: number;
  totalIncome: number;
  totalExpense: number;
}

const TransactionHistory: React.FC = () => {
  const { addNotification } = useUIStore();
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<TransactionSummary>({
    totalTransactions: 0,
    totalAmount: 0,
    totalIncome: 0,
    totalExpense: 0
  });
  const [filters, setFilters] = useState<TransactionFilters>({});
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0
  });

  const fetchTransactions = useCallback(async (customPagination?: { current: number; pageSize: number }) => {
    try {
      setLoading(true);
      const currentPagination = customPagination || pagination;
      const params = {
        page: currentPagination.current,
        limit: currentPagination.pageSize,
        ...filters
      };
      
      const response = await api.get('/payments/history', { params });
      if (response.data.success) {
        setTransactions(response.data.data.transactions);
        setPagination(prev => ({
          ...prev,
          total: response.data.data.total
        }));
      }
    } catch (error: unknown) {
      console.error('获取交易历史失败:', error);
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '无法获取交易历史，请稍后重试';
      addNotification({
        type: 'error',
        title: '获取交易历史失败',
        message: errorMessage || '无法获取交易历史，请稍后重试'
      });
    } finally {
      setLoading(false);
    }
  }, [filters, pagination, addNotification, setLoading, setTransactions, setPagination]);

  const fetchSummary = useCallback(async () => {
    try {
      const response = await api.get('/payments/summary', { 
        params: filters 
      });
      if (response.data.success) {
        setSummary(response.data.data);
      }
    } catch (error: unknown) {
      console.error('获取交易统计失败:', error);
    }
  }, [filters, setSummary]);

  useEffect(() => {
    fetchTransactions();
    fetchSummary();
  }, [fetchTransactions, fetchSummary]);

  useEffect(() => {
    fetchTransactions();
  }, [pagination.pageSize, fetchTransactions]);

  const handleExport = async () => {
    try {
      const response = await api.get('/payments/export', {
        params: filters,
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `transactions_${dayjs().format('YYYY-MM-DD')}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      addNotification({
        type: 'success',
        title: '导出成功',
        message: '交易记录已成功导出'
      });
    } catch (error: unknown) {
      console.error('导出交易记录失败:', error);
      addNotification({
        type: 'error',
        title: '导出失败',
        message: '导出交易记录失败，请稍后重试'
      });
    }
  };

  const getTypeTag = (type: string) => {
    const typeConfig = {
      payment: { color: 'red', text: '支付' },
      refund: { color: 'orange', text: '退款' },
      reward: { color: 'green', text: '奖励' },
      topup: { color: 'blue', text: '充值' }
    };
    const config = typeConfig[type as keyof typeof typeConfig] || { color: 'default', text: type };
    return <Tag color={config.color}>{config.text}</Tag>;
  };

  const getStatusTag = (status: string) => {
    const statusConfig = {
      completed: { color: 'success', text: '已完成' },
      pending: { color: 'processing', text: '处理中' },
      failed: { color: 'error', text: '失败' },
      cancelled: { color: 'default', text: '已取消' }
    };
    const config = statusConfig[status as keyof typeof statusConfig] || { color: 'default', text: status };
    return <Tag color={config.color}>{config.text}</Tag>;
  };

  const getAmountDisplay = (transaction: Transaction) => {
    const isIncome = transaction.type === 'refund' || transaction.type === 'reward' || transaction.type === 'topup';
    const prefix = isIncome ? '+' : '-';
    const color = isIncome ? '#52c41a' : '#ff4d4f';
    
    return (
      <Text style={{ color, fontWeight: 'bold' }}>
        {prefix}${transaction.amount.toFixed(2)}
      </Text>
    );
  };

  const columns: ColumnsType<Transaction> = [
    {
      title: '交易时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 180,
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm:ss'),
      sorter: true
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: getTypeTag,
      filters: [
        { text: '支付', value: 'payment' },
        { text: '退款', value: 'refund' },
        { text: '奖励', value: 'reward' },
        { text: '充值', value: 'topup' }
      ]
    },
    {
      title: '金额',
      dataIndex: 'amount',
      key: 'amount',
      width: 120,
      render: (_, record) => getAmountDisplay(record),
      sorter: true
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: getStatusTag,
      filters: [
        { text: '已完成', value: 'completed' },
        { text: '处理中', value: 'pending' },
        { text: '失败', value: 'failed' },
        { text: '已取消', value: 'cancelled' }
      ]
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (text: string) => (
        <Text ellipsis={{ tooltip: text }} style={{ maxWidth: 200 }}>
          {text}
        </Text>
      )
    },
    {
      title: '交易ID',
      dataIndex: 'id',
      key: 'id',
      width: 120,
      render: (id: string) => (
        <Text code copyable={{ text: id }}>
          {id.slice(0, 8)}...
        </Text>
      )
    }
  ];

  const handleTableChange = (paginationConfig: { current?: number; pageSize?: number }, _filtersConfig: Record<string, unknown>, _sorter: unknown) => {
    setPagination({
      ...pagination,
      current: paginationConfig.current || 1,
      pageSize: paginationConfig.pageSize || 10
    });
  };

  const handleFilterChange = (key: string, value: unknown) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
    setPagination(prev => ({ ...prev, current: 1 }));
  };

  const resetFilters = () => {
    setFilters({});
    setPagination(prev => ({ ...prev, current: 1 }));
  };

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      {/* 统计概览 */}
      <Row gutter={16}>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="总交易数"
              value={summary.totalTransactions}
              prefix={<DollarOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="总金额"
              value={summary.totalAmount}
              precision={2}
              prefix="$"
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="总收入"
              value={summary.totalIncome}
              precision={2}
              prefix="+$"
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="总支出"
              value={summary.totalExpense}
              precision={2}
              prefix="-$"
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 筛选器 */}
      <Card size="small">
        <Row gutter={16} align="middle">
          <Col span={6}>
            <Input
              placeholder="搜索交易描述"
              prefix={<SearchOutlined />}
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
              allowClear
            />
          </Col>
          <Col span={4}>
            <Select
              placeholder="交易类型"
              value={filters.type}
              onChange={(value) => handleFilterChange('type', value)}
              allowClear
              style={{ width: '100%' }}
            >
              <Option value="payment">支付</Option>
              <Option value="refund">退款</Option>
              <Option value="reward">奖励</Option>
              <Option value="topup">充值</Option>
            </Select>
          </Col>
          <Col span={4}>
            <Select
              placeholder="交易状态"
              value={filters.status}
              onChange={(value) => handleFilterChange('status', value)}
              allowClear
              style={{ width: '100%' }}
            >
              <Option value="completed">已完成</Option>
              <Option value="pending">处理中</Option>
              <Option value="failed">失败</Option>
              <Option value="cancelled">已取消</Option>
            </Select>
          </Col>
          <Col span={6}>
            <RangePicker
              value={filters.dateRange ? [dayjs(filters.dateRange[0]), dayjs(filters.dateRange[1])] : null}
              onChange={(dates) => {
                if (dates) {
                  handleFilterChange('dateRange', [dates[0]!.toISOString(), dates[1]!.toISOString()]);
                } else {
                  handleFilterChange('dateRange', undefined);
                }
              }}
              style={{ width: '100%' }}
            />
          </Col>
          <Col span={4}>
            <Space>
              <Button onClick={resetFilters}>
                重置
              </Button>
              <Button 
                type="primary" 
                icon={<DownloadOutlined />}
                onClick={handleExport}
              >
                导出
              </Button>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 交易列表 */}
      <Card
        title={
          <Space>
            <FilterOutlined />
            <span>交易记录</span>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={transactions}
          rowKey="id"
          loading={loading}
          pagination={{
            ...pagination,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条记录`
          }}
          onChange={handleTableChange}
          locale={{
            emptyText: (
              <Empty
                description="暂无交易记录"
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              />
            )
          }}
        />
      </Card>
    </Space>
  );
};

export default TransactionHistory;