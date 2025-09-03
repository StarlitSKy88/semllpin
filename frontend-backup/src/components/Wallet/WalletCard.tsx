import { Button, Card, Col, Divider, Row, Space, Statistic, Tag, Typography } from 'antd';

import React, { useState, useEffect } from 'react';

import { Wallet, Plus, History, DollarSign, Trophy } from 'lucide-react';
import { useUIStore } from '../../stores/uiStore';
import useNotificationStore from '../../stores/notificationStore';
import api from '../../utils/api';
import { useCallback } from 'react';

const { Text } = Typography; // Title removed as unused

interface WalletData {
  balance: number;
  totalIncome: number;
  totalExpense: number;
  lbsRewards: number;
  pendingRewards: number;
  currency: string;
}

interface WalletCardProps {
  onViewHistory?: () => void;
}

const WalletCard: React.FC<WalletCardProps> = ({ onViewHistory }) => {
  const { openModal } = useUIStore();
  const { addNotification } = useNotificationStore();
  const [walletData, setWalletData] = useState<WalletData>({
    balance: 0,
    totalIncome: 0,
    totalExpense: 0,
    lbsRewards: 0,
    pendingRewards: 0,
    currency: 'USD'
  });
  const [loading, setLoading] = useState(true);

  const fetchWalletData = useCallback(async () => {
    try {
      setLoading(true);
      const response = await api.get('/payments/wallet');
      if (response.data.success) {
        setWalletData(response.data.data);
      }
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : '未知错误';
      console.error('获取钱包数据失败:', error);
      addNotification({
        type: 'error',
        title: '获取钱包信息失败',
        message: errorMessage || '无法获取钱包信息，请稍后重试'
      });
    } finally {
      setLoading(false);
    }
  }, [addNotification]);

  useEffect(() => {
    fetchWalletData();
  }, [fetchWalletData]);

  const handleTopUp = () => {
    openModal({ type: 'topup' });
  };

  const handleViewHistory = () => {
    if (onViewHistory) {
      onViewHistory();
    }
  };

  const formatCurrency = (amount: number) => {
    return `$${amount.toFixed(2)}`;
  };

  return (
    <Card
      title={
        <Space>
          <Wallet style={{ color: '#1890ff' }} size={16} />
          <span>我的钱包</span>
        </Space>
      }
      extra={
        <Space>
          <Button 
            type="primary" 
            icon={<Plus size={16} />} 
            onClick={handleTopUp}
            size="small"
          >
            充值
          </Button>
          <Button 
            icon={<History size={16} />} 
            onClick={handleViewHistory}
            size="small"
          >
            历史
          </Button>
        </Space>
      }
      loading={loading}
    >
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {/* 主要余额显示 */}
        <div style={{ textAlign: 'center', padding: '20px 0' }}>
          <Statistic
            title="当前余额"
            value={walletData.balance}
            precision={2}
            prefix={<DollarSign style={{ color: '#52c41a' }} size={16} />}
            suffix={walletData.currency}
            valueStyle={{ 
              color: '#52c41a', 
              fontSize: '2.5rem', 
              fontWeight: 'bold' 
            }}
          />
        </div>

        <Divider />

        {/* 收支统计 */}
        <Row gutter={16}>
          <Col span={12}>
            <Card size="small" style={{ backgroundColor: '#f6ffed', border: '1px solid #b7eb8f' }}>
              <Statistic
                title="总收入"
                value={walletData.totalIncome}
                precision={2}
                prefix="+$"
                valueStyle={{ color: '#52c41a', fontSize: '1.2rem' }}
              />
            </Card>
          </Col>
          <Col span={12}>
            <Card size="small" style={{ backgroundColor: '#fff2e8', border: '1px solid #ffbb96' }}>
              <Statistic
                title="总支出"
                value={walletData.totalExpense}
                precision={2}
                prefix="-$"
                valueStyle={{ color: '#ff7875', fontSize: '1.2rem' }}
              />
            </Card>
          </Col>
        </Row>

        <Divider />

        {/* LBS奖励统计 */}
        <Card size="small" style={{ backgroundColor: '#f0f5ff', border: '1px solid #91d5ff' }}>
          <Row gutter={16} align="middle">
            <Col span={16}>
              <Space direction="vertical" size="small">
                <Text strong>
                  <Trophy style={{ color: '#faad14', marginRight: 8 }} size={16} />
                  LBS奖励
                </Text>
                <Space>
                  <Text>已获得: </Text>
                  <Text strong style={{ color: '#1890ff' }}>
                    {formatCurrency(walletData.lbsRewards)}
                  </Text>
                </Space>
              </Space>
            </Col>
            <Col span={8} style={{ textAlign: 'right' }}>
              {walletData.pendingRewards > 0 && (
                <Tag color="orange">
                  待发放: {formatCurrency(walletData.pendingRewards)}
                </Tag>
              )}
            </Col>
          </Row>
        </Card>

        {/* 快捷操作 */}
        <Row gutter={8}>
          <Col span={12}>
            <Button 
              block 
              type="primary" 
              icon={<Plus size={16} />}
              onClick={handleTopUp}
            >
              充值余额
            </Button>
          </Col>
          <Col span={12}>
            <Button 
              block 
              icon={<History size={16} />}
              onClick={handleViewHistory}
            >
              交易记录
            </Button>
          </Col>
        </Row>
      </Space>
    </Card>
  );
};

export default WalletCard;