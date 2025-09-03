import React, { useEffect, useState, useCallback } from 'react';
import { Button, Card, Descriptions, Result, Space, Spin, Typography } from 'antd';
import { CheckCircleOutlined, HomeOutlined, HistoryOutlined } from '@ant-design/icons';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useUIStore } from '../stores/uiStore';
import api from '../utils/api';

const { Title, Text } = Typography;

interface PaymentSession {
  id: string;
  status: string;
  amount: number;
  currency: string;
  customerEmail?: string;
  prankId: string;
  description: string;
}

const PaymentSuccessPage: React.FC = () => {
  const navigate = useNavigate();
  const { addNotification } = useUIStore();
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [sessionData, setSessionData] = useState<PaymentSession | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sessionId = searchParams.get('session_id');

  const fetchPaymentSession = useCallback(async () => {
    try {
      const response = await api.get(`/payments/session/${sessionId}`);
      
      if (response.data.success) {
        setSessionData(response.data.data);
        
        // 显示成功通知
        addNotification({
          type: 'success',
          title: '支付成功',
          message: `您已成功支付 $${response.data.data.amount} USD`
        });
      } else {
        throw new Error('获取支付信息失败');
      }
    } catch (error: unknown) {
      console.error('获取支付会话失败:', error);
      const errorMessage = error && typeof error === 'object' && 'response' in error
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message || '获取支付信息失败'
        : '获取支付信息失败';
      setError(errorMessage);
      
      addNotification({
        type: 'error',
        title: '错误',
        message: '获取支付信息失败'
      });
    } finally {
      setLoading(false);
    }
  }, [sessionId, addNotification]);

  useEffect(() => {
    if (!sessionId) {
      setError('缺少支付会话ID');
      setLoading(false);
      return;
    }

    fetchPaymentSession();
  }, [sessionId, fetchPaymentSession]);



  const handleGoHome = () => {
    navigate('/');
  };

  const handleViewHistory = () => {
    navigate('/profile?tab=payments');
  };

  const handleViewPrank = () => {
    if (sessionData?.prankId) {
      navigate(`/map?prank=${sessionData.prankId}`);
    }
  };

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '60vh' 
      }}>
        <Spin size="large" tip="正在验证支付信息..." spinning>
          <div style={{ width: 0, height: 0 }} />
        </Spin>
      </div>
    );
  }

  if (error || !sessionData) {
    return (
      <div style={{ padding: '40px 20px', maxWidth: 600, margin: '0 auto' }}>
        <Result
          status="error"
          title="支付验证失败"
          subTitle={error || '无法获取支付信息，请联系客服'}
          extra={[
            <Button key="home" type="primary" onClick={handleGoHome}>
              返回首页
            </Button>,
            <Button key="contact" onClick={() => window.open('mailto:support@smellpin.com')}>
              联系客服
            </Button>
          ]}
        />
      </div>
    );
  }

  return (
    <div style={{ padding: '40px 20px', maxWidth: 800, margin: '0 auto' }}>
      <Result
        icon={<CheckCircleOutlined style={{ color: '#52c41a' }} />}
        status="success"
        title="支付成功！"
        subTitle="感谢您的支付，您的恶搞标注已经生效。"
      />
      
      <Card 
        title="支付详情" 
        style={{ marginTop: 24 }}
        extra={
          <Text type="secondary">
            会话ID: {sessionData.id}
          </Text>
        }
      >
        <Descriptions column={1} bordered>
          <Descriptions.Item label="支付金额">
            <Text strong style={{ fontSize: 16, color: '#52c41a' }}>
              ${sessionData.amount} {sessionData.currency.toUpperCase()}
            </Text>
          </Descriptions.Item>
          
          <Descriptions.Item label="支付状态">
            <Text type="success">已完成</Text>
          </Descriptions.Item>
          
          <Descriptions.Item label="恶搞标注ID">
            <Text code>{sessionData.prankId}</Text>
          </Descriptions.Item>
          
          <Descriptions.Item label="支付描述">
            {sessionData.description}
          </Descriptions.Item>
          
          {sessionData.customerEmail && (
            <Descriptions.Item label="支付邮箱">
              {sessionData.customerEmail}
            </Descriptions.Item>
          )}
          
          <Descriptions.Item label="支付时间">
            {new Date().toLocaleString('zh-CN')}
          </Descriptions.Item>
        </Descriptions>
      </Card>
      
      <div style={{ textAlign: 'center', marginTop: 32 }}>
        <Space size="large">
          <Button 
            type="primary" 
            icon={<HomeOutlined />}
            onClick={handleGoHome}
            size="large"
          >
            返回首页
          </Button>
          
          <Button 
            icon={<HistoryOutlined />}
            onClick={handleViewHistory}
            size="large"
          >
            查看支付历史
          </Button>
          
          {sessionData.prankId && (
            <Button 
              onClick={handleViewPrank}
              size="large"
            >
              查看恶搞标注
            </Button>
          )}
        </Space>
      </div>
      
      <Card 
        style={{ marginTop: 24, backgroundColor: '#f6ffed', border: '1px solid #b7eb8f' }}
        size="small"
      >
        <Space direction="vertical" size="small">
          <Title level={5} style={{ margin: 0, color: '#389e0d' }}>
            🎉 支付成功提示
          </Title>
          <Text type="secondary">
            • 您的恶搞标注现在对所有用户可见
          </Text>
          <Text type="secondary">
            • 支付收据已发送到您的邮箱
          </Text>
          <Text type="secondary">
            • 如有问题，请联系客服：support@smellpin.com
          </Text>
        </Space>
      </Card>
    </div>
  );
};

export default PaymentSuccessPage;