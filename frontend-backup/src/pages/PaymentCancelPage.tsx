import React from 'react';
import { Alert, Button, Card, Result, Space, Typography } from 'antd';
import { XCircle, Home, CreditCard, HelpCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useUIStore } from '../stores/uiStore';

const { Title, Text, Paragraph } = Typography;

const PaymentCancelPage: React.FC = () => {
  const navigate = useNavigate();
  const { openModal } = useUIStore();

  const handleGoHome = () => {
    navigate('/');
  };

  const handleRetryPayment = () => {
    // 重新打开支付模态框
    openModal({ 
      type: 'payment',
      props: {
        // 可以传递之前的支付信息
      }
    });
    navigate('/');
  };

  const handleContactSupport = () => {
    window.open('mailto:support@smellpin.com?subject=支付问题咨询&body=我在支付过程中遇到了问题，请协助解决。');
  };

  const handleViewFAQ = () => {
    // 这里可以导航到FAQ页面或打开帮助模态框
    window.open('/help/payment-faq', '_blank');
  };

  return (
    <div style={{ padding: '40px 20px', maxWidth: 600, margin: '0 auto' }}>
      <Result
        icon={<XCircle style={{ color: '#ff4d4f' }} size={48} />}
        status="error"
        title="支付已取消"
        subTitle="您已取消了支付流程，恶搞标注未能创建。"
      />
      
      <Alert
        message="支付未完成"
        description="您的支付流程已被中断，没有产生任何费用。如果这是意外取消，您可以重新尝试支付。"
        type="warning"
        showIcon
        style={{ marginBottom: 24 }}
      />
      
      <Card title="可能的原因" style={{ marginBottom: 24 }}>
        <Space direction="vertical" size="small" style={{ width: '100%' }}>
          <Text>• 您主动取消了支付</Text>
          <Text>• 支付页面超时</Text>
          <Text>• 网络连接问题</Text>
          <Text>• 银行卡信息验证失败</Text>
          <Text>• 浏览器兼容性问题</Text>
        </Space>
      </Card>
      
      <div style={{ textAlign: 'center', marginBottom: 24 }}>
        <Space size="large" direction="vertical">
          <Space size="middle">
            <Button 
              type="primary" 
              icon={<CreditCard size={18} />}
              onClick={handleRetryPayment}
              size="large"
            >
              重新支付
            </Button>
            
            <Button 
              icon={<Home size={18} />}
              onClick={handleGoHome}
              size="large"
            >
              返回首页
            </Button>
          </Space>
          
          <Space size="middle">
            <Button 
              icon={<HelpCircle size={18} />}
              onClick={handleViewFAQ}
              type="link"
            >
              支付帮助
            </Button>
            
            <Button 
              onClick={handleContactSupport}
              type="link"
            >
              联系客服
            </Button>
          </Space>
        </Space>
      </div>
      
      <Card 
        style={{ backgroundColor: '#fff7e6', border: '1px solid #ffd591' }}
        size="small"
      >
        <Space direction="vertical" size="small">
          <Title level={5} style={{ margin: 0, color: '#d46b08' }}>
            💡 支付提示
          </Title>
          <Paragraph style={{ margin: 0 }}>
            <Text type="secondary">
              • 支付过程中请保持网络连接稳定
            </Text>
            <br />
            <Text type="secondary">
              • 确保银行卡有足够余额且未被冻结
            </Text>
            <br />
            <Text type="secondary">
              • 建议使用最新版本的浏览器
            </Text>
            <br />
            <Text type="secondary">
              • 如遇问题可尝试更换支付方式
            </Text>
          </Paragraph>
        </Space>
      </Card>
      
      <div style={{ textAlign: 'center', marginTop: 24 }}>
        <Text type="secondary" style={{ fontSize: 12 }}>
          如果您在支付过程中遇到技术问题，请联系我们的客服团队
          <br />
          邮箱：support@smellpin.com | 工作时间：9:00-18:00
        </Text>
      </div>
    </div>
  );
};

export default PaymentCancelPage;