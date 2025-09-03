import { Alert, Button, Card, Descriptions, Space, Typography } from 'antd';

import React from 'react';

import { CreditCardOutlined, ExperimentOutlined } from '@ant-design/icons';
import { useUIStore } from '../stores/uiStore';

const { Title, Text, Paragraph } = Typography;

const PaymentTestPage: React.FC = () => {
  const { openModal } = useUIStore();

  const handleOpenPaymentModal = () => {
    openModal({
      type: 'payment',
      props: {
        prankId: 'test_prank_' + Date.now(),
        amount: 5.00
      }
    });
  };

  return (
    <div style={{ padding: '40px 20px', maxWidth: 800, margin: '0 auto' }}>
      <Card>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <div style={{ textAlign: 'center' }}>
            <ExperimentOutlined style={{ fontSize: 48, color: '#1890ff', marginBottom: 16 }} />
            <Title level={2}>支付功能测试</Title>
            <Paragraph type="secondary">
              这是一个测试页面，用于验证 PayPal 支付集成功能。
            </Paragraph>
          </div>

          <Alert
            message="测试环境说明"
            description={
              <div>
                <p>当前为开发测试环境，使用 PayPal 沙盒模式：</p>
                <ul>
                  <li>不会产生真实费用</li>
                  <li>可以使用PayPal沙盒账户进行支付</li>
                  <li>支付流程与生产环境完全一致</li>
                </ul>
              </div>
            }
            type="info"
            showIcon
          />

          <Card title="PayPal沙盒账户信息" size="small">
            <Descriptions column={1} size="small">
              <Descriptions.Item label="测试买家账户">
                <Text code>buyer@example.com</Text>
              </Descriptions.Item>
              <Descriptions.Item label="测试密码">
                <Text code>password123</Text>
              </Descriptions.Item>
              <Descriptions.Item label="说明">
                <Text>使用PayPal沙盒账户登录进行测试支付</Text>
              </Descriptions.Item>
              <Descriptions.Item label="余额">
                <Text>沙盒账户默认有足够的测试余额</Text>
              </Descriptions.Item>
              <Descriptions.Item label="货币">
                <Text>支持USD等多种货币</Text>
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="支付流程测试">
            <Space direction="vertical" size="middle" style={{ width: '100%' }}>
              <Paragraph>
                点击下方按钮开始测试支付流程：
              </Paragraph>
              
              <ol>
                <li>点击"测试支付"按钮打开支付模态框</li>
                <li>输入支付金额（$1-$100）</li>
                <li>添加支付描述（可选）</li>
                <li>点击"继续支付"显示PayPal支付按钮</li>
                <li>使用PayPal沙盒账户完成支付</li>
                <li>验证支付成功通知</li>
              </ol>

              <div style={{ textAlign: 'center', marginTop: 24 }}>
                <Button 
                  type="primary" 
                  size="large"
                  icon={<CreditCardOutlined />}
                  onClick={handleOpenPaymentModal}
                >
                  测试支付功能
                </Button>
              </div>
            </Space>
          </Card>

          <Card title="API 端点" size="small">
            <Descriptions column={1} size="small">
              <Descriptions.Item label="创建支付订单">
                <Text code>POST /api/v1/payments/create</Text>
              </Descriptions.Item>
              <Descriptions.Item label="确认支付">
                <Text code>POST /api/v1/payments/confirm</Text>
              </Descriptions.Item>
              <Descriptions.Item label="获取支付状态">
                <Text code>GET /api/v1/payments/status/:orderId</Text>
              </Descriptions.Item>
              <Descriptions.Item label="支付历史">
                <Text code>GET /api/v1/payments/history</Text>
              </Descriptions.Item>
              <Descriptions.Item label="申请退款">
                <Text code>POST /api/v1/payments/refund</Text>
              </Descriptions.Item>
              <Descriptions.Item label="PayPal Webhook">
                <Text code>POST /api/v1/payments/webhook</Text>
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Alert
            message="注意事项"
            description={
              <div>
                <p>测试支付功能时请注意：</p>
                <ul>
                  <li>确保后端服务器正在运行（端口 3000）</li>
                  <li>需要配置有效的 PayPal 沙盒密钥</li>
                  <li>前端需要配置 PayPal 客户端ID</li>
                  <li>支付成功后会显示成功通知</li>
                </ul>
              </div>
            }
            type="warning"
            showIcon
          />
        </Space>
      </Card>
    </div>
  );
};

export default PaymentTestPage;