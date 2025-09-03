import { Alert, Button, Card, Col, Form, InputNumber, Modal, Row, Space, Spin, Typography } from 'antd';
import React, { useState, useEffect } from 'react';
import { PayPalScriptProvider, PayPalButtons } from '@paypal/react-paypal-js';
import { CreditCardOutlined, DollarOutlined, WalletOutlined, SafetyOutlined } from '@ant-design/icons';
import { useUIStore } from '../../stores/uiStore';
import useNotificationStore from '../../stores/notificationStore';
import api from '../../utils/api';

const { Text } = Typography; // Title and Paragraph removed as unused

interface TopUpFormData {
  amount: number;
}

// interface TopUpModalProps {
//   currentBalance?: number;
// } // removed as unused

const TopUpModal: React.FC = () => {
  const { modals, closeModal } = useUIStore();
  const { addNotification } = useNotificationStore();
  const topUpModal = modals.find((modal: { type: string; id: string; props?: { currentBalance?: number } }) => modal.type === 'topup');
  const isOpen = !!topUpModal;
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [selectedAmount, setSelectedAmount] = useState<number | null>(null);
  const [paymentData, setPaymentData] = useState<TopUpFormData | null>(null);
  const [showPayPal, setShowPayPal] = useState(false);

  const currentBalance: number = (topUpModal?.props?.currentBalance as number) || 0;

  // 预设充值金额
  const presetAmounts = [10, 25, 50, 100, 200, 500];

  useEffect(() => {
    if (isOpen) {
      form.resetFields();
      setSelectedAmount(null);
    }
  }, [isOpen, form]);

  const handleClose = () => {
    if (topUpModal) {
      closeModal(topUpModal.id);
    }
    form.resetFields();
    setLoading(false);
    setSelectedAmount(null);
    setPaymentData(null);
    setShowPayPal(false);
  };

  const handlePresetAmountClick = (amount: number) => {
    setSelectedAmount(amount);
    form.setFieldsValue({ amount });
  };

  const handleSubmit = async (values: TopUpFormData) => {
    setPaymentData(values);
    setShowPayPal(true);
  };

  const createPayPalOrder = async () => {
    if (!paymentData) {
      throw new Error('缺少支付信息');
    }

    try {
      const response = await api.post('/payments/create', {
        prankId: 'wallet_topup_' + Date.now(),
        amount: paymentData.amount,
        currency: 'usd',
        description: `钱包充值 $${paymentData.amount}`
      });

      if (response.data.success && response.data.data.payment_order) {
        return response.data.data.payment_order.id;
      } else {
        throw new Error('创建PayPal订单失败');
      }
    } catch (error: unknown) {
      console.error('PayPal订单创建失败:', error);
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '创建PayPal订单失败，请稍后重试';
      addNotification({
        type: 'error',
        title: '充值失败',
        message: errorMessage || '创建PayPal订单失败，请稍后重试'
      });
      throw error;
    }
  };

  const onPayPalApprove = async (data: { orderID: string }) => {
    try {
      setLoading(true);
      const response = await api.post('/payments/confirm', {
        order_id: data.orderID
      });

      if (response.data.success) {
        addNotification({
          type: 'success',
          title: '充值成功',
          message: `成功充值 $${paymentData?.amount}！`
        });
        handleClose();
        // 可以在这里触发钱包余额刷新
      } else {
        throw new Error('充值确认失败');
      }
    } catch (error: unknown) {
      console.error('PayPal充值确认失败:', error);
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '充值确认失败，请稍后重试';
      addNotification({
        type: 'error',
        title: '充值失败',
        message: errorMessage || '充值确认失败，请稍后重试'
      });
    } finally {
      setLoading(false);
    }
  };

  const onPayPalError = (error: unknown) => {
    console.error('PayPal充值错误:', error);
    addNotification({
      type: 'error',
      title: '充值错误',
      message: 'PayPal充值过程中发生错误，请稍后重试'
    });
    setLoading(false);
  };

  const calculateNewBalance = (amount: number) => {
    return currentBalance + amount;
  };

  return (
    <Modal
      title={
        <Space>
          <WalletOutlined style={{ color: '#1890ff' }} />
          <span>钱包充值</span>
        </Space>
      }
      open={isOpen}
      onCancel={handleClose}
      footer={null}
      width={600}
      destroyOnClose
    >
      <Spin spinning={loading}>
        <div style={{ padding: '20px 0' }}>
          {/* 当前余额显示 */}
          <Card size="small" style={{ marginBottom: 24, backgroundColor: '#f6ffed', border: '1px solid #b7eb8f' }}>
            <Row align="middle">
              <Col span={12}>
                <Space>
                  <DollarOutlined style={{ color: '#52c41a' }} />
                  <Text strong>当前余额:</Text>
                  <Text strong style={{ color: '#52c41a', fontSize: '1.2rem' }}>
                    ${currentBalance.toFixed(2)}
                  </Text>
                </Space>
              </Col>
              <Col span={12} style={{ textAlign: 'right' }}>
                {selectedAmount && (
                  <Space>
                    <Text type="secondary">充值后:</Text>
                    <Text strong style={{ color: '#1890ff', fontSize: '1.1rem' }}>
                      ${calculateNewBalance(selectedAmount).toFixed(2)}
                    </Text>
                  </Space>
                )}
              </Col>
            </Row>
          </Card>

          <Alert
            message="安全充值"
            description="我们使用业界领先的支付处理商，确保您的支付信息安全。所有交易都经过加密处理。"
            type="info"
            showIcon
            icon={<SafetyOutlined />}
            style={{ marginBottom: 24 }}
          />
          
          {!showPayPal ? (
            <Form
              form={form}
              layout="vertical"
              onFinish={handleSubmit}
              initialValues={{
                amount: selectedAmount || undefined
              }}
            >
            {/* 预设金额选择 */}
            <Form.Item label="选择充值金额">
              <Row gutter={[8, 8]}>
                {presetAmounts.map(amount => (
                  <Col span={8} key={amount}>
                    <Button
                      block
                      type={selectedAmount === amount ? 'primary' : 'default'}
                      onClick={() => handlePresetAmountClick(amount)}
                      style={{ height: 48 }}
                    >
                      <div>
                        <div style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                          ${amount}
                        </div>
                        {amount >= 100 && (
                          <div style={{ fontSize: '0.8rem', color: '#52c41a' }}>
                            推荐
                          </div>
                        )}
                      </div>
                    </Button>
                  </Col>
                ))}
              </Row>
            </Form.Item>

            {/* 自定义金额输入 */}
            <Form.Item
              label="或输入自定义金额 (USD)"
              name="amount"
              rules={[
                { required: true, message: '请输入充值金额' },
                { type: 'number', min: 5, max: 1000, message: '充值金额必须在 $5-$1000 之间' }
              ]}
            >
              <InputNumber
                style={{ width: '100%' }}
                prefix={<DollarOutlined />}
                min={5}
                max={1000}
                step={1}
                precision={2}
                placeholder="输入充值金额"
                onChange={(value) => setSelectedAmount(value || null)}
              />
            </Form.Item>



            {/* 充值说明 */}
            <Alert
              message="充值说明"
              description={
                <ul style={{ margin: 0, paddingLeft: 16 }}>
                  <li>充值金额将立即添加到您的钱包余额</li>
                  <li>可用于支付恶搞标注和其他平台服务</li>
                  <li>充值金额不可提现，仅限平台内使用</li>
                  <li>如有疑问，请联系客服支持</li>
                </ul>
              }
              type="warning"
              showIcon
              style={{ marginBottom: 24 }}
            />

            <Form.Item style={{ marginBottom: 0 }}>
              <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
                <Button onClick={handleClose}>
                  取消
                </Button>
                <Button 
                  type="primary" 
                  htmlType="submit"
                  loading={loading}
                  icon={<CreditCardOutlined />}
                  disabled={!selectedAmount || selectedAmount < 5}
                >
                  继续支付
                </Button>
              </Space>
            </Form.Item>
          </Form>
        ) : (
          <div>
            <div style={{ marginBottom: 16 }}>
              <Text strong>充值金额: ${paymentData?.amount}</Text>
            </div>
            
            <PayPalScriptProvider options={{
              clientId: import.meta.env.VITE_PAYPAL_CLIENT_ID || "test",
              currency: "USD"
            }}>
              <PayPalButtons
                createOrder={createPayPalOrder}
                onApprove={onPayPalApprove}
                onError={onPayPalError}
                disabled={loading}
                style={{
                  layout: "vertical",
                  color: "blue",
                  shape: "rect",
                  label: "paypal"
                }}
              />
            </PayPalScriptProvider>
            
            <Button 
              onClick={() => setShowPayPal(false)}
              style={{ width: '100%', marginTop: 16 }}
            >
              返回修改金额
            </Button>
          </div>
        )}
        </div>
      </Spin>
    </Modal>
  );
};

export default TopUpModal;