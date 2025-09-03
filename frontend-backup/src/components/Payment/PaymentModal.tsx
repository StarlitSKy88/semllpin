import { Alert, Button, Form, Input, InputNumber, Modal, Space, Spin, Typography } from 'antd';
import React, { useState, useEffect } from 'react';
import { PayPalScriptProvider, PayPalButtons } from '@paypal/react-paypal-js';
import { CreditCardOutlined, DollarOutlined } from '@ant-design/icons';
import { useUIStore } from '../../stores/uiStore';
import useNotificationStore from '../../stores/notificationStore';
import api from '../../utils/api';

const { Text } = Typography; // Title removed as unused

interface PaymentFormData {
  amount: number;
  description?: string;
}

const PaymentModal: React.FC = () => {
  const { modals, closeModal } = useUIStore();
  const { addNotification } = useNotificationStore();
  const isOpen = modals.some(modal => modal.type === 'payment');
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [prankId, setPrankId] = useState<string>('');
  const [paymentData, setPaymentData] = useState<PaymentFormData | null>(null);
  const [showPayPal, setShowPayPal] = useState(false);

  useEffect(() => {
    if (isOpen) {
      // 这里可以从 modal data 中获取 prankId
      // 暂时使用模拟数据
      setPrankId('prank_' + Date.now());
      form.resetFields();
    }
  }, [isOpen, form]);

  const handleClose = () => {
    const paymentModal = modals.find(modal => modal.type === 'payment');
    if (paymentModal) {
      closeModal(paymentModal.id);
    }
    form.resetFields();
    setLoading(false);
    setPaymentData(null);
    setShowPayPal(false);
  };

  const handleSubmit = async (values: PaymentFormData) => {
    if (!prankId) {
      addNotification({
        type: 'error',
        title: '错误',
        message: '缺少恶搞标注信息'
      });
      return;
    }

    setPaymentData(values);
    setShowPayPal(true);
  };

  const createPayPalOrder = async () => {
    if (!paymentData || !prankId) {
      throw new Error('缺少支付信息');
    }

    try {
      const response = await api.post('/payments/create', {
        prankId,
        amount: paymentData.amount,
        currency: 'usd',
        description: paymentData.description || `为恶搞标注 ${prankId} 支付`
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
        title: '支付失败',
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
          title: '支付成功',
          message: '您的支付已成功处理！'
        });
        handleClose();
        // 可以在这里添加成功后的跳转逻辑
      } else {
        throw new Error('支付确认失败');
      }
    } catch (error: unknown) {
      console.error('PayPal支付确认失败:', error);
      const errorMessage = error instanceof Error && 'response' in error 
        ? (error as { response?: { data?: { message?: string } } }).response?.data?.message 
        : '支付确认失败，请稍后重试';
      addNotification({
        type: 'error',
        title: '支付失败',
        message: errorMessage || '支付确认失败，请稍后重试'
      });
    } finally {
      setLoading(false);
    }
  };

  const onPayPalError = (error: unknown) => {
    console.error('PayPal支付错误:', error);
    addNotification({
      type: 'error',
      title: '支付错误',
      message: 'PayPal支付过程中发生错误，请稍后重试'
    });
    setLoading(false);
  };

  return (
    <Modal
      title={
        <Space>
          <CreditCardOutlined />
          <span>支付恶搞标注</span>
        </Space>
      }
      open={isOpen}
      onCancel={handleClose}
      footer={null}
      width={500}
      destroyOnHidden
    >
      <Spin spinning={loading}>
        <div style={{ padding: '20px 0' }}>
          <Alert
            message="安全支付"
            description="我们使用 PayPal 提供安全的支付处理，您的支付信息将得到最高级别的保护。"
            type="info"
            showIcon
            style={{ marginBottom: 24 }}
          />
          
          <Form
            form={form}
            layout="vertical"
            onFinish={handleSubmit}
            initialValues={{
              amount: 5.00
            }}
          >
            <Form.Item
              label="支付金额 (USD)"
              name="amount"
              rules={[
                { required: true, message: '请输入支付金额' },
                { type: 'number', min: 1, max: 100, message: '支付金额必须在 $1-$100 之间' }
              ]}
            >
              <InputNumber
                style={{ width: '100%' }}
                prefix={<DollarOutlined />}
                min={1}
                max={100}
                step={0.01}
                precision={2}
                placeholder="输入支付金额"
              />
            </Form.Item>

            <Form.Item
              label="支付描述（可选）"
              name="description"
            >
              <Input.TextArea
                rows={3}
                placeholder="为这次支付添加描述..."
                maxLength={200}
                showCount
              />
            </Form.Item>

            <div style={{ marginBottom: 16 }}>
              <Text type="secondary">
                恶搞标注ID: {prankId}
              </Text>
            </div>

            {!showPayPal ? (
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
                  >
                    继续支付
                  </Button>
                </Space>
              </Form.Item>
            ) : (
              <div style={{ marginTop: 24 }}>
                <PayPalScriptProvider options={{
                  clientId: import.meta.env.VITE_PAYPAL_CLIENT_ID || "test",
                  currency: "USD"
                }}>
                  <PayPalButtons
                    style={{ layout: "vertical" }}
                    createOrder={createPayPalOrder}
                    onApprove={onPayPalApprove}
                    onError={onPayPalError}
                    disabled={loading}
                  />
                </PayPalScriptProvider>
                
                <div style={{ textAlign: 'center', marginTop: 16 }}>
                  <Button onClick={() => setShowPayPal(false)}>
                    返回修改金额
                  </Button>
                </div>
              </div>
            )}
          </Form>
        </div>
      </Spin>
    </Modal>
  );
};

export default PaymentModal;