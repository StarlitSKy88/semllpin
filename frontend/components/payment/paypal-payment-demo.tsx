"use client";

import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { 
  PayPalProvider, 
  PayPalQuickButton, 
  PayPalPaymentInfo, 
  PayPalStatus 
} from './paypal-button';
import { toast } from 'sonner';

/**
 * PayPal支付演示组件
 * 展示如何使用PayPal支付功能
 */
export const PayPalPaymentDemo: React.FC = () => {
  const [paymentData, setPaymentData] = useState({
    amount: 5.99,
    currency: 'USD',
    description: 'SmellPin气味标注费用',
    annotationId: ''
  });
  
  const [paymentStatus, setPaymentStatus] = useState<'idle' | 'loading' | 'success' | 'error' | 'cancelled'>('idle');
  const [statusMessage, setStatusMessage] = useState('');

  // PayPal配置
  const paypalConfig = {
    clientId: process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID || 'ARxxxxxx', // 从环境变量获取
    environment: (process.env.PAYPAL_ENVIRONMENT as 'sandbox' | 'production') || 'sandbox'
  };

  /**
   * 支付成功处理
   */
  const handlePaymentSuccess = (data: any) => {
    console.log('PayPal payment success:', data);
    setPaymentStatus('success');
    setStatusMessage(`支付成功！订单ID: ${data.orderId}`);
    toast.success('支付成功！您的标注已创建。');
    
    // 这里可以添加创建标注的逻辑
    // 例如：调用API创建标注，更新UI状态等
  };

  /**
   * 支付错误处理
   */
  const handlePaymentError = (error: any) => {
    console.error('PayPal payment error:', error);
    setPaymentStatus('error');
    setStatusMessage(`支付失败: ${error.message || '未知错误'}`);
    toast.error('支付失败，请重试。');
  };

  /**
   * 支付取消处理
   */
  const handlePaymentCancel = () => {
    setPaymentStatus('cancelled');
    setStatusMessage('支付已取消');
    toast.info('支付已取消');
  };

  /**
   * 表单数据变更处理
   */
  const handleInputChange = (field: string, value: string | number) => {
    setPaymentData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // 重置支付状态
    if (paymentStatus !== 'idle') {
      setPaymentStatus('idle');
      setStatusMessage('');
    }
  };

  /**
   * 重置支付状态
   */
  const resetPayment = () => {
    setPaymentStatus('idle');
    setStatusMessage('');
  };

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>PayPal支付演示</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 支付信息表单 */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="amount">支付金额</Label>
              <Input
                id="amount"
                type="number"
                step="0.01"
                min="0.01"
                value={paymentData.amount}
                onChange={(e) => handleInputChange('amount', parseFloat(e.target.value) || 0.01)}
              />
            </div>
            
            <div>
              <Label htmlFor="currency">货币</Label>
              <select
                id="currency"
                className="w-full p-2 border border-gray-300 rounded-md"
                value={paymentData.currency}
                onChange={(e) => handleInputChange('currency', e.target.value)}
              >
                <option value="USD">美元 (USD)</option>
                <option value="EUR">欧元 (EUR)</option>
                <option value="GBP">英镑 (GBP)</option>
                <option value="CNY">人民币 (CNY)</option>
                <option value="JPY">日元 (JPY)</option>
              </select>
            </div>
          </div>

          <div>
            <Label htmlFor="description">支付描述</Label>
            <Textarea
              id="description"
              value={paymentData.description}
              onChange={(e) => handleInputChange('description', e.target.value)}
              placeholder="输入支付描述..."
            />
          </div>

          <div>
            <Label htmlFor="annotationId">标注ID (可选)</Label>
            <Input
              id="annotationId"
              value={paymentData.annotationId}
              onChange={(e) => handleInputChange('annotationId', e.target.value)}
              placeholder="输入相关标注ID..."
            />
          </div>
        </CardContent>
      </Card>

      {/* 支付信息显示 */}
      <PayPalPaymentInfo
        amount={paymentData.amount}
        currency={paymentData.currency}
        description={paymentData.description}
      />

      {/* 支付状态显示 */}
      <PayPalStatus
        status={paymentStatus}
        message={statusMessage}
      />

      {/* PayPal支付按钮 */}
      <Card>
        <CardHeader>
          <CardTitle>完成支付</CardTitle>
        </CardHeader>
        <CardContent>
          {paymentStatus === 'success' ? (
            <div className="text-center space-y-4">
              <p className="text-green-600 font-medium">支付成功完成！</p>
              <Button onClick={resetPayment} variant="outline">
                进行新的支付
              </Button>
            </div>
          ) : (
            <PayPalQuickButton
              clientId={paypalConfig.clientId}
              environment={paypalConfig.environment}
              amount={paymentData.amount}
              currency={paymentData.currency}
              description={paymentData.description}
              annotationId={paymentData.annotationId || undefined}
              onSuccess={handlePaymentSuccess}
              onError={handlePaymentError}
              onCancel={handlePaymentCancel}
              disabled={!paymentData.description.trim() || paymentData.amount <= 0}
              style={{
                layout: 'vertical',
                color: 'gold',
                shape: 'rect',
                label: 'paypal',
                height: 50
              }}
            />
          )}
        </CardContent>
      </Card>

      {/* 开发信息 */}
      <Card className="border-dashed border-gray-300">
        <CardHeader>
          <CardTitle className="text-sm text-gray-600">开发信息</CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-gray-500">
          <div className="space-y-1">
            <p><strong>环境:</strong> {paypalConfig.environment}</p>
            <p><strong>Client ID:</strong> {paypalConfig.clientId.substring(0, 10)}...</p>
            <p><strong>支付状态:</strong> {paymentStatus}</p>
          </div>
          
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
            <p className="text-yellow-800 text-xs">
              <strong>注意:</strong> 这是沙盒环境，使用测试账户进行支付。
              请使用PayPal提供的测试买家账户进行测试。
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default PayPalPaymentDemo;