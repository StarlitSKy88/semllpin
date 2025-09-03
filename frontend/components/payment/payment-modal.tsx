'use client';

import React, { useState, useEffect } from 'react';
import { usePaymentStore } from '@/lib/stores/payment-store';
import { paymentService, CreatePaymentIntentRequest } from '@/lib/services/payment-service';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  CreditCard,
  Smartphone,
  Wallet,
  AlertCircle,
  CheckCircle,
  Loader2,
  MapPin,
  DollarSign
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface PaymentModalProps {
  isOpen: boolean;
  onClose: () => void;
  annotationData?: {
    location: string;
    description: string;
    coordinates: [number, number];
  };
  onPaymentSuccess?: (paymentId: string) => void;
}

type PaymentStep = 'amount' | 'method' | 'confirm' | 'processing' | 'success' | 'error';

export function PaymentModal({ 
  isOpen, 
  onClose, 
  annotationData,
  onPaymentSuccess 
}: PaymentModalProps) {
  const {
    isLoading,
    error,
    currentPaymentIntent,
    paymentMethods,
    createPaymentIntent,
    confirmPayment,
    loadPaymentMethods,
    clearError
  } = usePaymentStore();

  const [currentStep, setCurrentStep] = useState<PaymentStep>('amount');
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [selectedPaymentMethod, setSelectedPaymentMethod] = useState<string>('');
  const [amountError, setAmountError] = useState('');

  useEffect(() => {
    if (isOpen) {
      loadPaymentMethods();
      setCurrentStep('amount');
      setAmount('');
      setDescription('');
      setSelectedPaymentMethod('');
      setAmountError('');
      clearError();
    }
  }, [isOpen, loadPaymentMethods, clearError]);

  useEffect(() => {
    if (annotationData) {
      setDescription(`恶搞标注 - ${annotationData.location}`);
    }
  }, [annotationData]);

  const handleAmountChange = (value: string) => {
    setAmount(value);
    setAmountError('');
    
    const numAmount = parseFloat(value);
    if (isNaN(numAmount)) {
      setAmountError('请输入有效金额');
      return;
    }
    
    const amountInCents = Math.round(numAmount * 100);
    const validation = paymentService.validatePaymentAmount(amountInCents);
    if (!validation.isValid) {
      setAmountError(validation.error || '金额无效');
    }
  };

  const handleNextStep = async () => {
    if (currentStep === 'amount') {
      const numAmount = parseFloat(amount);
      if (isNaN(numAmount) || numAmount <= 0) {
        setAmountError('请输入有效金额');
        return;
      }
      
      const amountInCents = Math.round(numAmount * 100);
      const validation = paymentService.validatePaymentAmount(amountInCents);
      if (!validation.isValid) {
        setAmountError(validation.error || '金额无效');
        return;
      }
      
      setCurrentStep('method');
    } else if (currentStep === 'method') {
      if (!selectedPaymentMethod) {
        return;
      }
      setCurrentStep('confirm');
    } else if (currentStep === 'confirm') {
      await handlePayment();
    }
  };

  const handlePayment = async () => {
    try {
      setCurrentStep('processing');
      
      const amountInCents = Math.round(parseFloat(amount) * 100);
      
      const paymentRequest: CreatePaymentIntentRequest = {
        amount: amountInCents,
        currency: 'cny',
        description: description || '恶搞标注支付',
        annotationId: annotationData ? `ann_${Date.now()}` : undefined,
        metadata: {
          location: annotationData?.location || '',
          coordinates: annotationData?.coordinates.join(',') || ''
        }
      };
      
      const paymentIntent = await createPaymentIntent(paymentRequest);
      
      // 模拟支付确认过程
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const confirmedPayment = await confirmPayment(paymentIntent.id, selectedPaymentMethod);
      
      if (confirmedPayment.status === 'succeeded') {
        setCurrentStep('success');
        onPaymentSuccess?.(confirmedPayment.id);
      } else {
        setCurrentStep('error');
      }
    } catch (error) {
      console.error('Payment failed:', error);
      setCurrentStep('error');
    }
  };

  const handleClose = () => {
    if (currentStep !== 'processing') {
      onClose();
    }
  };

  const getStepTitle = () => {
    switch (currentStep) {
      case 'amount':
        return '设置标注金额';
      case 'method':
        return '选择支付方式';
      case 'confirm':
        return '确认支付信息';
      case 'processing':
        return '处理支付中...';
      case 'success':
        return '支付成功！';
      case 'error':
        return '支付失败';
      default:
        return '支付';
    }
  };

  const renderAmountStep = () => (
    <div className="space-y-6">
      <div className="space-y-4">
        <div>
          <Label htmlFor="amount">标注金额 (元)</Label>
          <div className="relative mt-2">
            <DollarSign className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              id="amount"
              type="number"
              placeholder="输入金额"
              value={amount}
              onChange={(e) => handleAmountChange(e.target.value)}
              className={cn('pl-10', {
                'border-red-500': amountError
              })}
              min="1"
              max="1000"
              step="0.01"
            />
          </div>
          {amountError && (
            <p className="text-sm text-red-600 mt-1 flex items-center">
              <AlertCircle className="h-4 w-4 mr-1" />
              {amountError}
            </p>
          )}
          <p className="text-sm text-muted-foreground mt-1">
            金额范围：1-1000元
          </p>
        </div>
        
        <div>
          <Label htmlFor="description">标注描述</Label>
          <Textarea
            id="description"
            placeholder="描述这个恶搞标注的内容..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="mt-2"
            rows={3}
          />
        </div>
      </div>
      
      {annotationData && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-start space-x-3">
              <MapPin className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="font-medium">{annotationData.location}</p>
                <p className="text-sm text-muted-foreground">
                  {annotationData.description}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  坐标: {annotationData.coordinates[0].toFixed(6)}, {annotationData.coordinates[1].toFixed(6)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
      
      <div className="bg-blue-50 p-4 rounded-lg">
        <h4 className="font-medium text-blue-900 mb-2">支付说明</h4>
        <ul className="text-sm text-blue-800 space-y-1">
          <li>• 支付成功后，标注将立即生效</li>
          <li>• 其他用户发现此标注可获得奖励</li>
          <li>• 平台收取5-10%手续费</li>
          <li>• 违规内容将被删除且不退款</li>
        </ul>
      </div>
    </div>
  );

  const renderMethodStep = () => (
    <div className="space-y-4">
      <div className="grid gap-3">
        {paymentMethods.map((method) => (
          <Card
            key={method.id}
            className={cn(
              'cursor-pointer transition-all hover:shadow-md',
              selectedPaymentMethod === method.id
                ? 'ring-2 ring-blue-500 bg-blue-50'
                : 'hover:bg-gray-50'
            )}
            onClick={() => setSelectedPaymentMethod(method.id)}
          >
            <CardContent className="p-4">
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center h-10 w-10 rounded-full bg-gray-100">
                  {method.type === 'card' ? (
                    <CreditCard className="h-5 w-5" />
                  ) : method.type === 'alipay' ? (
                    <Smartphone className="h-5 w-5 text-blue-600" />
                  ) : (
                    <Wallet className="h-5 w-5 text-green-600" />
                  )}
                </div>
                <div className="flex-1">
                  <p className="font-medium">
                    {method.type === 'card' ? '银行卡' :
                     method.type === 'alipay' ? '支付宝' : '微信支付'}
                  </p>
                  {method.card && (
                    <p className="text-sm text-muted-foreground">
                      {method.card.brand.toUpperCase()} •••• {method.card.last4}
                    </p>
                  )}
                  {method.billing_details?.name && (
                    <p className="text-sm text-muted-foreground">
                      {method.billing_details.name}
                    </p>
                  )}
                </div>
                {selectedPaymentMethod === method.id && (
                  <CheckCircle className="h-5 w-5 text-blue-500" />
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      
      <Button variant="outline" className="w-full">
        <CreditCard className="h-4 w-4 mr-2" />
        添加新的支付方式
      </Button>
    </div>
  );

  const renderConfirmStep = () => {
    const selectedMethod = paymentMethods.find(m => m.id === selectedPaymentMethod);
    const amountInCents = Math.round(parseFloat(amount) * 100);
    const fee = Math.round(amountInCents * 0.05); // 5%手续费
    const total = amountInCents;
    
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="pt-6">
            <div className="space-y-4">
              <div className="flex justify-between">
                <span>标注金额</span>
                <span className="font-medium">{paymentService.formatAmount(amountInCents)}</span>
              </div>
              <div className="flex justify-between text-sm text-muted-foreground">
                <span>平台手续费 (5%)</span>
                <span>{paymentService.formatAmount(fee)}</span>
              </div>
              <Separator />
              <div className="flex justify-between font-medium text-lg">
                <span>总计</span>
                <span>{paymentService.formatAmount(total)}</span>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="space-y-3">
              <h4 className="font-medium">支付方式</h4>
              {selectedMethod && (
                <div className="flex items-center space-x-3">
                  <div className="flex items-center justify-center h-8 w-8 rounded-full bg-gray-100">
                    {selectedMethod.type === 'card' ? (
                      <CreditCard className="h-4 w-4" />
                    ) : selectedMethod.type === 'alipay' ? (
                      <Smartphone className="h-4 w-4 text-blue-600" />
                    ) : (
                      <Wallet className="h-4 w-4 text-green-600" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium">
                      {selectedMethod.type === 'card' ? '银行卡' :
                       selectedMethod.type === 'alipay' ? '支付宝' : '微信支付'}
                    </p>
                    {selectedMethod.card && (
                      <p className="text-sm text-muted-foreground">
                        {selectedMethod.card.brand.toUpperCase()} •••• {selectedMethod.card.last4}
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="space-y-3">
              <h4 className="font-medium">标注信息</h4>
              <div className="space-y-2">
                <p className="text-sm">
                  <span className="text-muted-foreground">描述：</span>
                  {description || '恶搞标注'}
                </p>
                {annotationData && (
                  <p className="text-sm">
                    <span className="text-muted-foreground">位置：</span>
                    {annotationData.location}
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  };

  const renderProcessingStep = () => (
    <div className="text-center py-8">
      <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4 text-blue-500" />
      <h3 className="text-lg font-medium mb-2">正在处理支付...</h3>
      <p className="text-muted-foreground">请稍候，不要关闭此窗口</p>
    </div>
  );

  const renderSuccessStep = () => (
    <div className="text-center py-8">
      <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500" />
      <h3 className="text-lg font-medium mb-2">支付成功！</h3>
      <p className="text-muted-foreground mb-6">
        您的恶搞标注已创建成功，其他用户现在可以发现并获得奖励。
      </p>
      <div className="space-y-2 text-sm">
        <p><span className="text-muted-foreground">支付金额：</span>{paymentService.formatAmount(Math.round(parseFloat(amount) * 100))}</p>
        <p><span className="text-muted-foreground">支付ID：</span>{currentPaymentIntent?.id}</p>
      </div>
    </div>
  );

  const renderErrorStep = () => (
    <div className="text-center py-8">
      <AlertCircle className="h-12 w-12 mx-auto mb-4 text-red-500" />
      <h3 className="text-lg font-medium mb-2">支付失败</h3>
      <p className="text-muted-foreground mb-6">
        {error || '支付过程中出现错误，请重试。'}
      </p>
      <Button onClick={() => setCurrentStep('amount')} variant="outline">
        重新支付
      </Button>
    </div>
  );

  const renderStepContent = () => {
    switch (currentStep) {
      case 'amount':
        return renderAmountStep();
      case 'method':
        return renderMethodStep();
      case 'confirm':
        return renderConfirmStep();
      case 'processing':
        return renderProcessingStep();
      case 'success':
        return renderSuccessStep();
      case 'error':
        return renderErrorStep();
      default:
        return null;
    }
  };

  const canProceed = () => {
    switch (currentStep) {
      case 'amount':
        return amount && !amountError && description;
      case 'method':
        return selectedPaymentMethod;
      case 'confirm':
        return true;
      default:
        return false;
    }
  };

  const getButtonText = () => {
    switch (currentStep) {
      case 'amount':
        return '下一步';
      case 'method':
        return '下一步';
      case 'confirm':
        return `支付 ${paymentService.formatAmount(Math.round(parseFloat(amount || '0') * 100))}`;
      case 'success':
        return '完成';
      default:
        return '下一步';
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <Wallet className="h-5 w-5" />
            <span>{getStepTitle()}</span>
          </DialogTitle>
          <DialogDescription>
            {currentStep === 'amount' && '设置您的恶搞标注金额和描述'}
            {currentStep === 'method' && '选择您偏好的支付方式'}
            {currentStep === 'confirm' && '确认支付信息无误后完成支付'}
            {currentStep === 'processing' && '正在安全处理您的支付'}
            {currentStep === 'success' && '恶搞标注创建成功'}
            {currentStep === 'error' && '支付遇到问题，请重试'}
          </DialogDescription>
        </DialogHeader>
        
        <div className="py-4">
          {renderStepContent()}
        </div>
        
        {['amount', 'method', 'confirm', 'success'].includes(currentStep) && (
          <div className="flex space-x-3 pt-4">
            {currentStep !== 'amount' && currentStep !== 'success' && (
              <Button
                variant="outline"
                onClick={() => {
                  if (currentStep === 'method') setCurrentStep('amount');
                  if (currentStep === 'confirm') setCurrentStep('method');
                }}
                disabled={isLoading}
              >
                上一步
              </Button>
            )}
            <Button
              className="flex-1"
              onClick={currentStep === 'success' ? handleClose : handleNextStep}
              disabled={!canProceed() || isLoading}
            >
              {isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {getButtonText()}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default PaymentModal;