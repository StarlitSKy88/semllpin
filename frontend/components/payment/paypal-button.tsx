"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { PayPalButtons, PayPalScriptProvider } from '@paypal/react-paypal-js';
import { Button } from '@/components/ui/button';
import { Loader2, AlertCircle } from 'lucide-react';
import { PayPalClient, PayPalSDKManager, PayPalConfig, PayPalButtonStyle } from '@/lib/paypal';
import { toast } from 'sonner';

// PayPal按钮组件属性
export interface PayPalButtonProps {
  amount: number;
  currency?: string;
  description: string;
  annotationId?: string;
  onSuccess?: (data: any) => void;
  onError?: (error: any) => void;
  onCancel?: () => void;
  style?: PayPalButtonStyle;
  disabled?: boolean;
  className?: string;
}

// PayPal支付提供者属性
export interface PayPalProviderProps {
  children: React.ReactNode;
  clientId: string;
  currency?: string;
  environment?: 'sandbox' | 'production';
}

/**
 * PayPal脚本提供者组件
 */
export const PayPalProvider: React.FC<PayPalProviderProps> = ({
  children,
  clientId,
  currency = 'USD',
  environment = 'sandbox'
}) => {
  const initialOptions = {
    'client-id': clientId,
    currency: currency,
    intent: 'capture' as const,
    'data-client-token': undefined
  };

  return (
    <PayPalScriptProvider options={initialOptions}>
      {children}
    </PayPalScriptProvider>
  );
};

/**
 * PayPal支付按钮组件
 */
export const PayPalButton: React.FC<PayPalButtonProps> = ({
  amount,
  currency = 'USD',
  description,
  annotationId,
  onSuccess,
  onError,
  onCancel,
  style = {},
  disabled = false,
  className = ''
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [orderId, setOrderId] = useState<string | null>(null);
  
  const paypalClient = new PayPalClient();

  // 默认按钮样式
  const defaultStyle: PayPalButtonStyle = {
    layout: 'vertical',
    color: 'gold',
    shape: 'rect',
    label: 'paypal',
    height: 45,
    ...style
  };

  // 验证金额
  const isValidAmount = amount > 0 && !isNaN(amount);

  /**
   * 创建PayPal订单
   */
  const createOrder = useCallback(async (data: any, actions: any) => {
    try {
      setLoading(true);
      setError(null);

      // 调用后端API创建PayPal订单
      const response = await paypalClient.createOrder({
        amount,
        currency,
        description,
        annotationId
      });

      setOrderId(response.id);
      return response.id;

    } catch (error) {
      console.error('Create PayPal order error:', error);
      const errorMessage = error instanceof Error ? error.message : '创建订单失败';
      setError(errorMessage);
      onError?.(error);
      toast.error(errorMessage);
      throw error;
    } finally {
      setLoading(false);
    }
  }, [amount, currency, description, annotationId, paypalClient, onError]);

  /**
   * 批准PayPal订单后的处理
   */
  const onApprove = useCallback(async (data: any, actions: any) => {
    try {
      setLoading(true);
      setError(null);

      if (!orderId) {
        throw new Error('订单ID未找到');
      }

      // 调用后端API捕获支付
      const response = await paypalClient.captureOrder({
        orderId: orderId,
        payerId: data.payerID
      });

      // 成功回调
      onSuccess?.({
        orderId: response.id,
        paymentId: response.id,
        payerId: data.payerID,
        amount,
        currency
      });

      toast.success('支付成功！');

    } catch (error) {
      console.error('Capture PayPal payment error:', error);
      const errorMessage = error instanceof Error ? error.message : '支付处理失败';
      setError(errorMessage);
      onError?.(error);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [orderId, paypalClient, onSuccess, onError, amount, currency]);

  /**
   * 处理支付取消
   */
  const onCancelHandler = useCallback((data: any) => {
    setLoading(false);
    setError(null);
    onCancel?.();
    toast.info('支付已取消');
  }, [onCancel]);

  /**
   * 处理支付错误
   */
  const onErrorHandler = useCallback((err: any) => {
    console.error('PayPal payment error:', err);
    const errorMessage = err?.message || '支付过程中出现错误';
    setError(errorMessage);
    setLoading(false);
    onError?.(err);
    toast.error(errorMessage);
  }, [onError]);

  // 如果金额无效，显示错误状态
  if (!isValidAmount) {
    return (
      <div className={`paypal-button-container ${className}`}>
        <Button 
          disabled 
          variant="destructive" 
          className="w-full"
        >
          <AlertCircle className="w-4 h-4 mr-2" />
          无效金额
        </Button>
      </div>
    );
  }

  return (
    <div className={`paypal-button-container ${className}`}>
      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center text-red-800">
            <AlertCircle className="w-4 h-4 mr-2 flex-shrink-0" />
            <span className="text-sm">{error}</span>
          </div>
        </div>
      )}

      <PayPalButtons
        disabled={disabled || loading}
        style={defaultStyle}
        createOrder={createOrder}
        onApprove={onApprove}
        onCancel={onCancelHandler}
        onError={onErrorHandler}
        forceReRender={[amount, currency, disabled]}
      />

      {loading && (
        <div className="flex items-center justify-center mt-3 text-gray-600">
          <Loader2 className="w-4 h-4 animate-spin mr-2" />
          <span className="text-sm">处理支付中...</span>
        </div>
      )}
    </div>
  );
};

/**
 * PayPal快捷支付按钮组件（带提供者包装）
 */
export interface PayPalQuickButtonProps extends PayPalButtonProps {
  clientId: string;
  environment?: 'sandbox' | 'production';
}

export const PayPalQuickButton: React.FC<PayPalQuickButtonProps> = ({
  clientId,
  environment = 'sandbox',
  currency = 'USD',
  ...buttonProps
}) => {
  return (
    <PayPalProvider
      clientId={clientId}
      currency={currency}
      environment={environment}
    >
      <PayPalButton
        currency={currency}
        {...buttonProps}
      />
    </PayPalProvider>
  );
};

/**
 * PayPal支付信息显示组件
 */
export interface PayPalPaymentInfoProps {
  amount: number;
  currency?: string;
  description: string;
  className?: string;
}

export const PayPalPaymentInfo: React.FC<PayPalPaymentInfoProps> = ({
  amount,
  currency = 'USD',
  description,
  className = ''
}) => {
  const formatAmount = (amount: number, currency: string): string => {
    const decimalPlaces = ['JPY', 'KRW', 'VND', 'IDR'].includes(currency) ? 0 : 2;
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency,
      minimumFractionDigits: decimalPlaces,
      maximumFractionDigits: decimalPlaces,
    }).format(amount);
  };

  return (
    <div className={`paypal-payment-info bg-gray-50 p-4 rounded-lg ${className}`}>
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm text-gray-600">支付金额:</span>
        <span className="text-lg font-semibold text-gray-900">
          {formatAmount(amount, currency)}
        </span>
      </div>
      
      <div className="flex justify-between items-start">
        <span className="text-sm text-gray-600">描述:</span>
        <span className="text-sm text-gray-900 text-right max-w-xs">
          {description}
        </span>
      </div>

      <div className="mt-3 pt-3 border-t border-gray-200">
        <div className="flex items-center justify-center">
          <img 
            src="https://www.paypalobjects.com/webstatic/mktg/logo/AM_mc_vs_dc_ae.jpg" 
            alt="PayPal" 
            className="h-6"
          />
          <span className="ml-2 text-xs text-gray-500">安全支付</span>
        </div>
      </div>
    </div>
  );
};

/**
 * PayPal支付状态组件
 */
export interface PayPalStatusProps {
  status: 'idle' | 'loading' | 'success' | 'error' | 'cancelled';
  message?: string;
  className?: string;
}

export const PayPalStatus: React.FC<PayPalStatusProps> = ({
  status,
  message,
  className = ''
}) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'loading':
        return {
          icon: <Loader2 className="w-5 h-5 animate-spin" />,
          color: 'text-blue-600',
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200'
        };
      case 'success':
        return {
          icon: <div className="w-5 h-5 rounded-full bg-green-500 flex items-center justify-center text-white text-xs">✓</div>,
          color: 'text-green-600',
          bgColor: 'bg-green-50',
          borderColor: 'border-green-200'
        };
      case 'error':
        return {
          icon: <AlertCircle className="w-5 h-5" />,
          color: 'text-red-600',
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200'
        };
      case 'cancelled':
        return {
          icon: <div className="w-5 h-5 rounded-full bg-gray-500 flex items-center justify-center text-white text-xs">✕</div>,
          color: 'text-gray-600',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200'
        };
      default:
        return {
          icon: null,
          color: 'text-gray-600',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200'
        };
    }
  };

  if (status === 'idle') {
    return null;
  }

  const config = getStatusConfig();

  return (
    <div className={`paypal-status flex items-center p-3 rounded-lg border ${config.bgColor} ${config.borderColor} ${className}`}>
      {config.icon && (
        <div className={`mr-3 ${config.color}`}>
          {config.icon}
        </div>
      )}
      
      <div className={`flex-1 ${config.color}`}>
        <span className="text-sm font-medium">
          {message || `支付${status === 'loading' ? '处理中' : status === 'success' ? '成功' : status === 'error' ? '失败' : '已取消'}`}
        </span>
      </div>
    </div>
  );
};

export default PayPalButton;