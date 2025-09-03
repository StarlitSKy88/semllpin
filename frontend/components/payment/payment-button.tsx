'use client';

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { PaymentModal } from './payment-modal';
import { Wallet, DollarSign } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PaymentButtonProps {
  className?: string;
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  annotationData?: {
    location: string;
    description: string;
    coordinates: [number, number];
  };
  onPaymentSuccess?: (paymentId: string) => void;
  children?: React.ReactNode;
  disabled?: boolean;
}

export function PaymentButton({
  className,
  variant = 'default',
  size = 'default',
  annotationData,
  onPaymentSuccess,
  children,
  disabled = false
}: PaymentButtonProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handlePaymentSuccess = (paymentId: string) => {
    setIsModalOpen(false);
    onPaymentSuccess?.(paymentId);
  };

  return (
    <>
      <Button
        className={cn(className)}
        variant={variant}
        size={size}
        onClick={() => setIsModalOpen(true)}
        disabled={disabled}
      >
        {children || (
          <>
            <Wallet className="h-4 w-4 mr-2" />
            创建付费标注
          </>
        )}
      </Button>
      
      <PaymentModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        annotationData={annotationData}
        onPaymentSuccess={handlePaymentSuccess}
      />
    </>
  );
}

// 快速支付按钮组件
interface QuickPaymentButtonProps {
  amount: number;
  description: string;
  className?: string;
  onPaymentSuccess?: (paymentId: string) => void;
  disabled?: boolean;
}

export function QuickPaymentButton({
  amount,
  description,
  className,
  onPaymentSuccess,
  disabled = false
}: QuickPaymentButtonProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handlePaymentSuccess = (paymentId: string) => {
    setIsModalOpen(false);
    onPaymentSuccess?.(paymentId);
  };

  return (
    <>
      <Button
        className={cn('bg-green-600 hover:bg-green-700', className)}
        onClick={() => setIsModalOpen(true)}
        disabled={disabled}
      >
        <DollarSign className="h-4 w-4 mr-2" />
        支付 ¥{amount}
      </Button>
      
      <PaymentModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onPaymentSuccess={handlePaymentSuccess}
      />
    </>
  );
}

export default PaymentButton;