import { useState, useEffect, useCallback } from 'react';
import { smsService } from '../services/sms-service';

interface UseSMSCodeOptions {
  phone: string;
  type: 'login' | 'register';
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

interface UseSMSCodeReturn {
  isLoading: boolean;
  countdown: number;
  canSend: boolean;
  sendCode: () => Promise<void>;
  error: string | null;
  clearError: () => void;
}

export function useSMSCode({
  phone,
  type,
  onSuccess,
  onError
}: UseSMSCodeOptions): UseSMSCodeReturn {
  const [isLoading, setIsLoading] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // 更新倒计时
  useEffect(() => {
    if (countdown <= 0) return;

    const timer = setInterval(() => {
      const remaining = smsService.getCooldownCountdown(phone);
      setCountdown(remaining);
      
      if (remaining <= 0) {
        clearInterval(timer);
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [countdown, phone]);

  // 检查初始冷却状态
  useEffect(() => {
    const remaining = smsService.getCooldownCountdown(phone);
    setCountdown(remaining);
  }, [phone]);

  const sendCode = useCallback(async () => {
    if (isLoading || countdown > 0) return;

    setIsLoading(true);
    setError(null);

    try {
      const success = await smsService.sendCode({
        phone,
        type,
        onSuccess: () => {
          setCountdown(60); // 开始倒计时
          onSuccess?.();
        },
        onError: (errorMsg) => {
          setError(errorMsg);
          onError?.(errorMsg);
        }
      });

      if (success) {
        setCountdown(60);
      }
    } catch (err: any) {
      const errorMsg = err.message || '发送失败';
      setError(errorMsg);
      onError?.(errorMsg);
    } finally {
      setIsLoading(false);
    }
  }, [phone, type, isLoading, countdown, onSuccess, onError]);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const canSend = !isLoading && countdown <= 0 && phone.length === 11;

  return {
    isLoading,
    countdown,
    canSend,
    sendCode,
    error,
    clearError
  };
}