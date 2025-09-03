/**
 * 现代化通知组件
 * 基于设计令牌系统的统一通知实现
 */

import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import Button from './Button';

export interface NotificationProps {
  id?: string;
  type?: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  duration?: number;
  closable?: boolean;
  showIcon?: boolean;
  action?: {
    label: string;
    onClick: () => void;
  };
  onClose?: () => void;
  className?: string;
}

const Notification: React.FC<NotificationProps> = ({
  id: _id,
  type = 'info',
  title,
  message,
  duration = 4000,
  closable = true,
  showIcon = true,
  action,
  onClose,
  className,
}) => {
  useTheme();
  const [visible, setVisible] = useState(true);
  const [isLeaving, setIsLeaving] = useState(false);

  // 自动关闭
  useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => {
        handleClose();
      }, duration);

      return () => clearTimeout(timer);
    }
  }, [duration]);

  // 处理关闭
  const handleClose = () => {
    setIsLeaving(true);
    setTimeout(() => {
      setVisible(false);
      onClose?.();
    }, 300);
  };

  if (!visible) return null;

  // 类型配置
  const typeConfig = {
    success: {
      icon: CheckCircle,
      bgColor: 'bg-floral-50 dark:bg-floral-900/20',
      borderColor: 'border-floral-200 dark:border-floral-800',
      iconColor: 'text-floral-500 dark:text-floral-400',
      titleColor: 'text-floral-800 dark:text-floral-200',
      messageColor: 'text-floral-700 dark:text-floral-300',
    },
    error: {
      icon: AlertCircle,
      bgColor: 'bg-pomegranate-50 dark:bg-pomegranate-900/20',
      borderColor: 'border-pomegranate-200 dark:border-pomegranate-800',
      iconColor: 'text-pomegranate-500 dark:text-pomegranate-400',
      titleColor: 'text-pomegranate-800 dark:text-pomegranate-200',
      messageColor: 'text-pomegranate-700 dark:text-pomegranate-300',
    },
    warning: {
      icon: AlertTriangle,
      bgColor: 'bg-pomegranate-50 dark:bg-pomegranate-900/20',
      borderColor: 'border-pomegranate-200 dark:border-pomegranate-800',
      iconColor: 'text-pomegranate-400 dark:text-pomegranate-300',
      titleColor: 'text-pomegranate-700 dark:text-pomegranate-200',
      messageColor: 'text-pomegranate-600 dark:text-pomegranate-300',
    },
    info: {
      icon: Info,
      bgColor: 'bg-floral-50 dark:bg-floral-900/20',
      borderColor: 'border-floral-200 dark:border-floral-800',
      iconColor: 'text-floral-500 dark:text-floral-400',
      titleColor: 'text-floral-800 dark:text-floral-200',
      messageColor: 'text-floral-700 dark:text-floral-300',
    },
  };

  const config = typeConfig[type];
  const IconComponent = config.icon;

  return (
    <div
      className={cn(
        'max-w-sm w-full bg-white dark:bg-gray-800 shadow-lg rounded-lg pointer-events-auto',
        'border transform transition-all duration-300 ease-out',
        config.bgColor,
        config.borderColor,
        isLeaving
          ? 'translate-x-full opacity-0 scale-95'
          : 'translate-x-0 opacity-100 scale-100',
        className
      )}
      role="alert"
      aria-live="polite"
    >
      <div className="p-4">
        <div className="flex items-start">
          {/* 图标 */}
          {showIcon && (
            <div className="flex-shrink-0">
              <IconComponent
                className={cn('h-5 w-5', config.iconColor)}
                aria-hidden="true"
              />
            </div>
          )}

          {/* 内容 */}
          <div className={cn('ml-3 w-0 flex-1', !showIcon && 'ml-0')}>
            {title && (
              <p className={cn('text-sm font-medium', config.titleColor)}>
                {title}
              </p>
            )}
            <p className={cn('text-sm', config.messageColor, title && 'mt-1')}>
              {message}
            </p>

            {/* 操作按钮 */}
            {action && (
              <div className="mt-3">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={action.onClick}
                  className={cn(
                    'text-sm font-medium',
                    config.iconColor,
                    'hover:bg-white/50 dark:hover:bg-gray-700/50'
                  )}
                >
                  {action.label}
                </Button>
              </div>
            )}
          </div>

          {/* 关闭按钮 */}
          {closable && (
            <div className="ml-4 flex-shrink-0 flex">
              <Button
                variant="ghost"
                size="sm"
                icon={<X />}
                onClick={handleClose}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                aria-label="关闭通知"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// 通知容器组件
export interface NotificationContainerProps {
  position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' | 'top-center' | 'bottom-center';
  className?: string;
  children: React.ReactNode;
}

export const NotificationContainer: React.FC<NotificationContainerProps> = ({
  position = 'top-right',
  className,
  children,
}) => {
  const positionStyles = {
    'top-right': 'top-4 right-4',
    'top-left': 'top-4 left-4',
    'bottom-right': 'bottom-4 right-4',
    'bottom-left': 'bottom-4 left-4',
    'top-center': 'top-4 left-1/2 transform -translate-x-1/2',
    'bottom-center': 'bottom-4 left-1/2 transform -translate-x-1/2',
  };

  return createPortal(
    <div
      className={cn(
        'fixed z-50 flex flex-col space-y-4 pointer-events-none',
        positionStyles[position],
        className
      )}
      aria-live="polite"
      aria-label="通知区域"
    >
      {children}
    </div>,
    document.body
  );
};

// 通知管理器
class NotificationManager {
  private notifications: (NotificationProps & { id: string })[] = [];
  private listeners: ((notifications: (NotificationProps & { id: string })[]) => void)[] = [];

  // 添加通知
  add(notification: Omit<NotificationProps, 'id'>) {
    const id = Math.random().toString(36).substr(2, 9);
    const newNotification = { ...notification, id };
    
    this.notifications.push(newNotification);
    this.notify();

    return id;
  }

  // 移除通知
  remove(id: string) {
    this.notifications = this.notifications.filter(n => n.id !== id);
    this.notify();
  }

  // 清空所有通知
  clear() {
    this.notifications = [];
    this.notify();
  }

  // 订阅通知变化
  subscribe(listener: (notifications: (NotificationProps & { id: string })[]) => void) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  // 通知监听器
  private notify() {
    this.listeners.forEach(listener => listener([...this.notifications]));
  }

  // 获取当前通知列表
  getNotifications() {
    return [...this.notifications];
  }
}

// 全局通知管理器实例
export const notificationManager = new NotificationManager();

// 通知提供者组件
export interface NotificationProviderProps {
  position?: NotificationContainerProps['position'];
  maxCount?: number;
  children: React.ReactNode;
}

export const NotificationProvider: React.FC<NotificationProviderProps> = ({
  position = 'top-right',
  maxCount = 5,
  children,
}) => {
  const [notifications, setNotifications] = useState<(NotificationProps & { id: string })[]>([]);

  useEffect(() => {
    const unsubscribe = notificationManager.subscribe(setNotifications);
    return unsubscribe;
  }, []);

  // 限制通知数量
  const visibleNotifications = notifications.slice(-maxCount);

  return (
    <>
      {children}
      <NotificationContainer position={position}>
        {visibleNotifications.map((notification) => (
          <Notification
            key={notification.id}
            {...notification}
            onClose={() => notificationManager.remove(notification.id!)}
          />
        ))}
      </NotificationContainer>
    </>
  );
};

// 便捷方法
export const notification = {
  success: (message: string, options?: Partial<NotificationProps>) => {
    return notificationManager.add({ ...options, type: 'success', message });
  },
  error: (message: string, options?: Partial<NotificationProps>) => {
    return notificationManager.add({ ...options, type: 'error', message });
  },
  warning: (message: string, options?: Partial<NotificationProps>) => {
    return notificationManager.add({ ...options, type: 'warning', message });
  },
  info: (message: string, options?: Partial<NotificationProps>) => {
    return notificationManager.add({ ...options, type: 'info', message });
  },
  remove: (id: string) => {
    notificationManager.remove(id);
  },
  clear: () => {
    notificationManager.clear();
  },
};

// Hook for using notifications
export const useNotification = () => {
  return notification;
};

export default Notification;