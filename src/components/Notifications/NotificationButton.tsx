/**
 * 通知按钮组件
 * 显示通知图标和未读数量，点击打开通知中心
 */

import React, { useState, useEffect } from 'react';
import { Bell, BellRing } from 'lucide-react';
import useNotificationStore from '../../stores/notificationStore';
import NotificationCenter from './NotificationCenter';

interface NotificationButtonProps {
  className?: string;
  showLabel?: boolean;
}

const NotificationButton: React.FC<NotificationButtonProps> = ({ 
  className = '',
  showLabel = false 
}) => {
  const { unreadCount, isConnected } = useNotificationStore();
  // connectionState
  const [isOpen, setIsOpen] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);

  // 当有新通知时触发动画
  useEffect(() => {
    if (unreadCount > 0) {
      setIsAnimating(true);
      const timer = setTimeout(() => setIsAnimating(false), 1000);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [unreadCount]);

  const handleClick = () => {
    setIsOpen(!isOpen);
  };

  const handleClose = () => {
    setIsOpen(false);
  };

  return (
    <>
      <button
        onClick={handleClick}
        className={`relative flex items-center space-x-2 rounded-lg p-2 transition-all hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
          isAnimating ? 'animate-pulse' : ''
        } ${className}`}
        title="通知中心"
      >
        {/* 通知图标 */}
        <div className="relative">
          {unreadCount > 0 ? (
            <BellRing className={`h-5 w-5 text-gray-600 ${
              isAnimating ? 'animate-bounce' : ''
            }`} />
          ) : (
            <Bell className="h-5 w-5 text-gray-600" />
          )}
          
          {/* 未读数量徽章 */}
          {unreadCount > 0 && (
            <span className={`absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-xs font-medium text-white ${
              isAnimating ? 'animate-ping' : ''
            }`}>
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
          
          {/* 连接状态指示器 */}
          <div className={`absolute -bottom-1 -right-1 h-2 w-2 rounded-full ${
            isConnected ? 'bg-green-400' : 'bg-red-400'
          }`} />
        </div>
        
        {/* 标签文本 */}
        {showLabel && (
          <span className="text-sm font-medium text-gray-700">
            通知
            {unreadCount > 0 && (
              <span className="ml-1 text-red-500">({unreadCount})</span>
            )}
          </span>
        )}
      </button>
      
      {/* 通知中心 */}
      <NotificationCenter isOpen={isOpen} onClose={handleClose} />
    </>
  );
};

export default NotificationButton;