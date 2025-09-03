import { useEffect, useCallback } from 'react';
import { useAuthStore } from '../stores/authStore';
import useNotificationStore from '../stores/notificationStore';

interface NotificationData {
  id: string;
  type: string;
  title: string;
  content: string;
  message?: string;
  sender?: {
    id: string;
    username: string;
    avatar_url?: string;
  };
  actionUrl?: string;
  createdAt: string;
  read?: boolean;
}

interface UseWebSocketOptions {
  onNewNotification?: (notification: NotificationData) => void;
  onUnreadCountUpdate?: (count: number) => void;
  onConnectionChange?: (connected: boolean) => void;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  unreadCount: number;
  markNotificationAsRead: (id: string) => void;
  refreshUnreadCount: () => void;
  connect: () => void;
  disconnect: () => void;
}

const useWebSocket = (options: UseWebSocketOptions = {}): UseWebSocketReturn => {
  const { token, isAuthenticated } = useAuthStore();
  const { isConnected, unreadCount, connectWebSocket, disconnectWebSocket } = useNotificationStore();
  const { onUnreadCountUpdate, onConnectionChange } = options;

  // 连接WebSocket
  const connect = useCallback(() => {
    if (!isAuthenticated || !token) {
      console.log('用户未认证，跳过WebSocket连接');
      return;
    }
    connectWebSocket();
  }, [isAuthenticated, token, connectWebSocket]);

  // 断开WebSocket
  const disconnect = useCallback(() => {
    disconnectWebSocket();
  }, [disconnectWebSocket]);

  // 标记通知为已读
  const markNotificationAsRead = useCallback((id: string) => {
    // 这里可以调用API标记为已读
    console.log('标记通知为已读:', id);
  }, []);

  // 刷新未读数量
  const refreshUnreadCount = useCallback(() => {
    // 这里可以调用API刷新未读数量
    console.log('刷新未读数量');
  }, []);

  // 自动连接/断开逻辑
  useEffect(() => {
    if (isAuthenticated && token) {
      connect();
    } else {
      disconnect();
    }
  }, [isAuthenticated, token, connect, disconnect]);

  // 监听连接状态变化
  useEffect(() => {
    onConnectionChange?.(isConnected);
  }, [isConnected, onConnectionChange]);

  // 监听未读数量变化
  useEffect(() => {
    onUnreadCountUpdate?.(unreadCount);
  }, [unreadCount, onUnreadCountUpdate]);

  return {
    isConnected,
    unreadCount,
    markNotificationAsRead,
    refreshUnreadCount,
    connect,
    disconnect
  };
};

export default useWebSocket;