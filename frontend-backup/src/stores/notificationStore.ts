import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'reward';
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
  data?: unknown;
}

// WebSocket消息类型
interface WebSocketMessage {
  type: 'location_update' | 'reward_notification' | 'system_message';
  message?: string;
  // 位置更新相关
  nearbyAnnotations?: Array<{
    id: string;
    title: string;
    latitude: number;
    longitude: number;
  }>;
  // 奖励通知相关
  amount?: number;
  annotationId?: string;
  // 系统消息相关
  level?: 'info' | 'warning' | 'error' | 'success';
  title?: string;
}



interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  isConnected: boolean;
  socket: WebSocket | null;
}

interface NotificationActions {
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
  connectWebSocket: () => void;
  disconnectWebSocket: () => void;
  handleWebSocketMessage: (data: WebSocketMessage) => void;
  handleLocationUpdate: (data: WebSocketMessage) => void;
  handleRewardNotification: (data: WebSocketMessage) => void;
  handleSystemMessage: (data: WebSocketMessage) => void;
}

type NotificationStore = NotificationState & NotificationActions;

const useNotificationStore = create<NotificationStore>()(persist(
  (set, get) => ({
    // 初始状态
    notifications: [],
    unreadCount: 0,
    isConnected: false,
    socket: null,

    // 添加通知
    addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => {
      const newNotification: Notification = {
        ...notification,
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        timestamp: Date.now(),
        read: false,
      };

      set((state: NotificationState) => ({
        notifications: [newNotification, ...state.notifications],
        unreadCount: state.unreadCount + 1,
      }));
    },

    // 标记为已读
    markAsRead: (id: string) => {
      set((state: NotificationState) => {
        const notifications = state.notifications.map((notification: Notification) =>
          notification.id === id ? { ...notification, read: true } : notification
        );
        const unreadCount = notifications.filter((n: Notification) => !n.read).length;
        return { notifications, unreadCount };
      });
    },

    // 标记全部为已读
    markAllAsRead: () => {
      set((state: NotificationState) => ({
        notifications: state.notifications.map((notification: Notification) => ({
          ...notification,
          read: true,
        })),
        unreadCount: 0,
      }));
    },

    // 移除通知
    removeNotification: (id: string) => {
      set((state: NotificationState) => {
        const notifications = state.notifications.filter((n: Notification) => n.id !== id);
        const unreadCount = notifications.filter((n: Notification) => !n.read).length;
        return { notifications, unreadCount };
      });
    },

    // 清空所有通知
    clearAll: () => {
      set({ notifications: [], unreadCount: 0 });
    },

    // 连接WebSocket
    connectWebSocket: () => {
      // 安全获取token
      let token: string | null = null;
      try {
        if (typeof window !== 'undefined' && window.localStorage) {
          token = localStorage.getItem('auth_token');
        }
      } catch (error) {
        console.warn('无法访问localStorage:', error);
        return;
      }
      
      if (!token) return;

      const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:3001';
      const socket = new WebSocket(`${wsUrl}?token=${token}`);

      socket.onopen = () => {
        console.log('WebSocket连接已建立');
        set({ isConnected: true, socket });
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          get().handleWebSocketMessage(data);
        } catch (error) {
          console.error('WebSocket消息解析失败:', error);
        }
      };

      socket.onclose = () => {
        console.log('WebSocket连接已关闭');
        set({ isConnected: false, socket: null });
      };

      socket.onerror = (error) => {
        console.error('WebSocket错误:', error);
        set({ isConnected: false, socket: null });
      };
    },

    // 断开WebSocket
    disconnectWebSocket: () => {
      const { socket } = get();
      if (socket) {
        socket.close();
        set({ isConnected: false, socket: null });
      }
    },

    // 处理WebSocket消息
    handleWebSocketMessage: (data: WebSocketMessage) => {
      const { addNotification } = get();
      
      switch (data.type) {
        case 'location_update':
          get().handleLocationUpdate(data);
          break;
        case 'reward_notification':
          get().handleRewardNotification(data);
          break;
        case 'system_message':
          get().handleSystemMessage(data);
          break;
        default:
          addNotification({
            type: 'info',
            title: '新消息',
            message: data.message || '收到新消息',
            data,
          });
      }
    },

    // 处理位置更新
    handleLocationUpdate: (data: WebSocketMessage) => {
      const { addNotification } = get();
      
      if (data.nearbyAnnotations && data.nearbyAnnotations.length > 0) {
        addNotification({
          type: 'info',
          title: '发现附近标注',
          message: `发现 ${data.nearbyAnnotations.length} 个附近的标注点`,
          data,
        });
      }
    },

    // 处理奖励通知
    handleRewardNotification: (data: WebSocketMessage) => {
      const { addNotification } = get();
      
      if (data.amount) {
        addNotification({
          type: 'reward',
          title: '🎉 获得奖励!',
          message: `恭喜您获得 ${data.amount} 积分奖励！`,
          data,
        });
      }

      // 播放奖励音效
      if ('Audio' in window) {
        try {
          const audio = new Audio('/sounds/reward.mp3');
          audio.volume = 0.3;
          audio.play().catch(() => {
            // 忽略音频播放失败
          });
        } catch {
          // 忽略音频播放失败
        }
      }
    },

    // 处理系统消息
    handleSystemMessage: (data: WebSocketMessage) => {
      const { addNotification } = get();
      
      addNotification({
        type: data.level || 'info',
        title: data.title || '系统通知',
        message: data.message || '',
        data,
      });
    },
  }),
  {
    name: 'notification-storage',
    partialize: (state) => ({
      notifications: state.notifications.slice(0, 50), // 只保存最近50条通知
    }),
  }
));

export default useNotificationStore;