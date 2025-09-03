/**
 * 通知状态管理
 * 使用Zustand管理通知相关状态
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import websocketService, { type RewardNotification, type GeofenceNotification, type AchievementNotification } from '../services/websocketService';

interface Notification {
  id: string;
  type: 'reward' | 'geofence' | 'achievement' | 'system';
  title: string;
  message: string;
  data?: any;
  timestamp: string;
  read: boolean;
  persistent: boolean; // 是否持久化显示
}

interface NotificationSettings {
  enabled: boolean;
  sound: boolean;
  vibration: boolean;
  browserNotifications: boolean;
  rewardNotifications: boolean;
  geofenceNotifications: boolean;
  achievementNotifications: boolean;
  systemNotifications: boolean;
}

interface NotificationStore {
  // 状态
  notifications: Notification[];
  unreadCount: number;
  isConnected: boolean;
  connectionState: string;
  settings: NotificationSettings;

  // 操作
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  removeNotification: (id: string) => void;
  clearAllNotifications: () => void;
  updateSettings: (settings: Partial<NotificationSettings>) => void;

  // WebSocket相关
  connectWebSocket: (token: string) => Promise<void>;
  disconnectWebSocket: () => void;
  updateConnectionState: (state: string, connected: boolean) => void;

  // 通知处理
  handleRewardNotification: (data: RewardNotification) => void;
  handleGeofenceNotification: (data: GeofenceNotification) => void;
  handleAchievementNotification: (data: AchievementNotification) => void;
  handleSystemMessage: (data: any) => void;
}

const defaultSettings: NotificationSettings = {
  enabled: true,
  sound: true,
  vibration: true,
  browserNotifications: true,
  rewardNotifications: true,
  geofenceNotifications: true,
  achievementNotifications: true,
  systemNotifications: true,
};

const useNotificationStore = create<NotificationStore>()(persist(
  (set, get) => ({
    // 初始状态
    notifications: [],
    unreadCount: 0,
    isConnected: false,
    connectionState: 'disconnected',
    settings: defaultSettings,

    // 添加通知
    addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => {
      const newNotification: Notification = {
        ...notification,
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
      };

      set((state: any) => {
        const notifications = [newNotification, ...state.notifications];
        // 限制通知数量，保留最新的100条
        const limitedNotifications = notifications.slice(0, 100);

        return {
          notifications: limitedNotifications,
          unreadCount: state.unreadCount + (newNotification.read ? 0 : 1),
        };
      });

      // 播放通知音效
      if (get().settings.sound && get().settings.enabled) {
        playNotificationSound(notification.type);
      }

      // 触发振动
      if (get().settings.vibration && get().settings.enabled && 'vibrate' in navigator) {
        navigator.vibrate([200, 100, 200]);
      }
    },

    // 标记为已读
    markAsRead: (id: string) => {
      set((state: NotificationStore) => {
        const notifications = state.notifications.map((notification: Notification) => {
          if (notification.id === id && !notification.read) {
            websocketService.markNotificationRead(id);
            return { ...notification, read: true };
          }
          return notification;
        });

        const unreadCount = notifications.filter((n: Notification) => !n.read).length;

        return { notifications, unreadCount };
      });
    },

    // 标记所有为已读
    markAllAsRead: () => {
      set((state: NotificationStore) => {
        const notifications = state.notifications.map((notification: Notification) => {
          if (!notification.read) {
            websocketService.markNotificationRead(notification.id);
          }
          return { ...notification, read: true };
        });

        return { notifications, unreadCount: 0 };
      });
    },

    // 移除通知
    removeNotification: (id: string) => {
      set((state: NotificationStore) => {
        const notification = state.notifications.find((n: Notification) => n.id === id);
        const notifications = state.notifications.filter((n: Notification) => n.id !== id);
        const unreadCount = notification && !notification.read
          ? state.unreadCount - 1
          : state.unreadCount;

        return { notifications, unreadCount };
      });
    },

    // 清空所有通知
    clearAllNotifications: () => {
      set({ notifications: [], unreadCount: 0 });
    },

    // 更新设置
    updateSettings: (newSettings: Partial<NotificationSettings>) => {
      set((state: NotificationStore) => ({
        settings: { ...state.settings, ...newSettings },
      }));
    },

    // 连接WebSocket
    connectWebSocket: async (token: string) => {
      try {
        await websocketService.connect(token);

        // 注册事件监听器
        websocketService.on('connected', () => {
          get().updateConnectionState('connected', true);
        });

        websocketService.on('connection_closed', () => {
          get().updateConnectionState('disconnected', false);
        });

        websocketService.on('connection_error', () => {
          get().updateConnectionState('error', false);
        });

        websocketService.on('reward_earned', (data) => {
          if (get().settings.rewardNotifications) {
            get().handleRewardNotification(data);
          }
        });

        websocketService.on('geofence_entered', (data) => {
          if (get().settings.geofenceNotifications) {
            get().handleGeofenceNotification(data);
          }
        });

        websocketService.on('achievement_unlocked', (data) => {
          if (get().settings.achievementNotifications) {
            get().handleAchievementNotification(data);
          }
        });

        websocketService.on('system_message', (data) => {
          if (get().settings.systemNotifications) {
            get().handleSystemMessage(data);
          }
        });

        // 订阅通知
        websocketService.subscribeNotifications();

      } catch (error) {
        console.error('WebSocket连接失败:', error);
        get().updateConnectionState('error', false);
        throw error;
      }
    },

    // 断开WebSocket
    disconnectWebSocket: () => {
      websocketService.disconnect();
      set({ isConnected: false, connectionState: 'disconnected' });
    },

    // 更新连接状态
    updateConnectionState: (state: string, connected: boolean) => {
      set({ connectionState: state as any, isConnected: connected });
    },

    // 处理奖励通知
    handleRewardNotification: (data: any) => {
      get().addNotification({
        type: 'reward',
        title: '🎉 获得奖励！',
        message: `在${data.geofenceName}获得${data.amount}积分`,
        data,
        read: false,
        persistent: true,
      });
    },

    // 处理地理围栏通知
    handleGeofenceNotification: (data: any) => {
      get().addNotification({
        type: 'geofence',
        title: '📍 发现新地点！',
        message: `进入${data.name}，可获得${data.potentialReward}积分`,
        data,
        read: false,
        persistent: false,
      });
    },

    // 处理成就通知
    handleAchievementNotification: (data: any) => {
      get().addNotification({
        type: 'achievement',
        title: '🏆 成就解锁！',
        message: `解锁成就：${data.name}`,
        data,
        read: false,
        persistent: true,
      });
    },

    // 处理系统消息
    handleSystemMessage: (data: any) => {
      get().addNotification({
        type: 'system',
        title: '系统消息',
        message: data.message,
        data,
        read: false,
        persistent: false,
      });
    },
  }),
  {
    name: 'notification-store',
    partialize: (state: any) => ({
      settings: state.settings,
      notifications: state.notifications.filter((n: any) => n.persistent), // 只持久化重要通知
    }),
  },
));

/**
 * 播放通知音效
 * @param type 通知类型
 */
function playNotificationSound(type: string): void {
  try {
    const audio = new Audio();

    switch (type) {
      case 'reward':
        audio.src = '/sounds/reward.mp3';
        break;
      case 'achievement':
        audio.src = '/sounds/achievement.mp3';
        break;
      case 'geofence':
        audio.src = '/sounds/geofence.mp3';
        break;
      default:
        audio.src = '/sounds/notification.mp3';
    }

    audio.volume = 0.5;
    audio.play().catch(error => {
      console.log('播放通知音效失败:', error);
    });
  } catch (error) {
    console.log('创建音频对象失败:', error);
  }
}

/**
 * 请求通知权限
 */
export async function requestNotificationPermission(): Promise<boolean> {
  if ('Notification' in window) {
    if (Notification.permission === 'granted') {
      return true;
    } else if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
  }
  return false;
}

/**
 * 检查通知权限状态
 */
export function getNotificationPermission(): string {
  if ('Notification' in window) {
    return Notification.permission;
  }
  return 'unsupported';
}

export default useNotificationStore;
export type { Notification, NotificationSettings };
