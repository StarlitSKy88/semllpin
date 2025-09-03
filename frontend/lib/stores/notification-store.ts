'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface Notification {
  id: string;
  type: 'annotation_found' | 'reward_received' | 'annotation_approved' | 'annotation_rejected' | 'system' | 'social';
  title: string;
  message: string;
  data?: any;
  read: boolean;
  createdAt: string;
  expiresAt?: string;
}

interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  addNotification: (notification: Omit<Notification, 'id' | 'createdAt' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
  fetchNotifications: () => Promise<void>;
  subscribeToNotifications: () => void;
  unsubscribeFromNotifications: () => void;
}

// 模拟通知数据
const mockNotifications: Notification[] = [
  {
    id: '1',
    type: 'annotation_found',
    title: '标注被发现！',
    message: '你的标注"搞笑厕所"被用户小明发现了，获得奖励 ¥5.00',
    data: { annotationId: 'ann_1', reward: 5.00, finder: '小明' },
    read: false,
    createdAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30分钟前
  },
  {
    id: '2',
    type: 'reward_received',
    title: '收益到账',
    message: '恭喜你发现标注"神秘小店"，获得奖励 ¥8.50',
    data: { annotationId: 'ann_2', reward: 8.50 },
    read: false,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), // 2小时前
  },
  {
    id: '3',
    type: 'annotation_approved',
    title: '标注审核通过',
    message: '你的标注"有趣的涂鸦"已通过审核并发布',
    data: { annotationId: 'ann_3' },
    read: true,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), // 1天前
  },
  {
    id: '4',
    type: 'annotation_rejected',
    title: '标注审核未通过',
    message: '你的标注"测试内容"未通过审核，原因：内容不符合平台规范',
    data: { annotationId: 'ann_4', reason: '内容不符合平台规范' },
    read: true,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2).toISOString(), // 2天前
  },
  {
    id: '5',
    type: 'system',
    title: '系统维护通知',
    message: '系统将于今晚23:00-01:00进行维护升级，期间可能影响部分功能使用',
    read: false,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(), // 6小时前
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(), // 1天后过期
  },
];

export const useNotificationStore = create<NotificationState>()(persist(
  (set, get) => ({
    notifications: [],
    unreadCount: 0,
    isLoading: false,
    error: null,

    addNotification: (notification) => {
      const newNotification: Notification = {
        ...notification,
        id: Date.now().toString(),
        createdAt: new Date().toISOString(),
        read: false,
      };
      
      set((state) => ({
        notifications: [newNotification, ...state.notifications],
        unreadCount: state.unreadCount + 1,
      }));
    },

    markAsRead: (id) => {
      set((state) => {
        const notifications = state.notifications.map(notification => 
          notification.id === id ? { ...notification, read: true } : notification
        );
        const unreadCount = notifications.filter(n => !n.read).length;
        
        return { notifications, unreadCount };
      });
    },

    markAllAsRead: () => {
      set((state) => ({
        notifications: state.notifications.map(notification => ({ ...notification, read: true })),
        unreadCount: 0,
      }));
    },

    removeNotification: (id) => {
      set((state) => {
        const notifications = state.notifications.filter(notification => notification.id !== id);
        const unreadCount = notifications.filter(n => !n.read).length;
        
        return { notifications, unreadCount };
      });
    },

    clearNotifications: () => {
      set({ notifications: [], unreadCount: 0 });
    },

    fetchNotifications: async () => {
      set({ isLoading: true, error: null });
      
      try {
        // TODO: 替换为实际API调用
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // 过滤过期通知
        const now = new Date().toISOString();
        const validNotifications = mockNotifications.filter(notification => 
          !notification.expiresAt || notification.expiresAt > now
        );
        
        const unreadCount = validNotifications.filter(n => !n.read).length;
        
        set({ 
          notifications: validNotifications,
          unreadCount,
          isLoading: false 
        });
      } catch (error) {
        set({ 
          error: error instanceof Error ? error.message : '获取通知失败',
          isLoading: false 
        });
      }
    },

    subscribeToNotifications: () => {
      // TODO: 实现WebSocket或Server-Sent Events订阅
      console.log('订阅实时通知');
      
      // 模拟定期检查新通知
      const interval = setInterval(() => {
        // 这里可以调用API检查新通知
        console.log('检查新通知...');
      }, 30000); // 每30秒检查一次
      
      // 存储interval ID以便后续清理
      (window as any).notificationInterval = interval;
    },

    unsubscribeFromNotifications: () => {
      console.log('取消订阅实时通知');
      
      if ((window as any).notificationInterval) {
        clearInterval((window as any).notificationInterval);
        delete (window as any).notificationInterval;
      }
    },
  }),
  {
    name: 'notification-store',
    partialize: (state) => ({
      notifications: state.notifications,
      unreadCount: state.unreadCount,
    }),
  }
));

// 通知类型配置
export const notificationConfig = {
  annotation_found: {
    icon: '🎯',
    color: 'text-green-600',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200',
  },
  reward_received: {
    icon: '💰',
    color: 'text-yellow-600',
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
  },
  annotation_approved: {
    icon: '✅',
    color: 'text-blue-600',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
  },
  annotation_rejected: {
    icon: '❌',
    color: 'text-red-600',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
  },
  system: {
    icon: '🔧',
    color: 'text-gray-600',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-200',
  },
  social: {
    icon: '👥',
    color: 'text-purple-600',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
  },
};

// 工具函数
export const formatNotificationTime = (createdAt: string): string => {
  const now = new Date();
  const created = new Date(createdAt);
  const diffInMinutes = Math.floor((now.getTime() - created.getTime()) / (1000 * 60));
  
  if (diffInMinutes < 1) {
    return '刚刚';
  } else if (diffInMinutes < 60) {
    return `${diffInMinutes}分钟前`;
  } else if (diffInMinutes < 1440) {
    const hours = Math.floor(diffInMinutes / 60);
    return `${hours}小时前`;
  } else {
    const days = Math.floor(diffInMinutes / 1440);
    return `${days}天前`;
  }
};