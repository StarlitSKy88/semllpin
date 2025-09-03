'use client';

import { useEffect } from 'react';
import { toast } from 'sonner';
import { useNotificationStore, notificationConfig, type Notification } from '@/lib/stores/notification-store';
import { useAuthStore } from '@/lib/stores/auth-store';

interface NotificationProviderProps {
  children: React.ReactNode;
}

export default function NotificationProvider({ children }: NotificationProviderProps) {
  const { isAuthenticated, user } = useAuthStore();
  const { 
    notifications, 
    subscribeToNotifications, 
    unsubscribeFromNotifications,
    markAsRead 
  } = useNotificationStore();
  
  // 监听新通知并显示 toast
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const unsubscribe = subscribeToNotifications();
    
    return () => {
      unsubscribe();
    };
  }, [isAuthenticated, subscribeToNotifications]);
  
  // 监听通知变化，显示 toast
  useEffect(() => {
    const latestNotification = notifications[0];
    if (latestNotification && !latestNotification.read) {
      const config = notificationConfig[latestNotification.type];
      
      toast(latestNotification.title, {
        description: latestNotification.message,
        icon: config.icon,
        action: {
          label: '查看',
          onClick: () => {
            markAsRead(latestNotification.id);
            
            // 根据通知类型跳转到相应页面
            switch (latestNotification.type) {
              case 'annotation_found':
              case 'reward_received':
                window.location.href = '/wallet';
                break;
              case 'annotation_approved':
              case 'annotation_rejected':
                window.location.href = '/profile/annotations';
                break;
              default:
                break;
            }
          },
        },
        duration: 5000,
      });
    }
  }, [notifications, markAsRead]);
  
  // 模拟接收通知（开发环境）
  useEffect(() => {
    if (!isAuthenticated || !user || process.env.NODE_ENV !== 'development') return;
    
    // 模拟每30秒接收一个随机通知
    const interval = setInterval(() => {
      const mockNotifications: Omit<Notification, 'id' | 'createdAt' | 'read'>[] = [
        {
          type: 'annotation_found',
          title: '标注被发现！',
          message: '你在"星巴克咖啡"的标注被用户发现，获得奖励 ¥5.00',
          userId: user.id,
          data: { amount: 5.00, location: '星巴克咖啡' }
        },
        {
          type: 'reward_received',
          title: '收益到账',
          message: '恭喜你获得 ¥3.50 的发现奖励',
          userId: user.id,
          data: { amount: 3.50 }
        },
        {
          type: 'annotation_approved',
          title: '标注审核通过',
          message: '你的标注"这里的咖啡超级香"已通过审核',
          userId: user.id,
          data: { annotationId: 'mock-id' }
        },
        {
          type: 'system',
          title: '系统维护通知',
          message: '系统将于今晚23:00-01:00进行维护，期间可能影响部分功能',
          userId: user.id,
          data: {}
        }
      ];
      
      const randomNotification = mockNotifications[Math.floor(Math.random() * mockNotifications.length)];
      
      // 添加到通知store（这里应该是从服务器推送）
      const newNotification: Notification = {
        ...randomNotification,
        id: `mock-${Date.now()}`,
        createdAt: new Date().toISOString(),
        read: false
      };
      
      // 模拟添加通知到store
      useNotificationStore.getState().addNotification(newNotification);
    }, 30000); // 30秒
    
    return () => clearInterval(interval);
  }, [isAuthenticated, user]);
  
  return <>{children}</>;
}