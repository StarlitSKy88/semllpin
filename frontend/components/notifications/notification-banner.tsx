'use client';

import { useState, useEffect } from 'react';
import { X, AlertTriangle, Info, CheckCircle, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useNotificationStore, type Notification } from '@/lib/stores/notification-store';

interface NotificationBannerProps {
  notification: Notification;
  onDismiss: (id: string) => void;
}

function NotificationBanner({ notification, onDismiss }: NotificationBannerProps) {
  const getIcon = () => {
    switch (notification.type) {
      case 'system':
        return <Info className="h-4 w-4" />;
      case 'reward_received':
      case 'annotation_approved':
        return <CheckCircle className="h-4 w-4" />;
      case 'annotation_rejected':
        return <AlertTriangle className="h-4 w-4" />;
      default:
        return <AlertCircle className="h-4 w-4" />;
    }
  };
  
  const getVariant = (): 'default' | 'destructive' => {
    switch (notification.type) {
      case 'annotation_rejected':
        return 'destructive';
      default:
        return 'default';
    }
  };
  
  return (
    <Alert variant={getVariant()} className="relative">
      {getIcon()}
      <AlertDescription className="pr-8">
        <span className="font-medium">{notification.title}</span>
        {notification.message && (
          <span className="ml-2">{notification.message}</span>
        )}
      </AlertDescription>
      <Button
        variant="ghost"
        size="sm"
        className="absolute right-2 top-2 h-6 w-6 p-0"
        onClick={() => onDismiss(notification.id)}
      >
        <X className="h-4 w-4" />
      </Button>
    </Alert>
  );
}

export default function NotificationBanners() {
  const { notifications, removeNotification } = useNotificationStore();
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());
  
  // 只显示重要的未读通知作为横幅
  const bannerNotifications = notifications.filter(notification => 
    !notification.read && 
    !dismissedIds.has(notification.id) &&
    ['system', 'reward_received', 'annotation_approved', 'annotation_rejected'].includes(notification.type)
  ).slice(0, 3); // 最多显示3个横幅
  
  const handleDismiss = (id: string) => {
    setDismissedIds(prev => new Set([...prev, id]));
    // 可选：同时标记为已读
    // markAsRead(id);
  };
  
  if (bannerNotifications.length === 0) {
    return null;
  }
  
  return (
    <div className="space-y-2">
      {bannerNotifications.map((notification) => (
        <NotificationBanner
          key={notification.id}
          notification={notification}
          onDismiss={handleDismiss}
        />
      ))}
    </div>
  );
}