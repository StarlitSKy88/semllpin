'use client';

import { useState, useEffect } from 'react';
import { Bell, X, Check, Trash2, Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import { useNotificationStore, notificationConfig, formatNotificationTime, type Notification } from '@/lib/stores/notification-store';
import { toast } from 'sonner';

interface NotificationItemProps {
  notification: Notification;
  onMarkAsRead: (id: string) => void;
  onRemove: (id: string) => void;
}

function NotificationItem({ notification, onMarkAsRead, onRemove }: NotificationItemProps) {
  const config = notificationConfig[notification.type];
  
  const handleClick = () => {
    if (!notification.read) {
      onMarkAsRead(notification.id);
    }
    
    // 根据通知类型执行相应操作
    switch (notification.type) {
      case 'annotation_found':
      case 'reward_received':
        // 跳转到钱包页面
        window.location.href = '/wallet';
        break;
      case 'annotation_approved':
      case 'annotation_rejected':
        // 跳转到我的标注页面
        window.location.href = '/profile/annotations';
        break;
      default:
        break;
    }
  };
  
  return (
    <div
      className={`p-4 border-l-4 cursor-pointer transition-all hover:bg-gray-50 ${
        notification.read ? 'opacity-70' : ''
      } ${config.borderColor} ${config.bgColor}`}
      onClick={handleClick}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-3 flex-1">
          <div className="text-2xl">{config.icon}</div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2">
              <h4 className={`font-medium ${config.color}`}>
                {notification.title}
              </h4>
              {!notification.read && (
                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
              )}
            </div>
            <p className="text-sm text-gray-600 mt-1 line-clamp-2">
              {notification.message}
            </p>
            <p className="text-xs text-gray-400 mt-2">
              {formatNotificationTime(notification.createdAt)}
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-1 ml-2">
          {!notification.read && (
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                onMarkAsRead(notification.id);
              }}
              className="h-8 w-8 p-0"
            >
              <Check className="h-4 w-4" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              onRemove(notification.id);
            }}
            className="h-8 w-8 p-0 text-red-500 hover:text-red-700"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

interface NotificationSettingsProps {
  settings: NotificationSettings;
  onSettingsChange: (settings: NotificationSettings) => void;
}

interface NotificationSettings {
  annotationFound: boolean;
  rewardReceived: boolean;
  annotationApproved: boolean;
  annotationRejected: boolean;
  systemNotifications: boolean;
  socialNotifications: boolean;
  emailNotifications: boolean;
  pushNotifications: boolean;
}

function NotificationSettings({ settings, onSettingsChange }: NotificationSettingsProps) {
  const updateSetting = (key: keyof NotificationSettings, value: boolean) => {
    onSettingsChange({ ...settings, [key]: value });
  };
  
  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium mb-4">通知类型</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="annotation-found">标注被发现</Label>
            <Switch
              id="annotation-found"
              checked={settings.annotationFound}
              onCheckedChange={(checked) => updateSetting('annotationFound', checked)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="reward-received">收益到账</Label>
            <Switch
              id="reward-received"
              checked={settings.rewardReceived}
              onCheckedChange={(checked) => updateSetting('rewardReceived', checked)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="annotation-approved">标注审核通过</Label>
            <Switch
              id="annotation-approved"
              checked={settings.annotationApproved}
              onCheckedChange={(checked) => updateSetting('annotationApproved', checked)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="annotation-rejected">标注审核未通过</Label>
            <Switch
              id="annotation-rejected"
              checked={settings.annotationRejected}
              onCheckedChange={(checked) => updateSetting('annotationRejected', checked)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="system-notifications">系统通知</Label>
            <Switch
              id="system-notifications"
              checked={settings.systemNotifications}
              onCheckedChange={(checked) => updateSetting('systemNotifications', checked)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="social-notifications">社交通知</Label>
            <Switch
              id="social-notifications"
              checked={settings.socialNotifications}
              onCheckedChange={(checked) => updateSetting('socialNotifications', checked)}
            />
          </div>
        </div>
      </div>
      
      <Separator />
      
      <div>
        <h3 className="text-lg font-medium mb-4">通知方式</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="email-notifications">邮件通知</Label>
            <Switch
              id="email-notifications"
              checked={settings.emailNotifications}
              onCheckedChange={(checked) => updateSetting('emailNotifications', checked)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="push-notifications">推送通知</Label>
            <Switch
              id="push-notifications"
              checked={settings.pushNotifications}
              onCheckedChange={(checked) => updateSetting('pushNotifications', checked)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

export default function NotificationCenter() {
  const {
    notifications,
    unreadCount,
    isLoading,
    error,
    markAsRead,
    markAllAsRead,
    removeNotification,
    clearNotifications,
    fetchNotifications,
    subscribeToNotifications,
    unsubscribeFromNotifications,
  } = useNotificationStore();
  
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState<'all' | 'unread'>('all');
  const [settings, setSettings] = useState<NotificationSettings>({
    annotationFound: true,
    rewardReceived: true,
    annotationApproved: true,
    annotationRejected: true,
    systemNotifications: true,
    socialNotifications: true,
    emailNotifications: false,
    pushNotifications: true,
  });
  
  useEffect(() => {
    fetchNotifications();
    subscribeToNotifications();
    
    return () => {
      unsubscribeFromNotifications();
    };
  }, [fetchNotifications, subscribeToNotifications, unsubscribeFromNotifications]);
  
  const filteredNotifications = notifications.filter(notification => {
    if (filter === 'unread') {
      return !notification.read;
    }
    return true;
  });
  
  const handleMarkAllAsRead = () => {
    markAllAsRead();
    toast.success('所有通知已标记为已读');
  };
  
  const handleClearAll = () => {
    clearNotifications();
    toast.success('所有通知已清除');
  };
  
  const handleSettingsChange = (newSettings: NotificationSettings) => {
    setSettings(newSettings);
    // TODO: 保存设置到服务器
    toast.success('通知设置已保存');
  };
  
  return (
    <Sheet open={isOpen} onOpenChange={setIsOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="sm" className="relative">
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <Badge 
              variant="destructive" 
              className="absolute -top-2 -right-2 h-5 w-5 flex items-center justify-center p-0 text-xs"
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </Badge>
          )}
        </Button>
      </SheetTrigger>
      
      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle className="flex items-center justify-between">
            <span>通知中心</span>
            <div className="flex items-center space-x-2">
              {unreadCount > 0 && (
                <Badge variant="secondary">{unreadCount} 条未读</Badge>
              )}
            </div>
          </SheetTitle>
          <SheetDescription>
            查看和管理你的通知消息
          </SheetDescription>
        </SheetHeader>
        
        <Tabs defaultValue="notifications" className="mt-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="notifications">通知</TabsTrigger>
            <TabsTrigger value="settings">设置</TabsTrigger>
          </TabsList>
          
          <TabsContent value="notifications" className="space-y-4">
            {/* 操作按钮 */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Button
                  variant={filter === 'all' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter('all')}
                >
                  全部
                </Button>
                <Button
                  variant={filter === 'unread' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter('unread')}
                >
                  未读
                </Button>
              </div>
              
              <div className="flex items-center space-x-2">
                {unreadCount > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleMarkAllAsRead}
                  >
                    全部已读
                  </Button>
                )}
                {notifications.length > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleClearAll}
                    className="text-red-500 hover:text-red-700"
                  >
                    清空
                  </Button>
                )}
              </div>
            </div>
            
            {/* 通知列表 */}
            <ScrollArea className="h-[500px]">
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-gray-500">加载中...</div>
                </div>
              ) : error ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-red-500">{error}</div>
                </div>
              ) : filteredNotifications.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                  <Bell className="h-12 w-12 mb-4 opacity-50" />
                  <p>{filter === 'unread' ? '没有未读通知' : '暂无通知'}</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {filteredNotifications.map((notification) => (
                    <NotificationItem
                      key={notification.id}
                      notification={notification}
                      onMarkAsRead={markAsRead}
                      onRemove={removeNotification}
                    />
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>
          
          <TabsContent value="settings">
            <ScrollArea className="h-[500px]">
              <NotificationSettings
                settings={settings}
                onSettingsChange={handleSettingsChange}
              />
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}