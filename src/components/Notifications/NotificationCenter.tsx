/**
 * 通知中心组件
 * 显示和管理所有通知
 */

import React, { useState } from 'react';
import { Bell, X, Check, CheckCheck, Trash2, Settings, Wifi, WifiOff } from 'lucide-react';
import useNotificationStore, { type Notification } from '../../stores/notificationStore';
import { formatDistanceToNow } from 'date-fns';
import { zhCN } from 'date-fns/locale';

interface NotificationCenterProps {
  isOpen: boolean;
  onClose: () => void;
}

const NotificationCenter: React.FC<NotificationCenterProps> = ({ isOpen, onClose }) => {
  const {
    notifications,
    unreadCount,
    isConnected,
    // connectionState,
    markAsRead,
    markAllAsRead,
    removeNotification,
    clearAllNotifications,
    // settings
  } = useNotificationStore();
  
  const [filter, setFilter] = useState<'all' | 'unread' | 'reward' | 'geofence' | 'achievement' | 'system'>('all');
  const [showSettings, setShowSettings] = useState(false);

  // 过滤通知
  const filteredNotifications = notifications.filter(notification => {
    if (filter === 'all') return true;
    if (filter === 'unread') return !notification.read;
    return notification.type === filter;
  });

  // 获取连接状态图标和颜色
  const getConnectionStatus = () => {
    if (isConnected) {
      return { icon: Wifi, color: 'text-green-500', text: '已连接' };
    } else {
      return { icon: WifiOff, color: 'text-red-500', text: '未连接' };
    }
  };

  const connectionStatus = getConnectionStatus();
  const ConnectionIcon = connectionStatus.icon;

  // 获取通知类型图标
  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'reward':
        return '🎉';
      case 'geofence':
        return '📍';
      case 'achievement':
        return '🏆';
      case 'system':
        return 'ℹ️';
      default:
        return '🔔';
    }
  };

  // 获取通知类型颜色
  const getNotificationColor = (type: string) => {
    switch (type) {
      case 'reward':
        return 'border-l-yellow-500 bg-yellow-50';
      case 'geofence':
        return 'border-l-blue-500 bg-blue-50';
      case 'achievement':
        return 'border-l-purple-500 bg-purple-50';
      case 'system':
        return 'border-l-gray-500 bg-gray-50';
      default:
        return 'border-l-gray-400 bg-gray-50';
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* 背景遮罩 */}
      <div className="absolute inset-0 bg-black bg-opacity-50" onClick={onClose} />
      
      {/* 通知面板 */}
      <div className="absolute right-0 top-0 h-full w-full max-w-md bg-white shadow-xl">
        {/* 头部 */}
        <div className="flex items-center justify-between border-b border-gray-200 p-4">
          <div className="flex items-center space-x-2">
            <Bell className="h-5 w-5 text-gray-600" />
            <h2 className="text-lg font-semibold text-gray-900">通知中心</h2>
            {unreadCount > 0 && (
              <span className="rounded-full bg-red-500 px-2 py-1 text-xs text-white">
                {unreadCount}
              </span>
            )}
          </div>
          
          <div className="flex items-center space-x-2">
            {/* 连接状态 */}
            <div className={`flex items-center space-x-1 ${connectionStatus.color}`}>
              <ConnectionIcon className="h-4 w-4" />
              <span className="text-xs">{connectionStatus.text}</span>
            </div>
            
            {/* 设置按钮 */}
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
            >
              <Settings className="h-4 w-4" />
            </button>
            
            {/* 关闭按钮 */}
            <button
              onClick={onClose}
              className="rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* 设置面板 */}
        {showSettings && (
          <NotificationSettings onClose={() => setShowSettings(false)} />
        )}

        {/* 过滤器 */}
        <div className="border-b border-gray-200 p-4">
          <div className="flex space-x-2 overflow-x-auto">
            {[
              { key: 'all', label: '全部' },
              { key: 'unread', label: '未读' },
              { key: 'reward', label: '奖励' },
              { key: 'geofence', label: '地点' },
              { key: 'achievement', label: '成就' },
              { key: 'system', label: '系统' }
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setFilter(key as 'all' | 'unread' | 'reward' | 'geofence' | 'achievement' | 'system')}
                className={`whitespace-nowrap rounded-full px-3 py-1 text-sm font-medium transition-colors ${
                  filter === key
                    ? 'bg-blue-100 text-blue-700'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {label}
                {key === 'unread' && unreadCount > 0 && (
                  <span className="ml-1 text-xs">({unreadCount})</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* 操作按钮 */}
        {notifications.length > 0 && (
          <div className="border-b border-gray-200 p-4">
            <div className="flex space-x-2">
              <button
                onClick={markAllAsRead}
                disabled={unreadCount === 0}
                className="flex items-center space-x-1 rounded-lg bg-blue-100 px-3 py-1 text-sm text-blue-700 hover:bg-blue-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <CheckCheck className="h-4 w-4" />
                <span>全部已读</span>
              </button>
              
              <button
                onClick={clearAllNotifications}
                className="flex items-center space-x-1 rounded-lg bg-red-100 px-3 py-1 text-sm text-red-700 hover:bg-red-200"
              >
                <Trash2 className="h-4 w-4" />
                <span>清空全部</span>
              </button>
            </div>
          </div>
        )}

        {/* 通知列表 */}
        <div className="flex-1 overflow-y-auto">
          {filteredNotifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-8 text-gray-500">
              <Bell className="h-12 w-12 text-gray-300" />
              <p className="mt-2 text-sm">
                {filter === 'unread' ? '没有未读通知' : '暂无通知'}
              </p>
            </div>
          ) : (
            <div className="space-y-2 p-4">
              {filteredNotifications.map((notification) => (
                <NotificationItem
                  key={notification.id}
                  notification={notification}
                  onMarkAsRead={markAsRead}
                  onRemove={removeNotification}
                  getIcon={getNotificationIcon}
                  getColor={getNotificationColor}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// 通知项组件
interface NotificationItemProps {
  notification: Notification;
  onMarkAsRead: (id: string) => void;
  onRemove: (id: string) => void;
  getIcon: (type: string) => string;
  getColor: (type: string) => string;
}

const NotificationItem: React.FC<NotificationItemProps> = ({
  notification,
  onMarkAsRead,
  onRemove,
  getIcon,
  getColor
}) => {
  const handleClick = () => {
    if (!notification.read) {
      onMarkAsRead(notification.id);
    }
  };

  return (
    <div
      className={`border-l-4 rounded-lg p-3 transition-all hover:shadow-md cursor-pointer ${
        getColor(notification.type)
      } ${
        notification.read ? 'opacity-75' : 'shadow-sm'
      }`}
      onClick={handleClick}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-3 flex-1">
          <span className="text-lg">{getIcon(notification.type)}</span>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2">
              <h4 className={`text-sm font-medium ${
                notification.read ? 'text-gray-600' : 'text-gray-900'
              }`}>
                {notification.title}
              </h4>
              {!notification.read && (
                <div className="h-2 w-2 rounded-full bg-blue-500" />
              )}
            </div>
            
            <p className={`mt-1 text-sm ${
              notification.read ? 'text-gray-500' : 'text-gray-700'
            }`}>
              {notification.message}
            </p>
            
            <p className="mt-1 text-xs text-gray-400">
              {formatDistanceToNow(new Date(notification.timestamp), {
                addSuffix: true,
                locale: zhCN
              })}
            </p>
            
            {/* 奖励详情 */}
            {notification.type === 'reward' && notification.data && (
              <div className="mt-2 text-xs text-gray-600">
                <div className="flex items-center space-x-2">
                  <span>基础: {notification.data.breakdown?.baseReward || 0}</span>
                  <span>衰减: ×{notification.data.breakdown?.timeDecayFactor || 1}</span>
                  {notification.data.breakdown?.firstDiscovererBonus > 0 && (
                    <span className="text-yellow-600">首发: +{notification.data.breakdown.firstDiscovererBonus}</span>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
        
        <div className="flex items-center space-x-1 ml-2">
          {!notification.read && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onMarkAsRead(notification.id);
              }}
              className="rounded-lg p-1 text-gray-400 hover:bg-white hover:text-gray-600"
              title="标记为已读"
            >
              <Check className="h-3 w-3" />
            </button>
          )}
          
          <button
            onClick={(e) => {
              e.stopPropagation();
              onRemove(notification.id);
            }}
            className="rounded-lg p-1 text-gray-400 hover:bg-white hover:text-red-600"
            title="删除通知"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </div>
    </div>
  );
};

// 通知设置组件
interface NotificationSettingsProps {
  onClose: () => void;
}

const NotificationSettings: React.FC<NotificationSettingsProps> = ({ onClose: _onClose }) => {
  const { settings, updateSettings } = useNotificationStore();

  const handleToggle = (key: keyof typeof settings) => {
    updateSettings({ [key]: !settings[key] });
  };

  return (
    <div className="border-b border-gray-200 bg-gray-50 p-4">
      <div className="space-y-3">
        <h3 className="text-sm font-medium text-gray-900">通知设置</h3>
        
        {[
          { key: 'enabled', label: '启用通知' },
          { key: 'sound', label: '声音提醒' },
          { key: 'vibration', label: '振动提醒' },
          { key: 'browserNotifications', label: '浏览器通知' },
          { key: 'rewardNotifications', label: '奖励通知' },
          { key: 'geofenceNotifications', label: '地点通知' },
          { key: 'achievementNotifications', label: '成就通知' },
          { key: 'systemNotifications', label: '系统通知' }
        ].map(({ key, label }) => (
          <div key={key} className="flex items-center justify-between">
            <span className="text-sm text-gray-700">{label}</span>
            <button
              onClick={() => handleToggle(key as keyof typeof settings)}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                settings[key as keyof typeof settings]
                  ? 'bg-blue-600'
                  : 'bg-gray-300'
              }`}
            >
              <span
                className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                  settings[key as keyof typeof settings]
                    ? 'translate-x-5'
                    : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

export default NotificationCenter;