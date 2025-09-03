import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion } from 'framer-motion';
import { 
  Bell, 
  X, 
  Check, 
  Trash2, 
  Heart, 
  MessageCircle, 
  MapPin, 
  Award, 
  Info,
  Settings,
  MoreVertical,
  AlertCircle
} from 'lucide-react';
import { MicroInteraction } from './InteractionFeedback';
import { useMobile } from '../hooks/useMobile';
import { useNetworkStatus } from '../hooks/useNetworkStatus';
import EmptyState from './EmptyState';

interface Notification {
  id: string;
  type: 'like' | 'comment' | 'follow' | 'system' | 'achievement' | 'pin';
  title: string;
  message: string;
  timestamp: Date;
  isRead: boolean;
  avatar?: string;
  image?: string;
  actionUrl?: string;
  priority: 'low' | 'medium' | 'high';
  category: 'social' | 'system' | 'achievement';
}

interface NotificationSystemProps {
  isOpen: boolean;
  onClose: () => void;
  onNotificationClick?: (notification: Notification) => void;
}

const NotificationSystem: React.FC<NotificationSystemProps> = ({
  isOpen,
  onClose,
  onNotificationClick
}) => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [filter, setFilter] = useState<'all' | 'unread' | 'social' | 'system'>('all');

  const [selectedNotifications, setSelectedNotifications] = useState<Set<string>>(new Set());
  const { isMobile } = useMobile();
  const { isOnline } = useNetworkStatus();
  const containerRef = useRef<HTMLDivElement>(null);

  // 模拟通知数据
  const mockNotifications: Notification[] = useMemo(() => [
    {
      id: '1',
      type: 'like',
      title: '新的点赞',
      message: '张三 点赞了你的气味标注 "咖啡香气"',
      timestamp: new Date(Date.now() - 300000),
      isRead: false,
      avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=friendly%20person%20avatar%20smiling&image_size=square',
      priority: 'medium',
      category: 'social'
    },
    {
      id: '2',
      type: 'comment',
      title: '新评论',
      message: '李四 评论了你的标注："这个地方的花香真的很棒！"',
      timestamp: new Date(Date.now() - 600000),
      isRead: false,
      avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=happy%20person%20profile%20photo&image_size=square',
      priority: 'high',
      category: 'social'
    },
    {
      id: '3',
      type: 'follow',
      title: '新关注者',
      message: '王五 开始关注你了',
      timestamp: new Date(Date.now() - 1200000),
      isRead: true,
      avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=professional%20person%20headshot&image_size=square',
      priority: 'medium',
      category: 'social'
    },
    {
      id: '4',
      type: 'achievement',
      title: '获得新成就',
      message: '恭喜！你获得了 "探索者" 徽章',
      timestamp: new Date(Date.now() - 1800000),
      isRead: false,
      priority: 'high',
      category: 'achievement'
    },
    {
      id: '5',
      type: 'system',
      title: '系统更新',
      message: 'SmellPin 已更新到 v2.1.0，新增了更多功能',
      timestamp: new Date(Date.now() - 3600000),
      isRead: true,
      priority: 'low',
      category: 'system'
    }
  ], []);

  useEffect(() => {
    if (isOpen) {
      setNotifications(mockNotifications);
    }
  }, [isOpen, mockNotifications]);

  // 键盘导航支持
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;
      
      if (e.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const getNotificationIcon = (type: Notification['type']) => {
    switch (type) {
      case 'like': return <Heart className="w-5 h-5 text-red-500" />;
      case 'comment': return <MessageCircle className="w-5 h-5 text-blue-500" />;
      case 'follow': return <Bell className="w-5 h-5 text-green-500" />;
      case 'pin': return <MapPin className="w-5 h-5 text-purple-500" />;
      case 'achievement': return <Award className="w-5 h-5 text-yellow-500" />;
      case 'system': return <Info className="w-5 h-5 text-gray-500" />;
      default: return <Bell className="w-5 h-5 text-gray-500" />;
    }
  };

  const getPriorityColor = (priority: Notification['priority']) => {
    switch (priority) {
      case 'high': return 'border-l-red-500';
      case 'medium': return 'border-l-yellow-500';
      case 'low': return 'border-l-gray-300';
      default: return 'border-l-gray-300';
    }
  };

  const formatTimestamp = (timestamp: Date) => {
    const now = new Date();
    const diff = now.getTime() - timestamp.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return '刚刚';
    if (minutes < 60) return `${minutes}分钟前`;
    if (hours < 24) return `${hours}小时前`;
    if (days < 7) return `${days}天前`;
    return timestamp.toLocaleDateString('zh-CN');
  };

  const filteredNotifications = notifications.filter(notification => {
    switch (filter) {
      case 'unread': return !notification.isRead;
      case 'social': return notification.category === 'social';
      case 'system': return notification.category === 'system';
      default: return true;
    }
  });

  const unreadCount = notifications.filter(n => !n.isRead).length;

  const handleNotificationClick = (notification: Notification) => {
    // 标记为已读
    setNotifications(prev => 
      prev.map(n => 
        n.id === notification.id ? { ...n, isRead: true } : n
      )
    );
    
    onNotificationClick?.(notification);
  };

  const handleMarkAsRead = (notificationId: string) => {
    setNotifications(prev => 
      prev.map(n => 
        n.id === notificationId ? { ...n, isRead: true } : n
      )
    );
  };

  const handleMarkAllAsRead = () => {
    setNotifications(prev => 
      prev.map(n => ({ ...n, isRead: true }))
    );
  };

  const handleDeleteNotification = (notificationId: string) => {
    setNotifications(prev => 
      prev.filter(n => n.id !== notificationId)
    );
  };

  const handleBulkAction = (action: 'read' | 'delete') => {
    if (action === 'read') {
      setNotifications(prev => 
        prev.map(n => 
          selectedNotifications.has(n.id) ? { ...n, isRead: true } : n
        )
      );
    } else if (action === 'delete') {
      setNotifications(prev => 
        prev.filter(n => !selectedNotifications.has(n.id))
      );
    }
    setSelectedNotifications(new Set());
  };

  const toggleNotificationSelection = (notificationId: string) => {
    setSelectedNotifications(prev => {
      const newSet = new Set(prev);
      if (newSet.has(notificationId)) {
        newSet.delete(notificationId);
      } else {
        newSet.add(notificationId);
      }
      return newSet;
    });
  };

  if (!isOpen) return null;

  return (
    <>
      {/* 背景遮罩 */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* 通知面板 */}
      <motion.div
        ref={containerRef}
        initial={{ opacity: 0, x: isMobile ? 0 : 300, y: isMobile ? 300 : 0 }}
        animate={{ opacity: 1, x: 0, y: 0 }}
        exit={{ opacity: 0, x: isMobile ? 0 : 300, y: isMobile ? 300 : 0 }}
        className={`fixed z-50 bg-white shadow-2xl ${
          isMobile 
            ? 'inset-x-4 bottom-4 top-20 rounded-xl'
            : 'top-16 right-4 w-96 max-h-[80vh] rounded-lg'
        }`}
        role="dialog"
        aria-labelledby="notifications-title"
        aria-modal={true}
      >
        {/* 头部 */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Bell className="w-5 h-5 text-gray-700" />
            <h2 id="notifications-title" className="text-lg font-semibold text-gray-800">
              通知
            </h2>
            {unreadCount > 0 && (
              <span className="px-2 py-1 text-xs bg-red-500 text-white rounded-full">
                {unreadCount}
              </span>
            )}
          </div>
          
          <div className="flex items-center gap-2">
            {unreadCount > 0 && (
              <MicroInteraction type="hover">
                <button
                  onClick={handleMarkAllAsRead}
                  className="text-sm text-blue-600 hover:text-blue-700 transition-colors"
                  aria-label="全部标记为已读"
                >
                  全部已读
                </button>
              </MicroInteraction>
            )}
            
            <MicroInteraction type="hover">
              <button
                onClick={onClose}
                className="p-1 text-gray-500 hover:text-gray-700 transition-colors"
                aria-label="关闭通知"
              >
                <X className="w-5 h-5" />
              </button>
            </MicroInteraction>
          </div>
        </div>

        {/* 筛选器 */}
        <div className="p-4 border-b border-gray-200">
          <div className="flex gap-2 overflow-x-auto">
            {[
              { key: 'all', label: '全部' },
              { key: 'unread', label: '未读' },
              { key: 'social', label: '社交' },
              { key: 'system', label: '系统' }
            ].map(filterOption => (
              <button
                key={filterOption.key}
                onClick={() => setFilter(filterOption.key as 'all' | 'unread' | 'social' | 'system')}
                className={`px-3 py-1 text-sm rounded-full whitespace-nowrap transition-colors ${
                  filter === filterOption.key
                    ? 'bg-blue-500 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {filterOption.label}
              </button>
            ))}
          </div>
        </div>

        {/* 批量操作 */}
        {selectedNotifications.size > 0 && (
          <div className="p-4 bg-blue-50 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700">
                已选择 {selectedNotifications.size} 项
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => handleBulkAction('read')}
                  className="text-sm text-blue-600 hover:text-blue-700 transition-colors"
                >
                  标记已读
                </button>
                <button
                  onClick={() => handleBulkAction('delete')}
                  className="text-sm text-red-600 hover:text-red-700 transition-colors"
                >
                  删除
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 通知列表 */}
        <div className="flex-1 overflow-y-auto">
          {!isOnline && (
            <div className="p-4 bg-yellow-50 border-b border-yellow-200">
              <div className="flex items-center gap-2 text-yellow-800">
                <AlertCircle className="w-4 h-4" />
                <span className="text-sm">网络连接断开，无法获取最新通知</span>
              </div>
            </div>
          )}

          {filteredNotifications.length > 0 ? (
            <div className="divide-y divide-gray-100">
              {filteredNotifications.map((notification, index) => (
                <motion.div
                  key={notification.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className={`relative p-4 hover:bg-gray-50 transition-colors cursor-pointer border-l-4 ${
                    getPriorityColor(notification.priority)
                  } ${
                    !notification.isRead ? 'bg-blue-50/50' : ''
                  }`}
                  onClick={() => handleNotificationClick(notification)}
                >
                  {/* 选择框 */}
                  <div className="absolute top-4 left-2">
                    <input
                      type="checkbox"
                      checked={selectedNotifications.has(notification.id)}
                      onChange={(e) => {
                        e.stopPropagation();
                        toggleNotificationSelection(notification.id);
                      }}
                      className="w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500"
                      aria-label={`选择通知: ${notification.title}`}
                    />
                  </div>

                  <div className="ml-6 flex items-start gap-3">
                    {/* 头像或图标 */}
                    <div className="flex-shrink-0">
                      {notification.avatar ? (
                        <img
                          src={notification.avatar}
                          alt="用户头像"
                          className="w-10 h-10 rounded-full"
                        />
                      ) : (
                        <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                          {getNotificationIcon(notification.type)}
                        </div>
                      )}
                    </div>

                    {/* 内容 */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <p className={`text-sm font-medium ${
                            notification.isRead ? 'text-gray-700' : 'text-gray-900'
                          }`}>
                            {notification.title}
                          </p>
                          <p className={`text-sm mt-1 ${
                            notification.isRead ? 'text-gray-500' : 'text-gray-700'
                          }`}>
                            {notification.message}
                          </p>
                          <p className="text-xs text-gray-400 mt-2">
                            {formatTimestamp(notification.timestamp)}
                          </p>
                        </div>

                        {/* 操作菜单 */}
                        <div className="flex items-center gap-1">
                          {!notification.isRead && (
                            <div className="w-2 h-2 bg-blue-500 rounded-full" aria-label="未读" />
                          )}
                          
                          <div className="relative group">
                            <button
                              onClick={(e) => e.stopPropagation()}
                              className="p-1 text-gray-400 hover:text-gray-600 transition-colors opacity-0 group-hover:opacity-100"
                              aria-label="更多操作"
                            >
                              <MoreVertical className="w-4 h-4" />
                            </button>
                            
                            {/* 下拉菜单 */}
                            <div className="absolute right-0 top-full mt-1 w-32 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                              {!notification.isRead && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleMarkAsRead(notification.id);
                                  }}
                                  className="w-full px-3 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2"
                                >
                                  <Check className="w-3 h-3" />
                                  标记已读
                                </button>
                              )}
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleDeleteNotification(notification.id);
                                }}
                                className="w-full px-3 py-2 text-left text-sm text-red-600 hover:bg-red-50 flex items-center gap-2"
                              >
                                <Trash2 className="w-3 h-3" />
                                删除
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          ) : (
            <div className="p-8">
              <EmptyState
                type="no-data"
                title="暂无通知"
                description={filter === 'unread' ? '所有通知都已读完' : '还没有收到任何通知'}
                icon={<Bell className="w-12 h-12 text-gray-400" />}
              />
            </div>
          )}
        </div>

        {/* 底部操作 */}
        {filteredNotifications.length > 0 && (
          <div className="p-4 border-t border-gray-200 bg-gray-50">
            <div className="flex items-center justify-between">
              <button className="text-sm text-gray-600 hover:text-gray-800 transition-colors flex items-center gap-1">
                <Settings className="w-4 h-4" />
                通知设置
              </button>
              
              <span className="text-xs text-gray-500">
                共 {notifications.length} 条通知
              </span>
            </div>
          </div>
        )}
      </motion.div>
    </>
  );
};

// 通知按钮组件
export const NotificationButton: React.FC<{
  onClick: () => void;
  unreadCount?: number;
}> = ({ onClick, unreadCount = 0 }) => {
  return (
    <MicroInteraction type="hover">
      <button
        onClick={onClick}
        className="relative p-2 text-gray-600 hover:text-gray-800 transition-colors"
        aria-label={`通知 ${unreadCount > 0 ? `(${unreadCount} 条未读)` : ''}`}
      >
        <Bell className="w-6 h-6" />
        {unreadCount > 0 && (
          <motion.span
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-medium"
          >
            {unreadCount > 99 ? '99+' : unreadCount}
          </motion.span>
        )}
      </button>
    </MicroInteraction>
  );
};

export default NotificationSystem;