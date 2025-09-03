import React, { useState, useEffect, useCallback } from 'react';
import { Avatar, Badge, Button, Card, Col, DatePicker, Divider, Empty, Input, List, Modal, Row, Select, Slider, Space, Spin, Statistic, Switch, Tabs, Tag, Typography, Upload } from 'antd';

import {
  Bell,
  Settings,
  Check,
  History,
  Upload as UploadIcon,
  Download,
  Trash2,
  PlayCircle,
  User,
  MessageCircle,
  Heart,
  Share
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  getUserNotifications, 
  markNotificationAsRead, 
  markAllNotificationsAsRead,
  getNotificationSettings,
  updateNotificationSettings,
  sendTestNotification
  // deleteNotifications // Removed as unused
} from '../utils/api';
import useWebSocket from '../hooks/useWebSocket';
import type { NotificationData } from '../services/websocketService';
import pushNotificationService from '../services/pushNotificationService';
import { notificationSoundService } from '../services/notificationSoundService';
import { notificationHistoryService } from '../services/notificationHistoryService';
import type { NotificationHistoryItem, NotificationFilter } from '../services/notificationHistoryService';
import { DecorativeElements } from '../components/UI/DecorativeElements';


const { Title, Text } = Typography;
// const { TabPane } = Tabs; // Removed as unused

interface Notification {
  id: string;
  type: string;
  title: string;
  content: string;
  is_read: boolean;
  created_at: string;
  from_user_id?: string;
  from_username?: string;
  from_avatar_url?: string;
  related_id?: string;
  related_type?: string;
}

interface NotificationPageData {
  notifications: Notification[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

const NOTIFICATION_TYPES = {
  follow: { icon: <User size={16} />, color: '#7f1d1d', label: '关注' },
  comment: { icon: <MessageCircle size={16} />, color: '#059669', label: '评论' },
  like: { icon: <Heart size={16} />, color: '#dc2626', label: '点赞' },
  share: { icon: <Share size={16} />, color: '#f59e0b', label: '分享' },
  system: { icon: <Bell size={16} />, color: '#7f1d1d', label: '系统' }
};

const NotificationPage: React.FC = () => {
  const navigate = useNavigate();
  const [data, setData] = useState<NotificationPageData | null>(null);
  const [loading, setLoading] = useState(false);
  const [currentPage] = useState(1);
  const [activeTab, setActiveTab] = useState('all');
  const [settings, setSettings] = useState({
    email_notifications: true,
    push_notifications: true,
    follow_notifications: true,
    comment_notifications: true,
    like_notifications: true,
    share_notifications: true
  });
  const [, setSettingsLoading] = useState(false); // settingsLoading removed as unused
  const [pushSupported, setPushSupported] = useState(false);
  const [pushSubscribed, setPushSubscribed] = useState(false);
  const [pushLoading, setPushLoading] = useState(false);
  
  // 声音设置状态
  const [soundSettings, setSoundSettings] = useState<{
    enabled: boolean;
    volume: number;
    customSound?: string;
    availableSounds?: string[];
  }>({ enabled: true, volume: 0.5 });
  const [customSoundUploading, setCustomSoundUploading] = useState(false);
  
  // 历史记录状态
  const [historyNotifications, setHistoryNotifications] = useState<NotificationHistoryItem[]>([]);
  const [historyStats, setHistoryStats] = useState<{
    total: number;
    unread: number;
    byType: Record<string, number>;
    todayCount?: number;
    weekCount?: number;
  }>({ total: 0, unread: 0, byType: {} });
  const [historyFilter, setHistoryFilter] = useState<NotificationFilter>({});
  const [historyPagination, setHistoryPagination] = useState({ page: 1, pageSize: 20 });
  const [searchKeyword, setSearchKeyword] = useState('');
  
  const pageSize = 20;

  // WebSocket连接管理
  const { isConnected, unreadCount, markNotificationAsRead: wsMarkAsRead } = useWebSocket({
    onNewNotification: (notification: NotificationData) => {
      // 实时添加新通知到列表
      if (data) {
        setData((prev: NotificationPageData | null) => {
          if (!prev) return null;
          // 将NotificationData转换为Notification格式
          const newNotification: Notification = {
            id: notification.id,
            type: notification.type || 'info',
            title: notification.title || '新通知',
            content: notification.content || '',
            is_read: false,
            created_at: new Date().toISOString()
          };
          
          return {
            ...prev,
            notifications: [newNotification, ...prev.notifications],
            pagination: {
              ...prev.pagination,
              total: prev.pagination.total + 1
            }
          };
        });
      }
    },
    onUnreadCountUpdate: (count) => {
      console.log('未读通知数量更新:', count);
    }
  });

  // 加载通知列表
  const loadNotifications = useCallback(async (page = 1, unreadOnly = false) => {
    try {
      setLoading(true);
      const response = await getUserNotifications(page, pageSize, unreadOnly);
      setData(response.data);
    } catch (error) {
      console.error('加载通知失败:', error);
    } finally {
      setLoading(false);
    }
  }, [pageSize]);

  useEffect(() => {
    const unreadOnly = activeTab === 'unread';
    loadNotifications(currentPage, unreadOnly);
  }, [currentPage, activeTab, loadNotifications]);

  // 加载通知设置
  const loadNotificationSettings = useCallback(async () => {
    try {
      setSettingsLoading(true);
      const response = await getNotificationSettings();
      setSettings(response.data.data);
    } catch (error) {
      console.error('加载通知设置失败:', error);
    } finally {
      setSettingsLoading(false);
    }
  }, []);

  // 初始化PWA推送通知状态
  const initializePushNotification = useCallback(async () => {
    const supported = pushNotificationService.isPushSupported();
    setPushSupported(supported);
    
    if (supported) {
      const status = await pushNotificationService.getSubscriptionStatus();
      setPushSubscribed(status.isSubscribed);
    }
  }, []);
  
  // 初始化声音设置
  const initializeSoundSettings = useCallback(() => {
    const settings = notificationSoundService.getSoundSettings();
    setSoundSettings(settings);
  }, []);
  
  // 加载历史记录
  const loadHistoryNotifications = useCallback(() => {
    const result = notificationHistoryService.getNotifications(historyFilter, historyPagination);
    setHistoryNotifications(result.notifications);
    
    const stats = notificationHistoryService.getStats();
    setHistoryStats(stats);
  }, [historyFilter, historyPagination]);

  useEffect(() => {
    if (activeTab === 'settings') {
      loadNotificationSettings();
      initializePushNotification();
    }
    
    // 加载历史记录（仅在历史标签页时）
    if (activeTab === 'history') {
      loadHistoryNotifications();
    }
  }, [activeTab, historyFilter, historyPagination, loadNotificationSettings, initializePushNotification, loadHistoryNotifications]);

  // 标记通知为已读
  const handleMarkAsRead = async (notificationId: string) => {
    try {
      await markNotificationAsRead(notificationId);
      
      // 同时通过WebSocket标记已读
      wsMarkAsRead(notificationId);
      
      // 更新本地状态
      if (data) {
        const updatedNotifications = data.notifications.map(notif => 
          notif.id === notificationId ? { ...notif, is_read: true } : notif
        );
        setData({ ...data, notifications: updatedNotifications });
      }
    } catch (error) {
      console.error('标记已读失败:', error);
    }
  };

  // 标记所有通知为已读
  const handleMarkAllAsRead = async () => {
    try {
      await markAllNotificationsAsRead();
      // 重新加载通知
      loadNotifications(currentPage, activeTab === 'unread');
    } catch (error) {
      console.error('标记所有已读失败:', error);
    }
  };

  // 处理通知点击
  const handleNotificationClick = async (notification: Notification) => {
    // 标记为已读
    if (!notification.is_read) {
      await handleMarkAsRead(notification.id);
    }

    // 根据通知类型导航到相应页面
    if (notification.related_type === 'annotation' && notification.related_id) {
      navigate(`/map?annotation=${notification.related_id}`);
    } else if (notification.related_type === 'user' && notification.from_user_id) {
      navigate(`/users/${notification.from_user_id}`);
    }
  };

  // 格式化时间
  const formatTime = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return '刚刚';
    if (diffInHours < 24) return `${diffInHours}小时前`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}天前`;
    return date.toLocaleDateString('zh-CN');
  };

  // 获取通知类型信息
  const getNotificationTypeInfo = (type: string) => {
    return NOTIFICATION_TYPES[type as keyof typeof NOTIFICATION_TYPES] || NOTIFICATION_TYPES.system;
  };

  // 处理设置变更
  const handleSettingChange = async (key: string, value: boolean) => {
    try {
      const newSettings = { ...settings, [key]: value };
      setSettings(newSettings);
      
      // 调用API保存设置
      await updateNotificationSettings({ [key]: value });
    } catch (error) {
      console.error('保存设置失败:', error);
      // 回滚设置
      setSettings(prev => ({ ...prev, [key]: !value }));
    }
  };

  // 发送测试通知
  const handleSendTestNotification = async () => {
    try {
      await sendTestNotification('system');
      // 重新加载通知列表
      loadNotifications(currentPage, activeTab === 'unread');
    } catch (error) {
      console.error('发送测试通知失败:', error);
    }
  };

  // 初始化声音设置
  useEffect(() => {
    initializeSoundSettings();
  }, [initializeSoundSettings]);

  // 组件挂载时初始化PWA推送通知
  useEffect(() => {
    initializePushNotification();
  }, [initializePushNotification]);

  // 订阅PWA推送通知
  const handleSubscribePush = async () => {
    setPushLoading(true);
    try {
      const subscriptionData = await pushNotificationService.subscribeToPush();
      if (subscriptionData) {
        const success = await pushNotificationService.sendSubscriptionToServer(subscriptionData);
        if (success) {
          setPushSubscribed(true);
        }
      }
    } catch (error: unknown) {
      console.error('订阅失败:', error instanceof Error ? error.message : String(error));
    } finally {
      setPushLoading(false);
    }
  };

  // 取消订阅PWA推送通知
  const handleUnsubscribePush = async () => {
    setPushLoading(true);
    try {
      const success = await pushNotificationService.unsubscribeFromPush();
      if (success) {
        await pushNotificationService.removeSubscriptionFromServer();
        setPushSubscribed(false);
      }
    } catch (error: unknown) {
      console.error('取消订阅失败:', error instanceof Error ? error.message : String(error));
    } finally {
      setPushLoading(false);
    }
  };

  // 测试PWA推送通知
  const handleTestPushNotification = async () => {
    try {
      const success = await pushNotificationService.testPushNotification();
      if (!success) {
        console.error('PWA推送通知测试失败');
      }
    } catch (error: unknown) {
      console.error('测试失败:', error instanceof Error ? error.message : String(error));
    }
  };
  
  // 声音设置处理函数
  const handleSoundEnabledChange = (enabled: boolean) => {
     notificationSoundService.setSoundEnabled(enabled);
     setSoundSettings((prev) => ({ ...prev, enabled }));
   };
   
   const handleVolumeChange = (volume: number) => {
     notificationSoundService.setVolume(volume / 100);
     setSoundSettings((prev) => ({ ...prev, volume: volume / 100 }));
   };
  
  const handleTestSound = async (soundType: string) => {
    try {
      await notificationSoundService.testSound(soundType);
    } catch {
      console.error('播放测试声音失败');
    }
  };
  
  const handleCustomSoundUpload = async (file: File, soundType: string) => {
    try {
      setCustomSoundUploading(true);
      const url = URL.createObjectURL(file);
      notificationSoundService.setCustomSound(soundType, url);
      initializeSoundSettings();
    } catch {
      console.error('上传自定义声音失败');
    } finally {
      setCustomSoundUploading(false);
    }
  };
  
  // 历史记录处理函数
  const handleHistorySearch = (keyword: string) => {
     setSearchKeyword(keyword);
     setHistoryFilter((prev: NotificationFilter) => ({ ...prev, keyword }));
   };
  
  const handleHistoryFilter = (filter: Partial<NotificationFilter>) => {
     setHistoryFilter((prev: NotificationFilter) => ({ ...prev, ...filter }));
   };
  
  const handleMarkHistoryAsRead = (ids: string[]) => {
    notificationHistoryService.markAsRead(ids);
    loadHistoryNotifications();
  };
  
  const handleDeleteHistory = (ids: string[]) => {
    notificationHistoryService.deleteNotifications(ids);
    loadHistoryNotifications();
  };
  
  const handleClearHistory = () => {
    Modal.confirm({
      title: '确认清空历史记录',
      content: '此操作将删除所有通知历史记录，且无法恢复。',
      onOk: () => {
        notificationHistoryService.clearHistory();
        loadHistoryNotifications();
      }
    });
  };
  
  const handleExportHistory = () => {
    const data = notificationHistoryService.exportHistory('json');
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `notification-history-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // 通知列表组件
  const NotificationList = () => (
    <div>
      {/* 操作栏 */}
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <Text type="secondary">
            {data ? `共 ${data.pagination.total} 条通知` : ''}
          </Text>
        </div>
        <Button 
          type="link" 
          onClick={handleMarkAllAsRead}
          disabled={!data?.notifications.some(n => !n.is_read)}
        >
          全部标记为已读
        </Button>
      </div>

      {/* 通知列表 */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px 0' }}>
          <Spin size="large" />
          <div style={{ marginTop: 16 }}>加载中...</div>
        </div>
      ) : data?.notifications.length === 0 ? (
        <Empty
          description={activeTab === 'unread' ? '没有未读通知' : '暂无通知'}
          style={{ padding: '40px 0' }}
        />
      </div>
    </div>
      ) : (
        <List
          itemLayout="horizontal"
          dataSource={data?.notifications || []}
          renderItem={(notification) => {
            const typeInfo = getNotificationTypeInfo(notification.type);
            return (
              <List.Item
                key={notification.id}
                style={{
                  backgroundColor: notification.is_read ? 'transparent' : '#f6ffed',
                  padding: '16px',
                  borderRadius: '8px',
                  marginBottom: '8px',
                  cursor: 'pointer',
                  border: notification.is_read ? '1px solid #f0f0f0' : '1px solid #b7eb8f'
                }}
                onClick={() => handleNotificationClick(notification)}
                actions={[
                  !notification.is_read && (
                    <Button
                      key="read"
                      type="link"
                      size="small"
                      icon={<Check size={16} />}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleMarkAsRead(notification.id);
                      }}
                    >
                      标记已读
                    </Button>
                  )
                ].filter(Boolean)}
              >
                <List.Item.Meta
                  avatar={
                    <Badge dot={!notification.is_read}>
                      {notification.from_avatar_url ? (
                        <Avatar src={notification.from_avatar_url} size="large" />
                      ) : (
                        <Avatar 
                          style={{ backgroundColor: typeInfo.color }}
                          icon={typeInfo.icon}
                          size="large"
                        />
                      )}
                    </Badge>
                  }
                  title={
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontWeight: notification.is_read ? 'normal' : 'bold' }}>
                        {notification.title}
                      </span>
                      <Tag color={typeInfo.color}>
                        {typeInfo.label}
                      </Tag>
                      <Text type="secondary" style={{ fontSize: '12px' }}>
                        {formatTime(notification.created_at)}
                      </Text>
                    </div>
                  }
                  description={
                    <div>
                      <Text style={{ color: notification.is_read ? '#666' : '#333' }}>
                        {notification.content}
                      </Text>
                      {notification.from_username && (
                        <div style={{ marginTop: 4 }}>
                          <Text type="secondary" style={{ fontSize: '12px' }}>
                            来自: {notification.from_username}
                          </Text>
                        </div>
                      )}
                    </div>
                  }
                />
              </List.Item>
            );
          }}
        />
      )}
    </div>
  );

  // 通知设置组件
  const NotificationSettings = () => (
    <div>
      <Title level={4}>通知设置</Title>
      <Text type="secondary">管理你的通知偏好设置</Text>
      
      <Divider />
      
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Card title="通知方式" size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <Text strong>邮件通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>通过邮件接收重要通知</Text>
              </div>
              <Switch 
                checked={settings.email_notifications}
                onChange={(checked) => handleSettingChange('email_notifications', checked)}
              />
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <Text strong>推送通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>浏览器推送通知</Text>
              </div>
              <Switch 
                checked={settings.push_notifications}
                onChange={(checked) => handleSettingChange('push_notifications', checked)}
              />
            </div>
          </Space>
        </Card>

        <Card title="通知类型" size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <User style={{ marginRight: 8, color: '#1890ff' }} size={16} />
                <Text strong>关注通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>有人关注你时通知</Text>
              </div>
              <Switch 
                checked={settings.follow_notifications}
                onChange={(checked) => handleSettingChange('follow_notifications', checked)}
              />
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <MessageCircle style={{ marginRight: 8, color: '#52c41a' }} size={16} />
                <Text strong>评论通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>有人评论你的标注时通知</Text>
              </div>
              <Switch 
                checked={settings.comment_notifications}
                onChange={(checked) => handleSettingChange('comment_notifications', checked)}
              />
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <Heart style={{ marginRight: 8, color: '#eb2f96' }} size={16} />
                <Text strong>点赞通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>有人点赞你的内容时通知</Text>
              </div>
              <Switch 
                checked={settings.like_notifications}
                onChange={(checked) => handleSettingChange('like_notifications', checked)}
              />
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <Share style={{ marginRight: 8, color: '#722ed1' }} size={16} />
                <Text strong>分享通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>有人分享你的标注时通知</Text>
              </div>
              <Switch 
                checked={settings.share_notifications}
                onChange={(checked) => handleSettingChange('share_notifications', checked)}
              />
            </div>
          </Space>
        </Card>

        <Card title="测试功能" size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <Text strong>发送测试通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>测试通知系统是否正常工作</Text>
              </div>
              <Button 
                type="primary"
                onClick={handleSendTestNotification}
                loading={loading}
              >
                发送测试
              </Button>
            </div>
            
            {pushSupported && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <Text strong>测试PWA推送</Text>
                  <br />
                  <Text type="secondary" style={{ fontSize: '12px' }}>测试PWA推送通知功能</Text>
                </div>
                <Button 
                  type="default"
                  onClick={handleTestPushNotification}
                  disabled={!pushSubscribed}
                >
                  测试PWA推送
                </Button>
              </div>
            )}
          </Space>
        </Card>
        
        {pushSupported && (
          <Card title="PWA推送通知" size="small">
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  PWA推送通知可以在应用未打开时向您发送通知，即使浏览器关闭也能收到。
                </Text>
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <Text strong>启用PWA推送通知</Text>
                  <br />
                  <Text type="secondary" style={{ fontSize: '12px' }}>
                    状态: {pushSubscribed ? '已订阅' : '未订阅'}
                  </Text>
                </div>
                <Switch 
                  checked={pushSubscribed}
                  loading={pushLoading}
                  onChange={(checked) => {
                    if (checked) {
                      handleSubscribePush();
                    } else {
                      handleUnsubscribePush();
                    }
                  }}
                />
              </div>
            </Space>
          </Card>
        )}
        
        <Card title="声音通知" size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <Text strong>启用声音通知</Text>
                <br />
                <Text type="secondary" style={{ fontSize: '12px' }}>接收通知时播放提示音</Text>
              </div>
              <Switch
                checked={soundSettings.enabled}
                onChange={handleSoundEnabledChange}
              />
            </div>
            
            {soundSettings.enabled && (
              <>
                <div>
                  <Text strong style={{ marginBottom: 8, display: 'block' }}>音量设置</Text>
                  <Slider
                    value={Math.round((soundSettings.volume || 0.5) * 100)}
                    onChange={handleVolumeChange}
                    tooltip={{ formatter: (value) => `${value}%` }}
                  />
                </div>
                
                <div>
                  <Text strong style={{ marginBottom: 8, display: 'block' }}>声音测试</Text>
                  <Space wrap>
                    {soundSettings.availableSounds?.map((soundType: string) => (
                      <Button
                        key={soundType}
                        size="small"
                        icon={<PlayCircle size={16} />}
                        onClick={() => handleTestSound(soundType)}
                      >
                        {soundType}
                      </Button>
                    ))}
                  </Space>
                </div>
                
                <div>
                  <Text strong style={{ marginBottom: 8, display: 'block' }}>自定义声音</Text>
                  <Upload
                    accept="audio/*"
                    showUploadList={false}
                    beforeUpload={(file) => {
                      handleCustomSoundUpload(file, 'notification');
                      return false;
                    }}
                  >
                    <Button icon={<UploadIcon size={16} />} loading={customSoundUploading}>
                      上传自定义声音
                    </Button>
                  </Upload>
                </div>
              </>
            )}
          </Space>
        </Card>
      </Space>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50 relative">
      {/* 装饰元素 */}
      <DecorativeElements variant="background" className="absolute inset-0" animate />
      <DecorativeElements variant="floating" className="absolute top-10 left-10" animate />
      <DecorativeElements variant="floating" className="absolute top-20 right-20" animate />
      <DecorativeElements variant="floating" className="absolute bottom-20 left-20" animate />
      <DecorativeElements variant="floating" className="absolute bottom-10 right-10" animate />
      
      <div className="relative z-10" style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* 页面标题 */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <Title level={2} style={{ margin: 0, color: '#7f1d1d' }}>
            <Bell style={{ marginRight: 8, color: '#dc2626' }} size={24} />
            通知中心
          </Title>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Badge 
              status={isConnected ? 'success' : 'error'} 
              text={isConnected ? '实时通知已连接' : '实时通知未连接'}
            />
            {unreadCount > 0 && (
              <Badge count={unreadCount} style={{ backgroundColor: '#52c41a' }} />
            )}
          </div>
        </div>
        <Text type="secondary">
          查看和管理你的所有通知
        </Text>
      </div>

      {/* 标签页 */}
      <Card>
        <Tabs 
          activeKey={activeTab} 
          onChange={setActiveTab}
          items={[
            {
              key: 'all',
              label: (
                <span>
                  <Bell size={16} />
                  全部通知
                </span>
              ),
              children: <NotificationList />
            },
            {
              key: 'unread',
              label: (
                <span>
                  <Badge 
                    count={data?.notifications.filter(n => !n.is_read).length || 0}
                    size="small"
                    offset={[10, 0]}
                  >
                    <Bell size={16} />
                    未读通知
                  </Badge>
                </span>
              ),
              children: <NotificationList />
            },
            {
              key: 'history',
              label: (
                <span>
                  <History size={16} />
                  历史记录
                </span>
              ),
              children: (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  {/* 历史统计 */}
                  <Card title="通知统计">
                    <Row gutter={16}>
                      <Col span={6}>
                        <Statistic 
                          title={<span style={{ color: '#7f1d1d' }}>总通知数</span>} 
                          value={historyStats.total || 0} 
                          valueStyle={{ color: '#7f1d1d' }}
                        />
                      </Col>
                      <Col span={6}>
                        <Statistic 
                          title={<span style={{ color: '#dc2626' }}>未读通知</span>} 
                          value={historyStats.unread || 0} 
                          valueStyle={{ color: '#dc2626' }}
                        />
                      </Col>
                      <Col span={6}>
                        <Statistic 
                          title={<span style={{ color: '#f59e0b' }}>今日通知</span>} 
                          value={historyStats.todayCount || 0} 
                          valueStyle={{ color: '#f59e0b' }}
                        />
                      </Col>
                      <Col span={6}>
                        <Statistic 
                          title={<span style={{ color: '#059669' }}>本周通知</span>} 
                          value={historyStats.weekCount || 0} 
                          valueStyle={{ color: '#059669' }}
                        />
                      </Col>
                    </Row>
                  </Card>
                  
                  {/* 搜索和过滤 */}
                  <Card>
                    <Space style={{ width: '100%' }} direction="vertical">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        <Input.Search
                          placeholder="搜索通知内容"
                          value={searchKeyword}
                          onChange={(e) => setSearchKeyword(e.target.value)}
                          onSearch={handleHistorySearch}
                          style={{ width: 300 }}
                        />
                        <Select
                          placeholder="通知类型"
                          style={{ width: 150 }}
                          allowClear
                          onChange={(value) => handleHistoryFilter({ type: value ? [value] : undefined })}
                        >
                          <Select.Option value="new_annotation">新标注</Select.Option>
                          <Select.Option value="nearby_activity">附近活动</Select.Option>
                          <Select.Option value="system_message">系统消息</Select.Option>
                        </Select>
                        <Select
                          placeholder="优先级"
                          style={{ width: 120 }}
                          allowClear
                          onChange={(value) => handleHistoryFilter({ priority: value ? [value] : undefined })}
                        >
                          <Select.Option value="high">高</Select.Option>
                          <Select.Option value="medium">中</Select.Option>
                          <Select.Option value="low">低</Select.Option>
                        </Select>
                        <DatePicker.RangePicker
                          onChange={(dates) => {
                            if (dates && dates[0] && dates[1]) {
                              handleHistoryFilter({
                                dateRange: {
                                  start: dates[0].toDate(),
                                  end: dates[1].toDate()
                                }
                              });
                            } else {
                              handleHistoryFilter({ dateRange: undefined });
                            }
                          }}
                        />
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Button
                          icon={<Download size={16} />}
                          onClick={handleExportHistory}
                        >
                          导出历史
                        </Button>
                        <Button
                          icon={<Trash2 size={16} />}
                          danger
                          onClick={handleClearHistory}
                        >
                          清空历史
                        </Button>
                      </div>
                    </Space>
                  </Card>
                  
                  {/* 历史记录列表 */}
                  <Card title="通知历史">
                    <List
                      dataSource={historyNotifications}
                      renderItem={(item) => (
                        <List.Item
                          actions={[
                            <Button
                              key="read"
                              size="small"
                              type={item.read ? 'default' : 'primary'}
                              onClick={() => handleMarkHistoryAsRead([item.id])}
                              disabled={item.read}
                            >
                              {item.read ? '已读' : '标记已读'}
                            </Button>,
                            <Button
                              key="delete"
                              size="small"
                              danger
                              onClick={() => handleDeleteHistory([item.id])}
                            >
                              删除
                            </Button>
                          ]}
                        >
                          <List.Item.Meta
                            avatar={
                              <Badge dot={!item.read}>
                                <Avatar icon={<Bell size={16} />} />
                              </Badge>
                            }
                            title={
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span>{item.title}</span>
                                <Tag color={item.priority === 'high' ? 'red' : item.priority === 'medium' ? 'orange' : 'blue'}>
                                  {item.priority}
                                </Tag>
                                <Tag>{item.source}</Tag>
                              </div>
                            }
                            description={
                              <div>
                                <div>{item.message}</div>
                                <div style={{ fontSize: '12px', color: '#999', marginTop: 4 }}>
                                  {item.timestamp.toLocaleString()}
                                </div>
                              </div>
                            }
                          />
                        </List.Item>
                      )}
                      pagination={{
                        current: historyPagination.page,
                        pageSize: historyPagination.pageSize,
                        total: historyStats.total || 0,
                        onChange: (page, pageSize) => {
                          setHistoryPagination({ page, pageSize: pageSize || 20 });
                        }
                      }}
                    />
                  </Card>
                </div>
              )
            },
            {
              key: 'settings',
              label: (
                <span>
                  <Settings size={16} />
                  通知设置
                </span>
              ),
              children: <NotificationSettings />
            }
          ]}
        />
      </Card>
    </div>
  );
};

export default NotificationPage;