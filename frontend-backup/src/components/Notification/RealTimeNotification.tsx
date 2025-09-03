import React, { useState, useEffect } from 'react';
import { Avatar, Badge, Button, Dropdown, Empty, List, Spin, Typography } from 'antd';
import { BellOutlined, CheckOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { getUserNotifications, markNotificationAsRead, markAllNotificationsAsRead } from '../../utils/api';

const { Text } = Typography;

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

interface NotificationData {
  notifications: Notification[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

const RealTimeNotification: React.FC = () => {
  const navigate = useNavigate();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(false);
  const [dropdownVisible, setDropdownVisible] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  // 加载最新通知
  const loadRecentNotifications = async () => {
    try {
      setLoading(true);
      const response = await getUserNotifications(1, 10, false);
      const data: NotificationData = response.data;
      setNotifications(data.notifications);
      setUnreadCount(data.notifications.filter(n => !n.is_read).length);
    } catch (error) {
      console.error('加载通知失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecentNotifications();
    
    // 设置定时刷新（每30秒）
    const interval = setInterval(loadRecentNotifications, 30000);
    
    return () => clearInterval(interval);
  }, []);

  // 标记通知为已读
  const handleMarkAsRead = async (notificationId: string, event?: React.MouseEvent) => {
    if (event) {
      event.stopPropagation();
    }
    
    try {
      await markNotificationAsRead(notificationId);
      // 更新本地状态
      const updatedNotifications = notifications.map(notif => 
        notif.id === notificationId ? { ...notif, is_read: true } : notif
      );
      setNotifications(updatedNotifications);
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (error) {
      console.error('标记已读失败:', error);
    }
  };

  // 标记所有通知为已读
  const handleMarkAllAsRead = async () => {
    try {
      await markAllNotificationsAsRead();
      const updatedNotifications = notifications.map(notif => ({ ...notif, is_read: true }));
      setNotifications(updatedNotifications);
      setUnreadCount(0);
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

    // 关闭下拉菜单
    setDropdownVisible(false);

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
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return '刚刚';
    if (diffInMinutes < 60) return `${diffInMinutes}分钟前`;
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours}小时前`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}天前`;
    return date.toLocaleDateString('zh-CN');
  };

  // 下拉菜单内容
  const dropdownContent = (
    <div style={{ width: 350, maxHeight: 400, overflow: 'hidden' }}>
      {/* 头部 */}
      <div style={{ 
        padding: '12px 16px', 
        borderBottom: '1px solid #f0f0f0',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <Text strong>通知</Text>
        <div>
          {unreadCount > 0 && (
            <Button 
              type="link" 
              size="small"
              onClick={handleMarkAllAsRead}
            >
              全部已读
            </Button>
          )}
          <Button 
            type="link" 
            size="small"
            onClick={() => {
              setDropdownVisible(false);
              navigate('/notifications');
            }}
          >
            查看全部
          </Button>
        </div>
      </div>

      {/* 通知列表 */}
      <div style={{ maxHeight: 300, overflowY: 'auto' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '20px 0' }}>
            <Spin size="small" />
          </div>
        ) : notifications.length === 0 ? (
          <Empty
            description="暂无通知"
            style={{ padding: '20px 0' }}
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          />
        ) : (
          <List
            itemLayout="horizontal"
            dataSource={notifications.slice(0, 8)} // 只显示前8条
            renderItem={(notification) => (
              <List.Item
                key={notification.id}
                style={{
                  padding: '12px 16px',
                  backgroundColor: notification.is_read ? 'transparent' : '#f6ffed',
                  cursor: 'pointer',
                  borderBottom: '1px solid #f5f5f5'
                }}
                onClick={() => handleNotificationClick(notification)}
                actions={[
                  !notification.is_read && (
                    <Button
                      key="read"
                      type="link"
                      size="small"
                      icon={<CheckOutlined />}
                      onClick={(e) => handleMarkAsRead(notification.id, e)}
                      style={{ padding: 0 }}
                    />
                  )
                ].filter(Boolean)}
              >
                <List.Item.Meta
                  avatar={
                    <Badge dot={!notification.is_read} size="small">
                      {notification.from_avatar_url ? (
                        <Avatar src={notification.from_avatar_url} size="small" />
                      ) : (
                        <Avatar 
                          style={{ backgroundColor: '#1890ff' }}
                          icon={<BellOutlined />}
                          size="small"
                        />
                      )}
                    </Badge>
                  }
                  title={
                    <div>
                      <Text 
                        style={{ 
                          fontSize: '13px',
                          fontWeight: notification.is_read ? 'normal' : 'bold',
                          display: 'block',
                          marginBottom: '2px'
                        }}
                      >
                        {notification.title}
                      </Text>
                      <Text 
                        type="secondary" 
                        style={{ fontSize: '11px' }}
                      >
                        {formatTime(notification.created_at)}
                      </Text>
                    </div>
                  }
                  description={
                    <Text 
                      style={{ 
                        fontSize: '12px',
                        color: notification.is_read ? '#666' : '#333',
                        display: '-webkit-box',
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: 'vertical',
                        overflow: 'hidden'
                      }}
                    >
                      {notification.content}
                    </Text>
                  }
                />
              </List.Item>
            )}
          />
        )}
      </div>
    </div>
  );

  return (
    <Dropdown
      popupRender={() => dropdownContent}
      trigger={['click']}
      placement="bottomRight"
      open={dropdownVisible}
      onOpenChange={setDropdownVisible}
    >
      <div style={{ cursor: 'pointer', padding: '0 8px' }}>
        <Badge count={unreadCount} size="small" offset={[0, 0]}>
          <BellOutlined 
            style={{ 
              fontSize: '18px',
              color: unreadCount > 0 ? '#1890ff' : '#666'
            }} 
          />
        </Badge>
      </div>
    </Dropdown>
  );
};

export default RealTimeNotification;