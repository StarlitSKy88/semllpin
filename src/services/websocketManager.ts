import websocketServiceInstance from './websocketService';

// 全局WebSocket服务实例
let websocketService: typeof websocketServiceInstance | null = null;

// 设置WebSocket服务实例
export const setWebSocketService = (service: typeof websocketServiceInstance) => {
  websocketService = service;
};

// 获取WebSocket服务实例
export const getWebSocketService = (): typeof websocketServiceInstance | null => {
  return websocketService;
};

// 发送实时通知（支持去重和优先级）
export const sendRealtimeNotification = async (
  _userId: string,
  notification: {
    type: string;
    title: string;
    message: string;
    data?: any;
    priority?: 'low' | 'medium' | 'high';
    deduplicate?: boolean;
  },
): Promise<boolean> => {
  if (!websocketService) {
    console.warn('WebSocket服务未初始化');
    return false;
  }

  try {
    // 发送社交通知
    websocketService.send({
      id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: notification.type,
      title: notification.title,
      message: notification.message,
      data: notification.data || {},
      priority: notification.priority || 'medium',
      timestamp: new Date().toISOString(),
      read: false
    });
    const success = true;
    
    return success;
  } catch (error) {
    console.error('发送实时通知失败:', error);
    return false;
  }
};

// 批量发送实时通知
export const sendRealtimeNotificationToUsers = async (userIds: string[], notification: any) => {
  if (!websocketService) {
    console.warn('WebSocket服务未初始化');
    return {
      total: userIds.length,
      online: 0,
      offline: userIds.length,
      failed: userIds.length
    };
  }

  let successCount = 0;
  const results = await Promise.allSettled(
    userIds.map(userId => sendRealtimeNotification(userId, notification))
  );

  results.forEach(result => {
    if (result.status === 'fulfilled' && result.value) {
      successCount++;
    }
  });

  return {
    total: userIds.length,
    online: successCount,
    offline: userIds.length - successCount,
  };
};

// 批量发送通知（优化版本）
export const sendBatchNotifications = async (
  notifications: Array<{
    userId: string;
    notification: {
      type: string;
      title: string;
      message: string;
      data?: any;
      priority?: 'low' | 'medium' | 'high';
      deduplicate?: boolean;
    };
    options?: any;
  }>,
): Promise<{ sent: number; failed: number }> => {
  if (!websocketService) {
    console.warn('WebSocket服务未初始化');
    return { sent: 0, failed: notifications.length };
  }

  try {
    // 使用连接池的批量发送功能
    const connectionPool = (websocketService as any).connectionPool;
    if (connectionPool && connectionPool.sendBatchNotifications) {
      return await connectionPool.sendBatchNotifications(notifications);
    }

    // 回退到逐个发送
    let sent = 0;
    let failed = 0;

    for (const { userId, notification } of notifications) {
      try {
        // TODO: 实现发送通知到用户的逻辑
        console.log(`发送通知给用户 ${userId}:`, notification);
        const success = false;
        if (success) {
          sent++;
        } else {
          failed++;
        }
      } catch (error) {
        console.error(`批量发送通知失败 (用户: ${userId}):`, error);
        failed++;
      }
    }

    return { sent, failed };
  } catch (error) {
    console.error('批量发送通知失败:', error);
    return { sent: 0, failed: notifications.length };
  }
};

// 广播系统通知
export const broadcastSystemNotification = async (notification: any) => {
  // TODO: 实现系统通知广播逻辑
  console.log('广播系统通知:', notification);
  return false;
};

// 广播系统通知（支持地理位置）
export const broadcastSystemNotificationWithLocation = (
  notification: {
    type: string;
    title: string;
    message: string;
    data?: any;
    location?: {
      latitude: number;
      longitude: number;
      radius?: number; // 米
    };
  },
): number => {
  if (!websocketService) {
    console.warn('WebSocket服务未初始化');
    return 0;
  }

  try {
    const connectionPool = (websocketService as any).connectionPool;
    if (connectionPool && connectionPool.broadcastToRoom) {
      // 如果有地理位置限制，广播到特定区域
      if (notification.location) {
        const roomId = `location:${notification.location.latitude.toFixed(3)}_${notification.location.longitude.toFixed(3)}`;
        return connectionPool.broadcastToRoom(roomId, notification);
      } else {
        // 广播给所有用户
        return connectionPool.broadcastToRoom('global', notification);
      }
    }

    return 0;
  } catch (error) {
    console.error('广播系统通知失败:', error);
    return 0;
  }
};

// 检查用户是否在线
export const isUserOnline = (_userId: string): boolean => {
  // TODO: 实现用户在线状态检查逻辑
  return false;
};

// 获取在线用户数量
export const getOnlineUserCount = (): number => {
  // TODO: 实现在线用户数量统计逻辑
  return 0;
};

// 获取连接统计信息
export const getConnectionStats = (): any => {
  if (!websocketService) {
    return null;
  }

  try {
    const connectionPool = (websocketService as any).connectionPool;
    if (connectionPool && connectionPool.getConnectionStats) {
      return connectionPool.getConnectionStats();
    }
    return null;
  } catch (error) {
    console.error('获取连接统计失败:', error);
    return null;
  }
};

// 获取详细统计信息
export const getDetailedStats = (): any => {
  if (!websocketService) {
    return null;
  }

  try {
    const connectionPool = (websocketService as any).connectionPool;
    if (connectionPool && connectionPool.getDetailedStats) {
      return connectionPool.getDetailedStats();
    }
    return null;
  } catch (error) {
    console.error('获取详细统计失败:', error);
    return null;
  }
};
