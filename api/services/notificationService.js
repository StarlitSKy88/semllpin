/**
 * 奖励通知服务
 * 负责处理实时奖励通知推送和PWA通知
 */

class NotificationService {
  constructor() {
    this.wsConnections = new Map(); // 存储WebSocket连接
    this.notificationQueue = new Map(); // 离线通知队列
  }

  /**
   * 注册WebSocket连接
   * @param {string} userId - 用户ID
   * @param {WebSocket} ws - WebSocket连接
   */
  registerConnection(userId, ws) {
    this.wsConnections.set(userId, ws);
    
    // 发送离线通知
    this.sendQueuedNotifications(userId);
    
    // 监听连接关闭
    ws.on('close', () => {
      this.wsConnections.delete(userId);
    });
    
    // 发送连接确认
    this.sendMessage(userId, {
      type: 'connection_established',
      timestamp: new Date().toISOString()
    });
  }

  /**
   * 发送奖励通知
   * @param {string} userId - 用户ID
   * @param {Object} rewardData - 奖励数据
   */
  async sendRewardNotification(userId, rewardData) {
    const notification = {
      type: 'reward_earned',
      data: {
        id: rewardData.id,
        amount: rewardData.amount,
        rewardType: rewardData.reward_type,
        geofenceName: rewardData.geofence_name,
        location: {
          latitude: rewardData.latitude,
          longitude: rewardData.longitude
        },
        breakdown: {
          baseReward: rewardData.base_reward,
          timeDecayFactor: rewardData.time_decay_factor,
          firstDiscovererBonus: rewardData.first_discoverer_bonus,
          extraReward: rewardData.extra_reward
        },
        timestamp: rewardData.created_at
      },
      timestamp: new Date().toISOString()
    };

    // 尝试实时发送
    const sent = this.sendMessage(userId, notification);
    
    // 如果用户离线，加入队列
    if (!sent) {
      this.queueNotification(userId, notification);
    }

    // 发送PWA推送通知
    await this.sendPushNotification(userId, {
      title: '🎉 获得奖励！',
      body: `在${rewardData.geofence_name}获得${rewardData.amount}积分`,
      icon: '/icons/reward-icon.png',
      badge: '/icons/badge-icon.png',
      data: {
        type: 'reward',
        rewardId: rewardData.id,
        url: '/rewards'
      }
    });
  }

  /**
   * 发送地理围栏进入通知
   * @param {string} userId - 用户ID
   * @param {Object} geofenceData - 地理围栏数据
   */
  async sendGeofenceEntryNotification(userId, geofenceData) {
    const notification = {
      type: 'geofence_entered',
      data: {
        geofenceId: geofenceData.id,
        name: geofenceData.name,
        description: geofenceData.description,
        rewardType: geofenceData.reward_type,
        potentialReward: geofenceData.base_reward,
        location: {
          latitude: geofenceData.latitude,
          longitude: geofenceData.longitude
        }
      },
      timestamp: new Date().toISOString()
    };

    this.sendMessage(userId, notification);

    // 发送PWA推送通知
    await this.sendPushNotification(userId, {
      title: '📍 发现新地点！',
      body: `进入${geofenceData.name}，可获得${geofenceData.base_reward}积分`,
      icon: '/icons/location-icon.png',
      data: {
        type: 'geofence',
        geofenceId: geofenceData.id,
        url: '/map'
      }
    });
  }

  /**
   * 发送成就解锁通知
   * @param {string} userId - 用户ID
   * @param {Object} achievementData - 成就数据
   */
  async sendAchievementNotification(userId, achievementData) {
    const notification = {
      type: 'achievement_unlocked',
      data: {
        id: achievementData.id,
        name: achievementData.name,
        description: achievementData.description,
        icon: achievementData.icon,
        reward: achievementData.reward
      },
      timestamp: new Date().toISOString()
    };

    this.sendMessage(userId, notification);

    await this.sendPushNotification(userId, {
      title: '🏆 成就解锁！',
      body: `解锁成就：${achievementData.name}`,
      icon: '/icons/achievement-icon.png',
      data: {
        type: 'achievement',
        achievementId: achievementData.id,
        url: '/achievements'
      }
    });
  }

  /**
   * 发送WebSocket消息
   * @param {string} userId - 用户ID
   * @param {Object} message - 消息内容
   * @returns {boolean} 是否发送成功
   */
  sendMessage(userId, message) {
    const ws = this.wsConnections.get(userId);
    if (ws && ws.readyState === ws.OPEN) {
      try {
        ws.send(JSON.stringify(message));
        return true;
      } catch (error) {
        console.error('发送WebSocket消息失败:', error);
        this.wsConnections.delete(userId);
        return false;
      }
    }
    return false;
  }

  /**
   * 将通知加入离线队列
   * @param {string} userId - 用户ID
   * @param {Object} notification - 通知内容
   */
  queueNotification(userId, notification) {
    if (!this.notificationQueue.has(userId)) {
      this.notificationQueue.set(userId, []);
    }
    
    const queue = this.notificationQueue.get(userId);
    queue.push(notification);
    
    // 限制队列长度，避免内存溢出
    if (queue.length > 50) {
      queue.shift();
    }
  }

  /**
   * 发送排队的通知
   * @param {string} userId - 用户ID
   */
  sendQueuedNotifications(userId) {
    const queue = this.notificationQueue.get(userId);
    if (queue && queue.length > 0) {
      queue.forEach(notification => {
        this.sendMessage(userId, notification);
      });
      this.notificationQueue.delete(userId);
    }
  }

  /**
   * 发送PWA推送通知
   * @param {string} userId - 用户ID
   * @param {Object} payload - 推送内容
   */
  async sendPushNotification(userId, payload) {
    try {
      // 这里需要集成推送服务（如Firebase FCM或Web Push）
      // 暂时记录日志，实际实现需要根据具体推送服务配置
      console.log(`PWA推送通知 [用户${userId}]:`, payload);
      
      // TODO: 实现实际的推送逻辑
      // const subscription = await this.getUserPushSubscription(userId);
      // if (subscription) {
      //   await webpush.sendNotification(subscription, JSON.stringify(payload));
      // }
    } catch (error) {
      console.error('发送PWA推送通知失败:', error);
    }
  }

  /**
   * 获取用户在线状态
   * @param {string} userId - 用户ID
   * @returns {boolean} 是否在线
   */
  isUserOnline(userId) {
    const ws = this.wsConnections.get(userId);
    return ws && ws.readyState === ws.OPEN;
  }

  /**
   * 获取在线用户数量
   * @returns {number} 在线用户数
   */
  getOnlineUserCount() {
    return this.wsConnections.size;
  }

  /**
   * 广播消息给所有在线用户
   * @param {Object} message - 消息内容
   */
  broadcast(message) {
    this.wsConnections.forEach((ws, userId) => {
      this.sendMessage(userId, message);
    });
  }

  /**
   * 清理过期的离线通知
   */
  cleanupExpiredNotifications() {
    const now = new Date();
    const expireTime = 24 * 60 * 60 * 1000; // 24小时
    
    this.notificationQueue.forEach((queue, userId) => {
      const validNotifications = queue.filter(notification => {
        const notificationTime = new Date(notification.timestamp);
        return (now - notificationTime) < expireTime;
      });
      
      if (validNotifications.length === 0) {
        this.notificationQueue.delete(userId);
      } else {
        this.notificationQueue.set(userId, validNotifications);
      }
    });
  }
}

// 创建单例实例
const notificationService = new NotificationService();

// 定期清理过期通知
setInterval(() => {
  notificationService.cleanupExpiredNotifications();
}, 60 * 60 * 1000); // 每小时清理一次

module.exports = notificationService;