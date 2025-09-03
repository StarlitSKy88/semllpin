/**
 * WebSocket客户端服务
 * 处理实时通知连接和消息处理
 */

interface NotificationData {
  type: string;
  data: any;
  timestamp: string;
}

interface RewardNotification {
  id: string;
  amount: number;
  rewardType: string;
  geofenceName: string;
  location: {
    latitude: number;
    longitude: number;
  };
  breakdown: {
    baseReward: number;
    timeDecayFactor: number;
    firstDiscovererBonus: number;
    extraReward: number;
  };
  timestamp: string;
}

interface GeofenceNotification {
  geofenceId: string;
  name: string;
  description: string;
  rewardType: string;
  potentialReward: number;
  location: {
    latitude: number;
    longitude: number;
  };
}

interface AchievementNotification {
  id: string;
  name: string;
  description: string;
  icon: string;
  reward: number;
}

type NotificationHandler = (data: any) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private isConnecting = false;
  private handlers: Map<string, NotificationHandler[]> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private connectionPromise: Promise<void> | null = null;

  /**
   * 连接WebSocket服务器
   * @param token JWT认证token
   */
  async connect(token: string): Promise<void> {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return this.connectionPromise || Promise.resolve();
    }

    this.isConnecting = true;
    this.connectionPromise = new Promise((resolve, reject) => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsUrl = `${protocol}//${host}/ws?token=${encodeURIComponent(token)}`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          console.log('WebSocket连接已建立');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          this.startHeartbeat();
          this.emit('connection_established', { timestamp: new Date().toISOString() });
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const notification: NotificationData = JSON.parse(event.data);
            this.handleNotification(notification);
          } catch (error) {
            console.error('解析WebSocket消息失败:', error);
          }
        };

        this.ws.onclose = (event) => {
          console.log('WebSocket连接关闭:', event.code, event.reason);
          this.isConnecting = false;
          this.stopHeartbeat();
          this.emit('connection_closed', { code: event.code, reason: event.reason });

          // 自动重连
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect(token);
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket连接错误:', error);
          this.isConnecting = false;
          this.emit('connection_error', { error });
          reject(error);
        };
      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });

    return this.connectionPromise;
  }

  /**
   * 断开WebSocket连接
   */
  disconnect(): void {
    if (this.ws) {
      this.stopHeartbeat();
      this.ws.close(1000, '用户主动断开连接');
      this.ws = null;
    }
    this.reconnectAttempts = this.maxReconnectAttempts; // 阻止自动重连
  }

  /**
   * 发送消息到服务器
   * @param data 消息数据
   */
  send(data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    } else {
      console.warn('WebSocket未连接，无法发送消息');
    }
  }

  /**
   * 订阅通知类型
   * @param notifications 通知类型数组
   */
  subscribeNotifications(notifications: string[] = ['all']): void {
    this.send({
      type: 'subscribe_notifications',
      notifications,
    });
  }

  /**
   * 标记通知为已读
   * @param notificationId 通知ID
   */
  markNotificationRead(notificationId: string): void {
    this.send({
      type: 'mark_notification_read',
      notificationId,
    });
  }

  /**
   * 请求位置更新
   */
  requestLocationUpdate(): void {
    this.send({
      type: 'request_location_update',
    });
  }

  /**
   * 获取在线状态
   */
  getOnlineStatus(): void {
    this.send({
      type: 'get_online_status',
    });
  }

  /**
   * 注册事件处理器
   * @param event 事件类型
   * @param handler 处理函数
   */
  on(event: string, handler: NotificationHandler): void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, []);
    }
    this.handlers.get(event)!.push(handler);
  }

  /**
   * 移除事件处理器
   * @param event 事件类型
   * @param handler 处理函数
   */
  off(event: string, handler: NotificationHandler): void {
    const handlers = this.handlers.get(event);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  /**
   * 触发事件
   * @param event 事件类型
   * @param data 事件数据
   */
  private emit(event: string, data: any): void {
    const handlers = this.handlers.get(event);
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(data);
        } catch (error) {
          console.error(`事件处理器执行失败 [${event}]:`, error);
        }
      });
    }
  }

  /**
   * 处理接收到的通知
   * @param notification 通知数据
   */
  private handleNotification(notification: NotificationData): void {
    console.log('收到通知:', notification);

    switch (notification.type) {
      case 'reward_earned':
        this.handleRewardNotification(notification.data);
        break;
      case 'geofence_entered':
        this.handleGeofenceNotification(notification.data);
        break;
      case 'achievement_unlocked':
        this.handleAchievementNotification(notification.data);
        break;
      case 'connection_established':
        this.emit('connected', notification.data);
        break;
      case 'pong':
        // 心跳响应，不需要特殊处理
        break;
      case 'system_message':
        this.emit('system_message', notification.data);
        break;
      case 'server_status':
        this.emit('server_status', notification.data);
        break;
      default:
        this.emit(notification.type, notification.data);
    }
  }

  /**
   * 处理奖励通知
   * @param data 奖励数据
   */
  private handleRewardNotification(data: RewardNotification): void {
    this.emit('reward_earned', data);

    // 显示浏览器通知
    this.showBrowserNotification(
      '🎉 获得奖励！',
      `在${data.geofenceName}获得${data.amount}积分`,
      '/icons/reward-icon.png',
    );
  }

  /**
   * 处理地理围栏通知
   * @param data 地理围栏数据
   */
  private handleGeofenceNotification(data: GeofenceNotification): void {
    this.emit('geofence_entered', data);

    this.showBrowserNotification(
      '📍 发现新地点！',
      `进入${data.name}，可获得${data.potentialReward}积分`,
      '/icons/location-icon.png',
    );
  }

  /**
   * 处理成就通知
   * @param data 成就数据
   */
  private handleAchievementNotification(data: AchievementNotification): void {
    this.emit('achievement_unlocked', data);

    this.showBrowserNotification(
      '🏆 成就解锁！',
      `解锁成就：${data.name}`,
      '/icons/achievement-icon.png',
    );
  }

  /**
   * 显示浏览器通知
   * @param title 标题
   * @param body 内容
   * @param icon 图标
   */
  private async showBrowserNotification(title: string, body: string, icon?: string): Promise<void> {
    if ('Notification' in window) {
      if (Notification.permission === 'granted') {
        const options: NotificationOptions = { body };
        if (icon) {
          options.icon = icon;
        }
        new Notification(title, options);
      } else if (Notification.permission !== 'denied') {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
          const options: NotificationOptions = { body };
          if (icon) {
            options.icon = icon;
          }
          new Notification(title, options);
        }
      }
    }
  }

  /**
   * 开始心跳检测
   */
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      this.send({ type: 'ping' });
    }, 30000); // 每30秒发送一次心跳
  }

  /**
   * 停止心跳检测
   */
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  /**
   * 安排重连
   * @param token JWT token
   */
  private scheduleReconnect(token: string): void {
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1); // 指数退避

    console.log(`${delay}ms后尝试第${this.reconnectAttempts}次重连...`);

    setTimeout(() => {
      this.connect(token).catch(error => {
        console.error('重连失败:', error);
      });
    }, delay);
  }

  /**
   * 获取连接状态
   */
  get isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /**
   * 获取连接状态文本
   */
  get connectionState(): string {
    if (!this.ws) {
      return 'disconnected';
    }

    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'connected';
      case WebSocket.CLOSING:
        return 'closing';
      case WebSocket.CLOSED:
        return 'closed';
      default:
        return 'unknown';
    }
  }
}

// 创建单例实例
const websocketService = new WebSocketService();

export default websocketService;
export type {
  NotificationData,
  RewardNotification,
  GeofenceNotification,
  AchievementNotification,
  NotificationHandler,
};
