import { io, Socket } from 'socket.io-client';
import { notification } from 'antd';

export interface NotificationData {
  id: string;
  type: string;
  title: string;
  content: string;
  sender?: {
    id: string;
    username: string;
    avatar_url?: string;
  };
  actionUrl?: string;
  createdAt: string;
  realtime?: boolean;
}

interface UnreadCountData {
  count: number;
  timestamp: string;
}

class WebSocketService {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private isConnecting = false;
  private listeners: Map<string, ((...args: unknown[]) => void)[]> = new Map();

  constructor() {
    this.initializeEventListeners();
  }

  // 连接WebSocket
  public connect(token: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      if (this.socket?.connected) {
        resolve(true);
        return;
      }

      if (this.isConnecting) {
        reject(new Error('正在连接中...'));
        return;
      }

      this.isConnecting = true;

      try {
        const serverUrl = import.meta.env.VITE_WS_URL || 
          (import.meta.env.VITE_NODE_ENV === 'production' 
            ? 'https://api.smellpin.com'
            : 'http://localhost:3000');
        
        this.socket = io(serverUrl, {
          auth: {
            token: token
          },
          transports: ['websocket', 'polling'],
          timeout: 10000,
          forceNew: true
        });

        this.setupEventHandlers();

        this.socket.on('connect', () => {
          console.log('WebSocket连接成功');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          resolve(true);
        });

        this.socket.on('connect_error', (error) => {
          console.error('WebSocket连接失败:', error);
          this.isConnecting = false;
          reject(error);
        });

      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  // 断开连接
  public disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.reconnectAttempts = 0;
    console.log('WebSocket已断开连接');
  }

  // 设置事件处理器
  private setupEventHandlers() {
    if (!this.socket) return;

    // 连接成功
    this.socket.on('connected', (data) => {
      console.log('WebSocket认证成功:', data);
      this.emit('connected', data);
    });

    // 接收新通知
    this.socket.on('new_notification', (data: NotificationData) => {
      console.log('收到新通知:', data);
      this.handleNewNotification(data);
      this.emit('new_notification', data);
    });

    // 未读通知数量更新
    this.socket.on('unread_count', (data: UnreadCountData) => {
      console.log('未读通知数量:', data.count);
      this.emit('unread_count', data);
    });

    // 通知标记已读确认
    this.socket.on('notification_marked_read', (data) => {
      console.log('通知标记已读:', data);
      this.emit('notification_marked_read', data);
    });

    // 系统通知
    this.socket.on('system_notification', (data) => {
      console.log('收到系统通知:', data);
      this.handleSystemNotification(data);
      this.emit('system_notification', data);
    });

    // 心跳响应
    this.socket.on('pong', (data) => {
      console.log('心跳响应:', data);
    });

    // 断开连接
    this.socket.on('disconnect', (reason) => {
      console.log('WebSocket连接断开:', reason);
      this.emit('disconnect', reason);
      
      // 自动重连
      if (reason === 'io server disconnect') {
        // 服务器主动断开，不重连
        return;
      }
      
      this.attemptReconnect();
    });

    // 连接错误
    this.socket.on('error', (error) => {
      console.error('WebSocket错误:', error);
      this.emit('error', error);
    });
  }

  // 处理新通知
  private handleNewNotification(data: NotificationData) {
    // 显示桌面通知
    this.showDesktopNotification(data);
    
    // 显示应用内通知
    this.showInAppNotification(data);
  }

  // 处理系统通知
  private handleSystemNotification(data: { content?: string; message?: string }) {
    notification.warning({
      message: '系统通知',
      description: data.content || data.message,
      duration: 0, // 不自动关闭
      placement: 'topRight'
    });
  }

  // 显示桌面通知
  private showDesktopNotification(data: NotificationData) {
    if (!('Notification' in window)) {
      return;
    }

    if (Notification.permission === 'granted') {
      const notification = new Notification(data.title, {
        body: data.content,
        icon: '/favicon.ico',
        tag: data.id,
        requireInteraction: true
      });

      notification.onclick = () => {
        window.focus();
        if (data.actionUrl) {
          window.location.href = data.actionUrl;
        }
        notification.close();
      };
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(permission => {
        if (permission === 'granted') {
          this.showDesktopNotification(data);
        }
      });
    }
  }

  // 显示应用内通知
  private showInAppNotification(data: NotificationData) {
    const typeMap: { [key: string]: 'success' | 'info' | 'warning' | 'error' } = {
      'follow': 'info',
      'comment': 'info',
      'like': 'success',
      'share': 'info',
      'system': 'warning'
    };

    notification[typeMap[data.type] || 'info']({
      message: data.title,
      description: data.content,
      duration: 4.5,
      placement: 'topRight',
      onClick: () => {
        if (data.actionUrl) {
          window.location.href = data.actionUrl;
        }
      }
    });
  }

  // 标记通知为已读
  public markNotificationAsRead(notificationId: string) {
    if (this.socket?.connected) {
      this.socket.emit('mark_notification_read', { notificationId });
    }
  }

  // 获取未读通知数量
  public getUnreadCount() {
    if (this.socket?.connected) {
      this.socket.emit('get_unread_count');
    }
  }

  // 发送心跳
  public ping() {
    if (this.socket?.connected) {
      this.socket.emit('ping');
    }
  }

  // 尝试重连
  private attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('达到最大重连次数，停止重连');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    console.log(`${delay}ms后尝试第${this.reconnectAttempts}次重连...`);
    
    setTimeout(() => {
      if (this.socket && !this.socket.connected) {
        this.socket.connect();
      }
    }, delay);
  }

  // 初始化事件监听器系统
  private initializeEventListeners() {
    this.listeners = new Map();
  }

  // 添加事件监听器
  public on(event: string, callback: (...args: unknown[]) => void) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  // 移除事件监听器
  public off(event: string, callback?: (...args: unknown[]) => void) {
    if (!this.listeners.has(event)) return;
    
    if (callback) {
      const callbacks = this.listeners.get(event)!;
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    } else {
      this.listeners.delete(event);
    }
  }

  // 触发事件
  private emit(event: string, data?: unknown) {
    if (this.listeners.has(event)) {
      this.listeners.get(event)!.forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`事件监听器执行失败 (${event}):`, error);
        }
      });
    }
  }

  // 检查连接状态
  public isConnected(): boolean {
    return this.socket?.connected || false;
  }

  // 获取连接状态
  public getConnectionStatus() {
    if (!this.socket) return 'disconnected';
    if (this.socket.connected) return 'connected';
    if (this.isConnecting) return 'connecting';
    return 'disconnected';
  }
}

// 创建全局实例
export const websocketService = new WebSocketService();
export default websocketService;