import { Socket } from 'socket.io';
import { logger } from '../utils/logger';

// 连接信息接口
interface ConnectionInfo {
  socket: Socket;
  userId: string;
  connectedAt: Date;
  lastActivity: Date;
  userAgent?: string;
  ipAddress?: string;
  roomIds: Set<string>;
}

// 连接统计信息
interface ConnectionStats {
  totalConnections: number;
  activeConnections: number;
  totalUsers: number;
  averageConnectionTime: number;
  connectionsPerMinute: number;
  disconnectionsPerMinute: number;
}

// 通知去重信息
interface NotificationDedup {
  hash: string;
  timestamp: Date;
  recipients: Set<string>;
}

// WebSocket连接池管理器
class WebSocketConnectionPool {
  private connections: Map<string, ConnectionInfo> = new Map();
  private userConnections: Map<string, Set<string>> = new Map();
  private rooms: Map<string, Set<string>> = new Map();
  private notificationHistory: Map<string, NotificationDedup> = new Map();
  private connectionStats: ConnectionStats = {
    totalConnections: 0,
    activeConnections: 0,
    totalUsers: 0,
    averageConnectionTime: 0,
    connectionsPerMinute: 0,
    disconnectionsPerMinute: 0,
  };
  private cleanupInterval: NodeJS.Timeout | null = null;
  private statsInterval: NodeJS.Timeout | null = null;
  private recentConnections: Date[] = [];
  private recentDisconnections: Date[] = [];

  constructor() {
    this.startCleanupTask();
    this.startStatsCollection();
  }

  // 添加连接
  addConnection(socket: Socket, userId: string): void {
    const connectionInfo: ConnectionInfo = {
      socket,
      userId,
      connectedAt: new Date(),
      lastActivity: new Date(),
      userAgent: socket.handshake.headers['user-agent'] as string,
      ipAddress: socket.handshake.address || 'unknown',
      roomIds: new Set(),
    };

    // 存储连接信息
    this.connections.set(socket.id, connectionInfo);

    // 更新用户连接映射
    if (!this.userConnections.has(userId)) {
      this.userConnections.set(userId, new Set());
    }
    this.userConnections.get(userId)!.add(socket.id);

    // 更新统计信息
    this.connectionStats.totalConnections++;
    this.connectionStats.activeConnections++;
    this.connectionStats.totalUsers = this.userConnections.size;
    this.recentConnections.push(new Date());

    // 加入用户专属房间
    socket.join(`user:${userId}`);
    this.joinRoom(socket.id, `user:${userId}`);

    logger.info(`WebSocket连接已添加: ${socket.id} (用户: ${userId})`);
  }

  // 移除连接
  removeConnection(socketId: string): void {
    const connectionInfo = this.connections.get(socketId);
    if (!connectionInfo) {
      return;
    }

    const { userId, connectedAt, roomIds } = connectionInfo;

    // 离开所有房间
    roomIds.forEach(roomId => {
      this.leaveRoom(socketId, roomId);
    });

    // 更新用户连接映射
    const userSockets = this.userConnections.get(userId);
    if (userSockets) {
      userSockets.delete(socketId);
      if (userSockets.size === 0) {
        this.userConnections.delete(userId);
      }
    }

    // 移除连接信息
    this.connections.delete(socketId);

    // 更新统计信息
    this.connectionStats.activeConnections--;
    this.connectionStats.totalUsers = this.userConnections.size;
    this.recentDisconnections.push(new Date());

    // 计算连接时长
    const connectionDuration = Date.now() - connectedAt.getTime();
    this.updateAverageConnectionTime(connectionDuration);

    logger.info(`WebSocket连接已移除: ${socketId} (用户: ${userId}, 连接时长: ${Math.round(connectionDuration / 1000)}秒)`);
  }

  // 更新连接活动时间
  updateActivity(socketId: string): void {
    const connectionInfo = this.connections.get(socketId);
    if (connectionInfo) {
      connectionInfo.lastActivity = new Date();
    }
  }

  // 加入房间
  joinRoom(socketId: string, roomId: string): void {
    const connectionInfo = this.connections.get(socketId);
    if (!connectionInfo) {
      return;
    }

    // 更新连接信息
    connectionInfo.roomIds.add(roomId);
    connectionInfo.socket.join(roomId);

    // 更新房间映射
    if (!this.rooms.has(roomId)) {
      this.rooms.set(roomId, new Set());
    }
    this.rooms.get(roomId)!.add(socketId);

    logger.debug(`Socket ${socketId} 加入房间: ${roomId}`);
  }

  // 离开房间
  leaveRoom(socketId: string, roomId: string): void {
    const connectionInfo = this.connections.get(socketId);
    if (connectionInfo) {
      connectionInfo.roomIds.delete(roomId);
      connectionInfo.socket.leave(roomId);
    }

    // 更新房间映射
    const roomSockets = this.rooms.get(roomId);
    if (roomSockets) {
      roomSockets.delete(socketId);
      if (roomSockets.size === 0) {
        this.rooms.delete(roomId);
      }
    }

    logger.debug(`Socket ${socketId} 离开房间: ${roomId}`);
  }

  // 获取用户的所有连接
  getUserConnections(userId: string): ConnectionInfo[] {
    const socketIds = this.userConnections.get(userId) || new Set();
    return Array.from(socketIds)
      .map(socketId => this.connections.get(socketId))
      .filter(Boolean) as ConnectionInfo[];
  }

  // 检查用户是否在线
  isUserOnline(userId: string): boolean {
    const userSockets = this.userConnections.get(userId);
    return userSockets ? userSockets.size > 0 : false;
  }

  // 获取房间中的所有连接
  getRoomConnections(roomId: string): ConnectionInfo[] {
    const socketIds = this.rooms.get(roomId) || new Set();
    return Array.from(socketIds)
      .map(socketId => this.connections.get(socketId))
      .filter(Boolean) as ConnectionInfo[];
  }

  // 发送通知给用户（支持去重）
  async sendNotificationToUser(
    userId: string,
    notification: any,
    options: {
      deduplicate?: boolean;
      deduplicationWindow?: number; // 毫秒
      priority?: 'low' | 'medium' | 'high';
    } = {},
  ): Promise<boolean> {
    const {
      deduplicate = true,
      deduplicationWindow = 60000, // 1分钟
      priority = 'medium',
    } = options;

    // 通知去重检查
    if (deduplicate) {
      const notificationHash = this.generateNotificationHash(notification);
      const existingNotification = this.notificationHistory.get(notificationHash);

      if (existingNotification) {
        const timeDiff = Date.now() - existingNotification.timestamp.getTime();
        if (timeDiff < deduplicationWindow && existingNotification.recipients.has(userId)) {
          logger.debug(`通知去重: 用户 ${userId} 在 ${timeDiff}ms 内已收到相同通知`);
          return false;
        }
      }
    }

    const userConnections = this.getUserConnections(userId);
    if (userConnections.length === 0) {
      logger.debug(`用户 ${userId} 不在线，无法发送实时通知`);
      return false;
    }

    // 根据优先级选择发送策略
    let targetConnections = userConnections;
    if (priority === 'high') {
      // 高优先级：发送给所有连接
      targetConnections = userConnections;
    } else if (priority === 'medium') {
      // 中优先级：发送给最新的连接
      targetConnections = userConnections
        .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
        .slice(0, 1);
    } else {
      // 低优先级：发送给最活跃的连接
      targetConnections = userConnections
        .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
        .slice(0, 1);
    }

    // 发送通知
    let sent = false;
    for (const connection of targetConnections) {
      try {
        connection.socket.emit('notification', notification);
        this.updateActivity(connection.socket.id);
        sent = true;
      } catch (error) {
        logger.error(`发送通知失败 (Socket: ${connection.socket.id}):`, error);
      }
    }

    // 记录通知历史（用于去重）
    if (deduplicate && sent) {
      const notificationHash = this.generateNotificationHash(notification);
      const existingNotification = this.notificationHistory.get(notificationHash);

      if (existingNotification) {
        existingNotification.recipients.add(userId);
        existingNotification.timestamp = new Date();
      } else {
        this.notificationHistory.set(notificationHash, {
          hash: notificationHash,
          timestamp: new Date(),
          recipients: new Set([userId]),
        });
      }
    }

    return sent;
  }

  // 批量发送通知
  async sendBatchNotifications(
    notifications: Array<{ userId: string; notification: any; options?: any }>,
  ): Promise<{ sent: number; failed: number }> {
    let sent = 0;
    let failed = 0;

    // 按用户分组通知
    const userNotifications = new Map<string, any[]>();
    notifications.forEach(({ userId, notification }) => {
      if (!userNotifications.has(userId)) {
        userNotifications.set(userId, []);
      }
      userNotifications.get(userId)!.push(notification);
    });

    // 批量发送
    for (const [userId, userNotifs] of userNotifications) {
      try {
        const success = await this.sendNotificationToUser(userId, {
          type: 'batch_notifications',
          notifications: userNotifs,
          count: userNotifs.length,
        });

        if (success) {
          sent += userNotifs.length;
        } else {
          failed += userNotifs.length;
        }
      } catch (error) {
        logger.error(`批量发送通知失败 (用户: ${userId}):`, error);
        failed += userNotifs.length;
      }
    }

    logger.info(`批量通知发送完成: 成功 ${sent}, 失败 ${failed}`);
    return { sent, failed };
  }

  // 广播通知到房间
  broadcastToRoom(roomId: string, notification: any): number {
    const roomConnections = this.getRoomConnections(roomId);
    let sent = 0;

    roomConnections.forEach(connection => {
      try {
        connection.socket.emit('notification', notification);
        this.updateActivity(connection.socket.id);
        sent++;
      } catch (error) {
        logger.error(`广播通知失败 (Socket: ${connection.socket.id}):`, error);
      }
    });

    logger.debug(`房间 ${roomId} 广播通知: 发送给 ${sent} 个连接`);
    return sent;
  }

  // 生成通知哈希（用于去重）
  private generateNotificationHash(notification: any): string {
    const hashContent = {
      type: notification.type,
      title: notification.title,
      message: notification.message,
      data: notification.data,
    };
    return Buffer.from(JSON.stringify(hashContent)).toString('base64');
  }

  // 更新平均连接时间
  private updateAverageConnectionTime(duration: number): void {
    const currentAvg = this.connectionStats.averageConnectionTime;
    const totalConnections = this.connectionStats.totalConnections;

    this.connectionStats.averageConnectionTime =
      (currentAvg * (totalConnections - 1) + duration) / totalConnections;
  }

  // 启动清理任务
  private startCleanupTask(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupInactiveConnections();
      this.cleanupNotificationHistory();
    }, 5 * 60 * 1000); // 每5分钟清理一次
  }

  // 启动统计收集
  private startStatsCollection(): void {
    this.statsInterval = setInterval(() => {
      this.updateConnectionRates();
    }, 60 * 1000); // 每分钟更新一次统计
  }

  // 清理非活跃连接
  private cleanupInactiveConnections(): void {
    const now = Date.now();
    const inactiveThreshold = 30 * 60 * 1000; // 30分钟
    let cleaned = 0;

    for (const [socketId, connectionInfo] of this.connections) {
      const inactiveTime = now - connectionInfo.lastActivity.getTime();
      if (inactiveTime > inactiveThreshold) {
        // 检查连接是否仍然有效
        if (connectionInfo.socket.disconnected) {
          this.removeConnection(socketId);
          cleaned++;
        }
      }
    }

    if (cleaned > 0) {
      logger.info(`清理了 ${cleaned} 个非活跃连接`);
    }
  }

  // 清理通知历史
  private cleanupNotificationHistory(): void {
    const now = Date.now();
    const historyThreshold = 60 * 60 * 1000; // 1小时
    let cleaned = 0;

    for (const [hash, notification] of this.notificationHistory) {
      const age = now - notification.timestamp.getTime();
      if (age > historyThreshold) {
        this.notificationHistory.delete(hash);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug(`清理了 ${cleaned} 条通知历史记录`);
    }
  }

  // 更新连接速率统计
  private updateConnectionRates(): void {
    const now = Date.now();
    const oneMinuteAgo = now - 60 * 1000;

    // 清理旧的连接记录
    this.recentConnections = this.recentConnections.filter(
      timestamp => timestamp.getTime() > oneMinuteAgo,
    );
    this.recentDisconnections = this.recentDisconnections.filter(
      timestamp => timestamp.getTime() > oneMinuteAgo,
    );

    // 更新统计
    this.connectionStats.connectionsPerMinute = this.recentConnections.length;
    this.connectionStats.disconnectionsPerMinute = this.recentDisconnections.length;
  }

  // 获取连接统计信息
  getConnectionStats(): ConnectionStats {
    return { ...this.connectionStats };
  }

  // 获取详细连接信息
  getDetailedStats(): any {
    const roomStats = Array.from(this.rooms.entries()).map(([roomId, sockets]) => ({
      roomId,
      connectionCount: sockets.size,
    }));

    const userStats = Array.from(this.userConnections.entries()).map(([userId, sockets]) => ({
      userId,
      connectionCount: sockets.size,
    }));

    return {
      ...this.connectionStats,
      rooms: roomStats,
      users: userStats,
      notificationHistorySize: this.notificationHistory.size,
    };
  }

  // 清理资源
  cleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    if (this.statsInterval) {
      clearInterval(this.statsInterval);
      this.statsInterval = null;
    }

    this.connections.clear();
    this.userConnections.clear();
    this.rooms.clear();
    this.notificationHistory.clear();
    this.recentConnections = [];
    this.recentDisconnections = [];

    logger.info('WebSocket连接池已清理');
  }
}

export default WebSocketConnectionPool;
export { ConnectionInfo, ConnectionStats, NotificationDedup };
