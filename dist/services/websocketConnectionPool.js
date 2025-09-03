"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const logger_1 = require("../utils/logger");
class WebSocketConnectionPool {
    constructor() {
        this.connections = new Map();
        this.userConnections = new Map();
        this.rooms = new Map();
        this.notificationHistory = new Map();
        this.connectionStats = {
            totalConnections: 0,
            activeConnections: 0,
            totalUsers: 0,
            averageConnectionTime: 0,
            connectionsPerMinute: 0,
            disconnectionsPerMinute: 0,
        };
        this.cleanupInterval = null;
        this.statsInterval = null;
        this.recentConnections = [];
        this.recentDisconnections = [];
        this.startCleanupTask();
        this.startStatsCollection();
    }
    addConnection(socket, userId) {
        const connectionInfo = {
            socket,
            userId,
            connectedAt: new Date(),
            lastActivity: new Date(),
            userAgent: socket.handshake.headers['user-agent'],
            ipAddress: socket.handshake.address || 'unknown',
            roomIds: new Set(),
        };
        this.connections.set(socket.id, connectionInfo);
        if (!this.userConnections.has(userId)) {
            this.userConnections.set(userId, new Set());
        }
        this.userConnections.get(userId).add(socket.id);
        this.connectionStats.totalConnections++;
        this.connectionStats.activeConnections++;
        this.connectionStats.totalUsers = this.userConnections.size;
        this.recentConnections.push(new Date());
        socket.join(`user:${userId}`);
        this.joinRoom(socket.id, `user:${userId}`);
        logger_1.logger.info(`WebSocket连接已添加: ${socket.id} (用户: ${userId})`);
    }
    removeConnection(socketId) {
        const connectionInfo = this.connections.get(socketId);
        if (!connectionInfo) {
            return;
        }
        const { userId, connectedAt, roomIds } = connectionInfo;
        roomIds.forEach(roomId => {
            this.leaveRoom(socketId, roomId);
        });
        const userSockets = this.userConnections.get(userId);
        if (userSockets) {
            userSockets.delete(socketId);
            if (userSockets.size === 0) {
                this.userConnections.delete(userId);
            }
        }
        this.connections.delete(socketId);
        this.connectionStats.activeConnections--;
        this.connectionStats.totalUsers = this.userConnections.size;
        this.recentDisconnections.push(new Date());
        const connectionDuration = Date.now() - connectedAt.getTime();
        this.updateAverageConnectionTime(connectionDuration);
        logger_1.logger.info(`WebSocket连接已移除: ${socketId} (用户: ${userId}, 连接时长: ${Math.round(connectionDuration / 1000)}秒)`);
    }
    updateActivity(socketId) {
        const connectionInfo = this.connections.get(socketId);
        if (connectionInfo) {
            connectionInfo.lastActivity = new Date();
        }
    }
    joinRoom(socketId, roomId) {
        const connectionInfo = this.connections.get(socketId);
        if (!connectionInfo) {
            return;
        }
        connectionInfo.roomIds.add(roomId);
        connectionInfo.socket.join(roomId);
        if (!this.rooms.has(roomId)) {
            this.rooms.set(roomId, new Set());
        }
        this.rooms.get(roomId).add(socketId);
        logger_1.logger.debug(`Socket ${socketId} 加入房间: ${roomId}`);
    }
    leaveRoom(socketId, roomId) {
        const connectionInfo = this.connections.get(socketId);
        if (connectionInfo) {
            connectionInfo.roomIds.delete(roomId);
            connectionInfo.socket.leave(roomId);
        }
        const roomSockets = this.rooms.get(roomId);
        if (roomSockets) {
            roomSockets.delete(socketId);
            if (roomSockets.size === 0) {
                this.rooms.delete(roomId);
            }
        }
        logger_1.logger.debug(`Socket ${socketId} 离开房间: ${roomId}`);
    }
    getUserConnections(userId) {
        const socketIds = this.userConnections.get(userId) || new Set();
        return Array.from(socketIds)
            .map(socketId => this.connections.get(socketId))
            .filter(Boolean);
    }
    isUserOnline(userId) {
        const userSockets = this.userConnections.get(userId);
        return userSockets ? userSockets.size > 0 : false;
    }
    getRoomConnections(roomId) {
        const socketIds = this.rooms.get(roomId) || new Set();
        return Array.from(socketIds)
            .map(socketId => this.connections.get(socketId))
            .filter(Boolean);
    }
    async sendNotificationToUser(userId, notification, options = {}) {
        const { deduplicate = true, deduplicationWindow = 60000, priority = 'medium', } = options;
        if (deduplicate) {
            const notificationHash = this.generateNotificationHash(notification);
            const existingNotification = this.notificationHistory.get(notificationHash);
            if (existingNotification) {
                const timeDiff = Date.now() - existingNotification.timestamp.getTime();
                if (timeDiff < deduplicationWindow && existingNotification.recipients.has(userId)) {
                    logger_1.logger.debug(`通知去重: 用户 ${userId} 在 ${timeDiff}ms 内已收到相同通知`);
                    return false;
                }
            }
        }
        const userConnections = this.getUserConnections(userId);
        if (userConnections.length === 0) {
            logger_1.logger.debug(`用户 ${userId} 不在线，无法发送实时通知`);
            return false;
        }
        let targetConnections = userConnections;
        if (priority === 'high') {
            targetConnections = userConnections;
        }
        else if (priority === 'medium') {
            targetConnections = userConnections
                .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
                .slice(0, 1);
        }
        else {
            targetConnections = userConnections
                .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
                .slice(0, 1);
        }
        let sent = false;
        for (const connection of targetConnections) {
            try {
                connection.socket.emit('notification', notification);
                this.updateActivity(connection.socket.id);
                sent = true;
            }
            catch (error) {
                logger_1.logger.error(`发送通知失败 (Socket: ${connection.socket.id}):`, error);
            }
        }
        if (deduplicate && sent) {
            const notificationHash = this.generateNotificationHash(notification);
            const existingNotification = this.notificationHistory.get(notificationHash);
            if (existingNotification) {
                existingNotification.recipients.add(userId);
                existingNotification.timestamp = new Date();
            }
            else {
                this.notificationHistory.set(notificationHash, {
                    hash: notificationHash,
                    timestamp: new Date(),
                    recipients: new Set([userId]),
                });
            }
        }
        return sent;
    }
    async sendBatchNotifications(notifications) {
        let sent = 0;
        let failed = 0;
        const userNotifications = new Map();
        notifications.forEach(({ userId, notification }) => {
            if (!userNotifications.has(userId)) {
                userNotifications.set(userId, []);
            }
            userNotifications.get(userId).push(notification);
        });
        for (const [userId, userNotifs] of userNotifications) {
            try {
                const success = await this.sendNotificationToUser(userId, {
                    type: 'batch_notifications',
                    notifications: userNotifs,
                    count: userNotifs.length,
                });
                if (success) {
                    sent += userNotifs.length;
                }
                else {
                    failed += userNotifs.length;
                }
            }
            catch (error) {
                logger_1.logger.error(`批量发送通知失败 (用户: ${userId}):`, error);
                failed += userNotifs.length;
            }
        }
        logger_1.logger.info(`批量通知发送完成: 成功 ${sent}, 失败 ${failed}`);
        return { sent, failed };
    }
    broadcastToRoom(roomId, notification) {
        const roomConnections = this.getRoomConnections(roomId);
        let sent = 0;
        roomConnections.forEach(connection => {
            try {
                connection.socket.emit('notification', notification);
                this.updateActivity(connection.socket.id);
                sent++;
            }
            catch (error) {
                logger_1.logger.error(`广播通知失败 (Socket: ${connection.socket.id}):`, error);
            }
        });
        logger_1.logger.debug(`房间 ${roomId} 广播通知: 发送给 ${sent} 个连接`);
        return sent;
    }
    generateNotificationHash(notification) {
        const hashContent = {
            type: notification.type,
            title: notification.title,
            message: notification.message,
            data: notification.data,
        };
        return Buffer.from(JSON.stringify(hashContent)).toString('base64');
    }
    updateAverageConnectionTime(duration) {
        const currentAvg = this.connectionStats.averageConnectionTime;
        const totalConnections = this.connectionStats.totalConnections;
        this.connectionStats.averageConnectionTime =
            (currentAvg * (totalConnections - 1) + duration) / totalConnections;
    }
    startCleanupTask() {
        this.cleanupInterval = setInterval(() => {
            this.cleanupInactiveConnections();
            this.cleanupNotificationHistory();
        }, 5 * 60 * 1000);
    }
    startStatsCollection() {
        this.statsInterval = setInterval(() => {
            this.updateConnectionRates();
        }, 60 * 1000);
    }
    cleanupInactiveConnections() {
        const now = Date.now();
        const inactiveThreshold = 30 * 60 * 1000;
        let cleaned = 0;
        for (const [socketId, connectionInfo] of this.connections) {
            const inactiveTime = now - connectionInfo.lastActivity.getTime();
            if (inactiveTime > inactiveThreshold) {
                if (connectionInfo.socket.disconnected) {
                    this.removeConnection(socketId);
                    cleaned++;
                }
            }
        }
        if (cleaned > 0) {
            logger_1.logger.info(`清理了 ${cleaned} 个非活跃连接`);
        }
    }
    cleanupNotificationHistory() {
        const now = Date.now();
        const historyThreshold = 60 * 60 * 1000;
        let cleaned = 0;
        for (const [hash, notification] of this.notificationHistory) {
            const age = now - notification.timestamp.getTime();
            if (age > historyThreshold) {
                this.notificationHistory.delete(hash);
                cleaned++;
            }
        }
        if (cleaned > 0) {
            logger_1.logger.debug(`清理了 ${cleaned} 条通知历史记录`);
        }
    }
    updateConnectionRates() {
        const now = Date.now();
        const oneMinuteAgo = now - 60 * 1000;
        this.recentConnections = this.recentConnections.filter(timestamp => timestamp.getTime() > oneMinuteAgo);
        this.recentDisconnections = this.recentDisconnections.filter(timestamp => timestamp.getTime() > oneMinuteAgo);
        this.connectionStats.connectionsPerMinute = this.recentConnections.length;
        this.connectionStats.disconnectionsPerMinute = this.recentDisconnections.length;
    }
    getConnectionStats() {
        return { ...this.connectionStats };
    }
    getDetailedStats() {
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
    cleanup() {
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
        logger_1.logger.info('WebSocket连接池已清理');
    }
}
exports.default = WebSocketConnectionPool;
//# sourceMappingURL=websocketConnectionPool.js.map