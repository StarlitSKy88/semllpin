"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getDetailedStats = exports.getConnectionStats = exports.getOnlineUserCount = exports.isUserOnline = exports.broadcastSystemNotificationWithLocation = exports.broadcastSystemNotification = exports.sendBatchNotifications = exports.sendRealtimeNotificationToUsers = exports.sendRealtimeNotification = exports.getWebSocketService = exports.setWebSocketService = void 0;
let websocketService = null;
const setWebSocketService = (service) => {
    websocketService = service;
};
exports.setWebSocketService = setWebSocketService;
const getWebSocketService = () => {
    return websocketService;
};
exports.getWebSocketService = getWebSocketService;
const sendRealtimeNotification = async (userId, notification) => {
    if (!websocketService) {
        console.warn('WebSocket服务未初始化');
        return false;
    }
    try {
        console.log(`发送通知给用户 ${userId}:`, notification);
        return false;
    }
    catch (error) {
        console.error('发送实时通知失败:', error);
        return false;
    }
};
exports.sendRealtimeNotification = sendRealtimeNotification;
const sendRealtimeNotificationToUsers = async (userIds, notification) => {
    console.log(`批量发送通知给 ${userIds.length} 个用户:`, notification);
    return {
        total: userIds.length,
        online: 0,
        offline: userIds.length,
    };
};
exports.sendRealtimeNotificationToUsers = sendRealtimeNotificationToUsers;
const sendBatchNotifications = async (notifications) => {
    if (!websocketService) {
        console.warn('WebSocket服务未初始化');
        return { sent: 0, failed: notifications.length };
    }
    try {
        const connectionPool = websocketService.connectionPool;
        if (connectionPool && connectionPool.sendBatchNotifications) {
            return await connectionPool.sendBatchNotifications(notifications);
        }
        let sent = 0;
        let failed = 0;
        for (const { userId, notification } of notifications) {
            try {
                console.log(`发送通知给用户 ${userId}:`, notification);
                const success = false;
                if (success) {
                    sent++;
                }
                else {
                    failed++;
                }
            }
            catch (error) {
                console.error(`批量发送通知失败 (用户: ${userId}):`, error);
                failed++;
            }
        }
        return { sent, failed };
    }
    catch (error) {
        console.error('批量发送通知失败:', error);
        return { sent: 0, failed: notifications.length };
    }
};
exports.sendBatchNotifications = sendBatchNotifications;
const broadcastSystemNotification = async (notification) => {
    console.log('广播系统通知:', notification);
    return false;
};
exports.broadcastSystemNotification = broadcastSystemNotification;
const broadcastSystemNotificationWithLocation = (notification) => {
    if (!websocketService) {
        console.warn('WebSocket服务未初始化');
        return 0;
    }
    try {
        const connectionPool = websocketService.connectionPool;
        if (connectionPool && connectionPool.broadcastToRoom) {
            if (notification.location) {
                const roomId = `location:${notification.location.latitude.toFixed(3)}_${notification.location.longitude.toFixed(3)}`;
                return connectionPool.broadcastToRoom(roomId, notification);
            }
            else {
                return connectionPool.broadcastToRoom('global', notification);
            }
        }
        return 0;
    }
    catch (error) {
        console.error('广播系统通知失败:', error);
        return 0;
    }
};
exports.broadcastSystemNotificationWithLocation = broadcastSystemNotificationWithLocation;
const isUserOnline = (_userId) => {
    return false;
};
exports.isUserOnline = isUserOnline;
const getOnlineUserCount = () => {
    return 0;
};
exports.getOnlineUserCount = getOnlineUserCount;
const getConnectionStats = () => {
    if (!websocketService) {
        return null;
    }
    try {
        const connectionPool = websocketService.connectionPool;
        if (connectionPool && connectionPool.getConnectionStats) {
            return connectionPool.getConnectionStats();
        }
        return null;
    }
    catch (error) {
        console.error('获取连接统计失败:', error);
        return null;
    }
};
exports.getConnectionStats = getConnectionStats;
const getDetailedStats = () => {
    if (!websocketService) {
        return null;
    }
    try {
        const connectionPool = websocketService.connectionPool;
        if (connectionPool && connectionPool.getDetailedStats) {
            return connectionPool.getDetailedStats();
        }
        return null;
    }
    catch (error) {
        console.error('获取详细统计失败:', error);
        return null;
    }
};
exports.getDetailedStats = getDetailedStats;
//# sourceMappingURL=websocketManager.js.map