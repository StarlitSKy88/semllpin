import { Socket } from 'socket.io';
interface ConnectionInfo {
    socket: Socket;
    userId: string;
    connectedAt: Date;
    lastActivity: Date;
    userAgent?: string;
    ipAddress?: string;
    roomIds: Set<string>;
}
interface ConnectionStats {
    totalConnections: number;
    activeConnections: number;
    totalUsers: number;
    averageConnectionTime: number;
    connectionsPerMinute: number;
    disconnectionsPerMinute: number;
}
interface NotificationDedup {
    hash: string;
    timestamp: Date;
    recipients: Set<string>;
}
declare class WebSocketConnectionPool {
    private connections;
    private userConnections;
    private rooms;
    private notificationHistory;
    private connectionStats;
    private cleanupInterval;
    private statsInterval;
    private recentConnections;
    private recentDisconnections;
    constructor();
    addConnection(socket: Socket, userId: string): void;
    removeConnection(socketId: string): void;
    updateActivity(socketId: string): void;
    joinRoom(socketId: string, roomId: string): void;
    leaveRoom(socketId: string, roomId: string): void;
    getUserConnections(userId: string): ConnectionInfo[];
    isUserOnline(userId: string): boolean;
    getRoomConnections(roomId: string): ConnectionInfo[];
    sendNotificationToUser(userId: string, notification: any, options?: {
        deduplicate?: boolean;
        deduplicationWindow?: number;
        priority?: 'low' | 'medium' | 'high';
    }): Promise<boolean>;
    sendBatchNotifications(notifications: Array<{
        userId: string;
        notification: any;
        options?: any;
    }>): Promise<{
        sent: number;
        failed: number;
    }>;
    broadcastToRoom(roomId: string, notification: any): number;
    private generateNotificationHash;
    private updateAverageConnectionTime;
    private startCleanupTask;
    private startStatsCollection;
    private cleanupInactiveConnections;
    private cleanupNotificationHistory;
    private updateConnectionRates;
    getConnectionStats(): ConnectionStats;
    getDetailedStats(): any;
    cleanup(): void;
}
export default WebSocketConnectionPool;
export { ConnectionInfo, ConnectionStats, NotificationDedup };
//# sourceMappingURL=websocketConnectionPool.d.ts.map