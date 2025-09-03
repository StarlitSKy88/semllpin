import websocketServiceInstance from './websocketService';
export declare const setWebSocketService: (service: typeof websocketServiceInstance) => void;
export declare const getWebSocketService: () => typeof websocketServiceInstance | null;
export declare const sendRealtimeNotification: (userId: string, notification: {
    type: string;
    title: string;
    message: string;
    data?: any;
    priority?: "low" | "medium" | "high";
    deduplicate?: boolean;
}) => Promise<boolean>;
export declare const sendRealtimeNotificationToUsers: (userIds: string[], notification: any) => Promise<{
    total: number;
    online: number;
    offline: number;
}>;
export declare const sendBatchNotifications: (notifications: Array<{
    userId: string;
    notification: {
        type: string;
        title: string;
        message: string;
        data?: any;
        priority?: "low" | "medium" | "high";
        deduplicate?: boolean;
    };
    options?: any;
}>) => Promise<{
    sent: number;
    failed: number;
}>;
export declare const broadcastSystemNotification: (notification: any) => Promise<boolean>;
export declare const broadcastSystemNotificationWithLocation: (notification: {
    type: string;
    title: string;
    message: string;
    data?: any;
    location?: {
        latitude: number;
        longitude: number;
        radius?: number;
    };
}) => number;
export declare const isUserOnline: (_userId: string) => boolean;
export declare const getOnlineUserCount: () => number;
export declare const getConnectionStats: () => any;
export declare const getDetailedStats: () => any;
//# sourceMappingURL=websocketManager.d.ts.map