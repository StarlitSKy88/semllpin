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
declare class WebSocketService {
    private ws;
    private reconnectAttempts;
    private maxReconnectAttempts;
    private reconnectDelay;
    private isConnecting;
    private handlers;
    private heartbeatInterval;
    private connectionPromise;
    connect(token: string): Promise<void>;
    disconnect(): void;
    send(data: any): void;
    subscribeNotifications(notifications?: string[]): void;
    markNotificationRead(notificationId: string): void;
    requestLocationUpdate(): void;
    getOnlineStatus(): void;
    on(event: string, handler: NotificationHandler): void;
    off(event: string, handler: NotificationHandler): void;
    private emit;
    private handleNotification;
    private handleRewardNotification;
    private handleGeofenceNotification;
    private handleAchievementNotification;
    private showBrowserNotification;
    private startHeartbeat;
    private stopHeartbeat;
    private scheduleReconnect;
    get isConnected(): boolean;
    get connectionState(): string;
}
declare const websocketService: WebSocketService;
export default websocketService;
export type { NotificationData, RewardNotification, GeofenceNotification, AchievementNotification, NotificationHandler, };
//# sourceMappingURL=websocketService.d.ts.map