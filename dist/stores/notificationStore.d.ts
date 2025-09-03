import { type RewardNotification, type GeofenceNotification, type AchievementNotification } from '../services/websocketService';
interface Notification {
    id: string;
    type: 'reward' | 'geofence' | 'achievement' | 'system';
    title: string;
    message: string;
    data?: any;
    timestamp: string;
    read: boolean;
    persistent: boolean;
}
interface NotificationSettings {
    enabled: boolean;
    sound: boolean;
    vibration: boolean;
    browserNotifications: boolean;
    rewardNotifications: boolean;
    geofenceNotifications: boolean;
    achievementNotifications: boolean;
    systemNotifications: boolean;
}
interface NotificationStore {
    notifications: Notification[];
    unreadCount: number;
    isConnected: boolean;
    connectionState: string;
    settings: NotificationSettings;
    addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => void;
    markAsRead: (id: string) => void;
    markAllAsRead: () => void;
    removeNotification: (id: string) => void;
    clearAllNotifications: () => void;
    updateSettings: (settings: Partial<NotificationSettings>) => void;
    connectWebSocket: (token: string) => Promise<void>;
    disconnectWebSocket: () => void;
    updateConnectionState: (state: string, connected: boolean) => void;
    handleRewardNotification: (data: RewardNotification) => void;
    handleGeofenceNotification: (data: GeofenceNotification) => void;
    handleAchievementNotification: (data: AchievementNotification) => void;
    handleSystemMessage: (data: any) => void;
}
declare const useNotificationStore: import("zustand").UseBoundStore<Omit<import("zustand").StoreApi<NotificationStore>, "setState" | "persist"> & {
    setState(partial: NotificationStore | Partial<NotificationStore> | ((state: NotificationStore) => NotificationStore | Partial<NotificationStore>), replace?: false | undefined): unknown;
    setState(state: NotificationStore | ((state: NotificationStore) => NotificationStore), replace: true): unknown;
    persist: {
        setOptions: (options: Partial<import("zustand/middleware").PersistOptions<NotificationStore, {
            settings: any;
            notifications: any;
        }, unknown>>) => void;
        clearStorage: () => void;
        rehydrate: () => Promise<void> | void;
        hasHydrated: () => boolean;
        onHydrate: (fn: (state: NotificationStore) => void) => () => void;
        onFinishHydration: (fn: (state: NotificationStore) => void) => () => void;
        getOptions: () => Partial<import("zustand/middleware").PersistOptions<NotificationStore, {
            settings: any;
            notifications: any;
        }, unknown>>;
    };
}>;
export declare function requestNotificationPermission(): Promise<boolean>;
export declare function getNotificationPermission(): string;
export default useNotificationStore;
export type { Notification, NotificationSettings };
//# sourceMappingURL=notificationStore.d.ts.map