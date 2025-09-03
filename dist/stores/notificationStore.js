"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requestNotificationPermission = requestNotificationPermission;
exports.getNotificationPermission = getNotificationPermission;
const zustand_1 = require("zustand");
const middleware_1 = require("zustand/middleware");
const websocketService_1 = __importDefault(require("../services/websocketService"));
const defaultSettings = {
    enabled: true,
    sound: true,
    vibration: true,
    browserNotifications: true,
    rewardNotifications: true,
    geofenceNotifications: true,
    achievementNotifications: true,
    systemNotifications: true,
};
const useNotificationStore = (0, zustand_1.create)()((0, middleware_1.persist)((set, get) => ({
    notifications: [],
    unreadCount: 0,
    isConnected: false,
    connectionState: 'disconnected',
    settings: defaultSettings,
    addNotification: (notification) => {
        const newNotification = {
            ...notification,
            id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date().toISOString(),
        };
        set((state) => {
            const notifications = [newNotification, ...state.notifications];
            const limitedNotifications = notifications.slice(0, 100);
            return {
                notifications: limitedNotifications,
                unreadCount: state.unreadCount + (newNotification.read ? 0 : 1),
            };
        });
        if (get().settings.sound && get().settings.enabled) {
            playNotificationSound(notification.type);
        }
        if (get().settings.vibration && get().settings.enabled && 'vibrate' in navigator) {
            navigator.vibrate([200, 100, 200]);
        }
    },
    markAsRead: (id) => {
        set((state) => {
            const notifications = state.notifications.map((notification) => {
                if (notification.id === id && !notification.read) {
                    websocketService_1.default.markNotificationRead(id);
                    return { ...notification, read: true };
                }
                return notification;
            });
            const unreadCount = notifications.filter((n) => !n.read).length;
            return { notifications, unreadCount };
        });
    },
    markAllAsRead: () => {
        set((state) => {
            const notifications = state.notifications.map((notification) => {
                if (!notification.read) {
                    websocketService_1.default.markNotificationRead(notification.id);
                }
                return { ...notification, read: true };
            });
            return { notifications, unreadCount: 0 };
        });
    },
    removeNotification: (id) => {
        set((state) => {
            const notification = state.notifications.find((n) => n.id === id);
            const notifications = state.notifications.filter((n) => n.id !== id);
            const unreadCount = notification && !notification.read
                ? state.unreadCount - 1
                : state.unreadCount;
            return { notifications, unreadCount };
        });
    },
    clearAllNotifications: () => {
        set({ notifications: [], unreadCount: 0 });
    },
    updateSettings: (newSettings) => {
        set((state) => ({
            settings: { ...state.settings, ...newSettings },
        }));
    },
    connectWebSocket: async (token) => {
        try {
            await websocketService_1.default.connect(token);
            websocketService_1.default.on('connected', () => {
                get().updateConnectionState('connected', true);
            });
            websocketService_1.default.on('connection_closed', () => {
                get().updateConnectionState('disconnected', false);
            });
            websocketService_1.default.on('connection_error', () => {
                get().updateConnectionState('error', false);
            });
            websocketService_1.default.on('reward_earned', (data) => {
                if (get().settings.rewardNotifications) {
                    get().handleRewardNotification(data);
                }
            });
            websocketService_1.default.on('geofence_entered', (data) => {
                if (get().settings.geofenceNotifications) {
                    get().handleGeofenceNotification(data);
                }
            });
            websocketService_1.default.on('achievement_unlocked', (data) => {
                if (get().settings.achievementNotifications) {
                    get().handleAchievementNotification(data);
                }
            });
            websocketService_1.default.on('system_message', (data) => {
                if (get().settings.systemNotifications) {
                    get().handleSystemMessage(data);
                }
            });
            websocketService_1.default.subscribeNotifications();
        }
        catch (error) {
            console.error('WebSocket连接失败:', error);
            get().updateConnectionState('error', false);
            throw error;
        }
    },
    disconnectWebSocket: () => {
        websocketService_1.default.disconnect();
        set({ isConnected: false, connectionState: 'disconnected' });
    },
    updateConnectionState: (state, connected) => {
        set({ connectionState: state, isConnected: connected });
    },
    handleRewardNotification: (data) => {
        get().addNotification({
            type: 'reward',
            title: '🎉 获得奖励！',
            message: `在${data.geofenceName}获得${data.amount}积分`,
            data,
            read: false,
            persistent: true,
        });
    },
    handleGeofenceNotification: (data) => {
        get().addNotification({
            type: 'geofence',
            title: '📍 发现新地点！',
            message: `进入${data.name}，可获得${data.potentialReward}积分`,
            data,
            read: false,
            persistent: false,
        });
    },
    handleAchievementNotification: (data) => {
        get().addNotification({
            type: 'achievement',
            title: '🏆 成就解锁！',
            message: `解锁成就：${data.name}`,
            data,
            read: false,
            persistent: true,
        });
    },
    handleSystemMessage: (data) => {
        get().addNotification({
            type: 'system',
            title: '系统消息',
            message: data.message,
            data,
            read: false,
            persistent: false,
        });
    },
}), {
    name: 'notification-store',
    partialize: (state) => ({
        settings: state.settings,
        notifications: state.notifications.filter((n) => n.persistent),
    }),
}));
function playNotificationSound(type) {
    try {
        const audio = new Audio();
        switch (type) {
            case 'reward':
                audio.src = '/sounds/reward.mp3';
                break;
            case 'achievement':
                audio.src = '/sounds/achievement.mp3';
                break;
            case 'geofence':
                audio.src = '/sounds/geofence.mp3';
                break;
            default:
                audio.src = '/sounds/notification.mp3';
        }
        audio.volume = 0.5;
        audio.play().catch(error => {
            console.log('播放通知音效失败:', error);
        });
    }
    catch (error) {
        console.log('创建音频对象失败:', error);
    }
}
async function requestNotificationPermission() {
    if ('Notification' in window) {
        if (Notification.permission === 'granted') {
            return true;
        }
        else if (Notification.permission !== 'denied') {
            const permission = await Notification.requestPermission();
            return permission === 'granted';
        }
    }
    return false;
}
function getNotificationPermission() {
    if ('Notification' in window) {
        return Notification.permission;
    }
    return 'unsupported';
}
exports.default = useNotificationStore;
//# sourceMappingURL=notificationStore.js.map