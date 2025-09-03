"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useLBSStore = void 0;
const zustand_1 = require("zustand");
const middleware_1 = require("zustand/middleware");
const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:3001/api';
const defaultSettings = {
    trackingEnabled: true,
    highAccuracy: true,
    updateInterval: 30,
    backgroundTracking: false,
    autoReportLocation: true,
    notificationsEnabled: true,
};
exports.useLBSStore = (0, zustand_1.create)()((0, middleware_1.persist)((set, get) => ({
    isTracking: false,
    isOnline: navigator.onLine,
    lastReportTime: null,
    currentLocation: null,
    locationHistory: [],
    nearbyGeofences: [],
    enteredGeofences: [],
    recentRewards: [],
    totalRewards: 0,
    todayRewards: 0,
    settings: defaultSettings,
    isLoading: false,
    error: null,
    hasLocationPermission: false,
    hasNotificationPermission: false,
    startTracking: async () => {
        const hasPermission = await get().requestLocationPermission();
        if (!hasPermission) {
            set({ error: '需要位置权限才能开始追踪' });
            return;
        }
        set({ isTracking: true, error: null });
        if (navigator.geolocation) {
            const options = {
                enableHighAccuracy: get().settings.highAccuracy,
                timeout: 10000,
                maximumAge: 60000,
            };
            navigator.geolocation.watchPosition((position) => {
                const location = {
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude,
                    accuracy: position.coords.accuracy,
                    altitude: position.coords.altitude || undefined,
                    heading: position.coords.heading || undefined,
                    speed: position.coords.speed || undefined,
                    timestamp: Date.now(),
                };
                get().updateLocation(location);
                if (get().settings.autoReportLocation) {
                    get().reportLocation(location);
                }
            }, (error) => {
                console.error('位置获取失败:', error);
                set({ error: `位置获取失败: ${error.message}` });
            }, options);
        }
    },
    stopTracking: () => {
        set({ isTracking: false });
    },
    setTracking: (tracking) => {
        set({ isTracking: tracking });
    },
    updateLocation: (location) => {
        set((state) => ({
            currentLocation: location,
            locationHistory: [...state.locationHistory.slice(-99), location],
        }));
        get().checkGeofenceEntry(location);
    },
    reportLocation: async (location) => {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            set({ error: '未登录，无法上报位置' });
            return { success: false, message: '未登录' };
        }
        try {
            const response = await fetch(`${API_BASE_URL}/lbs/location/report`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                },
                body: JSON.stringify({
                    latitude: location.latitude,
                    longitude: location.longitude,
                    accuracy: location.accuracy,
                    timestamp: new Date(location.timestamp).toISOString(),
                }),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || '位置上报失败');
            }
            set({ lastReportTime: Date.now(), error: null });
            if (data.data.rewards && data.data.rewards.length > 0) {
                data.data.rewards.forEach((reward) => {
                    get().addReward(reward);
                });
            }
            if (data.data.geofences) {
                set({ nearbyGeofences: data.data.geofences });
            }
            return { success: true, rewards: data.data.rewards, geofences: data.data.geofences };
        }
        catch (error) {
            console.error('位置上报失败:', error);
            set({ error: error.message || '位置上报失败' });
            return { success: false, message: error.message };
        }
    },
    clearLocationHistory: () => {
        set({ locationHistory: [] });
    },
    fetchNearbyGeofences: async (location, radius = 1000) => {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            return;
        }
        set({ isLoading: true });
        try {
            const response = await fetch(`${API_BASE_URL}/lbs/geofences/nearby?lat=${location.latitude}&lng=${location.longitude}&radius=${radius}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            const data = await response.json();
            if (response.ok) {
                set({ nearbyGeofences: data.data, isLoading: false });
            }
            else {
                set({ error: data.message || '获取地理围栏失败', isLoading: false });
            }
        }
        catch (error) {
            set({ error: error.message || '获取地理围栏失败', isLoading: false });
        }
    },
    checkGeofenceEntry: (location) => {
        const { nearbyGeofences, enteredGeofences } = get();
        const newEnteredGeofences = [];
        nearbyGeofences.forEach((geofence) => {
            const distance = calculateDistance(location.latitude, location.longitude, geofence.latitude, geofence.longitude);
            if (distance <= geofence.radius) {
                newEnteredGeofences.push(geofence.id);
                if (!enteredGeofences.includes(geofence.id)) {
                    console.log(`进入地理围栏: ${geofence.name}`);
                }
            }
        });
        set({ enteredGeofences: newEnteredGeofences });
    },
    addReward: (reward) => {
        set((state) => ({
            recentRewards: [reward, ...state.recentRewards.slice(0, 19)],
            totalRewards: state.totalRewards + reward.finalPoints,
            todayRewards: isToday(reward.timestamp)
                ? state.todayRewards + reward.finalPoints
                : state.todayRewards,
        }));
    },
    fetchRewardHistory: async (limit = 20, offset = 0) => {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            return;
        }
        set({ isLoading: true });
        try {
            const response = await fetch(`${API_BASE_URL}/lbs/rewards/history?limit=${limit}&offset=${offset}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            const data = await response.json();
            if (response.ok) {
                if (offset === 0) {
                    set({ recentRewards: data.data, isLoading: false });
                }
                else {
                    set((state) => ({
                        recentRewards: [...state.recentRewards, ...data.data],
                        isLoading: false,
                    }));
                }
            }
            else {
                set({ error: data.message || '获取奖励历史失败', isLoading: false });
            }
        }
        catch (error) {
            set({ error: error.message || '获取奖励历史失败', isLoading: false });
        }
    },
    claimReward: async (rewardId) => {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            return;
        }
        try {
            const response = await fetch(`${API_BASE_URL}/lbs/rewards/${rewardId}/claim`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || '领取奖励失败');
            }
            set((state) => ({
                recentRewards: state.recentRewards.map((reward) => reward.id === rewardId ? { ...reward, claimed: true } : reward),
            }));
        }
        catch (error) {
            set({ error: error.message || '领取奖励失败' });
            throw error;
        }
    },
    updateSettings: (newSettings) => {
        set((state) => ({
            settings: { ...state.settings, ...newSettings },
        }));
    },
    requestLocationPermission: async () => {
        if (!navigator.geolocation) {
            set({ error: '浏览器不支持地理位置' });
            return false;
        }
        try {
            const permission = await navigator.permissions.query({ name: 'geolocation' });
            if (permission.state === 'granted') {
                set({ hasLocationPermission: true });
                return true;
            }
            else if (permission.state === 'prompt') {
                return new Promise((resolve) => {
                    navigator.geolocation.getCurrentPosition(() => {
                        set({ hasLocationPermission: true });
                        resolve(true);
                    }, () => {
                        set({ hasLocationPermission: false, error: '位置权限被拒绝' });
                        resolve(false);
                    });
                });
            }
            else {
                set({ hasLocationPermission: false, error: '位置权限被拒绝' });
                return false;
            }
        }
        catch (error) {
            return new Promise((resolve) => {
                navigator.geolocation.getCurrentPosition(() => {
                    set({ hasLocationPermission: true });
                    resolve(true);
                }, () => {
                    set({ hasLocationPermission: false, error: '位置权限被拒绝' });
                    resolve(false);
                });
            });
        }
    },
    requestNotificationPermission: async () => {
        if (!('Notification' in window)) {
            set({ error: '浏览器不支持通知' });
            return false;
        }
        try {
            const permission = await Notification.requestPermission();
            const granted = permission === 'granted';
            set({ hasNotificationPermission: granted });
            return granted;
        }
        catch (error) {
            set({ hasNotificationPermission: false, error: '通知权限请求失败' });
            return false;
        }
    },
    setLoading: (loading) => {
        set({ isLoading: loading });
    },
    setError: (error) => {
        set({ error });
    },
    setOnlineStatus: (online) => {
        set({ isOnline: online });
    },
    reset: () => {
        set({
            isTracking: false,
            currentLocation: null,
            locationHistory: [],
            nearbyGeofences: [],
            enteredGeofences: [],
            recentRewards: [],
            totalRewards: 0,
            todayRewards: 0,
            isLoading: false,
            error: null,
            lastReportTime: null,
        });
    },
}), {
    name: 'lbs-storage',
    partialize: (state) => ({
        settings: state.settings,
        totalRewards: state.totalRewards,
        hasLocationPermission: state.hasLocationPermission,
        hasNotificationPermission: state.hasNotificationPermission,
    }),
}));
function calculateDistance(lat1, lng1, lat2, lng2) {
    const R = 6371e3;
    const φ1 = (lat1 * Math.PI) / 180;
    const φ2 = (lat2 * Math.PI) / 180;
    const Δφ = ((lat2 - lat1) * Math.PI) / 180;
    const Δλ = ((lng2 - lng1) * Math.PI) / 180;
    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
        Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}
function isToday(timestamp) {
    const today = new Date();
    const date = new Date(timestamp);
    return (date.getDate() === today.getDate() &&
        date.getMonth() === today.getMonth() &&
        date.getFullYear() === today.getFullYear());
}
exports.default = exports.useLBSStore;
//# sourceMappingURL=lbsStore.js.map