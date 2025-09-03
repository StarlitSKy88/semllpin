/**
 * LBS状态管理
 * 使用Zustand管理LBS相关状态
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// 位置信息接口
interface Location {
  latitude: number;
  longitude: number;
  accuracy: number;
  altitude: number | undefined;
  heading: number | undefined;
  speed: number | undefined;
  timestamp: number;
}

// 地理围栏接口
interface Geofence {
  id: string;
  name: string;
  description?: string;
  latitude: number;
  longitude: number;
  radius: number;
  rewardType: 'discovery' | 'checkin' | 'stay' | 'social';
  baseReward: number;
  isActive: boolean;
  createdBy: string;
  createdAt: string;
  distance?: number; // 距离用户的距离
}

// 奖励记录接口
interface RewardRecord {
  id: string;
  userId: string;
  geofenceId: string;
  geofenceName: string;
  rewardType: 'discovery' | 'checkin' | 'stay' | 'social';
  baseReward: number;
  timeDecay: number;
  firstDiscoveryBonus: number;
  extraReward: number;
  finalPoints: number;
  latitude: number;
  longitude: number;
  timestamp: string;
  metadata?: any;
}

// 位置上报结果接口
interface LocationReportResponse {
  success: boolean;
  rewards?: RewardRecord[];
  geofences?: Geofence[];
  message?: string;
}

// LBS设置接口
interface LBSSettings {
  trackingEnabled: boolean;
  highAccuracy: boolean;
  updateInterval: number; // 秒
  backgroundTracking: boolean;
  autoReportLocation: boolean;
  notificationsEnabled: boolean;
}

// LBS状态接口
interface LBSState {
  // 追踪状态
  isTracking: boolean;
  isOnline: boolean;
  lastReportTime: number | null;

  // 位置信息
  currentLocation: Location | null;
  locationHistory: Location[];

  // 地理围栏
  nearbyGeofences: Geofence[];
  enteredGeofences: string[];

  // 奖励
  recentRewards: RewardRecord[];
  totalRewards: number;
  todayRewards: number;

  // 设置
  settings: LBSSettings;

  // 状态
  isLoading: boolean;
  error: string | null;

  // 权限
  hasLocationPermission: boolean;
  hasNotificationPermission: boolean;
}

// LBS操作接口
interface LBSActions {
  // 追踪控制
  startTracking: () => Promise<void>;
  stopTracking: () => void;
  setTracking: (tracking: boolean) => void;

  // 位置管理
  updateLocation: (location: Location) => void;
  reportLocation: (location: Location) => Promise<LocationReportResponse>;
  clearLocationHistory: () => void;

  // 地理围栏
  fetchNearbyGeofences: (location: Location, radius?: number) => Promise<void>;
  checkGeofenceEntry: (location: Location) => void;

  // 奖励管理
  addReward: (reward: RewardRecord) => void;
  fetchRewardHistory: (limit?: number, offset?: number) => Promise<void>;
  claimReward: (rewardId: string) => Promise<void>;

  // 设置管理
  updateSettings: (settings: Partial<LBSSettings>) => void;

  // 权限管理
  requestLocationPermission: () => Promise<boolean>;
  requestNotificationPermission: () => Promise<boolean>;

  // 状态管理
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setOnlineStatus: (online: boolean) => void;

  // 重置
  reset: () => void;
}

type LBSStore = LBSState & LBSActions;

const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:3001/api';

// 默认设置
const defaultSettings: LBSSettings = {
  trackingEnabled: true,
  highAccuracy: true,
  updateInterval: 30,
  backgroundTracking: false,
  autoReportLocation: true,
  notificationsEnabled: true,
};

export const useLBSStore = create<LBSStore>()(persist(
  (set, get) => ({
    // 初始状态
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

    // 开始追踪
    startTracking: async () => {
      const hasPermission = await get().requestLocationPermission();
      if (!hasPermission) {
        set({ error: '需要位置权限才能开始追踪' });
        return;
      }

      set({ isTracking: true, error: null });

      // 开始位置监听
      if (navigator.geolocation) {
        const options = {
          enableHighAccuracy: get().settings.highAccuracy,
          timeout: 10000,
          maximumAge: 60000,
        };

        navigator.geolocation.watchPosition(
          (position) => {
            const location: Location = {
              latitude: position.coords.latitude,
              longitude: position.coords.longitude,
              accuracy: position.coords.accuracy,
              altitude: position.coords.altitude || undefined,
              heading: position.coords.heading || undefined,
              speed: position.coords.speed || undefined,
              timestamp: Date.now(),
            };

            get().updateLocation(location);

            // 自动上报位置
            if (get().settings.autoReportLocation) {
              get().reportLocation(location);
            }
          },
          (error) => {
            console.error('位置获取失败:', error);
            set({ error: `位置获取失败: ${error.message}` });
          },
          options,
        );
      }
    },

    // 停止追踪
    stopTracking: () => {
      set({ isTracking: false });
    },

    // 设置追踪状态
    setTracking: (tracking: boolean) => {
      set({ isTracking: tracking });
    },

    // 更新位置
    updateLocation: (location: Location) => {
      set((state) => ({
        currentLocation: location,
        locationHistory: [...state.locationHistory.slice(-99), location], // 保留最近100个位置
      }));

      // 检查地理围栏
      get().checkGeofenceEntry(location);
    },

    // 上报位置
    reportLocation: async (location: Location) => {
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

        // 处理奖励
        if (data.data.rewards && data.data.rewards.length > 0) {
          data.data.rewards.forEach((reward: RewardRecord) => {
            get().addReward(reward);
          });
        }

        // 更新附近地理围栏
        if (data.data.geofences) {
          set({ nearbyGeofences: data.data.geofences });
        }

        return { success: true, rewards: data.data.rewards, geofences: data.data.geofences };
      } catch (error: any) {
        console.error('位置上报失败:', error);
        set({ error: error.message || '位置上报失败' });
        return { success: false, message: error.message };
      }
    },

    // 清除位置历史
    clearLocationHistory: () => {
      set({ locationHistory: [] });
    },

    // 获取附近地理围栏
    fetchNearbyGeofences: async (location: Location, radius = 1000) => {
      const token = localStorage.getItem('auth_token');
      if (!token) {
        return;
      }

      set({ isLoading: true });

      try {
        const response = await fetch(
          `${API_BASE_URL}/lbs/geofences/nearby?lat=${location.latitude}&lng=${location.longitude}&radius=${radius}`,
          {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          },
        );

        const data = await response.json();

        if (response.ok) {
          set({ nearbyGeofences: data.data, isLoading: false });
        } else {
          set({ error: data.message || '获取地理围栏失败', isLoading: false });
        }
      } catch (error: any) {
        set({ error: error.message || '获取地理围栏失败', isLoading: false });
      }
    },

    // 检查地理围栏进入
    checkGeofenceEntry: (location: Location) => {
      const { nearbyGeofences, enteredGeofences } = get();
      const newEnteredGeofences: string[] = [];

      nearbyGeofences.forEach((geofence) => {
        const distance = calculateDistance(
          location.latitude,
          location.longitude,
          geofence.latitude,
          geofence.longitude,
        );

        if (distance <= geofence.radius) {
          newEnteredGeofences.push(geofence.id);

          // 如果是新进入的地理围栏，触发通知
          if (!enteredGeofences.includes(geofence.id)) {
            // 这里可以触发通知或其他逻辑
            console.log(`进入地理围栏: ${geofence.name}`);
          }
        }
      });

      set({ enteredGeofences: newEnteredGeofences });
    },

    // 添加奖励
    addReward: (reward: RewardRecord) => {
      set((state) => ({
        recentRewards: [reward, ...state.recentRewards.slice(0, 19)], // 保留最近20个奖励
        totalRewards: state.totalRewards + reward.finalPoints,
        todayRewards: isToday(reward.timestamp)
          ? state.todayRewards + reward.finalPoints
          : state.todayRewards,
      }));
    },

    // 获取奖励历史
    fetchRewardHistory: async (limit = 20, offset = 0) => {
      const token = localStorage.getItem('auth_token');
      if (!token) {
        return;
      }

      set({ isLoading: true });

      try {
        const response = await fetch(
          `${API_BASE_URL}/lbs/rewards/history?limit=${limit}&offset=${offset}`,
          {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          },
        );

        const data = await response.json();

        if (response.ok) {
          if (offset === 0) {
            set({ recentRewards: data.data, isLoading: false });
          } else {
            set((state) => ({
              recentRewards: [...state.recentRewards, ...data.data],
              isLoading: false,
            }));
          }
        } else {
          set({ error: data.message || '获取奖励历史失败', isLoading: false });
        }
      } catch (error: any) {
        set({ error: error.message || '获取奖励历史失败', isLoading: false });
      }
    },

    // 领取奖励
    claimReward: async (rewardId: string) => {
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

        // 更新奖励状态
        set((state) => ({
          recentRewards: state.recentRewards.map((reward) =>
            reward.id === rewardId ? { ...reward, claimed: true } : reward,
          ),
        }));
      } catch (error: any) {
        set({ error: error.message || '领取奖励失败' });
        throw error;
      }
    },

    // 更新设置
    updateSettings: (newSettings: Partial<LBSSettings>) => {
      set((state) => ({
        settings: { ...state.settings, ...newSettings },
      }));
    },

    // 请求位置权限
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
        } else if (permission.state === 'prompt') {
          // 尝试获取位置以触发权限请求
          return new Promise((resolve) => {
            navigator.geolocation.getCurrentPosition(
              () => {
                set({ hasLocationPermission: true });
                resolve(true);
              },
              () => {
                set({ hasLocationPermission: false, error: '位置权限被拒绝' });
                resolve(false);
              },
            );
          });
        } else {
          set({ hasLocationPermission: false, error: '位置权限被拒绝' });
          return false;
        }
      } catch (error) {
        // 降级处理
        return new Promise((resolve) => {
          navigator.geolocation.getCurrentPosition(
            () => {
              set({ hasLocationPermission: true });
              resolve(true);
            },
            () => {
              set({ hasLocationPermission: false, error: '位置权限被拒绝' });
              resolve(false);
            },
          );
        });
      }
    },

    // 请求通知权限
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
      } catch (error) {
        set({ hasNotificationPermission: false, error: '通知权限请求失败' });
        return false;
      }
    },

    // 设置加载状态
    setLoading: (loading: boolean) => {
      set({ isLoading: loading });
    },

    // 设置错误
    setError: (error: string | null) => {
      set({ error });
    },

    // 设置在线状态
    setOnlineStatus: (online: boolean) => {
      set({ isOnline: online });
    },

    // 重置状态
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
  }),
  {
    name: 'lbs-storage',
    partialize: (state) => ({
      settings: state.settings,
      totalRewards: state.totalRewards,
      hasLocationPermission: state.hasLocationPermission,
      hasNotificationPermission: state.hasNotificationPermission,
    }),
  },
));

// 工具函数

// 计算两点间距离（米）
function calculateDistance(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number,
): number {
  const R = 6371e3; // 地球半径（米）
  const φ1 = (lat1 * Math.PI) / 180;
  const φ2 = (lat2 * Math.PI) / 180;
  const Δφ = ((lat2 - lat1) * Math.PI) / 180;
  const Δλ = ((lng2 - lng1) * Math.PI) / 180;

  const a =
    Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

// 检查是否是今天
function isToday(timestamp: string): boolean {
  const today = new Date();
  const date = new Date(timestamp);
  return (
    date.getDate() === today.getDate() &&
    date.getMonth() === today.getMonth() &&
    date.getFullYear() === today.getFullYear()
  );
}

export default useLBSStore;
export type { Location, Geofence, RewardRecord, LBSSettings };
