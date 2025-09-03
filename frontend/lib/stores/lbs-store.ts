import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import { lbsService, Coordinates, NearbyAnnotation, RewardClaim, LocationCheckResult, GeofenceRegion } from '../services/lbs-service';

interface LBSState {
  // 位置状态
  currentLocation: Coordinates | null;
  isLocationLoading: boolean;
  isWatchingLocation: boolean;
  locationError: string | null;
  locationPermission: 'granted' | 'denied' | 'prompt' | 'unknown';
  
  // 附近标注
  nearbyAnnotations: NearbyAnnotation[];
  isLoadingNearby: boolean;
  nearbyError: string | null;
  searchRadius: number;
  
  // 奖励相关
  rewardHistory: RewardClaim[];
  isLoadingRewards: boolean;
  rewardError: string | null;
  totalEarnings: number;
  
  // 地理围栏
  activeRegions: GeofenceRegion[];
  locationChecks: LocationCheckResult[];
  
  // 通知权限
  notificationPermission: boolean;
  
  // Actions
  getCurrentLocation: () => Promise<void>;
  startLocationWatch: () => Promise<void>;
  stopLocationWatch: () => void;
  loadNearbyAnnotations: (radius?: number) => Promise<void>;
  claimReward: (annotationId: string) => Promise<void>;
  loadRewardHistory: () => Promise<void>;
  checkLocationInRegions: (location: Coordinates) => void;
  requestNotificationPermission: () => Promise<void>;
  setSearchRadius: (radius: number) => void;
  clearLocationError: () => void;
  clearNearbyError: () => void;
  clearRewardError: () => void;
  reset: () => void;
}

const initialState = {
  currentLocation: null,
  isLocationLoading: false,
  isWatchingLocation: false,
  locationError: null,
  locationPermission: 'unknown' as const,
  nearbyAnnotations: [],
  isLoadingNearby: false,
  nearbyError: null,
  searchRadius: 1000, // 默认1公里
  rewardHistory: [],
  isLoadingRewards: false,
  rewardError: null,
  totalEarnings: 0,
  activeRegions: [],
  locationChecks: [],
  notificationPermission: false,
};

export const useLBSStore = create<LBSState>()(devtools(
  (set, get) => ({
    ...initialState,

    getCurrentLocation: async () => {
      set({ isLocationLoading: true, locationError: null });
      
      try {
        const location = await lbsService.getCurrentLocation();
        set({ 
          currentLocation: location, 
          isLocationLoading: false,
          locationPermission: 'granted'
        });
        
        // 自动检查附近标注
        get().loadNearbyAnnotations();
        
        // 检查地理围栏
        get().checkLocationInRegions(location);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '获取位置失败';
        set({ 
          locationError: errorMessage, 
          isLocationLoading: false,
          locationPermission: errorMessage.includes('denied') ? 'denied' : 'unknown'
        });
      }
    },

    startLocationWatch: async () => {
      if (get().isWatchingLocation) {
        return;
      }
      
      set({ isLocationLoading: true, locationError: null });
      
      try {
        await lbsService.startWatchingLocation();
        set({ 
          isWatchingLocation: true, 
          isLocationLoading: false,
          locationPermission: 'granted'
        });
        
        // 设置位置更新监听
        const checkInterval = setInterval(() => {
          const cachedLocation = lbsService.getCurrentLocationCached();
          if (cachedLocation) {
            const currentLocation = get().currentLocation;
            if (!currentLocation || 
                Math.abs(cachedLocation.latitude - currentLocation.latitude) > 0.0001 ||
                Math.abs(cachedLocation.longitude - currentLocation.longitude) > 0.0001) {
              set({ currentLocation: cachedLocation });
              get().checkLocationInRegions(cachedLocation);
            }
          }
        }, 5000); // 每5秒检查一次
        
        // 存储interval ID以便后续清理
        (window as any).lbsCheckInterval = checkInterval;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '开始位置监听失败';
        set({ 
          locationError: errorMessage, 
          isLocationLoading: false,
          locationPermission: errorMessage.includes('denied') ? 'denied' : 'unknown'
        });
      }
    },

    stopLocationWatch: () => {
      lbsService.stopWatchingLocation();
      set({ isWatchingLocation: false });
      
      // 清理定时器
      if ((window as any).lbsCheckInterval) {
        clearInterval((window as any).lbsCheckInterval);
        delete (window as any).lbsCheckInterval;
      }
    },

    loadNearbyAnnotations: async (radius?: number) => {
      const { currentLocation, searchRadius } = get();
      if (!currentLocation) {
        set({ nearbyError: '请先获取当前位置' });
        return;
      }
      
      const effectiveRadius = radius || searchRadius;
      set({ isLoadingNearby: true, nearbyError: null });
      
      try {
        const annotations = await lbsService.getNearbyAnnotations(currentLocation, effectiveRadius);
        set({ 
          nearbyAnnotations: annotations, 
          isLoadingNearby: false,
          searchRadius: effectiveRadius
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '加载附近标注失败';
        set({ nearbyError: errorMessage, isLoadingNearby: false });
      }
    },

    claimReward: async (annotationId: string) => {
      const { currentLocation } = get();
      if (!currentLocation) {
        set({ rewardError: '请先获取当前位置' });
        return;
      }
      
      set({ isLoadingRewards: true, rewardError: null });
      
      try {
        const claim = await lbsService.claimReward(annotationId, currentLocation);
        
        // 更新奖励历史
        const { rewardHistory, totalEarnings } = get();
        set({ 
          rewardHistory: [claim, ...rewardHistory],
          totalEarnings: totalEarnings + claim.amount,
          isLoadingRewards: false
        });
        
        // 更新附近标注状态
        const { nearbyAnnotations } = get();
        const updatedAnnotations = nearbyAnnotations.map(ann => 
          ann.id === annotationId 
            ? { ...ann, isDiscovered: true, canClaim: false }
            : ann
        );
        set({ nearbyAnnotations: updatedAnnotations });
        
        // 显示成功通知
        if (get().notificationPermission) {
          new Notification('奖励申请成功！', {
            body: `您已成功申请 ¥${claim.amount} 奖励，正在审核中...`,
            icon: '/icon-192x192.png'
          });
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '申请奖励失败';
        set({ rewardError: errorMessage, isLoadingRewards: false });
      }
    },

    loadRewardHistory: async () => {
      set({ isLoadingRewards: true, rewardError: null });
      
      try {
        const history = await lbsService.getRewardHistory();
        const total = history
          .filter(claim => claim.status === 'approved')
          .reduce((sum, claim) => sum + claim.amount, 0);
        
        set({ 
          rewardHistory: history, 
          totalEarnings: total,
          isLoadingRewards: false 
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : '加载奖励历史失败';
        set({ rewardError: errorMessage, isLoadingRewards: false });
      }
    },

    checkLocationInRegions: (location: Coordinates) => {
      const { activeRegions } = get();
      const checks = activeRegions.map(region => 
        lbsService.checkLocationInRegion(location, region)
      );
      
      set({ locationChecks: checks });
      
      // 检查是否有新的可领取奖励
      const claimableChecks = checks.filter(check => check.canClaimReward);
      if (claimableChecks.length > 0 && get().notificationPermission) {
        claimableChecks.forEach(check => {
          if (check.region) {
            new Notification('发现奖励区域！', {
              body: `您进入了奖励区域，可获得 ¥${check.rewardAmount} 奖励！`,
              icon: '/icon-192x192.png'
            });
          }
        });
      }
    },

    requestNotificationPermission: async () => {
      try {
        const granted = await lbsService.requestNotificationPermission();
        set({ notificationPermission: granted });
      } catch (error) {
        console.error('Failed to request notification permission:', error);
        set({ notificationPermission: false });
      }
    },

    setSearchRadius: (radius: number) => {
      set({ searchRadius: radius });
      // 自动重新加载附近标注
      if (get().currentLocation) {
        get().loadNearbyAnnotations(radius);
      }
    },

    clearLocationError: () => {
      set({ locationError: null });
    },

    clearNearbyError: () => {
      set({ nearbyError: null });
    },

    clearRewardError: () => {
      set({ rewardError: null });
    },

    reset: () => {
      // 停止位置监听
      get().stopLocationWatch();
      
      // 重置状态
      set(initialState);
    },
  }),
  {
    name: 'lbs-store',
  }
));

// 导出选择器函数
export const selectCurrentLocation = (state: LBSState) => state.currentLocation;
export const selectNearbyAnnotations = (state: LBSState) => state.nearbyAnnotations;
export const selectRewardHistory = (state: LBSState) => state.rewardHistory;
export const selectTotalEarnings = (state: LBSState) => state.totalEarnings;
export const selectLocationPermission = (state: LBSState) => state.locationPermission;
export const selectIsLocationLoading = (state: LBSState) => state.isLocationLoading;
export const selectLocationError = (state: LBSState) => state.locationError;