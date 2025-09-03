import { apiClient } from './api';

// 地理位置相关接口
export interface Coordinates {
  latitude: number;
  longitude: number;
  accuracy?: number;
  altitude?: number;
  altitudeAccuracy?: number;
  heading?: number;
  speed?: number;
}

export interface GeofenceRegion {
  id: string;
  center: Coordinates;
  radius: number; // 米
  annotationId: string;
  rewardAmount: number;
  isActive: boolean;
  createdAt: string;
}

export interface LocationCheckResult {
  isInside: boolean;
  distance: number; // 距离中心点的距离（米）
  region?: GeofenceRegion;
  canClaimReward: boolean;
  rewardAmount?: number;
}

export interface RewardClaim {
  id: string;
  userId: string;
  annotationId: string;
  regionId: string;
  amount: number;
  claimedAt: string;
  location: Coordinates;
  status: 'pending' | 'approved' | 'rejected';
}

export interface NearbyAnnotation {
  id: string;
  title: string;
  description: string;
  location: Coordinates;
  distance: number; // 米
  rewardAmount: number;
  isDiscovered: boolean;
  canClaim: boolean;
}

export interface LocationHistory {
  id: string;
  location: Coordinates;
  timestamp: string;
  accuracy: number;
  source: 'gps' | 'network' | 'passive';
}

class LBSService {
  private watchId: number | null = null;
  private currentLocation: Coordinates | null = null;
  private locationHistory: LocationHistory[] = [];
  private geofenceRegions: GeofenceRegion[] = [];
  private isWatching = false;

  // 获取当前位置
  async getCurrentLocation(options?: PositionOptions): Promise<Coordinates> {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('Geolocation is not supported by this browser'));
        return;
      }

      const defaultOptions: PositionOptions = {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 60000, // 1分钟缓存
        ...options
      };

      navigator.geolocation.getCurrentPosition(
        (position) => {
          const coords: Coordinates = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            altitude: position.coords.altitude || undefined,
            altitudeAccuracy: position.coords.altitudeAccuracy || undefined,
            heading: position.coords.heading || undefined,
            speed: position.coords.speed || undefined
          };
          
          this.currentLocation = coords;
          this.addLocationToHistory(coords, 'gps');
          resolve(coords);
        },
        (error) => {
          reject(new Error(`Location error: ${error.message}`));
        },
        defaultOptions
      );
    });
  }

  // 开始监听位置变化
  startWatchingLocation(options?: PositionOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('Geolocation is not supported'));
        return;
      }

      if (this.isWatching) {
        resolve();
        return;
      }

      const defaultOptions: PositionOptions = {
        enableHighAccuracy: true,
        timeout: 5000,
        maximumAge: 30000, // 30秒缓存
        ...options
      };

      this.watchId = navigator.geolocation.watchPosition(
        (position) => {
          const coords: Coordinates = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            altitude: position.coords.altitude || undefined,
            altitudeAccuracy: position.coords.altitudeAccuracy || undefined,
            heading: position.coords.heading || undefined,
            speed: position.coords.speed || undefined
          };
          
          this.currentLocation = coords;
          this.addLocationToHistory(coords, 'gps');
          this.checkGeofences(coords);
          
          if (!this.isWatching) {
            this.isWatching = true;
            resolve();
          }
        },
        (error) => {
          console.error('Location watch error:', error);
          if (!this.isWatching) {
            reject(new Error(`Location watch error: ${error.message}`));
          }
        },
        defaultOptions
      );
    });
  }

  // 停止监听位置变化
  stopWatchingLocation(): void {
    if (this.watchId !== null) {
      navigator.geolocation.clearWatch(this.watchId);
      this.watchId = null;
      this.isWatching = false;
    }
  }

  // 计算两点之间的距离（米）
  calculateDistance(coord1: Coordinates, coord2: Coordinates): number {
    const R = 6371e3; // 地球半径（米）
    const φ1 = coord1.latitude * Math.PI / 180;
    const φ2 = coord2.latitude * Math.PI / 180;
    const Δφ = (coord2.latitude - coord1.latitude) * Math.PI / 180;
    const Δλ = (coord2.longitude - coord1.longitude) * Math.PI / 180;

    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

    return R * c;
  }

  // 检查是否在地理围栏内
  checkLocationInRegion(location: Coordinates, region: GeofenceRegion): LocationCheckResult {
    const distance = this.calculateDistance(location, region.center);
    const isInside = distance <= region.radius;
    
    return {
      isInside,
      distance,
      region,
      canClaimReward: isInside && region.isActive,
      rewardAmount: isInside ? region.rewardAmount : undefined
    };
  }

  // 获取附近的标注
  async getNearbyAnnotations(location: Coordinates, radius: number = 1000): Promise<NearbyAnnotation[]> {
    try {
      // 模拟API调用
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // 模拟数据
      const mockAnnotations: NearbyAnnotation[] = [
        {
          id: 'ann_1',
          title: '臭豆腐摊位',
          description: '这里有最正宗的臭豆腐！',
          location: {
            latitude: location.latitude + 0.001,
            longitude: location.longitude + 0.001
          },
          distance: 150,
          rewardAmount: 5,
          isDiscovered: false,
          canClaim: true
        },
        {
          id: 'ann_2',
          title: '垃圾处理站',
          description: '注意异味区域',
          location: {
            latitude: location.latitude - 0.002,
            longitude: location.longitude + 0.0015
          },
          distance: 280,
          rewardAmount: 10,
          isDiscovered: true,
          canClaim: false
        },
        {
          id: 'ann_3',
          title: '榴莲店',
          description: '爱它或恨它的味道',
          location: {
            latitude: location.latitude + 0.003,
            longitude: location.longitude - 0.001
          },
          distance: 420,
          rewardAmount: 8,
          isDiscovered: false,
          canClaim: true
        }
      ];
      
      return mockAnnotations.filter(ann => ann.distance <= radius);
    } catch (error) {
      console.error('Failed to get nearby annotations:', error);
      return [];
    }
  }

  // 声明发现标注并申请奖励
  async claimReward(annotationId: string, location: Coordinates): Promise<RewardClaim> {
    try {
      // 模拟API调用
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const claim: RewardClaim = {
        id: `claim_${Date.now()}`,
        userId: 'user_123',
        annotationId,
        regionId: `region_${annotationId}`,
        amount: Math.floor(Math.random() * 20) + 5, // 5-25元随机奖励
        claimedAt: new Date().toISOString(),
        location,
        status: 'pending'
      };
      
      return claim;
    } catch (error) {
      console.error('Failed to claim reward:', error);
      throw error;
    }
  }

  // 获取奖励历史
  async getRewardHistory(): Promise<RewardClaim[]> {
    try {
      // 模拟API调用
      await new Promise(resolve => setTimeout(resolve, 300));
      
      const mockHistory: RewardClaim[] = [
        {
          id: 'claim_1',
          userId: 'user_123',
          annotationId: 'ann_1',
          regionId: 'region_ann_1',
          amount: 15,
          claimedAt: new Date(Date.now() - 86400000).toISOString(), // 1天前
          location: { latitude: 39.9042, longitude: 116.4074 },
          status: 'approved'
        },
        {
          id: 'claim_2',
          userId: 'user_123',
          annotationId: 'ann_2',
          regionId: 'region_ann_2',
          amount: 8,
          claimedAt: new Date(Date.now() - 172800000).toISOString(), // 2天前
          location: { latitude: 39.9052, longitude: 116.4084 },
          status: 'approved'
        }
      ];
      
      return mockHistory;
    } catch (error) {
      console.error('Failed to get reward history:', error);
      return [];
    }
  }

  // 验证位置准确性
  validateLocationAccuracy(location: Coordinates): boolean {
    // 检查精度是否足够（小于50米）
    if (location.accuracy && location.accuracy > 50) {
      return false;
    }
    
    // 检查坐标是否合理
    if (Math.abs(location.latitude) > 90 || Math.abs(location.longitude) > 180) {
      return false;
    }
    
    return true;
  }

  // 检测位置是否可疑（防作弊）
  detectSuspiciousLocation(location: Coordinates): boolean {
    const history = this.locationHistory.slice(-10); // 最近10个位置
    
    if (history.length < 2) {
      return false;
    }
    
    // 检查是否移动过快（超过100km/h）
    const lastLocation = history[history.length - 1];
    const prevLocation = history[history.length - 2];
    
    const distance = this.calculateDistance(prevLocation.location, lastLocation.location);
    const timeDiff = (new Date(lastLocation.timestamp).getTime() - new Date(prevLocation.timestamp).getTime()) / 1000; // 秒
    const speed = distance / timeDiff; // 米/秒
    const speedKmh = speed * 3.6; // 公里/小时
    
    if (speedKmh > 100) {
      console.warn('Suspicious location: too fast movement', { speedKmh, distance, timeDiff });
      return true;
    }
    
    return false;
  }

  // 添加位置到历史记录
  private addLocationToHistory(location: Coordinates, source: 'gps' | 'network' | 'passive'): void {
    const historyItem: LocationHistory = {
      id: `loc_${Date.now()}`,
      location,
      timestamp: new Date().toISOString(),
      accuracy: location.accuracy || 0,
      source
    };
    
    this.locationHistory.push(historyItem);
    
    // 只保留最近100个位置记录
    if (this.locationHistory.length > 100) {
      this.locationHistory = this.locationHistory.slice(-100);
    }
  }

  // 检查所有地理围栏
  private checkGeofences(location: Coordinates): void {
    this.geofenceRegions.forEach(region => {
      const result = this.checkLocationInRegion(location, region);
      if (result.isInside && result.canClaimReward) {
        // 触发地理围栏事件
        this.onGeofenceEnter(region, location);
      }
    });
  }

  // 地理围栏进入事件
  private onGeofenceEnter(region: GeofenceRegion, location: Coordinates): void {
    console.log('Entered geofence:', region.id, 'at location:', location);
    
    // 这里可以触发奖励通知或其他逻辑
    if (typeof window !== 'undefined' && 'Notification' in window) {
      if (Notification.permission === 'granted') {
        new Notification('发现奖励！', {
          body: `您进入了奖励区域，可获得 ¥${region.rewardAmount} 奖励！`,
          icon: '/icon-192x192.png'
        });
      }
    }
  }

  // 获取当前位置（缓存版本）
  getCurrentLocationCached(): Coordinates | null {
    return this.currentLocation;
  }

  // 获取位置历史
  getLocationHistory(): LocationHistory[] {
    return [...this.locationHistory];
  }

  // 清除位置历史
  clearLocationHistory(): void {
    this.locationHistory = [];
  }

  // 请求通知权限
  async requestNotificationPermission(): Promise<boolean> {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      return false;
    }
    
    if (Notification.permission === 'granted') {
      return true;
    }
    
    if (Notification.permission === 'denied') {
      return false;
    }
    
    const permission = await Notification.requestPermission();
    return permission === 'granted';
  }

  // 格式化距离显示
  formatDistance(meters: number): string {
    if (meters < 1000) {
      return `${Math.round(meters)}m`;
    } else {
      return `${(meters / 1000).toFixed(1)}km`;
    }
  }

  // 格式化位置显示
  formatCoordinates(coords: Coordinates): string {
    return `${coords.latitude.toFixed(6)}, ${coords.longitude.toFixed(6)}`;
  }
}

export const lbsService = new LBSService();
export default lbsService;