/**
 * 优化版LBS奖励追踪器组件
 * 解决超时问题，提升性能和稳定性
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { MapPin, Award, Clock, AlertTriangle, Wifi, WifiOff, Radar } from 'lucide-react';
import useNotificationStore from '../../stores/notificationStore';
import NotificationButton from '../Notifications/NotificationButton';
import { useAuthStore } from '../../stores/authStore';
import { useLBSStore, type Location } from '../../stores/lbsStore';
import RewardNotification from './RewardNotification';
import GeofenceMap from './GeofenceMap';
import AdvancedLBSComponents from './AdvancedLBSComponents';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';

// 增强的位置数据接口
interface EnhancedLocationData {
  longitude: number;
  latitude: number;
  accuracy: number;
  timestamp: string;
  speed?: number;
  heading?: number;
  altitude?: number;
  provider?: 'gps' | 'network' | 'passive' | 'fused';
  confidence?: number; // 位置置信度
  retryCount?: number; // 重试次数
}

// 位置获取配置
interface LocationConfig {
  timeout: number;
  maximumAge: number;
  enableHighAccuracy: boolean;
  retryAttempts: number;
  retryDelay: number;
}

// 默认配置（根据网络和设备性能调整）
const DEFAULT_LOCATION_CONFIGS = {
  // 高精度配置（WiFi/4G，新设备）
  high: {
    timeout: 10000,
    maximumAge: 30000,
    enableHighAccuracy: true,
    retryAttempts: 3,
    retryDelay: 2000
  } as LocationConfig,
  
  // 平衡配置（默认）
  balanced: {
    timeout: 8000,
    maximumAge: 60000,
    enableHighAccuracy: true,
    retryAttempts: 2,
    retryDelay: 3000
  } as LocationConfig,
  
  // 省电配置（3G/低端设备）
  economy: {
    timeout: 6000,
    maximumAge: 120000,
    enableHighAccuracy: false,
    retryAttempts: 1,
    retryDelay: 5000
  } as LocationConfig
};

// API超时配置
const API_CONFIG = {
  timeout: 15000, // API请求超时时间
  retryAttempts: 3,
  retryDelay: 1000,
  batchSize: 5, // 批量处理位置数据
  maxPendingReports: 50, // 最大待处理报告数
  offlineStorageKey: 'smellpin_offline_locations'
};

const OptimizedLBSRewardTracker: React.FC = () => {
  const { user, token } = useAuthStore();
  const { 
    isTracking, 
    currentLocation, 
    nearbyGeofences,
    recentRewards,
    setTracking,
    updateLocation,
    addReward,
    fetchNearbyGeofences,
    fetchRewardHistory
  } = useLBSStore();
  
  const { connectWebSocket, disconnectWebSocket, isConnected } = useNotificationStore();

  // 状态管理
  const [locationPermission, setLocationPermission] = useState<PermissionState>('prompt');
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [lastReportTime, setLastReportTime] = useState<Date | null>(null);
  const [accuracy, setAccuracy] = useState<number | null>(null);
  const [isReporting, setIsReporting] = useState(false);
  const [activeTab, setActiveTab] = useState('basic');
  const [connectionQuality, setConnectionQuality] = useState<'high' | 'medium' | 'low'>('medium');
  const [locationConfig, setLocationConfig] = useState<LocationConfig>(DEFAULT_LOCATION_CONFIGS.balanced);
  
  // 性能监控
  const [performanceStats, setPerformanceStats] = useState({
    successfulGets: 0,
    failedGets: 0,
    averageAccuracy: 0,
    averageResponseTime: 0,
    timeoutCount: 0,
    retryCount: 0
  });

  // 引用
  const watchIdRef = useRef<number | null>(null);
  const reportTimerRef = useRef<NodeJS.Timeout | null>(null);
  const pendingReportsRef = useRef<EnhancedLocationData[]>([]);
  const lastLocationRef = useRef<EnhancedLocationData | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const locationTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  
  // 自适应配置选择
  const selectOptimalConfig = useCallback(() => {
    // 检测网络连接质量
    const connection = (navigator as any).connection;
    let quality: 'high' | 'medium' | 'low' = 'medium';
    
    if (connection) {
      const { effectiveType, downlink, rtt } = connection;
      
      if (effectiveType === '4g' && downlink > 2 && rtt < 100) {
        quality = 'high';
      } else if (effectiveType === '3g' || downlink < 1 || rtt > 300) {
        quality = 'low';
      }
    }

    // 检测设备性能
    const memoryInfo = (performance as any).memory;
    if (memoryInfo && memoryInfo.usedJSHeapSize / memoryInfo.totalJSHeapSize > 0.8) {
      quality = quality === 'high' ? 'medium' : 'low';
    }

    setConnectionQuality(quality);
    
    const configMap = {
      high: DEFAULT_LOCATION_CONFIGS.high,
      medium: DEFAULT_LOCATION_CONFIGS.balanced,
      low: DEFAULT_LOCATION_CONFIGS.economy
    };
    
    setLocationConfig(configMap[quality]);
  }, []);

  // 检查位置权限
  const checkLocationPermission = useCallback(async () => {
    if (!navigator.geolocation) {
      console.error('设备不支持位置服务');
      return false;
    }

    try {
      if ('permissions' in navigator) {
        const permission = await navigator.permissions.query({ name: 'geolocation' });
        setLocationPermission(permission.state);
        
        permission.addEventListener('change', () => {
          setLocationPermission(permission.state);
        });
        
        return permission.state === 'granted';
      } else {
        // 旧版浏览器回退方案
        return new Promise<boolean>((resolve) => {
          navigator.geolocation.getCurrentPosition(
            () => resolve(true),
            () => resolve(false),
            { timeout: 1000 }
          );
        });
      }
    } catch (error) {
      console.error('检查位置权限失败:', error);
      return false;
    }
  }, []);

  // 增强的位置获取函数
  const getCurrentLocationEnhanced = useCallback(async (config = locationConfig): Promise<EnhancedLocationData> => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('设备不支持位置服务'));
        return;
      }

      let attemptCount = 0;
      const startTime = Date.now();

      const attemptLocation = () => {
        attemptCount++;
        
        // 清除之前的超时
        if (locationTimeoutRef.current) {
          clearTimeout(locationTimeoutRef.current);
        }

        const options: PositionOptions = {
          enableHighAccuracy: config.enableHighAccuracy,
          timeout: config.timeout,
          maximumAge: config.maximumAge
        };

        // 设置自定义超时（比原生超时稍长）
        locationTimeoutRef.current = setTimeout(() => {
          setPerformanceStats(prev => ({ ...prev, timeoutCount: prev.timeoutCount + 1 }));
          
          if (attemptCount < config.retryAttempts) {
            console.warn(`位置获取超时，正在重试 (${attemptCount}/${config.retryAttempts})`);
            setTimeout(attemptLocation, config.retryDelay);
          } else {
            reject(new Error('获取位置超时，请检查GPS信号或网络连接'));
          }
        }, config.timeout + 1000);

        navigator.geolocation.getCurrentPosition(
          (position) => {
            if (locationTimeoutRef.current) {
              clearTimeout(locationTimeoutRef.current);
            }

            const responseTime = Date.now() - startTime;
            const locationData: EnhancedLocationData = {
              latitude: position.coords.latitude,
              longitude: position.coords.longitude,
              accuracy: position.coords.accuracy,
              altitude: position.coords.altitude ?? undefined,
              heading: position.coords.heading ?? undefined,
              speed: position.coords.speed ?? undefined,
              timestamp: new Date().toISOString(),
              provider: config.enableHighAccuracy ? 'gps' : 'network',
              confidence: calculateLocationConfidence(position.coords.accuracy, responseTime),
              retryCount: attemptCount - 1
            };
            
            // 更新性能统计
            setPerformanceStats(prev => ({
              ...prev,
              successfulGets: prev.successfulGets + 1,
              averageAccuracy: (prev.averageAccuracy + position.coords.accuracy) / 2,
              averageResponseTime: (prev.averageResponseTime + responseTime) / 2,
              retryCount: prev.retryCount + (attemptCount - 1)
            }));
            
            setAccuracy(position.coords.accuracy);
            resolve(locationData);
          },
          (error) => {
            if (locationTimeoutRef.current) {
              clearTimeout(locationTimeoutRef.current);
            }

            let errorMessage = '获取位置失败';
            switch (error.code) {
              case error.PERMISSION_DENIED:
                errorMessage = '位置权限被拒绝，请在设置中允许位置访问';
                setLocationPermission('denied');
                break;
              case error.POSITION_UNAVAILABLE:
                errorMessage = '位置信息不可用，请检查GPS设置';
                break;
              case error.TIMEOUT:
                errorMessage = `获取位置超时 (${config.timeout}ms)`;
                break;
            }

            setPerformanceStats(prev => ({ ...prev, failedGets: prev.failedGets + 1 }));

            if (attemptCount < config.retryAttempts && error.code !== error.PERMISSION_DENIED) {
              console.warn(`位置获取失败，正在重试 (${attemptCount}/${config.retryAttempts}):`, errorMessage);
              setTimeout(attemptLocation, config.retryDelay);
            } else {
              reject(new Error(errorMessage));
            }
          },
          options
        );
      };

      attemptLocation();
    });
  }, [locationConfig]);

  // 计算位置置信度
  const calculateLocationConfidence = (accuracy: number, responseTime: number): number => {
    let confidence = 1.0;
    
    // 基于精度的置信度
    if (accuracy > 100) confidence *= 0.5;
    else if (accuracy > 50) confidence *= 0.7;
    else if (accuracy > 20) confidence *= 0.9;
    
    // 基于响应时间的置信度
    if (responseTime > 10000) confidence *= 0.6;
    else if (responseTime > 5000) confidence *= 0.8;
    
    return Math.max(0.1, Math.min(1.0, confidence));
  };

  // 批量上报位置（带重试和离线支持）
  const reportLocationsBatch = useCallback(async (locations: EnhancedLocationData[]): Promise<void> => {
    if (!token || !user || locations.length === 0) {
      return;
    }

    // 创建新的AbortController
    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      setIsReporting(true);
      
      const response = await fetch('/api/lbs/location/batch-report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          locations,
          deviceInfo: {
            userAgent: navigator.userAgent,
            connectionType: connectionQuality,
            batteryLevel: (navigator as any).getBattery ? await (navigator as any).getBattery().then((battery: any) => battery.level) : null
          }
        }),
        signal: abortController.signal
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      
      if (result.success) {
        setLastReportTime(new Date());
        
        // 处理奖励
        if (result.rewards && result.rewards.length > 0) {
          result.rewards.forEach((reward: any) => {
            addReward({
              id: reward.id,
              userId: user.id,
              geofenceId: reward.geofenceId,
              geofenceName: reward.geofenceName,
              rewardType: reward.rewardType,
              baseReward: reward.baseReward,
              timeDecay: reward.timeDecay || 0,
              firstDiscoveryBonus: reward.firstDiscoveryBonus || 0,
              extraReward: reward.extraReward || 0,
              finalPoints: reward.finalPoints,
              latitude: reward.latitude,
              longitude: reward.longitude,
              timestamp: reward.timestamp,
              metadata: reward.metadata
            });
          });
        }

        // 清除已成功上报的位置
        pendingReportsRef.current = [];
      }
    } catch (error: any) {
      if (error.name === 'AbortError') {
        console.log('位置上报被取消');
        return;
      }

      console.error('批量位置上报失败:', error);
      
      // 如果是网络错误，保存到离线存储
      if (!isOnline) {
        saveLocationsOffline(locations);
      }
      
      throw error;
    } finally {
      setIsReporting(false);
      abortControllerRef.current = null;
    }
  }, [token, user, isOnline, connectionQuality, addReward]);

  // 离线存储位置数据
  const saveLocationsOffline = useCallback((locations: EnhancedLocationData[]) => {
    try {
      const existingData = localStorage.getItem(API_CONFIG.offlineStorageKey);
      const offlineLocations = existingData ? JSON.parse(existingData) : [];
      
      const updatedLocations = [...offlineLocations, ...locations]
        .slice(-API_CONFIG.maxPendingReports); // 限制存储数量
      
      localStorage.setItem(API_CONFIG.offlineStorageKey, JSON.stringify(updatedLocations));
    } catch (error) {
      console.error('离线位置存储失败:', error);
    }
  }, []);

  // 恢复离线位置数据
  const restoreOfflineLocations = useCallback(async () => {
    try {
      const offlineData = localStorage.getItem(API_CONFIG.offlineStorageKey);
      if (offlineData) {
        const offlineLocations = JSON.parse(offlineData);
        if (offlineLocations.length > 0) {
          await reportLocationsBatch(offlineLocations);
          localStorage.removeItem(API_CONFIG.offlineStorageKey);
          console.log(`已恢复${offlineLocations.length}个离线位置记录`);
        }
      }
    } catch (error) {
      console.error('恢复离线位置失败:', error);
    }
  }, [reportLocationsBatch]);

  // 开始位置追踪（增强版）
  const startLocationTracking = useCallback(async () => {
    const hasPermission = await checkLocationPermission();
    if (!hasPermission) {
      console.error('无位置权限');
      return;
    }

    try {
      // 首次获取位置
      const initialLocation = await getCurrentLocationEnhanced();
      updateLocation({
        latitude: initialLocation.latitude,
        longitude: initialLocation.longitude,
        accuracy: initialLocation.accuracy,
        altitude: initialLocation.altitude ?? undefined,
        heading: initialLocation.heading ?? undefined,
        speed: initialLocation.speed ?? undefined,
        timestamp: new Date(initialLocation.timestamp).getTime()
      });

      // 添加到待处理队列
      pendingReportsRef.current.push(initialLocation);
      lastLocationRef.current = initialLocation;

      if (isTracking) {
        // 设置持续监听
        const options: PositionOptions = {
          enableHighAccuracy: locationConfig.enableHighAccuracy,
          timeout: locationConfig.timeout,
          maximumAge: 30000
        };

        watchIdRef.current = navigator.geolocation.watchPosition(
          (position) => {
            const locationData: EnhancedLocationData = {
              latitude: position.coords.latitude,
              longitude: position.coords.longitude,
              accuracy: position.coords.accuracy,
              altitude: position.coords.altitude ?? undefined,
              heading: position.coords.heading ?? undefined,
              speed: position.coords.speed ?? undefined,
              timestamp: new Date().toISOString(),
              provider: locationConfig.enableHighAccuracy ? 'gps' : 'network',
              confidence: calculateLocationConfidence(position.coords.accuracy, 0)
            };
            
            setAccuracy(position.coords.accuracy);
            
            // 更新本地位置状态
            updateLocation({
              latitude: position.coords.latitude,
              longitude: position.coords.longitude,
              accuracy: position.coords.accuracy,
              altitude: position.coords.altitude ?? undefined,
              heading: position.coords.heading ?? undefined,
              speed: position.coords.speed ?? undefined,
              timestamp: Date.now()
            } as Location);

            // 添加到待处理队列
            pendingReportsRef.current.push(locationData);
            lastLocationRef.current = locationData;

            // 达到批量大小时上报
            if (pendingReportsRef.current.length >= API_CONFIG.batchSize) {
              const locationsToReport = [...pendingReportsRef.current];
              pendingReportsRef.current = [];
              reportLocationsBatch(locationsToReport).catch(console.error);
            }
          },
          (error) => {
            console.error('位置监听错误:', error);
            // 重新配置并重试
            if (locationConfig.enableHighAccuracy && error.code === error.TIMEOUT) {
              setLocationConfig(DEFAULT_LOCATION_CONFIGS.economy);
            }
          },
          options
        );

        // 设置定期批量上报
        reportTimerRef.current = setInterval(() => {
          if (pendingReportsRef.current.length > 0) {
            const locationsToReport = [...pendingReportsRef.current];
            pendingReportsRef.current = [];
            reportLocationsBatch(locationsToReport).catch(console.error);
          }
        }, 30000); // 30秒间隔
      }
    } catch (error) {
      console.error('开始位置追踪失败:', error);
    }
  }, [checkLocationPermission, getCurrentLocationEnhanced, isTracking, locationConfig, updateLocation, reportLocationsBatch]);

  // 停止位置追踪
  const stopLocationTracking = useCallback(() => {
    if (watchIdRef.current !== null) {
      navigator.geolocation.clearWatch(watchIdRef.current);
      watchIdRef.current = null;
    }

    if (reportTimerRef.current) {
      clearInterval(reportTimerRef.current);
      reportTimerRef.current = null;
    }

    if (locationTimeoutRef.current) {
      clearTimeout(locationTimeoutRef.current);
      locationTimeoutRef.current = null;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }

    // 上报剩余位置数据
    if (pendingReportsRef.current.length > 0) {
      const locationsToReport = [...pendingReportsRef.current];
      pendingReportsRef.current = [];
      reportLocationsBatch(locationsToReport).catch(console.error);
    }
  }, [reportLocationsBatch]);

  // 网络状态监听
  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      restoreOfflineLocations();
    };

    const handleOffline = () => {
      setIsOnline(false);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [restoreOfflineLocations]);

  // 初始化和清理
  useEffect(() => {
    selectOptimalConfig();
    
    const interval = setInterval(selectOptimalConfig, 60000); // 每分钟重新评估配置
    
    return () => {
      clearInterval(interval);
      stopLocationTracking();
    };
  }, [selectOptimalConfig, stopLocationTracking]);

  // 追踪状态变化
  useEffect(() => {
    if (isTracking) {
      startLocationTracking();
    } else {
      stopLocationTracking();
    }
  }, [isTracking, startLocationTracking, stopLocationTracking]);

  // 手动获取位置
  const handleManualLocationUpdate = async () => {
    try {
      const location = await getCurrentLocationEnhanced();
      const locationsToReport = [location];
      await reportLocationsBatch(locationsToReport);
    } catch (error: any) {
      console.error('手动位置更新失败:', error);
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto p-4 space-y-6">
      {/* 性能状态指示器 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Radar className="h-5 w-5 text-blue-500" />
            <span>优化版LBS追踪器</span>
            <Badge variant={isOnline ? 'default' : 'destructive'}>
              {isOnline ? '在线' : '离线'}
            </Badge>
            <Badge variant="outline">
              {connectionQuality === 'high' ? '高速' : connectionQuality === 'medium' ? '中速' : '低速'}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <div className="text-gray-600">成功率</div>
              <div className="font-bold text-green-600">
                {performanceStats.successfulGets + performanceStats.failedGets > 0 
                  ? Math.round((performanceStats.successfulGets / (performanceStats.successfulGets + performanceStats.failedGets)) * 100)
                  : 0}%
              </div>
            </div>
            <div>
              <div className="text-gray-600">平均精度</div>
              <div className="font-bold text-blue-600">
                {Math.round(performanceStats.averageAccuracy)}m
              </div>
            </div>
            <div>
              <div className="text-gray-600">响应时间</div>
              <div className="font-bold text-yellow-600">
                {Math.round(performanceStats.averageResponseTime)}ms
              </div>
            </div>
            <div>
              <div className="text-gray-600">待处理</div>
              <div className="font-bold text-purple-600">
                {pendingReportsRef.current.length}
              </div>
            </div>
          </div>
          
          <div className="mt-4 flex items-center space-x-2">
            <Button
              onClick={() => setTracking(!isTracking)}
              variant={isTracking ? 'destructive' : 'default'}
              disabled={isReporting}
            >
              {isTracking ? '停止追踪' : '开始追踪'}
            </Button>
            
            <Button
              onClick={handleManualLocationUpdate}
              variant="outline"
              disabled={isReporting}
            >
              手动更新位置
            </Button>

            {lastReportTime && (
              <div className="text-sm text-gray-600">
                上次上报: {lastReportTime.toLocaleTimeString()}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 原有的标签页内容 */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="basic">基础功能</TabsTrigger>
          <TabsTrigger value="map">地图视图</TabsTrigger>
          <TabsTrigger value="advanced">高级功能</TabsTrigger>
        </TabsList>

        <TabsContent value="basic" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* 当前位置信息 */}
            {currentLocation && (
              <Card>
                <CardHeader>
                  <CardTitle>当前位置</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between">
                    <span>纬度:</span>
                    <span className="font-mono">{currentLocation.latitude.toFixed(6)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>经度:</span>
                    <span className="font-mono">{currentLocation.longitude.toFixed(6)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>精度:</span>
                    <span>±{Math.round(accuracy || 0)}米</span>
                  </div>
                  {currentLocation.speed && (
                    <div className="flex justify-between">
                      <span>速度:</span>
                      <span>{Math.round(currentLocation.speed * 3.6)}km/h</span>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 附近地理围栏 */}
            <Card>
              <CardHeader>
                <CardTitle>附近地理围栏</CardTitle>
              </CardHeader>
              <CardContent>
                {nearbyGeofences.length > 0 ? (
                  <div className="space-y-2">
                    {nearbyGeofences.slice(0, 3).map(geofence => (
                      <div key={geofence.id} className="flex items-center justify-between p-2 border rounded">
                        <div>
                          <div className="font-medium">{geofence.name}</div>
                          <div className="text-sm text-gray-600">
                            {geofence.distance && `${Math.round(geofence.distance)}米`}
                          </div>
                        </div>
                        <Badge variant="secondary">
                          +{geofence.baseReward}分
                        </Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-gray-500 text-center py-4">
                    暂无附近的地理围栏
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="map" className="mt-6">
          {currentLocation && (
            <GeofenceMap
              center={[currentLocation.longitude, currentLocation.latitude]}
              geofences={nearbyGeofences}
              userLocation={currentLocation}
              className="h-96"
              showUserAccuracy={true}
            />
          )}
        </TabsContent>

        <TabsContent value="advanced" className="mt-6">
          {currentLocation && (
            <AdvancedLBSComponents
              userLocation={currentLocation}
              geofenceTargets={nearbyGeofences.map(g => ({
                id: g.id,
                name: g.name,
                description: g.description,
                location: { longitude: g.longitude, latitude: g.latitude },
                type: 'geofence' as const,
                reward: g.baseReward,
                radius: g.radius,
                isActive: g.isActive
              }))}
              onTargetDetected={(target) => {
                console.log('检测到目标:', target);
              }}
            />
          )}
        </TabsContent>
      </Tabs>

      {/* 奖励通知 */}
      <RewardNotification />
    </div>
  );
};

export default OptimizedLBSRewardTracker;