/**
 * LBS奖励追踪器组件
 * 负责位置追踪、地理围栏检测和奖励显示
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { MapPin, Award, Clock, AlertTriangle, Wifi, WifiOff, Radar } from 'lucide-react';
// import { toast } from 'sonner'; // Install sonner package
const toast = {
  error: (message: string) => console.error('Toast error:', message),
  success: (message: string) => console.log('Toast success:', message),
  info: (message: string) => console.info('Toast info:', message),
};
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

interface LocationData {
  longitude: number;
  latitude: number;
  accuracy: number;
  timestamp: string;
  speed?: number;
  heading?: number;
  altitude?: number;
  provider?: 'gps' | 'network' | 'passive' | 'fused';
}

interface RewardResult {
  earned: boolean;
  amount: number;
  reason?: string;
  breakdown?: any;
}

interface GeofenceDetection {
  detected: boolean;
  count: number;
  geofences: Array<{
    id: string;
    name: string;
    type: string;
  }>;
}

interface LocationReportResponse {
  success: boolean;
  message: string;
  data: {
    locationReport: {
      id: string;
      timestamp: string;
    };
    verification: {
      confidence: number;
      riskLevel: string;
    };
    geofenceDetection: GeofenceDetection;
    reward: RewardResult | null;
  };
}

const LBSRewardTracker: React.FC = () => {
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
  
  // 通知服务
  const { connectWebSocket, disconnectWebSocket, isConnected } = useNotificationStore();

  const [locationPermission, setLocationPermission] = useState<PermissionState>('prompt');
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [lastReportTime, setLastReportTime] = useState<Date | null>(null);
  const [reportInterval] = useState(30000); // 30秒间隔
  const [accuracy, setAccuracy] = useState<number | null>(null);
  const [isReporting, setIsReporting] = useState(false);
  const [activeTab, setActiveTab] = useState('basic');
  
  const watchIdRef = useRef<number | null>(null);
  const reportTimerRef = useRef<NodeJS.Timeout | null>(null);
  const pendingReportsRef = useRef<LocationData[]>([]);

  // 检查位置权限
  const checkLocationPermission = useCallback(async () => {
    if (!navigator.geolocation) {
      toast.error('您的设备不支持位置服务');
      return false;
    }

    try {
      const permission = await navigator.permissions.query({ name: 'geolocation' });
      setLocationPermission(permission.state);
      
      permission.addEventListener('change', () => {
        setLocationPermission(permission.state);
      });

      return permission.state === 'granted';
    } catch (error) {
      console.warn('无法检查位置权限:', error);
      return true; // 降级处理
    }
  }, []);

  // 获取当前位置
  const getCurrentLocation = useCallback((): Promise<LocationData> => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('设备不支持位置服务'));
        return;
      }

      const options: PositionOptions = {
        enableHighAccuracy: true,
        timeout: 15000,
        maximumAge: 60000 // 1分钟缓存
      };

      navigator.geolocation.getCurrentPosition(
        (position) => {
          const locationData: LocationData = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            altitude: position.coords.altitude ?? undefined,
            heading: position.coords.heading ?? undefined,
            speed: position.coords.speed ?? undefined,
            timestamp: new Date().toISOString()
          };
          
          setAccuracy(position.coords.accuracy);
          resolve(locationData);
        },
        (error) => {
          let errorMessage = '获取位置失败';
          switch (error.code) {
            case error.PERMISSION_DENIED:
              errorMessage = '位置权限被拒绝';
              break;
            case error.POSITION_UNAVAILABLE:
              errorMessage = '位置信息不可用';
              break;
            case error.TIMEOUT:
              errorMessage = '获取位置超时';
              break;
          }
          reject(new Error(errorMessage));
        },
        options
      );
    });
  }, []);

  // 上报位置到服务器
  const reportLocation = useCallback(async (locationData: LocationData): Promise<LocationReportResponse | null> => {
    if (!token || !user) {
      console.warn('用户未登录，跳过位置上报');
      return null;
    }

    try {
      setIsReporting(true);
      
      const response = await fetch('/api/lbs/location/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(locationData)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result: LocationReportResponse = await response.json();
      
      if (result.success) {
        setLastReportTime(new Date());
        
        // 更新本地状态
        updateLocation({
          latitude: locationData.latitude,
          longitude: locationData.longitude,
          accuracy: locationData.accuracy,
          altitude: undefined,
          heading: undefined,
          speed: undefined,
          timestamp: typeof locationData.timestamp === 'string' ? new Date(locationData.timestamp).getTime() : Date.now()
        });

        // 如果获得奖励，添加到本地状态
        if (result.data.reward?.earned) {
          addReward({
            id: `temp_${Date.now()}`,
            userId: user?.id || '',
            geofenceId: result.data.geofenceDetection.geofences[0]?.id || '',
            geofenceName: result.data.geofenceDetection.geofences[0]?.name || '未知地点',
            rewardType: (result.data.geofenceDetection.geofences[0]?.type as 'discovery' | 'checkin' | 'stay' | 'social') || 'checkin',
            baseReward: result.data.reward.amount,
            timeDecay: 0,
            firstDiscoveryBonus: 0,
            extraReward: 0,
            finalPoints: result.data.reward.amount,
            latitude: locationData.latitude,
            longitude: locationData.longitude,
            timestamp: new Date().toISOString(),
            metadata: result.data.reward.breakdown
          });
        }

        return result;
      } else {
        throw new Error(result.message || '位置上报失败');
      }
    } catch (error) {
      console.error('位置上报错误:', error);
      
      // 如果是网络错误，将位置数据加入待上报队列
      if (!isOnline) {
        pendingReportsRef.current.push(locationData);
        toast.info('网络离线，位置数据已缓存');
      } else {
        toast.error(`位置上报失败: ${error instanceof Error ? error.message : '未知错误'}`);
      }
      
      return null;
    } finally {
      setIsReporting(false);
    }
  }, [token, user, isOnline, updateLocation, addReward]);

  // 处理待上报的位置数据
  const processPendingReports = useCallback(async () => {
    if (pendingReportsRef.current.length === 0 || !isOnline) {
      return;
    }

    const reports = [...pendingReportsRef.current];
    pendingReportsRef.current = [];

    for (const locationData of reports) {
      try {
        await reportLocation(locationData);
        await new Promise(resolve => setTimeout(resolve, 1000)); // 避免频繁请求
      } catch (error) {
        // 如果上报失败，重新加入队列
        pendingReportsRef.current.push(locationData);
        break;
      }
    }

    if (pendingReportsRef.current.length > 0) {
      toast.info(`还有 ${pendingReportsRef.current.length} 条位置数据待上报`);
    } else {
      toast.success('所有缓存的位置数据已上报完成');
    }
  }, [isOnline, reportLocation]);

  // 开始位置追踪
  const startTracking = useCallback(async () => {
    try {
      const hasPermission = await checkLocationPermission();
      if (!hasPermission) {
        toast.error('需要位置权限才能开始追踪');
        return;
      }

      // 首次获取位置
      const initialLocation = await getCurrentLocation();
      const reportResult = await reportLocation(initialLocation);
      
      if (reportResult?.data.reward?.earned) {
        toast.success(`获得奖励: ${reportResult.data.reward.amount} 分！`);
      }

      // 开始定期上报
      reportTimerRef.current = setInterval(async () => {
        try {
          const location = await getCurrentLocation();
          const result = await reportLocation(location);
          
          if (result?.data.reward?.earned) {
            toast.success(`获得奖励: ${result.data.reward.amount} 分！`);
          }
        } catch (error) {
          console.error('定期位置上报失败:', error);
        }
      }, reportInterval);

      // 开始位置监听
      if (navigator.geolocation) {
        const options: PositionOptions = {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 30000
        };

        watchIdRef.current = navigator.geolocation.watchPosition(
          (position) => {
            setAccuracy(position.coords.accuracy);
            
            // 更新本地位置状态
            updateLocation({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            altitude: position.coords.altitude || undefined,
            heading: position.coords.heading || undefined,
            speed: position.coords.speed || undefined,
            timestamp: Date.now()
          } as Location);
          },
          (error) => {
            console.error('位置监听错误:', error);
          },
          options
        );
      }

      setTracking(true);
      toast.success('位置追踪已开始');
      
      // 获取附近的地理围栏
      fetchNearbyGeofences({
        latitude: initialLocation.latitude,
        longitude: initialLocation.longitude,
        accuracy: initialLocation.accuracy,
        altitude: initialLocation.altitude,
        heading: initialLocation.heading,
        speed: initialLocation.speed,
        timestamp: initialLocation.timestamp
      } as Location);
      
    } catch (error) {
      console.error('开始追踪失败:', error);
      toast.error(`开始追踪失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }, [checkLocationPermission, getCurrentLocation, reportLocation, reportInterval, setTracking, updateLocation, fetchNearbyGeofences]);

  // 停止位置追踪
  const stopTracking = useCallback(() => {
    if (watchIdRef.current !== null) {
      navigator.geolocation.clearWatch(watchIdRef.current);
      watchIdRef.current = null;
    }

    if (reportTimerRef.current) {
      clearInterval(reportTimerRef.current);
      reportTimerRef.current = null;
    }

    setTracking(false);
    toast.info('位置追踪已停止');
  }, [setTracking]);

  // 初始化WebSocket连接
  const initializeWebSocket = useCallback(async () => {
    try {
      if (token && isOnline) {
        await connectWebSocket(token);
      }
    } catch (error) {
      console.error('WebSocket连接失败:', error);
    }
  }, [token, isOnline, connectWebSocket]);

  // 监听网络状态
  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      toast.success('网络已连接');
      processPendingReports();
      initializeWebSocket();
    };

    const handleOffline = () => {
      setIsOnline(false);
      toast.warning('网络已断开，位置数据将缓存');
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [processPendingReports, initializeWebSocket]);

  // 初始化WebSocket
  useEffect(() => {
    initializeWebSocket();
    
    return () => {
      disconnectWebSocket();
    };
  }, [initializeWebSocket, disconnectWebSocket]);

  // 组件卸载时清理
  useEffect(() => {
    return () => {
      if (watchIdRef.current !== null) {
        navigator.geolocation.clearWatch(watchIdRef.current);
      }
      if (reportTimerRef.current) {
        clearInterval(reportTimerRef.current);
      }
    };
  }, []);

  // 获取精度状态
  const getAccuracyStatus = () => {
    if (!accuracy) return { text: '未知', color: 'text-gray-500' };
    if (accuracy <= 10) return { text: '高精度', color: 'text-green-500' };
    if (accuracy <= 50) return { text: '中等精度', color: 'text-yellow-500' };
    return { text: '低精度', color: 'text-red-500' };
  };

  const accuracyStatus = getAccuracyStatus();

  return (
    <Card className="space-y-6">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <MapPin className="h-6 w-6 text-blue-500" />
            <CardTitle>LBS奖励追踪</CardTitle>
          </div>
          <div className="flex items-center space-x-2">
            {/* 通知按钮 */}
            <NotificationButton />
            
            {/* 在线状态 */}
            {isOnline ? (
              <Wifi className="h-5 w-5 text-green-500" />
            ) : (
              <WifiOff className="h-5 w-5 text-red-500" />
            )}
            
            {/* WebSocket连接状态 */}
            <div className={`h-2 w-2 rounded-full ${
              isConnected ? 'bg-blue-500' : 'bg-gray-400'
            }`} title={isConnected ? 'WebSocket已连接' : 'WebSocket未连接'} />
            
            <Badge variant={isOnline ? 'success' : 'destructive'}>
              {isOnline ? '在线' : '离线'}
            </Badge>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {/* 功能标签页 */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="basic" className="flex items-center space-x-2">
              <MapPin className="h-4 w-4" />
              <span>基础追踪</span>
            </TabsTrigger>
            <TabsTrigger value="advanced" className="flex items-center space-x-2">
              <Radar className="h-4 w-4" />
              <span>高级功能</span>
            </TabsTrigger>
          </TabsList>

          {/* 状态信息 */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <MapPin className="h-5 w-5 text-blue-500" />
                  <span className="text-sm font-medium text-gray-700">追踪状态</span>
                </div>
                <p className={`text-lg font-semibold mt-1 ${
                  isTracking ? 'text-green-600' : 'text-gray-600'
                }`}>
                  {isTracking ? '进行中' : '已停止'}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <Clock className="h-5 w-5 text-orange-500" />
                  <span className="text-sm font-medium text-gray-700">最后上报</span>
                </div>
                <p className="text-lg font-semibold text-gray-600 mt-1">
                  {lastReportTime ? lastReportTime.toLocaleTimeString() : '未上报'}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="h-5 w-5 text-yellow-500" />
                  <span className="text-sm font-medium text-gray-700">位置精度</span>
                </div>
                <p className={`text-lg font-semibold mt-1 ${accuracyStatus.color}`}>
                  {accuracyStatus.text}
                  {accuracy && (
                    <span className="text-sm text-gray-500 ml-1">
                      (±{Math.round(accuracy)}m)
                    </span>
                  )}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* 控制按钮 */}
          <div className="flex space-x-4">
            {!isTracking ? (
              <Button
                onClick={startTracking}
                disabled={!user || locationPermission === 'denied'}
                className="flex-1"
                size="lg"
              >
                开始追踪
              </Button>
            ) : (
              <Button
                onClick={stopTracking}
                variant="destructive"
                className="flex-1"
                size="lg"
              >
                停止追踪
              </Button>
            )}
            
            <Button
              onClick={() => fetchRewardHistory()}
              disabled={!user}
              variant="outline"
              size="lg"
            >
              刷新奖励
            </Button>
          </div>

          {/* 权限提示 */}
          {locationPermission === 'denied' && (
            <Card className="border-red-200 bg-red-50">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                  <span className="text-red-700 font-medium">位置权限被拒绝</span>
                </div>
                <p className="text-red-600 text-sm mt-1">
                  请在浏览器设置中允许位置访问权限，然后刷新页面。
                </p>
              </CardContent>
            </Card>
          )}

          {/* 离线提示 */}
          {!isOnline && pendingReportsRef.current.length > 0 && (
            <Card className="border-yellow-200 bg-yellow-50">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <WifiOff className="h-5 w-5 text-yellow-500" />
                  <span className="text-yellow-700 font-medium">网络离线</span>
                </div>
                <p className="text-yellow-600 text-sm mt-1">
                  有 {pendingReportsRef.current.length} 条位置数据待上报，网络恢复后将自动上报。
                </p>
              </CardContent>
            </Card>
          )}

          {/* 上报状态 */}
          {isReporting && (
            <Card className="border-blue-200 bg-blue-50">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
                  <span className="text-blue-700 font-medium">正在上报位置...</span>
                </div>
              </CardContent>
            </Card>
          )}

          {/* 当前位置信息 */}
          {currentLocation && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">当前位置</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">经度:</span>
                    <span className="ml-2 font-mono">{currentLocation.longitude.toFixed(6)}</span>
                  </div>
                  <div>
                    <span className="text-gray-600">纬度:</span>
                    <span className="ml-2 font-mono">{currentLocation.latitude.toFixed(6)}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* 附近地理围栏 */}
          {nearbyGeofences.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">附近地理围栏</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {nearbyGeofences.slice(0, 3).map((geofence) => (
                    <Card key={geofence.id} className="p-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">{geofence.name}</p>
                          <p className="text-sm text-gray-600">{geofence.description}</p>
                        </div>
                        <div className="text-right space-y-1">
                          <Badge variant="outline">
                            {Math.round(geofence.distance || 0)}m
                          </Badge>
                          <p className="text-xs text-gray-500">
                            {geofence.baseReward} 分
                          </p>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 最近奖励 */}
          {recentRewards.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">最近奖励</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {recentRewards.slice(0, 3).map((reward) => (
                    <Card key={reward.id} className="p-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Award className="h-4 w-4 text-yellow-500" />
                          <div>
                            <p className="font-medium text-gray-900">{reward.geofenceName}</p>
                            <p className="text-sm text-gray-600">
                              {new Date(reward.timestamp).toLocaleString()}
                            </p>
                          </div>
                        </div>
                        <div className="text-right space-y-1">
                          <Badge variant="success" className="text-lg font-bold">
                            +{reward.finalPoints}
                          </Badge>
                          <p className="text-xs text-gray-500">{reward.rewardType}</p>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <TabsContent value="basic" className="mt-4">
            {/* 地图组件 */}
            {currentLocation && (
              <GeofenceMap
                center={[currentLocation.longitude, currentLocation.latitude]}
                geofences={nearbyGeofences}
                userLocation={currentLocation}
                className="h-64 rounded-lg"
              />
            )}
          </TabsContent>

          <TabsContent value="advanced" className="mt-4">
            {/* 高级LBS组件 */}
            {currentLocation && (
              <AdvancedLBSComponents
                userLocation={{
                  longitude: currentLocation.longitude,
                  latitude: currentLocation.latitude
                }}
                geofenceTargets={nearbyGeofences.map(geofence => ({
                   id: geofence.id,
                   name: geofence.name,
                   location: {
                     longitude: geofence.longitude,
                     latitude: geofence.latitude
                   },
                   type: 'geofence' as const,
                   reward: geofence.baseReward,
                   radius: geofence.radius,
                   isActive: geofence.isActive
                 }))}
              />
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
      
      {/* 奖励通知组件 */}
      <RewardNotification />
    </Card>
  );
};

export default LBSRewardTracker;