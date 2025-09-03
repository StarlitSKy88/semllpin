import React, { useState, useEffect, useRef, useCallback } from 'react';
import { MapPin, Radar, Zap, Target } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import useNotificationStore from '../../stores/notificationStore';

export interface NearbyAnnotation {
  id: string;
  title: string;
  distance: number;
  reward: number;
  latitude: number;
  longitude: number;
  type: 'prank' | 'funny' | 'weird';
}

export interface UserLocation {
  lat: number;
  lng: number;
}

export interface RewardData {
  id: string;
  amount: number;
  source: string;
  timestamp: number;
}

interface LBSRewardTrackerProps {
  className?: string;
  onRewardFound?: (annotation: NearbyAnnotation) => void;
}

const LBSRewardTracker: React.FC<LBSRewardTrackerProps> = ({ 
  className = '', 
  onRewardFound 
}) => {
  const { user } = useAuthStore();
  const { addNotification } = useNotificationStore();
  const [isScanning, setIsScanning] = useState(false);
  const [nearbyAnnotations, setNearbyAnnotations] = useState<NearbyAnnotation[]>([]);
  const [userLocation, setUserLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [scanRadius] = useState(100); // 扫描半径（米）
  // 用 ref 记录不会触发重渲染但需要跨渲染保存的值
  const userLocationRef = useRef<{ lat: number; lng: number } | null>(null);
  const lastScanTimeRef = useRef<number>(0);
  const scanIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const radarRef = useRef<HTMLDivElement>(null);

  // 获取用户位置（更新 state 和 ref）
  const getCurrentLocation = useCallback((): Promise<{ lat: number; lng: number }> => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('浏览器不支持地理定位'));
        return;
      }

      navigator.geolocation.getCurrentPosition(
        (position) => {
          const location = {
            lat: position.coords.latitude,
            lng: position.coords.longitude
          };
          setUserLocation(location);
          userLocationRef.current = location;
          resolve(location);
        },
        (error) => {
          let message = '获取位置失败';
          switch (error.code) {
            case error.PERMISSION_DENIED:
              message = '用户拒绝了地理定位请求';
              break;
            case error.POSITION_UNAVAILABLE:
              message = '位置信息不可用';
              break;
            case error.TIMEOUT:
              message = '获取位置超时';
              break;
          }
          reject(new Error(message));
        },
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 60000
        }
      );
    });
  }, []);

  // 扫描附近的标注（基于传入的位置，避免依赖变化导致回调重建）
  const scanNearbyAnnotations = useCallback(async (location: { lat: number; lng: number } | null) => {
    if (!user || !location) return;

    // 防止频繁扫描
    const now = Date.now();
    if (now - lastScanTimeRef.current < 5000) return;
    lastScanTimeRef.current = now;

    setIsScanning(true);

    try {
      const response = await fetch('/api/v1/lbs/nearby', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          latitude: location.lat,
          longitude: location.lng,
          radius: scanRadius
        })
      });

      if (!response.ok) {
        throw new Error('扫描失败');
      }

      const data = await response.json();
      const annotations = data.data || [];
      
      setNearbyAnnotations(annotations);

      // 检查是否有新的奖励
      annotations.forEach((annotation: NearbyAnnotation) => {
        if (annotation.distance <= 50) { // 50米内可以领取奖励
          onRewardFound?.(annotation);
          addNotification({
            type: 'reward',
            title: '🎯 发现奖励!',
            message: `在 ${annotation.distance}m 处发现「${annotation.title}」，可获得 ${annotation.reward} 积分！`
          });
        }
      });

    } catch (error) {
      console.error('扫描附近标注失败:', error);
      addNotification({
        type: 'error',
        title: '扫描失败',
        message: error instanceof Error ? error.message : '未知错误'
      });
    } finally {
      setIsScanning(false);
    }
  }, [user, scanRadius, onRewardFound, addNotification]);

  // 手动扫描
  const handleManualScan = useCallback(async () => {
    try {
      const loc = await getCurrentLocation();
      await scanNearbyAnnotations(loc);
    } catch (error) {
      addNotification({
        type: 'error',
        title: '扫描失败',
        message: error instanceof Error ? error.message : '获取位置失败'
      });
    }
  }, [getCurrentLocation, scanNearbyAnnotations, addNotification]);

  // 组件挂载/用户变化时启动或清理自动扫描
  useEffect(() => {
    if (!user) {
      // 没有用户则确保清理定时器
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
      }
      return;
    }

    let mounted = true;
    // 初始化定位并做一次扫描
    getCurrentLocation()
      .then((loc) => {
        if (!mounted) return;
        userLocationRef.current = loc;
        scanNearbyAnnotations(loc);
      })
      .catch((error) => {
        console.error('初始化位置失败:', error);
      });

    // 仅当没有定时器时设置，避免依赖变化导致反复创建
    if (!scanIntervalRef.current) {
      scanIntervalRef.current = setInterval(() => {
        getCurrentLocation()
          .then((loc) => {
            userLocationRef.current = loc;
            scanNearbyAnnotations(loc);
          })
          .catch((error) => {
            console.error('自动扫描失败:', error);
          });
      }, 10000); // 每10秒扫描一次
    }

    return () => {
      mounted = false;
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
      }
    };
  }, [user, getCurrentLocation, scanNearbyAnnotations]);

  // 雷达扫描动画效果
  useEffect(() => {
    if (isScanning && radarRef.current) {
      radarRef.current.style.animation = 'none';
      // 触发重排以重置动画
      void radarRef.current.offsetHeight;
      radarRef.current.style.animation = 'radar-sweep 2s ease-in-out';
    }
  }, [isScanning]);

  const getAnnotationIcon = (type: string) => {
    switch (type) {
      case 'prank': return '😈';
      case 'funny': return '😂';
      case 'weird': return '🤔';
      default: return '📍';
    }
  };

  const getDistanceColor = (distance: number) => {
    if (distance <= 50) return 'text-green-500';
    if (distance <= 100) return 'text-yellow-500';
    return 'text-gray-500';
  };

  return (
    <div className={`bg-white rounded-xl shadow-lg p-6 ${className}`}>
      {/* 头部 */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Radar className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900">LBS奖励追踪</h3>
            <p className="text-sm text-gray-500">
              扫描半径: {scanRadius}m
            </p>
          </div>
        </div>
        
        <button
          onClick={handleManualScan}
          disabled={isScanning}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <Target className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? '扫描中...' : '手动扫描'}</span>
        </button>
      </div>

      {/* 雷达显示区域 */}
      <div className="relative mb-6">
        <div className="w-full h-48 bg-gradient-to-br from-blue-50 to-indigo-100 rounded-lg relative overflow-hidden">
          {/* 雷达背景 */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-32 h-32 border-2 border-blue-300 rounded-full opacity-30"></div>
            <div className="absolute w-24 h-24 border-2 border-blue-400 rounded-full opacity-50"></div>
            <div className="absolute w-16 h-16 border-2 border-blue-500 rounded-full opacity-70"></div>
            <div className="absolute w-8 h-8 bg-blue-600 rounded-full"></div>
          </div>
          
          {/* 雷达扫描线 */}
          {isScanning && (
            <div 
              ref={radarRef}
              className="absolute inset-0 flex items-center justify-center"
            >
              <div className="w-32 h-32 relative">
                <div className="absolute top-0 left-1/2 w-0.5 h-16 bg-gradient-to-b from-blue-500 to-transparent transform -translate-x-0.5 origin-bottom animate-pulse"></div>
              </div>
            </div>
          )}
          
          {/* 附近标注点 */}
          {nearbyAnnotations.map((annotation, index) => {
            const angle = (index * 60) % 360;
            const distance = Math.min(annotation.distance / scanRadius, 1);
            const radius = 60 * (1 - distance);
            const x = Math.cos((angle * Math.PI) / 180) * radius;
            const y = Math.sin((angle * Math.PI) / 180) * radius;
            
            return (
              <div
                key={annotation.id}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 animate-pulse"
                style={{
                  left: `calc(50% + ${x}px)`,
                  top: `calc(50% + ${y}px)`
                }}
              >
                <div className="w-3 h-3 bg-red-500 rounded-full shadow-lg"></div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 附近标注列表 */}
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-gray-700 flex items-center">
          <MapPin className="w-4 h-4 mr-2" />
          附近发现 ({nearbyAnnotations.length})
        </h4>
        
        {nearbyAnnotations.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Zap className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>暂无附近的标注点</p>
            <p className="text-xs mt-1">移动到其他位置试试看</p>
          </div>
        ) : (
          <div className="max-h-40 overflow-y-auto space-y-2">
            {nearbyAnnotations.map((annotation) => (
              <div
                key={annotation.id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-lg">{getAnnotationIcon(annotation.type)}</span>
                  <div>
                    <p className="text-sm font-medium text-gray-900 truncate max-w-32">
                      {annotation.title}
                    </p>
                    <p className={`text-xs ${getDistanceColor(annotation.distance)}`}>
                      {annotation.distance}m
                    </p>
                  </div>
                </div>
                
                <div className="text-right">
                  <p className="text-sm font-semibold text-orange-600">
                    +{annotation.reward}
                  </p>
                  <p className="text-xs text-gray-500">积分</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 位置信息 */}
      {userLocation && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <p className="text-xs text-gray-500">
            当前位置: {userLocation.lat.toFixed(6)}, {userLocation.lng.toFixed(6)}
          </p>
        </div>
      )}

      <style>{`
        @keyframes radar-sweep {
          0% {
            transform: rotate(0deg);
          }
          100% {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </div>
  );
};

export default LBSRewardTracker;