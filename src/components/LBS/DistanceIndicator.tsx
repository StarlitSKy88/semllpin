/**
 * 距离指示器组件
 * 显示用户与目标地点的距离、方向和导航信息
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect } from 'react';
import { Navigation, MapPin, Target, Compass, Clock, Award } from 'lucide-react';

interface Location {
  longitude: number;
  latitude: number;
}

interface DistanceTarget {
  id: string;
  name: string;
  description?: string;
  location: Location;
  type: 'geofence' | 'poi' | 'destination';
  reward?: number;
  estimatedTime?: number; // 预计到达时间（分钟）
  isActive?: boolean;
}

interface DistanceInfo {
  distance: number; // 距离（米）
  bearing: number; // 方位角（度）
  direction: string; // 方向描述
  estimatedWalkTime: number; // 步行时间（分钟）
  estimatedDriveTime: number; // 驾车时间（分钟）
}

interface DistanceIndicatorProps {
  userLocation: Location;
  targets: DistanceTarget[];
  selectedTargetId?: string | undefined;
  className?: string;
  onTargetSelect?: (target: DistanceTarget) => void;
  showNavigation?: boolean;
  maxDisplayTargets?: number;
  sortBy?: 'distance' | 'reward' | 'name';
}

const DistanceIndicator: React.FC<DistanceIndicatorProps> = ({
  userLocation,
  targets,
  selectedTargetId,
  className = '',
  onTargetSelect,
  showNavigation = true,
  maxDisplayTargets = 5,
  sortBy = 'distance'
}) => {
  const [distanceInfos, setDistanceInfos] = useState<Map<string, DistanceInfo>>(new Map());
  const [selectedTarget, setSelectedTarget] = useState<DistanceTarget | null>(null);
  const [compassHeading, setCompassHeading] = useState<number>(0);
  const [isCompassSupported, setIsCompassSupported] = useState(false);

  // 计算两点间距离（米）
  const calculateDistance = (loc1: Location, loc2: Location): number => {
    const R = 6371000; // 地球半径（米）
    const lat1Rad = (loc1.latitude * Math.PI) / 180;
    const lat2Rad = (loc2.latitude * Math.PI) / 180;
    const deltaLatRad = ((loc2.latitude - loc1.latitude) * Math.PI) / 180;
    const deltaLonRad = ((loc2.longitude - loc1.longitude) * Math.PI) / 180;

    const a = Math.sin(deltaLatRad / 2) * Math.sin(deltaLatRad / 2) +
              Math.cos(lat1Rad) * Math.cos(lat2Rad) *
              Math.sin(deltaLonRad / 2) * Math.sin(deltaLonRad / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  };

  // 计算方位角（度）
  const calculateBearing = (loc1: Location, loc2: Location): number => {
    const lat1Rad = (loc1.latitude * Math.PI) / 180;
    const lat2Rad = (loc2.latitude * Math.PI) / 180;
    const deltaLonRad = ((loc2.longitude - loc1.longitude) * Math.PI) / 180;

    const y = Math.sin(deltaLonRad) * Math.cos(lat2Rad);
    const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) -
              Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLonRad);

    const bearingRad = Math.atan2(y, x);
    return (bearingRad * 180 / Math.PI + 360) % 360;
  };

  // 方位角转方向描述
  const bearingToDirection = (bearing: number): string => {
    const directions = [
      '北', '东北偏北', '东北', '东北偏东',
      '东', '东南偏东', '东南', '东南偏南',
      '南', '西南偏南', '西南', '西南偏西',
      '西', '西北偏西', '西北', '西北偏北'
    ];
    const index = Math.round(bearing / 22.5) % 16;
    return directions[index] || '北';
  };

  // 估算步行时间（分钟）
  const estimateWalkTime = (distance: number): number => {
    const walkingSpeed = 5000; // 5km/h = 5000m/h
    return Math.round((distance / walkingSpeed) * 60);
  };

  // 估算驾车时间（分钟）
  const estimateDriveTime = (distance: number): number => {
    const drivingSpeed = 30000; // 30km/h = 30000m/h（城市道路）
    return Math.round((distance / drivingSpeed) * 60);
  };

  // 格式化距离显示
  const formatDistance = (distance: number): string => {
    if (distance < 1000) {
      return `${Math.round(distance)}m`;
    } else {
      return `${(distance / 1000).toFixed(1)}km`;
    }
  };

  // 格式化时间显示
  const formatTime = (minutes: number): string => {
    if (minutes < 60) {
      return `${minutes}分钟`;
    } else {
      const hours = Math.floor(minutes / 60);
      const mins = minutes % 60;
      return `${hours}小时${mins > 0 ? mins + '分钟' : ''}`;
    }
  };

  // 获取设备方向（指南针）
  const initCompass = (): (() => void) | undefined => {
    if ('DeviceOrientationEvent' in window) {
      setIsCompassSupported(true);
      
      const handleOrientation = (event: DeviceOrientationEvent) => {
        if (event.alpha !== null) {
          setCompassHeading(360 - event.alpha); // 转换为地理方位
        }
      };
      
      // 请求权限（iOS 13+）
      if (typeof (DeviceOrientationEvent as any).requestPermission === 'function') {
        (DeviceOrientationEvent as any).requestPermission()
          .then((response: string) => {
            if (response === 'granted') {
              window.addEventListener('deviceorientation', handleOrientation);
            }
          })
          .catch(() => {
            setIsCompassSupported(false);
          });
      } else {
        window.addEventListener('deviceorientation', handleOrientation);
      }
      
      return () => {
        window.removeEventListener('deviceorientation', handleOrientation);
      };
    } else {
      setIsCompassSupported(false);
      return undefined;
    }
  };

  // 计算所有目标的距离信息
  useEffect(() => {
    const newDistanceInfos = new Map<string, DistanceInfo>();
    
    targets.forEach(target => {
      const distance = calculateDistance(userLocation, target.location);
      const bearing = calculateBearing(userLocation, target.location);
      const direction = bearingToDirection(bearing);
      const estimatedWalkTime = estimateWalkTime(distance);
      const estimatedDriveTime = estimateDriveTime(distance);
      
      newDistanceInfos.set(target.id, {
        distance,
        bearing,
        direction,
        estimatedWalkTime,
        estimatedDriveTime
      });
    });
    
    setDistanceInfos(newDistanceInfos);
  }, [userLocation, targets]);

  // 设置选中目标
  useEffect(() => {
    if (selectedTargetId) {
      const target = targets.find(t => t.id === selectedTargetId);
      setSelectedTarget(target || null);
    } else {
      setSelectedTarget(null);
    }
  }, [selectedTargetId, targets]);

  // 初始化指南针
  useEffect(() => {
    const cleanup = initCompass();
    return cleanup;
  }, []);

  // 排序目标
  const sortedTargets = [...targets].sort((a, b) => {
    const infoA = distanceInfos.get(a.id);
    const infoB = distanceInfos.get(b.id);
    
    if (!infoA || !infoB) return 0;
    
    switch (sortBy) {
      case 'distance':
        return infoA.distance - infoB.distance;
      case 'reward':
        return (b.reward || 0) - (a.reward || 0);
      case 'name':
        return a.name.localeCompare(b.name);
      default:
        return 0;
    }
  }).slice(0, maxDisplayTargets);

  // 处理目标选择
  const handleTargetClick = (target: DistanceTarget) => {
    setSelectedTarget(target);
    onTargetSelect?.(target);
  };

  // 获取方向箭头旋转角度
  const getArrowRotation = (bearing: number): number => {
    return isCompassSupported ? bearing - compassHeading : bearing;
  };

  return (
    <div className={`bg-white rounded-lg shadow-lg ${className}`}>
      {/* 标题栏 */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <div className="flex items-center space-x-2">
          <Navigation className="h-5 w-5 text-blue-500" />
          <h3 className="text-lg font-semibold text-gray-900">距离指示器</h3>
        </div>
        
        {isCompassSupported && (
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <Compass className="h-4 w-4" />
            <span>{Math.round(compassHeading)}°</span>
          </div>
        )}
      </div>

      {/* 选中目标详情 */}
      {selectedTarget && (
        <div className="p-4 bg-blue-50 border-b border-gray-200">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h4 className="font-semibold text-gray-900">{selectedTarget.name}</h4>
              {selectedTarget.description && (
                <p className="text-sm text-gray-600 mt-1">{selectedTarget.description}</p>
              )}
              
              {distanceInfos.has(selectedTarget.id) && (
                <div className="mt-2 grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">距离:</span>
                    <span className="ml-2 font-medium">
                      {formatDistance(distanceInfos.get(selectedTarget.id)!.distance)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-600">方向:</span>
                    <span className="ml-2 font-medium">
                      {distanceInfos.get(selectedTarget.id)!.direction}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-600">步行:</span>
                    <span className="ml-2 font-medium">
                      {formatTime(distanceInfos.get(selectedTarget.id)!.estimatedWalkTime)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-600">驾车:</span>
                    <span className="ml-2 font-medium">
                      {formatTime(distanceInfos.get(selectedTarget.id)!.estimatedDriveTime)}
                    </span>
                  </div>
                </div>
              )}
            </div>
            
            {/* 方向指示器 */}
            {distanceInfos.has(selectedTarget.id) && (
              <div className="ml-4 flex flex-col items-center">
                <div 
                  className="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center transform transition-transform duration-300"
                  style={{
                    transform: `rotate(${getArrowRotation(distanceInfos.get(selectedTarget.id)!.bearing)}deg)`
                  }}
                >
                  <Navigation className="h-6 w-6 text-white" />
                </div>
                <span className="text-xs text-gray-600 mt-1">
                  {Math.round(distanceInfos.get(selectedTarget.id)!.bearing)}°
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 目标列表 */}
      <div className="p-4">
        <div className="space-y-3">
          {sortedTargets.map(target => {
            const distanceInfo = distanceInfos.get(target.id);
            if (!distanceInfo) return null;
            
            const isSelected = selectedTarget?.id === target.id;
            
            return (
              <div
                key={target.id}
                onClick={() => handleTargetClick(target)}
                className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                  isSelected
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${
                        target.type === 'geofence' ? 'bg-yellow-500' :
                        target.type === 'poi' ? 'bg-blue-500' : 'bg-green-500'
                      }`} />
                      <h5 className="font-medium text-gray-900">{target.name}</h5>
                      {target.reward && (
                        <div className="flex items-center space-x-1 text-green-600">
                          <Award className="h-3 w-3" />
                          <span className="text-xs font-medium">+{target.reward}</span>
                        </div>
                      )}
                    </div>
                    
                    <div className="mt-1 flex items-center space-x-4 text-sm text-gray-600">
                      <div className="flex items-center space-x-1">
                        <MapPin className="h-3 w-3" />
                        <span>{formatDistance(distanceInfo.distance)}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Compass className="h-3 w-3" />
                        <span>{distanceInfo.direction}</span>
                      </div>
                      {showNavigation && (
                        <div className="flex items-center space-x-1">
                          <Clock className="h-3 w-3" />
                          <span>{formatTime(distanceInfo.estimatedWalkTime)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* 小型方向指示器 */}
                  <div className="ml-3 flex flex-col items-center">
                    <div 
                      className={`w-8 h-8 rounded-full flex items-center justify-center transform transition-transform duration-300 ${
                        isSelected ? 'bg-blue-500' : 'bg-gray-400'
                      }`}
                      style={{
                        transform: `rotate(${getArrowRotation(distanceInfo.bearing)}deg)`
                      }}
                    >
                      <Navigation className="h-4 w-4 text-white" />
                    </div>
                    <span className="text-xs text-gray-500 mt-1">
                      {Math.round(distanceInfo.bearing)}°
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        
        {targets.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            <Target className="h-8 w-8 mx-auto mb-2" />
            <p>暂无目标地点</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default DistanceIndicator;