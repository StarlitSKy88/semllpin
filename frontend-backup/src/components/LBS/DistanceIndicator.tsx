import React, { useState, useEffect } from 'react';
import { Navigation, MapPin, Target, Zap, Clock } from 'lucide-react';

interface AnnotationPoint {
  id: string;
  title: string;
  latitude: number;
  longitude: number;
  reward: number;
  type: 'prank' | 'funny' | 'weird';
  distance: number;
  direction: number; // 方向角度（0-360度）
}

export interface DistanceIndicatorProps {
  userLocation: { lat: number; lng: number } | null;
  annotations: AnnotationPoint[];
  maxDistance?: number; // 最大显示距离（米）
  onAnnotationSelect?: (annotation: AnnotationPoint) => void;
  className?: string;
}

const DistanceIndicator: React.FC<DistanceIndicatorProps> = ({
  userLocation,
  annotations,
  maxDistance = 500,
  onAnnotationSelect,
  className = ''
}) => {
  const [nearbyAnnotations, setNearbyAnnotations] = useState<AnnotationPoint[]>([]);
  const [selectedAnnotation, setSelectedAnnotation] = useState<AnnotationPoint | null>(null);
  const [userHeading, setUserHeading] = useState<number>(0); // 用户朝向

  // 计算两点间距离（米）
  const calculateDistance = (lat1: number, lng1: number, lat2: number, lng2: number): number => {
    const R = 6371e3; // 地球半径（米）
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lng2 - lng1) * Math.PI / 180;

    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

    return R * c;
  };

  // 计算方向角度
  const calculateBearing = (lat1: number, lng1: number, lat2: number, lng2: number): number => {
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δλ = (lng2 - lng1) * Math.PI / 180;

    const y = Math.sin(Δλ) * Math.cos(φ2);
    const x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(Δλ);

    const θ = Math.atan2(y, x);
    return (θ * 180 / Math.PI + 360) % 360;
  };

  // 获取设备朝向
  useEffect(() => {
    if ('DeviceOrientationEvent' in window) {
      const handleOrientation = (event: DeviceOrientationEvent) => {
        if (event.alpha !== null) {
          setUserHeading(event.alpha);
        }
      };

      window.addEventListener('deviceorientation', handleOrientation);
      return () => window.removeEventListener('deviceorientation', handleOrientation);
    }
  }, []);

  // 更新附近标注点的距离和方向
  useEffect(() => {
    if (!userLocation || !annotations.length) {
      setNearbyAnnotations([]);
      return;
    }

    const annotationsWithDistance = annotations
      .map(annotation => {
        const distance = calculateDistance(
          userLocation.lat,
          userLocation.lng,
          annotation.latitude,
          annotation.longitude
        );
        const direction = calculateBearing(
          userLocation.lat,
          userLocation.lng,
          annotation.latitude,
          annotation.longitude
        );

        return {
          ...annotation,
          distance: Math.round(distance),
          direction: Math.round(direction)
        };
      })
      .filter(annotation => annotation.distance <= maxDistance)
      .sort((a, b) => a.distance - b.distance);

    setNearbyAnnotations(annotationsWithDistance);
  }, [userLocation, annotations, maxDistance]);

  const getDistanceColor = (distance: number) => {
    if (distance <= 50) return 'text-green-500';
    if (distance <= 100) return 'text-yellow-500';
    if (distance <= 200) return 'text-orange-500';
    return 'text-red-500';
  };

  const getDistanceBackground = (distance: number) => {
    if (distance <= 50) return 'bg-green-100 border-green-200';
    if (distance <= 100) return 'bg-yellow-100 border-yellow-200';
    if (distance <= 200) return 'bg-orange-100 border-orange-200';
    return 'bg-red-100 border-red-200';
  };

  const getAnnotationIcon = (type: string) => {
    switch (type) {
      case 'prank': return '😈';
      case 'funny': return '😂';
      case 'weird': return '🤔';
      default: return '📍';
    }
  };

  const formatDistance = (distance: number) => {
    if (distance < 1000) {
      return `${distance}m`;
    }
    return `${(distance / 1000).toFixed(1)}km`;
  };

  const getDirectionArrow = (direction: number) => {
    const adjustedDirection = (direction - userHeading + 360) % 360;
    return {
      transform: `rotate(${adjustedDirection}deg)`
    };
  };

  const handleAnnotationClick = (annotation: AnnotationPoint) => {
    setSelectedAnnotation(annotation);
    onAnnotationSelect?.(annotation);
  };

  if (!userLocation) {
    return (
      <div className={`bg-white rounded-xl shadow-lg p-6 ${className}`}>
        <div className="text-center py-8">
          <MapPin className="w-12 h-12 mx-auto text-gray-400 mb-4" />
          <p className="text-gray-500">正在获取位置信息...</p>
          <p className="text-sm text-gray-400 mt-2">请允许访问您的位置</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white rounded-xl shadow-lg p-6 ${className}`}>
      {/* 头部 */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-100 rounded-lg">
            <Navigation className="w-6 h-6 text-indigo-600" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900">距离指示器</h3>
            <p className="text-sm text-gray-500">
              {nearbyAnnotations.length} 个附近标注
            </p>
          </div>
        </div>
        
        <div className="text-right">
          <p className="text-sm text-gray-500">扫描范围</p>
          <p className="text-lg font-semibold text-indigo-600">{maxDistance}m</p>
        </div>
      </div>

      {/* 罗盘显示 */}
      <div className="mb-6">
        <div className="relative w-32 h-32 mx-auto bg-gradient-to-br from-indigo-50 to-blue-100 rounded-full border-4 border-indigo-200">
          {/* 罗盘刻度 */}
          <div className="absolute inset-2 border border-indigo-300 rounded-full">
            {/* 方向标记 */}
            <div className="absolute top-1 left-1/2 transform -translate-x-1/2 text-xs font-bold text-indigo-600">N</div>
            <div className="absolute bottom-1 left-1/2 transform -translate-x-1/2 text-xs font-bold text-indigo-600">S</div>
            <div className="absolute left-1 top-1/2 transform -translate-y-1/2 text-xs font-bold text-indigo-600">W</div>
            <div className="absolute right-1 top-1/2 transform -translate-y-1/2 text-xs font-bold text-indigo-600">E</div>
            
            {/* 用户位置（中心点） */}
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-3 h-3 bg-indigo-600 rounded-full"></div>
            
            {/* 附近标注点 */}
            {nearbyAnnotations.slice(0, 8).map((annotation) => {
              const angle = annotation.direction || 0;
              const distance = Math.min(annotation.distance / maxDistance, 1);
              const radius = 40 * (1 - distance * 0.8); // 距离越近，点越靠近中心
              const x = Math.cos((angle - 90) * Math.PI / 180) * radius;
              const y = Math.sin((angle - 90) * Math.PI / 180) * radius;
              
              return (
                <div
                  key={annotation.id}
                  className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer"
                  style={{
                    left: `calc(50% + ${x}px)`,
                    top: `calc(50% + ${y}px)`
                  }}
                  onClick={() => handleAnnotationClick(annotation)}
                >
                  <div className={`w-2 h-2 rounded-full ${getDistanceColor(annotation.distance).replace('text-', 'bg-')} animate-pulse`}></div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 附近标注列表 */}
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-gray-700 flex items-center">
          <Target className="w-4 h-4 mr-2" />
          附近标注点
        </h4>
        
        {nearbyAnnotations.length === 0 ? (
          <div className="text-center py-6 text-gray-500">
            <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>附近暂无标注点</p>
            <p className="text-xs mt-1">移动到其他位置探索</p>
          </div>
        ) : (
          <div className="max-h-64 overflow-y-auto space-y-2">
            {nearbyAnnotations.map((annotation) => (
              <div
                key={annotation.id}
                className={`flex items-center justify-between p-3 border rounded-lg cursor-pointer transition-all hover:shadow-md ${
                  selectedAnnotation?.id === annotation.id 
                    ? 'border-indigo-300 bg-indigo-50' 
                    : getDistanceBackground(annotation.distance)
                }`}
                onClick={() => handleAnnotationClick(annotation)}
              >
                <div className="flex items-center space-x-3">
                  <span className="text-lg">{getAnnotationIcon(annotation.type)}</span>
                  <div>
                    <p className="text-sm font-medium text-gray-900 truncate max-w-32">
                      {annotation.title}
                    </p>
                    <div className="flex items-center space-x-2">
                      <p className={`text-xs font-semibold ${getDistanceColor(annotation.distance)}`}>
                        {formatDistance(annotation.distance)}
                      </p>
                      {annotation.direction !== undefined && (
                        <div className="flex items-center">
                          <Navigation 
                            className="w-3 h-3 text-gray-400" 
                            style={getDirectionArrow(annotation.direction)}
                          />
                          <span className="text-xs text-gray-500 ml-1">
                            {annotation.direction}°
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="text-right">
                  <div className="flex items-center space-x-1">
                    <Zap className="w-4 h-4 text-orange-500" />
                    <span className="text-sm font-semibold text-orange-600">
                      {annotation.reward}
                    </span>
                  </div>
                  {annotation.distance <= 50 && (
                    <p className="text-xs text-green-600 font-medium">可领取</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 选中标注详情 */}
      {selectedAnnotation && (
        <div className="mt-4 p-4 bg-indigo-50 border border-indigo-200 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <h5 className="font-medium text-indigo-900">选中标注</h5>
            <button
              onClick={() => setSelectedAnnotation(null)}
              className="text-indigo-600 hover:text-indigo-800 text-sm"
            >
              ✕
            </button>
          </div>
          <p className="text-sm text-indigo-800 mb-2">{selectedAnnotation.title}</p>
          <div className="flex items-center justify-between text-xs text-indigo-600">
            <span>距离: {formatDistance(selectedAnnotation.distance)}</span>
            <span>奖励: {selectedAnnotation.reward} 积分</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default DistanceIndicator;