import React, { useState, useEffect, useRef, useCallback, useId } from 'react';
import { MapPin, Navigation, Zap, RefreshCw, Eye, EyeOff } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import useNotificationStore from '../../stores/notificationStore';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';
import type { AccessibilityProps } from '../../utils/accessibility';
import type { AMapInstance, AMapMarker, AMapCircle } from '../../types/amap';

interface MapAnnotation {
  id: string;
  title: string;
  description: string;
  latitude: number;
  longitude: number;
  reward: number;
  type: 'prank' | 'funny' | 'weird';
  createdBy: string;

  createdAt: string;
  distance: number;
  canClaim?: boolean;
}

interface LBSMapProps extends AccessibilityProps {
  className?: string;
  onAnnotationSelect?: (annotation: MapAnnotation) => void;
  onRewardClaim?: (annotation: MapAnnotation) => void;
}

const LBSMap: React.FC<LBSMapProps> = ({
  className = '',
  onAnnotationSelect,
  onRewardClaim,
  'aria-label': ariaLabel,
  'aria-describedby': ariaDescribedby,
  ...accessibilityProps
}) => {
  const { user } = useAuthStore();
  const { addNotification } = useNotificationStore();
  const mapRef = useRef<HTMLDivElement>(null);
  const [map, setMap] = useState<AMapInstance | null>(null);
  
  // 无障碍功能
  const mapId = useId();
  const controlsId = useId();
  const detailsId = useId();
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([], {
    onIndexChange: (index) => {
      // 处理标注选择
      if (annotations[index]) {
        setSelectedAnnotation(annotations[index]);
        announce(`已选择标注: ${annotations[index].title}`);
      }
    }
  });
  
  const [userLocation, setUserLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [annotations, setAnnotations] = useState<MapAnnotation[]>([]);
  const [selectedAnnotation, setSelectedAnnotation] = useState<MapAnnotation | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showRewardRadius, setShowRewardRadius] = useState(true);
  const [mapStyle, setMapStyle] = useState<'roadmap' | 'satellite' | 'hybrid' | 'terrain'>('roadmap');
  const userMarkerRef = useRef<AMapMarker | null>(null);
  // 使用 ref 管理地图元素，避免 state 导致的重复渲染
  const annotationMarkersRef = useRef<AMapMarker[]>([]);
  const rewardCirclesRef = useRef<AMapCircle[]>([]);
  // 在开发模式下的简化与模拟支持
  const AMAP_KEY = (import.meta.env.VITE_AMAP_KEY as string | undefined);
  const USE_MOCK = (((import.meta.env.VITE_USE_MOCK as string | undefined) ?? (import.meta.env.DEV ? 'true' : 'false')) === 'true');
  const [mapDisabled, setMapDisabled] = useState<boolean>(false);

  // 初始化地图（传入当前位置，保证依赖稳定）
  const initializeMap = useCallback(async (center: { lat: number; lng: number }) => {
    if (!mapRef.current) return;
    if (mapDisabled) return;

    try {
      const AMap = window.AMap;
      if (!AMap) {
        console.error('地图API未加载');
        return;
      }

      const mapInstance = new AMap.Map(mapRef.current, {
        center: [center.lng, center.lat],
        zoom: 16,
        mapStyle: `amap://styles/${mapStyle}`,
        features: ['bg', 'road', 'building', 'point'],
        viewMode: '2D'
      });

      setMap(mapInstance);

      // 添加用户位置标记
      const userMarkerInstance = new AMap.Marker({
        position: [center.lng, center.lat],
        icon: new AMap.Icon({
          size: new AMap.Size(32, 32),
          image: 'data:image/svg+xml;base64,' + btoa(`
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
              <circle cx="16" cy="16" r="12" fill="#3B82F6" stroke="white" stroke-width="3"/>
              <circle cx="16" cy="16" r="6" fill="white"/>
            </svg>
          `),
          imageSize: new AMap.Size(32, 32)
        }),
        title: '我的位置',
        zIndex: 100
      });

      mapInstance.add([userMarkerInstance]);
      userMarkerRef.current = userMarkerInstance;

    } catch (error) {
      console.error('地图初始化失败:', error);
      addNotification({
        type: 'error',
        title: '地图加载失败',
        message: '无法初始化地图，请刷新页面重试'
      });
    }
  }, [mapStyle, addNotification, mapDisabled, setMap]);

  // 获取用户位置
  const getCurrentLocation = useCallback(() => {
    return new Promise<{ lat: number; lng: number }>((resolve, reject) => {
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

  // 获取标注类型颜色
  const getAnnotationColor = (type: string) => {
    switch (type) {
      case 'prank': return '#EF4444';
      case 'funny': return '#F59E0B';
      case 'weird': return '#8B5CF6';
      default: return '#6B7280';
    }
  };

  // 获取标注类型表情
  const getAnnotationEmoji = (type: string) => {
    switch (type) {
      case 'prank': return '😈';
      case 'funny': return '😂';
      case 'weird': return '🤔';
      default: return '📍';
    }
  };

  // 加载附近标注
  const loadNearbyAnnotations = useCallback(async () => {
    if (!userLocation || !user) return;

    setIsLoading(true);
    try {
      if (USE_MOCK) {
        const baseLat = userLocation.lat;
        const baseLng = userLocation.lng;
        const types: Array<'prank' | 'funny' | 'weird'> = ['prank', 'funny', 'weird'];
        const rand = (min: number, max: number) => Math.random() * (max - min) + min;
        const computeDistance = (dx: number, dy: number) => Math.round(Math.sqrt(dx * dx + dy * dy) * 111000);
        const mock: MapAnnotation[] = Array.from({ length: 6 }).map((_, i) => {
          const dLat = rand(-0.002, 0.002);
          const dLng = rand(-0.002, 0.002);
          return {
            id: `mock-${Date.now()}-${i}`,
            title: `恶搞标注 #${i + 1}`,
            description: '这是本地开发环境的模拟标注，便于快速冒烟测试。',
            latitude: baseLat + dLat,
            longitude: baseLng + dLng,
            reward: Math.floor(rand(5, 50)),
            type: types[i % types.length],
            createdBy: 'mock-user',
            createdAt: new Date().toISOString(),
            distance: computeDistance(dLat, dLng),
            canClaim: i % 2 === 0,
          };
        });
        setAnnotations(mock);
        return;
      }

      const response = await fetch('/api/v1/lbs/nearby', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          latitude: userLocation.lat,
          longitude: userLocation.lng,
          radius: 1000
        })
      });

      if (!response.ok) {
        throw new Error('加载标注失败');
      }

      const data = await response.json();
      setAnnotations(data.data || []);

    } catch (error) {
      console.error('加载附近标注失败:', error);
      addNotification({
        type: 'error',
        title: '加载失败',
        message: '无法加载附近的标注点'
      });
    } finally {
      setIsLoading(false);
    }
  }, [userLocation, user, addNotification, USE_MOCK]);

  // 领取奖励
  const handleClaimReward = async (annotation: MapAnnotation) => {
    if (!user || !annotation.canClaim) return;

    try {
      if (USE_MOCK) {
        addNotification({
          type: 'success',
          title: '🎉 奖励领取成功!',
          message: `获得 ${annotation.reward} 积分奖励！（模拟）`
        });
        onRewardClaim?.(annotation);
        setAnnotations(prev => prev.map(a => a.id === annotation.id ? { ...a, canClaim: false } : a));
        setSelectedAnnotation(prev => (prev && prev.id === annotation.id) ? { ...prev, canClaim: false } as MapAnnotation : prev);
        return;
      }

      const response = await fetch('/api/v1/lbs/claim-reward', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          annotationId: annotation.id,
          latitude: userLocation?.lat,
          longitude: userLocation?.lng
        })
      });

      if (!response.ok) {
        throw new Error('领取奖励失败');
      }

      const data = await response.json();
      addNotification({
        type: 'success',
        title: '🎉 奖励领取成功!',
        message: `获得 ${data.reward} 积分奖励！`
      });
      onRewardClaim?.(annotation);
      loadNearbyAnnotations();

    } catch (error) {
      console.error('领取奖励失败:', error);
      addNotification({
        type: 'error',
        title: '领取失败',
        message: error instanceof Error ? error.message : '未知错误'
      });
    }
  };

  // 更新用户位置
  const updateUserLocation = useCallback(async () => {
    try {
      const location = await getCurrentLocation();
      if (userMarkerRef.current && map) {
        userMarkerRef.current.setPosition([location.lng, location.lat]);
        map.setCenter([location.lng, location.lat]);
      }
      loadNearbyAnnotations();
    } catch (error) {
      addNotification({
        type: 'error',
        title: '位置更新失败',
        message: error instanceof Error ? error.message : '未知错误'
      });
    }
  }, [getCurrentLocation, map, loadNearbyAnnotations, addNotification]);

  // 键盘事件处理
  const handleMapKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    switch (event.key) {
      case 'Enter':
        if (selectedAnnotation && selectedAnnotation.canClaim) {
          handleClaimReward(selectedAnnotation);
        }
        break;
      case 'Escape':
        if (selectedAnnotation) {
          setSelectedAnnotation(null);
          announce('已关闭标注详情');
        }
        break;
      default:
        // 将React事件转换为原生事件以兼容useKeyboardNavigation
        const nativeEvent = new KeyboardEvent('keydown', {
          key: event.key,
          code: event.code,
          ctrlKey: event.ctrlKey,
          shiftKey: event.shiftKey,
          altKey: event.altKey,
          metaKey: event.metaKey
        });
        handleKeyDown(nativeEvent);
    }
  }, [selectedAnnotation, handleClaimReward, handleKeyDown, announce]);

  // 在地图上显示标注（使用 ref 管理地图元素，避免触发额外渲染）
  const displayAnnotationsOnMap = useCallback(() => {
    if (!map || !annotations.length) return;

    // 清除现有标记
    annotationMarkersRef.current.forEach(marker => map.remove([marker]));
    rewardCirclesRef.current.forEach(circle => map.remove([circle]));
    annotationMarkersRef.current = [];
    rewardCirclesRef.current = [];

    const newMarkers: AMapMarker[] = [];
    const newCircles: AMapCircle[] = [];

    annotations.forEach((annotation) => {
      const marker = new window.AMap.Marker({
        position: [annotation.longitude, annotation.latitude],
        icon: new window.AMap.Icon({
          size: new window.AMap.Size(40, 40),
          image: 'data:image/svg+xml;base64,' + btoa(`
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
              <circle cx="20" cy="20" r="18" fill="${getAnnotationColor(annotation.type)}" stroke="white" stroke-width="2"/>
              <text x="20" y="26" text-anchor="middle" fill="white" font-size="16">${getAnnotationEmoji(annotation.type)}</text>
            </svg>
          `),
          imageSize: new window.AMap.Size(40, 40)
        }),
        title: annotation.title,
        zIndex: 50
      });

      marker.on('click', () => {
        setSelectedAnnotation(annotation);
        onAnnotationSelect?.(annotation);
      });

      newMarkers.push(marker);
      map.add([marker]);

      if (showRewardRadius) {
        const circle = new window.AMap.Circle({
          center: [annotation.longitude, annotation.latitude],
          radius: 50,
          strokeColor: getAnnotationColor(annotation.type),
          strokeWeight: 2,
          strokeOpacity: 0.8,
          fillColor: getAnnotationColor(annotation.type),
          fillOpacity: 0.1,
          zIndex: 10
        });
        newCircles.push(circle);
        map.add([circle]);
      }
    });

    annotationMarkersRef.current = newMarkers;
    rewardCirclesRef.current = newCircles;
  }, [map, annotations, showRewardRadius, onAnnotationSelect]);

  // 初始化（仅在挂载时运行一次，避免依赖 userLocation 导致循环）
  useEffect(() => {
    getCurrentLocation()
      .then((location) => {
        if (!AMAP_KEY) {
          setMapDisabled(true);
          addNotification({
            type: 'warning',
            title: '地图未启用',
            message: '未配置 VITE_AMAP_KEY，已启用简化模式（不加载地图脚本）'
          });
          return;
        }

        const init = () => initializeMap(location);
        if (!window.AMap) {
          const script = document.createElement('script');
          script.src = `https://webapi.amap.com/maps?v=1.4.15&key=${AMAP_KEY}`;
          script.onload = init;
          script.onerror = () => {
            setMapDisabled(true);
            addNotification({
              type: 'warning',
              title: '地图未启用',
              message: '地图脚本加载失败，已启用简化模式'
            });
          };
          document.head.appendChild(script);
        } else {
          init();
        }
      })
      .catch((error) => {
        addNotification({
          type: 'error',
          title: '初始化失败',
          message: error.message
        });
      });
  }, [AMAP_KEY, initializeMap, addNotification, getCurrentLocation]);

  // 地图样式变化时仅更新样式，避免重新初始化地图
  useEffect(() => {
    if (map) {
      try {
        // @ts-ignore 高德地图实例提供 setMapStyle
        map.setMapStyle && map.setMapStyle(`amap://styles/${mapStyle}`);
      } catch {}
    }
  }, [mapStyle, map]);

  // 地图初始化后加载标注
  useEffect(() => {
    if (map && userLocation) {
      loadNearbyAnnotations();
    }
  }, [map, userLocation, loadNearbyAnnotations]);

  // 在地图上显示标注
  useEffect(() => {
    displayAnnotationsOnMap();
  }, [displayAnnotationsOnMap]);

  return (
    <div 
      className={`relative bg-white rounded-2xl shadow-xl overflow-hidden ring-1 ring-gray-100 ${className}`}
      id={mapId}
      aria-label={ariaLabel || '地理位置标注地图'}
      aria-describedby={ariaDescribedby}
      onKeyDown={handleMapKeyDown}
      tabIndex={0}
      {...accessibilityProps}
    >
      {/* 地图控制栏 */}
      <div 
        className="flex items-center justify-between p-4 md:p-5 bg-gradient-to-r from-blue-50 to-indigo-50 border-b border-gray-100"
        id={controlsId}
        role="toolbar"
        aria-label="地图控制工具栏"
      >
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-white rounded-xl shadow-sm ring-1 ring-blue-100">
            <MapPin className="w-5 h-5 text-blue-600" />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-gray-900">LBS地图</h3>
            <p className="text-sm text-gray-500">{annotations.length} 个附近标注</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          {/* 刷新位置 */}
          <button
            onClick={updateUserLocation}
            disabled={isLoading}
            className="p-2.5 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            title="刷新位置"
          >
            <RefreshCw className={`w-4 h-4 text-gray-600 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          
          {/* 切换奖励半径显示 */}
          <button
            onClick={() => setShowRewardRadius(!showRewardRadius)}
            className={`p-2.5 border rounded-xl transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              showRewardRadius 
                ? 'bg-blue-100 border-blue-200 text-blue-600' 
                : 'bg-white border-gray-200 text-gray-600 hover:bg-gray-50'
            }`}
            title="切换奖励半径显示"
          >
            {showRewardRadius ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
          </button>
          
          {/* 地图样式切换 */}
          <select
            value={mapStyle}
            onChange={(e) => setMapStyle(e.target.value as 'roadmap' | 'satellite' | 'hybrid' | 'terrain')}
            className="px-3 py-2.5 border border-gray-200 rounded-xl text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="roadmap">标准</option>
            <option value="satellite">卫星</option>
            <option value="hybrid">混合</option>
            <option value="terrain">地形</option>
          </select>
        </div>
      </div>
      
      {/* 地图容器 */}
      <div className="relative">
        {/* 地图未启用提示（非遮罩形式） */}
        {mapDisabled && (
          <div className="mx-4 my-4 md:mx-5 md:my-5">
            <div className="text-center max-w-2xl mx-auto px-4 py-3 md:px-6 md:py-4 bg-amber-50 border border-amber-200 text-amber-900 rounded-xl">
              <div className="mb-1">🚧 地图未启用（简化模式）</div>
              <p className="text-sm">未配置 VITE_AMAP_KEY 或脚本加载失败。开发环境下可使用模拟数据进行功能冒烟测试。</p>
            </div>
          </div>
        )}

        <div 
          ref={mapRef} 
          className="w-full h-[60vh] md:h-[70vh] bg-gray-50 grid place-items-center"
          role="application"
          aria-label="交互式地图区域"
          aria-describedby={controlsId}
        >
          {/* 地图加载中提示（非遮罩形式，仅在等待地图实例时显示） */}
          {!map && !mapDisabled && (
            <div className="text-center">
              <Navigation className="w-12 h-12 mx-auto text-gray-400 mb-4 animate-spin" />
              <p className="text-gray-600">正在加载地图...</p>
            </div>
          )}
        </div>
        
        {/* 加载指示器 */}
        {isLoading && (
          <div className="absolute top-4 left-4 md:top-5 md:left-5 bg-white/90 backdrop-blur rounded-xl shadow-lg px-3 py-2 flex items-center space-x-2 ring-1 ring-gray-100">
            <RefreshCw className="w-4 h-4 text-blue-600 animate-spin" />
            <span className="text-sm text-gray-700">加载中...</span>
          </div>
        )}
      </div>
      
      {/* 选中标注详情（底部浮层） */}
      {selectedAnnotation && (
        <>
          <div className="absolute inset-x-0 bottom-0 z-10">
            <div 
              className="mx-3 mb-3 md:mx-6 md:mb-6 rounded-2xl bg-white/95 supports-[backdrop-filter]:bg-white/85 backdrop-blur shadow-2xl border border-gray-100"
              id={detailsId}
              role="dialog"
              aria-labelledby={`${detailsId}-title`}
              aria-describedby={`${detailsId}-content`}
            >
              <div className="p-4 md:p-5">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <span className="text-xl" aria-hidden="true">{getAnnotationEmoji(selectedAnnotation.type)}</span>
                      <h4 
                        id={`${detailsId}-title`}
                        className="text-base md:text-lg font-semibold text-gray-900"
                      >
                        {selectedAnnotation.title}
                      </h4>
                    </div>
                    <p 
                      id={`${detailsId}-content`}
                      className="text-sm text-gray-600 mb-3 line-clamp-3"
                    >
                      {selectedAnnotation.description}
                    </p>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-gray-500">
                      <span className="px-2 py-1 bg-gray-50 rounded-md border border-gray-100">距离: {selectedAnnotation.distance}m</span>
                      <span className="px-2 py-1 bg-amber-50 text-amber-700 rounded-md border border-amber-100">奖励: {selectedAnnotation.reward} 积分</span>
                      <span className="px-2 py-1 bg-gray-50 rounded-md border border-gray-100">创建者: {selectedAnnotation.createdBy}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2 ml-3">
                    {selectedAnnotation.canClaim && (
                      <button
                        onClick={() => handleClaimReward(selectedAnnotation)}
                        className="flex items-center space-x-1 px-3 py-2 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-xl hover:from-green-700 hover:to-emerald-700 transition-colors shadow focus:outline-none focus:ring-2 focus:ring-green-500"
                        aria-label={`领取 ${selectedAnnotation.reward} 积分奖励`}
                      >
                        <Zap className="w-4 h-4" aria-hidden="true" />
                        <span>领取</span>
                      </button>
                    )}
                    
                    <button
                      onClick={() => setSelectedAnnotation(null)}
                      className="p-2 text-gray-400 hover:text-gray-600 transition-colors rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-gray-300"
                      aria-label="关闭"
                    >
                      ✕
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
          {/* 顶部渐变遮罩以提升底部可读性 */}
          <div className="absolute inset-x-0 bottom-0 h-24 z-0 pointer-events-none bg-gradient-to-t from-white via-white/70 to-transparent" />
        </>
      )}
    </div>
  );
};

export default LBSMap;