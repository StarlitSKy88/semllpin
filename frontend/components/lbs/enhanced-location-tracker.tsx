'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence, useAnimation } from 'framer-motion';
import { 
  Navigation, MapPin, Zap, Signal, Battery, Wifi, WifiOff,
  Target, Compass, Clock, TrendingUp, Activity, Radar,
  Settings, RefreshCw, Play, Pause, AlertTriangle,
  CheckCircle, Award, Eye, Bell, BellOff
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';

interface LocationData {
  latitude: number;
  longitude: number;
  accuracy: number;
  altitude?: number;
  speed?: number;
  heading?: number;
  timestamp: string;
}

interface NearbyReward {
  id: string;
  title: string;
  distance: number;
  rewardAmount: number;
  category: string;
  isDiscovered: boolean;
  canClaim: boolean;
  direction?: number; // Bearing in degrees
}

interface EnhancedLocationTrackerProps {
  className?: string;
  autoStart?: boolean;
  onLocationUpdate?: (location: LocationData) => void;
  onRewardDiscovery?: (reward: NearbyReward) => void;
  showNearbyRewards?: boolean;
  trackingRadius?: number;
}

const EnhancedLocationTracker: React.FC<EnhancedLocationTrackerProps> = ({
  className = "",
  autoStart = false,
  onLocationUpdate,
  onRewardDiscovery,
  showNearbyRewards = true,
  trackingRadius = 1000
}) => {
  // State management
  const [isTracking, setIsTracking] = useState(false);
  const [currentLocation, setCurrentLocation] = useState<LocationData | null>(null);
  const [locationHistory, setLocationHistory] = useState<LocationData[]>([]);
  const [nearbyRewards, setNearbyRewards] = useState<NearbyReward[]>([]);
  const [trackingAccuracy, setTrackingAccuracy] = useState<'high' | 'medium' | 'low'>('high');
  const [batteryOptimization, setBatteryOptimization] = useState(false);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [trackingRadius_, setTrackingRadius_] = useState(trackingRadius);
  const [isLoadingLocation, setIsLoadingLocation] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Performance monitoring
  const [locationUpdateCount, setLocationUpdateCount] = useState(0);
  const [lastUpdateTime, setLastUpdateTime] = useState<Date | null>(null);
  const [trackingStartTime, setTrackingStartTime] = useState<Date | null>(null);

  // Animation controls
  const radarAnimation = useAnimation();
  const compassAnimation = useAnimation();

  // Geolocation options based on accuracy setting
  const getLocationOptions = useCallback((): PositionOptions => {
    const accuracySettings = {
      high: {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 5000
      },
      medium: {
        enableHighAccuracy: true,
        timeout: 15000,
        maximumAge: 30000
      },
      low: {
        enableHighAccuracy: false,
        timeout: 20000,
        maximumAge: 60000
      }
    };

    return batteryOptimization 
      ? accuracySettings.low 
      : accuracySettings[trackingAccuracy];
  }, [trackingAccuracy, batteryOptimization]);

  // Mock nearby rewards (in real app, this would come from API)
  const mockNearbyRewards: NearbyReward[] = useMemo(() => [
    {
      id: '1',
      title: '神秘咖啡馆',
      distance: 120,
      rewardAmount: 15,
      category: 'food',
      isDiscovered: false,
      canClaim: true,
      direction: 45
    },
    {
      id: '2',
      title: '街头艺术墙',
      distance: 80,
      rewardAmount: 25,
      category: 'urban',
      isDiscovered: false,
      canClaim: true,
      direction: 180
    },
    {
      id: '3',
      title: '隐藏花园',
      distance: 200,
      rewardAmount: 30,
      category: 'nature',
      isDiscovered: true,
      canClaim: false,
      direction: 315
    }
  ], []);

  // Filter nearby rewards within tracking radius
  const filteredRewards = useMemo(() => 
    mockNearbyRewards.filter(reward => reward.distance <= trackingRadius_),
    [mockNearbyRewards, trackingRadius_]
  );

  // Update location
  const updateLocation = useCallback((position: GeolocationPosition) => {
    const locationData: LocationData = {
      latitude: position.coords.latitude,
      longitude: position.coords.longitude,
      accuracy: position.coords.accuracy,
      altitude: position.coords.altitude || undefined,
      speed: position.coords.speed || undefined,
      heading: position.coords.heading || undefined,
      timestamp: new Date().toISOString()
    };

    setCurrentLocation(locationData);
    setLocationHistory(prev => [...prev.slice(-49), locationData]); // Keep last 50 locations
    setLocationUpdateCount(prev => prev + 1);
    setLastUpdateTime(new Date());
    setError(null);

    onLocationUpdate?.(locationData);

    // Check for nearby rewards
    const newDiscoveries = filteredRewards.filter(reward => 
      !reward.isDiscovered && reward.distance <= 50 && reward.canClaim
    );

    newDiscoveries.forEach(reward => onRewardDiscovery?.(reward));
  }, [onLocationUpdate, onRewardDiscovery, filteredRewards]);

  // Handle location error
  const handleLocationError = useCallback((error: GeolocationPositionError) => {
    const errorMessages = {
      1: '位置访问被拒绝。请在设置中允许位置权限。',
      2: '无法获取位置信息。请检查网络连接。',
      3: '位置请求超时。请重试。'
    };

    setError(errorMessages[error.code as keyof typeof errorMessages] || '位置获取失败');
    setIsLoadingLocation(false);
  }, []);

  // Start location tracking
  const startTracking = useCallback(() => {
    if (!navigator.geolocation) {
      setError('您的浏览器不支持位置服务');
      return;
    }

    setIsTracking(true);
    setIsLoadingLocation(true);
    setError(null);
    setTrackingStartTime(new Date());
    setLocationUpdateCount(0);

    const options = getLocationOptions();
    
    const watchId = navigator.geolocation.watchPosition(
      updateLocation,
      handleLocationError,
      options
    );

    // Start animations
    radarAnimation.start({
      rotate: 360,
      transition: { duration: 2, repeat: Infinity, ease: "linear" }
    });

    // Store watch ID for cleanup
    (window as any).locationWatchId = watchId;

    // Get initial location
    navigator.geolocation.getCurrentPosition(
      (position) => {
        updateLocation(position);
        setIsLoadingLocation(false);
      },
      handleLocationError,
      options
    );
  }, [getLocationOptions, updateLocation, handleLocationError, radarAnimation]);

  // Stop location tracking
  const stopTracking = useCallback(() => {
    if ((window as any).locationWatchId) {
      navigator.geolocation.clearWatch((window as any).locationWatchId);
      delete (window as any).locationWatchId;
    }

    setIsTracking(false);
    setTrackingStartTime(null);
    radarAnimation.stop();
  }, [radarAnimation]);

  // Auto-start tracking if enabled
  useEffect(() => {
    if (autoStart) {
      startTracking();
    }

    return () => {
      if ((window as any).locationWatchId) {
        navigator.geolocation.clearWatch((window as any).locationWatchId);
      }
    };
  }, [autoStart, startTracking]);

  // Update nearby rewards
  useEffect(() => {
    if (currentLocation) {
      setNearbyRewards(filteredRewards);
    }
  }, [currentLocation, filteredRewards]);

  // Format distance
  const formatDistance = (meters: number): string => {
    return meters < 1000 ? `${Math.round(meters)}m` : `${(meters / 1000).toFixed(1)}km`;
  };

  // Format accuracy
  const getAccuracyColor = (accuracy: number): string => {
    if (accuracy <= 10) return 'text-green-400';
    if (accuracy <= 30) return 'text-yellow-400';
    return 'text-red-400';
  };

  // Calculate tracking duration
  const trackingDuration = useMemo(() => {
    if (!trackingStartTime) return null;
    const now = new Date();
    const diff = Math.floor((now.getTime() - trackingStartTime.getTime()) / 1000);
    const minutes = Math.floor(diff / 60);
    const seconds = diff % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }, [trackingStartTime, lastUpdateTime]);

  // Get direction arrow rotation
  const getDirectionRotation = (direction?: number): number => {
    if (!direction || !currentLocation?.heading) return direction || 0;
    return direction - currentLocation.heading;
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Main Status Card */}
      <Card className="bg-white/10 backdrop-blur-xl border-white/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-white flex items-center gap-2">
              <motion.div
                animate={radarAnimation}
                className="relative"
              >
                <Radar className="w-5 h-5" />
                {isTracking && (
                  <motion.div
                    className="absolute inset-0 border-2 border-blue-400 rounded-full"
                    animate={{ scale: [1, 1.5, 1], opacity: [1, 0, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                )}
              </motion.div>
              实时位置追踪
            </CardTitle>
            
            <div className="flex items-center gap-2">
              <Badge variant={isTracking ? "default" : "secondary"}>
                {isTracking ? (
                  <>
                    <Activity className="w-3 h-3 mr-1" />
                    追踪中
                  </>
                ) : (
                  '已停止'
                )}
              </Badge>
              
              <Button
                variant="ghost"
                size="sm"
                onClick={isTracking ? stopTracking : startTracking}
                disabled={isLoadingLocation}
                className="text-white hover:bg-white/10"
              >
                {isLoadingLocation ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : isTracking ? (
                  <Pause className="w-4 h-4" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
              </Button>
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-4">
          {/* Error Display */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-2 p-3 bg-red-500/20 border border-red-500/30 rounded-lg text-red-300"
            >
              <AlertTriangle className="w-4 h-4" />
              <span className="text-sm">{error}</span>
            </motion.div>
          )}

          {/* Location Info */}
          {currentLocation && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="grid grid-cols-2 gap-4"
            >
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <Navigation className="w-4 h-4 text-blue-400" />
                  <span className="text-white/70">坐标</span>
                </div>
                <div className="text-xs font-mono text-white bg-white/10 rounded px-2 py-1">
                  {currentLocation.latitude.toFixed(6)}, {currentLocation.longitude.toFixed(6)}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <Target className="w-4 h-4 text-green-400" />
                  <span className="text-white/70">精度</span>
                </div>
                <div className={`text-sm font-medium ${getAccuracyColor(currentLocation.accuracy)}`}>
                  ±{Math.round(currentLocation.accuracy)}m
                </div>
              </div>

              {currentLocation.speed !== undefined && currentLocation.speed > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm">
                    <TrendingUp className="w-4 h-4 text-purple-400" />
                    <span className="text-white/70">速度</span>
                  </div>
                  <div className="text-sm text-white">
                    {(currentLocation.speed * 3.6).toFixed(1)} km/h
                  </div>
                </div>
              )}

              {currentLocation.heading !== undefined && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm">
                    <Compass className="w-4 h-4 text-orange-400" />
                    <span className="text-white/70">方向</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <motion.div
                      style={{ rotate: currentLocation.heading }}
                      className="text-orange-400"
                    >
                      <Navigation className="w-4 h-4" />
                    </motion.div>
                    <span className="text-sm text-white">{Math.round(currentLocation.heading)}°</span>
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* Tracking Stats */}
          {isTracking && trackingDuration && (
            <div className="flex items-center justify-between text-xs text-white/60 pt-2 border-t border-white/10">
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {trackingDuration}
                </span>
                <span className="flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" />
                  {locationUpdateCount} 次更新
                </span>
              </div>
              {lastUpdateTime && (
                <span>{lastUpdateTime.toLocaleTimeString()}</span>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Nearby Rewards */}
      {showNearbyRewards && nearbyRewards.length > 0 && (
        <Card className="bg-white/10 backdrop-blur-xl border-white/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-white flex items-center gap-2">
              <Award className="w-5 h-5 text-yellow-400" />
              附近奖励 ({nearbyRewards.length})
            </CardTitle>
          </CardHeader>
          
          <CardContent className="space-y-3">
            <AnimatePresence>
              {nearbyRewards.map((reward, index) => (
                <motion.div
                  key={reward.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: index * 0.1 }}
                  className="flex items-center justify-between p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <MapPin className="w-5 h-5 text-blue-400" />
                      {reward.direction && (
                        <motion.div
                          className="absolute -inset-2 border border-blue-400/50 rounded-full"
                          style={{ 
                            rotate: getDirectionRotation(reward.direction),
                            borderTopColor: '#60a5fa'
                          }}
                        />
                      )}
                    </div>
                    
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-white font-medium text-sm">{reward.title}</span>
                        {reward.isDiscovered && (
                          <Eye className="w-3 h-3 text-green-400" />
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-white/60">
                        <span>{formatDistance(reward.distance)}</span>
                        <span>¥{reward.rewardAmount}</span>
                      </div>
                    </div>
                  </div>

                  {reward.canClaim && !reward.isDiscovered && reward.distance <= 50 && (
                    <Button
                      size="sm"
                      className="bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white"
                      onClick={() => onRewardDiscovery?.(reward)}
                    >
                      <Zap className="w-3 h-3 mr-1" />
                      领取
                    </Button>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
          </CardContent>
        </Card>
      )}

      {/* Settings Panel */}
      <Card className="bg-white/10 backdrop-blur-xl border-white/20">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Settings className="w-5 h-5" />
            追踪设置
          </CardTitle>
        </CardHeader>
        
        <CardContent className="space-y-4">
          {/* Tracking Accuracy */}
          <div>
            <Label className="text-white text-sm mb-2 block">追踪精度</Label>
            <div className="grid grid-cols-3 gap-2">
              {(['high', 'medium', 'low'] as const).map((level) => (
                <button
                  key={level}
                  onClick={() => setTrackingAccuracy(level)}
                  className={`p-2 rounded-lg text-xs transition-colors ${
                    trackingAccuracy === level
                      ? 'bg-blue-500 text-white'
                      : 'bg-white/10 text-white/70 hover:bg-white/20'
                  }`}
                >
                  {level === 'high' && '高精度'}
                  {level === 'medium' && '中等'}
                  {level === 'low' && '省电'}
                </button>
              ))}
            </div>
          </div>

          {/* Tracking Radius */}
          <div>
            <Label className="text-white text-sm mb-2 block">
              搜索半径: {formatDistance(trackingRadius_)}
            </Label>
            <Slider
              value={[trackingRadius_]}
              onValueChange={(value) => setTrackingRadius_(value[0])}
              max={5000}
              min={100}
              step={100}
              className="w-full"
            />
          </div>

          {/* Battery Optimization */}
          <div className="flex items-center justify-between">
            <Label className="text-white text-sm">省电模式</Label>
            <Switch
              checked={batteryOptimization}
              onCheckedChange={setBatteryOptimization}
            />
          </div>

          {/* Notifications */}
          <div className="flex items-center justify-between">
            <Label className="text-white text-sm flex items-center gap-2">
              {notificationsEnabled ? <Bell className="w-4 h-4" /> : <BellOff className="w-4 h-4" />}
              奖励通知
            </Label>
            <Switch
              checked={notificationsEnabled}
              onCheckedChange={setNotificationsEnabled}
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default EnhancedLocationTracker;