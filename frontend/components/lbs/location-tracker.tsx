'use client';

import React, { useEffect, useState } from 'react';
import { useLBSStore } from '@/lib/stores/lbs-store';
import { lbsService } from '@/lib/services/lbs-service';
import { MapPin, Navigation, Wifi, WifiOff, Award, Clock, AlertCircle, RefreshCw, Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';

interface LocationTrackerProps {
  autoStart?: boolean;
  showNearbyAnnotations?: boolean;
  showRewardHistory?: boolean;
  className?: string;
}

export function LocationTracker({
  autoStart = false,
  showNearbyAnnotations = true,
  showRewardHistory = true,
  className = ''
}: LocationTrackerProps) {
  const {
    currentLocation,
    isLocationLoading,
    isWatchingLocation,
    locationError,
    locationPermission,
    nearbyAnnotations,
    isLoadingNearby,
    nearbyError,
    searchRadius,
    rewardHistory,
    totalEarnings,
    notificationPermission,
    getCurrentLocation,
    startLocationWatch,
    stopLocationWatch,
    loadNearbyAnnotations,
    claimReward,
    loadRewardHistory,
    requestNotificationPermission,
    setSearchRadius,
    clearLocationError,
    clearNearbyError
  } = useLBSStore();

  const [showSettings, setShowSettings] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);

  useEffect(() => {
    if (autoStart) {
      getCurrentLocation();
    }
    
    // 请求通知权限
    requestNotificationPermission();
    
    // 加载奖励历史
    if (showRewardHistory) {
      loadRewardHistory();
    }
  }, [autoStart, showRewardHistory]);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (autoRefresh && currentLocation) {
      interval = setInterval(() => {
        loadNearbyAnnotations();
      }, 30000); // 每30秒刷新一次
    }
    
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [autoRefresh, currentLocation, loadNearbyAnnotations]);

  const handleStartTracking = async () => {
    if (isWatchingLocation) {
      stopLocationWatch();
    } else {
      await startLocationWatch();
    }
  };

  const handleRefreshLocation = () => {
    getCurrentLocation();
  };

  const handleRefreshNearby = () => {
    if (currentLocation) {
      loadNearbyAnnotations();
    }
  };

  const handleClaimReward = async (annotationId: string) => {
    await claimReward(annotationId);
  };

  const formatCoordinates = (lat: number, lng: number) => {
    return `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
  };

  const formatDistance = (meters: number) => {
    return lbsService.formatDistance(meters);
  };

  const getLocationAccuracyColor = (accuracy?: number) => {
    if (!accuracy) return 'text-gray-500';
    if (accuracy <= 10) return 'text-green-500';
    if (accuracy <= 50) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getLocationAccuracyText = (accuracy?: number) => {
    if (!accuracy) return '未知';
    if (accuracy <= 10) return '高精度';
    if (accuracy <= 50) return '中等精度';
    return '低精度';
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* 位置状态卡片 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <MapPin className="h-4 w-4" />
            当前位置
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowSettings(!showSettings)}
            >
              <Settings className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefreshLocation}
              disabled={isLocationLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLocationLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {locationError && (
            <Alert className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription className="flex items-center justify-between">
                {locationError}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearLocationError}
                >
                  ×
                </Button>
              </AlertDescription>
            </Alert>
          )}
          
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {isWatchingLocation ? (
                  <Wifi className="h-4 w-4 text-green-500" />
                ) : (
                  <WifiOff className="h-4 w-4 text-gray-400" />
                )}
                <span className="text-sm">
                  {isWatchingLocation ? '实时跟踪中' : '未开启跟踪'}
                </span>
              </div>
              <Button
                variant={isWatchingLocation ? "destructive" : "default"}
                size="sm"
                onClick={handleStartTracking}
                disabled={isLocationLoading}
              >
                {isWatchingLocation ? '停止跟踪' : '开始跟踪'}
              </Button>
            </div>
            
            {currentLocation && (
              <div className="space-y-2 text-sm">
                <div>
                  <span className="text-gray-500">坐标：</span>
                  <span className="font-mono">
                    {formatCoordinates(currentLocation.latitude, currentLocation.longitude)}
                  </span>
                </div>
                {currentLocation.accuracy && (
                  <div className="flex items-center gap-2">
                    <span className="text-gray-500">精度：</span>
                    <span className={getLocationAccuracyColor(currentLocation.accuracy)}>
                      {getLocationAccuracyText(currentLocation.accuracy)} (±{Math.round(currentLocation.accuracy)}m)
                    </span>
                  </div>
                )}
                {currentLocation.speed && currentLocation.speed > 0 && (
                  <div>
                    <span className="text-gray-500">速度：</span>
                    <span>{(currentLocation.speed * 3.6).toFixed(1)} km/h</span>
                  </div>
                )}
              </div>
            )}
            
            {!currentLocation && !isLocationLoading && (
              <Button
                variant="outline"
                onClick={getCurrentLocation}
                className="w-full"
              >
                <Navigation className="h-4 w-4 mr-2" />
                获取当前位置
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 设置面板 */}
      {showSettings && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">位置设置</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>搜索半径: {formatDistance(searchRadius)}</Label>
              <Slider
                value={[searchRadius]}
                onValueChange={(value) => setSearchRadius(value[0])}
                max={5000}
                min={100}
                step={100}
                className="w-full"
              />
            </div>
            
            <div className="flex items-center justify-between">
              <Label htmlFor="auto-refresh">自动刷新附近标注</Label>
              <Switch
                id="auto-refresh"
                checked={autoRefresh}
                onCheckedChange={setAutoRefresh}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <Label>通知权限</Label>
              <Badge variant={notificationPermission ? "default" : "secondary"}>
                {notificationPermission ? '已开启' : '未开启'}
              </Badge>
            </div>
            
            {!notificationPermission && (
              <Button
                variant="outline"
                size="sm"
                onClick={requestNotificationPermission}
                className="w-full"
              >
                开启通知权限
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* 附近标注 */}
      {showNearbyAnnotations && currentLocation && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Award className="h-4 w-4" />
              附近标注 ({nearbyAnnotations.length})
            </CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefreshNearby}
              disabled={isLoadingNearby}
            >
              <RefreshCw className={`h-4 w-4 ${isLoadingNearby ? 'animate-spin' : ''}`} />
            </Button>
          </CardHeader>
          <CardContent>
            {nearbyError && (
              <Alert className="mb-4">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription className="flex items-center justify-between">
                  {nearbyError}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearNearbyError}
                  >
                    ×
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            
            {nearbyAnnotations.length === 0 && !isLoadingNearby ? (
              <div className="text-center text-gray-500 py-4">
                <Award className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>附近暂无标注</p>
                <p className="text-xs">扩大搜索范围或移动到其他位置</p>
              </div>
            ) : (
              <div className="space-y-3">
                {nearbyAnnotations.map((annotation) => (
                  <div
                    key={annotation.id}
                    className="flex items-center justify-between p-3 border rounded-lg"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h4 className="font-medium text-sm">{annotation.title}</h4>
                        <Badge variant={annotation.isDiscovered ? "secondary" : "default"}>
                          {annotation.isDiscovered ? '已发现' : '未发现'}
                        </Badge>
                      </div>
                      <p className="text-xs text-gray-500 mb-2">{annotation.description}</p>
                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        <span>距离: {formatDistance(annotation.distance)}</span>
                        <span>奖励: ¥{annotation.rewardAmount}</span>
                      </div>
                    </div>
                    
                    {annotation.canClaim && !annotation.isDiscovered && (
                      <Button
                        size="sm"
                        onClick={() => handleClaimReward(annotation.id)}
                        disabled={isLoadingNearby}
                      >
                        领取奖励
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* 奖励历史 */}
      {showRewardHistory && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4" />
              奖励历史
              <Badge variant="outline">总收益: ¥{totalEarnings}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {rewardHistory.length === 0 ? (
              <div className="text-center text-gray-500 py-4">
                <Clock className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>暂无奖励记录</p>
                <p className="text-xs">探索附近的标注来获得奖励</p>
              </div>
            ) : (
              <div className="space-y-2">
                {rewardHistory.slice(0, 5).map((claim) => (
                  <div
                    key={claim.id}
                    className="flex items-center justify-between p-2 border rounded text-sm"
                  >
                    <div>
                      <div className="font-medium">¥{claim.amount}</div>
                      <div className="text-xs text-gray-500">
                        {new Date(claim.claimedAt).toLocaleDateString()}
                      </div>
                    </div>
                    <Badge
                      variant={
                        claim.status === 'approved' ? 'default' :
                        claim.status === 'pending' ? 'secondary' : 'destructive'
                      }
                    >
                      {claim.status === 'approved' ? '已到账' :
                       claim.status === 'pending' ? '审核中' : '已拒绝'}
                    </Badge>
                  </div>
                ))}
                
                {rewardHistory.length > 5 && (
                  <div className="text-center text-xs text-gray-500 pt-2">
                    还有 {rewardHistory.length - 5} 条记录...
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default LocationTracker;