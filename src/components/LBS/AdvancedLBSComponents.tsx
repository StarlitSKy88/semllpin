/**
 * 高级LBS组合组件
 * 整合雷达扫描、距离指示器和电池优化功能
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Radar, Navigation, Battery, MapPin, Target, Settings } from 'lucide-react';

import RadarScanner from './RadarScanner';
import DistanceIndicator from './DistanceIndicator';
import BatteryOptimizer from './BatteryOptimizer';

interface Location {
  longitude: number;
  latitude: number;
}

interface GeofenceTarget {
  id: string;
  name: string;
  description?: string;
  location: Location;
  type: 'geofence' | 'poi' | 'destination';
  reward?: number;
  radius?: number;
  isActive?: boolean;
}

interface RadarTarget {
  id: string;
  name: string;
  distance: number;
  bearing: number;
  type: 'user' | 'geofence' | 'poi';
  strength: number;
  data?: any;
}

interface PowerProfile {
  id: string;
  name: string;
  description: string;
  settings: {
    locationUpdateInterval: number;
    accuracyLevel: 'high' | 'medium' | 'low';
    backgroundSync: boolean;
    radarScanInterval: number;
    maxConcurrentRequests: number;
    cacheEnabled: boolean;
  };
  batteryThreshold: number;
  estimatedBatteryLife: number;
}

interface AdvancedLBSComponentsProps {
  userLocation: Location;
  geofenceTargets: GeofenceTarget[];
  onTargetDetected?: (target: RadarTarget) => void;
  onSettingsChange?: (settings: any) => void;
  className?: string;
}

const AdvancedLBSComponents: React.FC<AdvancedLBSComponentsProps> = ({
  userLocation,
  geofenceTargets,
  onTargetDetected,
  onSettingsChange,
  className = ''
}) => {
  const [activeTab, setActiveTab] = useState('radar');
  const [radarTargets, setRadarTargets] = useState<RadarTarget[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<GeofenceTarget | null>(null);
  const [currentPowerProfile, setCurrentPowerProfile] = useState<PowerProfile | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanRange, setScanRange] = useState(500); // 扫描范围（米）
  const [scanSpeed, setScanSpeed] = useState(2000); // 扫描速度（毫秒）
  const [optimizationStats, setOptimizationStats] = useState({
    batteryLevel: 100,
    estimatedRuntime: 0,
    powerSavings: 0
  });

  // 转换地理围栏目标为雷达目标
  const convertToRadarTargets = useCallback((targets: GeofenceTarget[], userLoc: Location): RadarTarget[] => {
    return targets.map(target => {
      const distance = calculateDistance(userLoc, target.location);
      const bearing = calculateBearing(userLoc, target.location);
      
      return {
        id: target.id,
        name: target.name,
        distance,
        bearing,
        type: target.type === 'destination' ? 'poi' : target.type as 'user' | 'geofence' | 'poi',
        strength: Math.max(0.1, Math.min(1, (scanRange - distance) / scanRange)),
        data: target
      };
    }).filter(target => target.distance <= scanRange);
  }, [scanRange]);

  // 计算两点间距离
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

  // 计算方位角
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

  // 处理雷达目标检测
  const handleTargetDetected = useCallback((target: RadarTarget) => {
    console.log('Target detected:', target);
    onTargetDetected?.(target);
    
    // 如果检测到地理围栏，自动选择为导航目标
    if (target.type === 'geofence' && target.data) {
      setSelectedTarget(target.data);
    }
  }, [onTargetDetected]);

  // 处理距离指示器目标选择
  const handleDistanceTargetSelect = useCallback((target: GeofenceTarget) => {
    setSelectedTarget(target);
    
    // 切换到雷达视图并高亮目标
    setActiveTab('radar');
  }, []);

  // 处理电池优化配置变化
  const handlePowerProfileChange = useCallback((profile: PowerProfile) => {
    setCurrentPowerProfile(profile);
    
    // 根据电源配置调整扫描参数
    setScanSpeed(profile.settings.radarScanInterval);
    
    // 根据精度等级调整扫描范围
    const rangeMultiplier = {
      'high': 1.0,
      'medium': 0.8,
      'low': 0.6
    };
    setScanRange(500 * rangeMultiplier[profile.settings.accuracyLevel]);
    
    // 通知父组件设置变化
    onSettingsChange?.({
      powerProfile: profile,
      scanRange: scanRange * rangeMultiplier[profile.settings.accuracyLevel],
      scanSpeed: profile.settings.radarScanInterval
    });
  }, [scanRange, onSettingsChange]);

  // 处理优化设置应用
  const handleOptimizationApply = useCallback((settings: PowerProfile['settings']) => {
    // 应用优化设置到各个组件
    setScanSpeed(settings.radarScanInterval);
    
    // 更新统计信息
    setOptimizationStats(prev => ({
      ...prev,
      powerSavings: prev.powerSavings + 5, // 模拟节电效果
      estimatedRuntime: settings.locationUpdateInterval > 30000 ? 8 : 4 // 预估运行时间
    }));
  }, []);

  // 切换扫描状态
  const toggleScanning = () => {
    setIsScanning(!isScanning);
  };

  // 更新雷达目标
  useEffect(() => {
    const targets = convertToRadarTargets(geofenceTargets, userLocation);
    setRadarTargets(targets);
  }, [geofenceTargets, userLocation, convertToRadarTargets]);

  // 模拟电池电量变化
  useEffect(() => {
    const interval = setInterval(() => {
      setOptimizationStats(prev => ({
        ...prev,
        batteryLevel: Math.max(0, prev.batteryLevel - (isScanning ? 0.1 : 0.05))
      }));
    }, 10000); // 每10秒更新一次

    return () => clearInterval(interval);
  }, [isScanning]);

  return (
    <div className={`w-full max-w-6xl mx-auto ${className}`}>
      {/* 状态概览 */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Target className="h-5 w-5 text-blue-500" />
            <span>高级LBS控制中心</span>
          </CardTitle>
          <CardDescription>
            集成雷达扫描、距离导航和电池优化功能
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* 扫描状态 */}
            <div className="flex items-center space-x-2">
              <div className={`w-3 h-3 rounded-full ${
                isScanning ? 'bg-green-500 animate-pulse' : 'bg-gray-400'
              }`} />
              <div>
                <div className="text-sm font-medium">
                  {isScanning ? '扫描中' : '已停止'}
                </div>
                <div className="text-xs text-gray-600">
                  范围: {scanRange}m
                </div>
              </div>
            </div>
            
            {/* 目标数量 */}
            <div className="flex items-center space-x-2">
              <MapPin className="h-4 w-4 text-blue-500" />
              <div>
                <div className="text-sm font-medium">
                  {radarTargets.length} 个目标
                </div>
                <div className="text-xs text-gray-600">
                  {geofenceTargets.filter(t => t.isActive).length} 个活跃
                </div>
              </div>
            </div>
            
            {/* 电池状态 */}
            <div className="flex items-center space-x-2">
              <Battery className="h-4 w-4 text-green-500" />
              <div>
                <div className="text-sm font-medium">
                  {Math.round(optimizationStats.batteryLevel)}%
                </div>
                <div className="text-xs text-gray-600">
                  预估 {optimizationStats.estimatedRuntime}h
                </div>
              </div>
            </div>
            
            {/* 当前配置 */}
            <div className="flex items-center space-x-2">
              <Settings className="h-4 w-4 text-purple-500" />
              <div>
                <div className="text-sm font-medium">
                  {currentPowerProfile?.name || '默认'}
                </div>
                <div className="text-xs text-gray-600">
                  节电 {optimizationStats.powerSavings}%
                </div>
              </div>
            </div>
          </div>
          
          {/* 控制按钮 */}
          <div className="mt-4 flex items-center space-x-2">
            <Button
              onClick={toggleScanning}
              variant={isScanning ? 'destructive' : 'default'}
              size="sm"
            >
              <Radar className="h-4 w-4 mr-2" />
              {isScanning ? '停止扫描' : '开始扫描'}
            </Button>
            
            {selectedTarget && (
              <Badge variant="secondary" className="flex items-center space-x-1">
                <Navigation className="h-3 w-3" />
                <span>导航至: {selectedTarget.name}</span>
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 功能标签页 */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="radar" className="flex items-center space-x-2">
            <Radar className="h-4 w-4" />
            <span>雷达扫描</span>
          </TabsTrigger>
          <TabsTrigger value="navigation" className="flex items-center space-x-2">
            <Navigation className="h-4 w-4" />
            <span>距离导航</span>
          </TabsTrigger>
          <TabsTrigger value="battery" className="flex items-center space-x-2">
            <Battery className="h-4 w-4" />
            <span>电池优化</span>
          </TabsTrigger>
        </TabsList>

        {/* 雷达扫描标签页 */}
        <TabsContent value="radar" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Radar className="h-5 w-5 text-green-500" />
                <span>雷达扫描器</span>
              </CardTitle>
              <CardDescription>
                实时扫描周围的地理围栏和兴趣点
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RadarScanner
                targets={radarTargets}
                isScanning={isScanning}
                maxRange={scanRange}
                scanSpeed={scanSpeed}
                onTargetDetected={handleTargetDetected}
                showGrid={true}
                className="w-full h-96"
              />
              
              {/* 扫描控制 */}
              <div className="mt-4 grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    扫描范围: {scanRange}m
                  </label>
                  <input
                    type="range"
                    min="100"
                    max="1000"
                    step="50"
                    value={scanRange}
                    onChange={(e) => setScanRange(Number(e.target.value))}
                    className="w-full"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    扫描速度: {scanSpeed}ms
                  </label>
                  <input
                    type="range"
                    min="1000"
                    max="5000"
                    step="500"
                    value={scanSpeed}
                    onChange={(e) => setScanSpeed(Number(e.target.value))}
                    className="w-full"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 距离导航标签页 */}
        <TabsContent value="navigation" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Navigation className="h-5 w-5 text-blue-500" />
                <span>距离导航</span>
              </CardTitle>
              <CardDescription>
                显示到目标地点的距离、方向和导航信息
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DistanceIndicator
                userLocation={userLocation}
                targets={geofenceTargets}
                selectedTargetId={selectedTarget?.id}
                onTargetSelect={handleDistanceTargetSelect}
                showNavigation={true}
                maxDisplayTargets={5}
                sortBy="distance"
                className="h-64"
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* 电池优化标签页 */}
        <TabsContent value="battery" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Battery className="h-5 w-5 text-green-500" />
                <span>电池优化</span>
              </CardTitle>
              <CardDescription>
                监控电池状态并优化LBS功能的电量消耗
              </CardDescription>
            </CardHeader>
            <CardContent>
              <BatteryOptimizer
                onProfileChange={handlePowerProfileChange}
                onOptimizationApply={handleOptimizationApply}
                className="w-full"
              />
              
              {/* 优化建议 */}
              <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                <h4 className="font-medium text-blue-900 mb-2">优化建议</h4>
                <ul className="text-sm text-blue-800 space-y-1">
                  <li>• 在低电量时自动切换到省电模式</li>
                  <li>• 减少后台位置更新频率可延长续航</li>
                  <li>• 启用缓存可减少网络请求次数</li>
                  <li>• 降低雷达扫描精度可节省处理器资源</li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AdvancedLBSComponents;