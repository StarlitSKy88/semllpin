/**
 * 电池优化组件
 * 监控和优化LBS功能的电池使用情况
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Battery, AlertTriangle, CheckCircle, Clock, Smartphone } from 'lucide-react';

interface BatteryInfo {
  level: number; // 电池电量百分比 (0-100)
  charging: boolean; // 是否正在充电
  chargingTime?: number; // 充电时间（秒）
  dischargingTime?: number; // 放电时间（秒）
}

interface PowerProfile {
  id: string;
  name: string;
  description: string;
  settings: {
    locationUpdateInterval: number; // 位置更新间隔（毫秒）
    accuracyLevel: 'high' | 'medium' | 'low'; // 精度等级
    backgroundSync: boolean; // 后台同步
    radarScanInterval: number; // 雷达扫描间隔（毫秒）
    maxConcurrentRequests: number; // 最大并发请求数
    cacheEnabled: boolean; // 缓存启用
  };
  batteryThreshold: number; // 电池阈值
  estimatedBatteryLife: number; // 预估电池续航（小时）
}

interface BatteryOptimizerProps {
  onProfileChange?: (profile: PowerProfile) => void;
  onOptimizationApply?: (settings: PowerProfile['settings']) => void;
  className?: string;
}

const BatteryOptimizer: React.FC<BatteryOptimizerProps> = ({
  onProfileChange,
  onOptimizationApply,
  className = ''
}) => {
  const [batteryInfo, setBatteryInfo] = useState<BatteryInfo | null>(null);
  const [currentProfile, setCurrentProfile] = useState<PowerProfile | null>(null);
  const [isSupported, setIsSupported] = useState(false);
  const [powerUsageStats, setPowerUsageStats] = useState({
    totalUsage: 0,
    locationRequests: 0,
    networkRequests: 0,
    lastOptimization: null as Date | null
  });
  const [autoOptimization, setAutoOptimization] = useState(true);

  // 预定义的电源配置文件
  const powerProfiles: PowerProfile[] = [
    {
      id: 'performance',
      name: '性能模式',
      description: '最佳性能，高精度定位，适合短时间使用',
      settings: {
        locationUpdateInterval: 5000, // 5秒
        accuracyLevel: 'high',
        backgroundSync: true,
        radarScanInterval: 2000, // 2秒
        maxConcurrentRequests: 5,
        cacheEnabled: true
      },
      batteryThreshold: 50,
      estimatedBatteryLife: 2
    },
    {
      id: 'balanced',
      name: '平衡模式',
      description: '性能与续航平衡，适合日常使用',
      settings: {
        locationUpdateInterval: 15000, // 15秒
        accuracyLevel: 'medium',
        backgroundSync: true,
        radarScanInterval: 5000, // 5秒
        maxConcurrentRequests: 3,
        cacheEnabled: true
      },
      batteryThreshold: 30,
      estimatedBatteryLife: 4
    },
    {
      id: 'power_saver',
      name: '省电模式',
      description: '最大化续航时间，降低更新频率',
      settings: {
        locationUpdateInterval: 60000, // 1分钟
        accuracyLevel: 'low',
        backgroundSync: false,
        radarScanInterval: 15000, // 15秒
        maxConcurrentRequests: 1,
        cacheEnabled: true
      },
      batteryThreshold: 15,
      estimatedBatteryLife: 8
    },
    {
      id: 'ultra_saver',
      name: '超级省电',
      description: '极限省电，仅基础功能',
      settings: {
        locationUpdateInterval: 300000, // 5分钟
        accuracyLevel: 'low',
        backgroundSync: false,
        radarScanInterval: 60000, // 1分钟
        maxConcurrentRequests: 1,
        cacheEnabled: true
      },
      batteryThreshold: 10,
      estimatedBatteryLife: 12
    }
  ];

  // 获取电池信息
  const getBatteryInfo = useCallback(async (): Promise<(() => void) | undefined> => {
    if ('getBattery' in navigator) {
      try {
        const battery = await (navigator as any).getBattery();
        const info: BatteryInfo = {
          level: Math.round(battery.level * 100),
          charging: battery.charging,
          chargingTime: battery.chargingTime,
          dischargingTime: battery.dischargingTime
        };
        setBatteryInfo(info);
        setIsSupported(true);
        
        // 监听电池状态变化
        const updateBatteryInfo = () => {
          setBatteryInfo({
            level: Math.round(battery.level * 100),
            charging: battery.charging,
            chargingTime: battery.chargingTime,
            dischargingTime: battery.dischargingTime
          });
        };
        
        battery.addEventListener('levelchange', updateBatteryInfo);
        battery.addEventListener('chargingchange', updateBatteryInfo);
        
        return () => {
          battery.removeEventListener('levelchange', updateBatteryInfo);
          battery.removeEventListener('chargingchange', updateBatteryInfo);
        };
      } catch (error) {
        console.warn('Battery API not supported:', error);
        setIsSupported(false);
        return undefined;
      }
    } else {
      setIsSupported(false);
      return undefined;
    }
  }, []);

  // 根据电池电量自动选择配置文件
  const getRecommendedProfile = useCallback((batteryLevel: number): PowerProfile => {
    if (batteryLevel <= 10) {
      return powerProfiles.find(p => p.id === 'ultra_saver')!;
    } else if (batteryLevel <= 20) {
      return powerProfiles.find(p => p.id === 'power_saver')!;
    } else if (batteryLevel <= 50) {
      return powerProfiles.find(p => p.id === 'balanced')!;
    } else {
      return powerProfiles.find(p => p.id === 'performance')!;
    }
  }, [powerProfiles]);

  // 应用优化设置
  const applyOptimization = useCallback((profile: PowerProfile) => {
    setCurrentProfile(profile);
    onProfileChange?.(profile);
    onOptimizationApply?.(profile.settings);
    
    // 更新统计信息
    setPowerUsageStats(prev => ({
      ...prev,
      lastOptimization: new Date()
    }));
    
    // 保存到本地存储
    localStorage.setItem('lbs_power_profile', JSON.stringify(profile));
  }, [onProfileChange, onOptimizationApply]);

  // 自动优化
  const performAutoOptimization = useCallback(() => {
    if (!batteryInfo || !autoOptimization) return;
    
    const recommendedProfile = getRecommendedProfile(batteryInfo.level);
    
    // 如果当前配置文件不是推荐的，则自动切换
    if (!currentProfile || currentProfile.id !== recommendedProfile.id) {
      applyOptimization(recommendedProfile);
    }
  }, [batteryInfo, autoOptimization, currentProfile, getRecommendedProfile, applyOptimization]);

  // 手动选择配置文件
  const selectProfile = (profileId: string) => {
    const profile = powerProfiles.find(p => p.id === profileId);
    if (profile) {
      applyOptimization(profile);
    }
  };



  // 获取电池状态颜色
  const getBatteryColor = (level: number, charging: boolean): string => {
    if (charging) return 'text-green-500';
    if (level <= 10) return 'text-red-500';
    if (level <= 20) return 'text-orange-500';
    if (level <= 50) return 'text-yellow-500';
    return 'text-green-500';
  };

  // 获取电池图标
  const getBatteryIcon = (_level: number, charging: boolean) => {
    if (charging) return <Battery className="h-4 w-4" />;
    return <Battery className="h-4 w-4" />;
  };

  // 格式化时间
  const formatTime = (seconds: number): string => {
    if (!seconds || seconds === Infinity) return '未知';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}小时${minutes}分钟`;
  };

  // 初始化
  useEffect(() => {
    const initBattery = async () => {
      const cleanup = await getBatteryInfo();
      return cleanup;
    };
    
    const cleanupPromise = initBattery();
    return () => {
      cleanupPromise.then(cleanup => cleanup?.());
    };
    
    // 从本地存储恢复配置
    const savedProfile = localStorage.getItem('lbs_power_profile');
    if (savedProfile) {
      try {
        const profile = JSON.parse(savedProfile);
        setCurrentProfile(profile);
      } catch (error) {
        console.warn('Failed to parse saved power profile:', error);
      }
    }
  }, [getBatteryInfo]);

  // 自动优化监听
  useEffect(() => {
    if (autoOptimization) {
      performAutoOptimization();
    }
  }, [batteryInfo?.level, autoOptimization, performAutoOptimization]);

  // 模拟电池信息（如果不支持Battery API）
  useEffect(() => {
    if (!isSupported) {
      // 模拟电池信息用于演示
      setBatteryInfo({
        level: 65,
        charging: false
      });
    }
  }, [isSupported]);

  return (
    <div className={`bg-white rounded-lg shadow-lg ${className}`}>
      {/* 标题栏 */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <div className="flex items-center space-x-2">
          <Battery className="h-5 w-5 text-green-500" />
          <h3 className="text-lg font-semibold text-gray-900">电池优化</h3>
        </div>
        
        {!isSupported && (
          <div className="flex items-center space-x-1 text-orange-500">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-sm">API不支持</span>
          </div>
        )}
      </div>

      {/* 电池状态 */}
      {batteryInfo && (
        <div className="p-4 border-b border-gray-200">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <div className={getBatteryColor(batteryInfo.level, batteryInfo.charging)}>
                {getBatteryIcon(batteryInfo.level, batteryInfo.charging)}
              </div>
              <span className="text-lg font-semibold">{batteryInfo.level}%</span>
              {batteryInfo.charging && (
                <span className="text-sm text-green-600">充电中</span>
              )}
            </div>
            
            <div className="text-right text-sm text-gray-600">
              {batteryInfo.charging && batteryInfo.chargingTime && (
                <div>充满需要: {formatTime(batteryInfo.chargingTime)}</div>
              )}
              {!batteryInfo.charging && batteryInfo.dischargingTime && (
                <div>剩余时间: {formatTime(batteryInfo.dischargingTime)}</div>
              )}
            </div>
          </div>
          
          {/* 电池电量条 */}
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className={`h-2 rounded-full transition-all duration-300 ${
                batteryInfo.charging ? 'bg-green-500' :
                batteryInfo.level <= 10 ? 'bg-red-500' :
                batteryInfo.level <= 20 ? 'bg-orange-500' :
                batteryInfo.level <= 50 ? 'bg-yellow-500' : 'bg-green-500'
              }`}
              style={{ width: `${batteryInfo.level}%` }}
            />
          </div>
        </div>
      )}

      {/* 自动优化开关 */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">自动优化</h4>
            <p className="text-sm text-gray-600">根据电池电量自动调整性能设置</p>
          </div>
          <button
            onClick={() => setAutoOptimization(!autoOptimization)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              autoOptimization ? 'bg-blue-500' : 'bg-gray-300'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                autoOptimization ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* 电源配置文件 */}
      <div className="p-4">
        <h4 className="font-medium text-gray-900 mb-3">电源配置文件</h4>
        <div className="space-y-2">
          {powerProfiles.map(profile => {
            const isActive = currentProfile?.id === profile.id;
            const isRecommended = batteryInfo && 
              getRecommendedProfile(batteryInfo.level).id === profile.id;
            
            return (
              <div
                key={profile.id}
                onClick={() => selectProfile(profile.id)}
                className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                  isActive
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <h5 className="font-medium text-gray-900">{profile.name}</h5>
                      {isActive && (
                        <CheckCircle className="h-4 w-4 text-blue-500" />
                      )}
                      {isRecommended && !isActive && (
                        <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full">
                          推荐
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-600 mt-1">{profile.description}</p>
                    
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-gray-500">
                      <div>更新间隔: {profile.settings.locationUpdateInterval / 1000}秒</div>
                      <div>精度: {profile.settings.accuracyLevel}</div>
                      <div>预估续航: {profile.estimatedBatteryLife}小时</div>
                      <div>电池阈值: {profile.batteryThreshold}%</div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 使用统计 */}
      <div className="p-4 border-t border-gray-200">
        <h4 className="font-medium text-gray-900 mb-3">使用统计</h4>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center space-x-2">
            <Smartphone className="h-4 w-4 text-gray-500" />
            <div>
              <div className="text-gray-600">位置请求</div>
              <div className="font-medium">{powerUsageStats.locationRequests}</div>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-4 w-4 text-gray-500" />
            <div>
              <div className="text-gray-600">网络请求</div>
              <div className="font-medium">{powerUsageStats.networkRequests}</div>
            </div>
          </div>
        </div>
        
        {powerUsageStats.lastOptimization && (
          <div className="mt-3 flex items-center space-x-2 text-sm text-gray-600">
            <Clock className="h-4 w-4" />
            <span>
              上次优化: {powerUsageStats.lastOptimization.toLocaleTimeString()}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export default BatteryOptimizer;