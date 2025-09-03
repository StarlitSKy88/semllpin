/**
 * LBS设置组件
 * 用于配置地理围栏检测、奖励通知等相关设置
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect } from 'react';
import { Settings, MapPin, Bell, Shield, Battery, Save, RotateCcw } from 'lucide-react';

interface LBSSettingsData {
  // 位置追踪设置
  locationTracking: {
    enabled: boolean;
    accuracy: 'high' | 'medium' | 'low';
    updateInterval: number; // 秒
    backgroundTracking: boolean;
    batteryOptimization: boolean;
  };
  
  // 地理围栏设置
  geofencing: {
    enabled: boolean;
    detectionRadius: number; // 米
    minStayDuration: number; // 秒
    maxDailyRewards: number;
    autoCheckin: boolean;
  };
  
  // 通知设置
  notifications: {
    enabled: boolean;
    rewardNotifications: boolean;
    geofenceEntry: boolean;
    geofenceExit: boolean;
    dailySummary: boolean;
    sound: boolean;
    vibration: boolean;
  };
  
  // 隐私设置
  privacy: {
    shareLocation: boolean;
    anonymousMode: boolean;
    dataRetention: number; // 天数
    allowAnalytics: boolean;
  };
  
  // 性能设置
  performance: {
    cacheSize: number; // MB
    offlineMode: boolean;
    dataCompression: boolean;
    lowDataMode: boolean;
  };
}

interface LBSSettingsProps {
  className?: string;
  onSettingsChange?: (settings: LBSSettingsData) => void;
}

const LBSSettings: React.FC<LBSSettingsProps> = ({
  className = '',
  onSettingsChange
}) => {
  const [settings, setSettings] = useState<LBSSettingsData>({
    locationTracking: {
      enabled: true,
      accuracy: 'high',
      updateInterval: 30,
      backgroundTracking: false,
      batteryOptimization: true
    },
    geofencing: {
      enabled: true,
      detectionRadius: 50,
      minStayDuration: 60,
      maxDailyRewards: 10,
      autoCheckin: true
    },
    notifications: {
      enabled: true,
      rewardNotifications: true,
      geofenceEntry: true,
      geofenceExit: false,
      dailySummary: true,
      sound: true,
      vibration: true
    },
    privacy: {
      shareLocation: false,
      anonymousMode: false,
      dataRetention: 90,
      allowAnalytics: true
    },
    performance: {
      cacheSize: 50,
      offlineMode: true,
      dataCompression: true,
      lowDataMode: false
    }
  });
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [activeTab, setActiveTab] = useState<'location' | 'geofencing' | 'notifications' | 'privacy' | 'performance'>('location');

  // 加载设置
  const loadSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const savedSettings = localStorage.getItem('lbs_settings');
      if (savedSettings) {
        const parsed = JSON.parse(savedSettings);
        setSettings(prev => ({ ...prev, ...parsed }));
      }
    } catch (err) {
      console.error('加载设置失败:', err);
      setError('加载设置失败');
    } finally {
      setLoading(false);
    }
  };

  // 保存设置
  const saveSettings = async () => {
    try {
      setSaving(true);
      setError(null);
      
      // 保存到本地存储
      localStorage.setItem('lbs_settings', JSON.stringify(settings));
      
      // 通知父组件
      onSettingsChange?.(settings);
      
      setHasChanges(false);
    } catch (err) {
      console.error('保存设置失败:', err);
      setError('保存设置失败');
    } finally {
      setSaving(false);
    }
  };

  // 重置设置
  const resetSettings = () => {
    const defaultSettings: LBSSettingsData = {
      locationTracking: {
        enabled: true,
        accuracy: 'high',
        updateInterval: 30,
        backgroundTracking: false,
        batteryOptimization: true
      },
      geofencing: {
        enabled: true,
        detectionRadius: 50,
        minStayDuration: 60,
        maxDailyRewards: 10,
        autoCheckin: true
      },
      notifications: {
        enabled: true,
        rewardNotifications: true,
        geofenceEntry: true,
        geofenceExit: false,
        dailySummary: true,
        sound: true,
        vibration: true
      },
      privacy: {
        shareLocation: false,
        anonymousMode: false,
        dataRetention: 90,
        allowAnalytics: true
      },
      performance: {
        cacheSize: 50,
        offlineMode: true,
        dataCompression: true,
        lowDataMode: false
      }
    };
    
    setSettings(defaultSettings);
    setHasChanges(true);
  };

  // 更新设置
  const updateSetting = (category: keyof LBSSettingsData, key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
    setHasChanges(true);
  };

  // 获取精度描述
  const getAccuracyDescription = (accuracy: string) => {
    const descriptions = {
      high: '高精度 (GPS + 网络，耗电较多)',
      medium: '中等精度 (网络定位，平衡模式)',
      low: '低精度 (基站定位，省电模式)'
    };
    return descriptions[accuracy as keyof typeof descriptions] || '';
  };

  // 获取更新间隔描述
  const getIntervalDescription = (interval: number) => {
    if (interval < 60) return `${interval}秒 (高频率，耗电较多)`;
    if (interval < 300) return `${interval}秒 (中等频率)`;
    return `${interval}秒 (低频率，省电)`;
  };

  useEffect(() => {
    loadSettings();
  }, []);

  if (loading) {
    return (
      <div className={`bg-white rounded-lg shadow-sm p-6 ${className}`}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-gray-200 rounded w-1/3"></div>
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-12 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const tabs = [
    { id: 'location', label: '位置追踪', icon: MapPin },
    { id: 'geofencing', label: '地理围栏', icon: Shield },
    { id: 'notifications', label: '通知设置', icon: Bell },
    { id: 'privacy', label: '隐私设置', icon: Shield },
    { id: 'performance', label: '性能设置', icon: Battery }
  ];

  return (
    <div className={`bg-white rounded-lg shadow-sm ${className}`}>
      {/* 头部 */}
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Settings className="h-6 w-6 text-gray-600" />
            <h2 className="text-lg font-semibold text-gray-900">LBS设置</h2>
          </div>
          
          <div className="flex space-x-2">
            <button
              onClick={resetSettings}
              className="flex items-center space-x-1 px-3 py-2 text-sm text-gray-600 hover:text-gray-900 border border-gray-300 rounded-md hover:bg-gray-50"
            >
              <RotateCcw className="h-4 w-4" />
              <span>重置</span>
            </button>
            
            <button
              onClick={saveSettings}
              disabled={!hasChanges || saving}
              className="flex items-center space-x-1 px-4 py-2 text-sm text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md"
            >
              <Save className="h-4 w-4" />
              <span>{saving ? '保存中...' : '保存设置'}</span>
            </button>
          </div>
        </div>
        
        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <div className="text-red-700 text-sm">{error}</div>
          </div>
        )}
        
        {hasChanges && (
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
            <div className="text-yellow-700 text-sm">设置已修改，请保存更改</div>
          </div>
        )}
      </div>

      {/* 标签页 */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8 px-6">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'location' | 'geofencing' | 'notifications' | 'privacy' | 'performance')}
                className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* 设置内容 */}
      <div className="p-6">
        {/* 位置追踪设置 */}
        {activeTab === 'location' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-gray-900">位置追踪</h3>
                <p className="text-sm text-gray-600">配置位置获取和追踪相关设置</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.locationTracking.enabled}
                  onChange={(e) => updateSetting('locationTracking', 'enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">定位精度</label>
                <select
                  value={settings.locationTracking.accuracy}
                  onChange={(e) => updateSetting('locationTracking', 'accuracy', e.target.value)}
                  disabled={!settings.locationTracking.enabled}
                  className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                >
                  <option value="high">高精度</option>
                  <option value="medium">中等精度</option>
                  <option value="low">低精度</option>
                </select>
                <p className="text-xs text-gray-500 mt-1">{getAccuracyDescription(settings.locationTracking.accuracy)}</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  更新间隔: {settings.locationTracking.updateInterval}秒
                </label>
                <input
                  type="range"
                  min="10"
                  max="300"
                  step="10"
                  value={settings.locationTracking.updateInterval}
                  onChange={(e) => updateSetting('locationTracking', 'updateInterval', parseInt(e.target.value))}
                  disabled={!settings.locationTracking.enabled}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed"
                />
                <p className="text-xs text-gray-500 mt-1">{getIntervalDescription(settings.locationTracking.updateInterval)}</p>
              </div>

              <div className="space-y-3">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={settings.locationTracking.backgroundTracking}
                    onChange={(e) => updateSetting('locationTracking', 'backgroundTracking', e.target.checked)}
                    disabled={!settings.locationTracking.enabled}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                  />
                  <span className="ml-2 text-sm text-gray-700">后台位置追踪</span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={settings.locationTracking.batteryOptimization}
                    onChange={(e) => updateSetting('locationTracking', 'batteryOptimization', e.target.checked)}
                    disabled={!settings.locationTracking.enabled}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                  />
                  <span className="ml-2 text-sm text-gray-700">电池优化模式</span>
                </label>
              </div>
            </div>
          </div>
        )}

        {/* 地理围栏设置 */}
        {activeTab === 'geofencing' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-gray-900">地理围栏</h3>
                <p className="text-sm text-gray-600">配置地理围栏检测和奖励相关设置</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.geofencing.enabled}
                  onChange={(e) => updateSetting('geofencing', 'enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  检测半径: {settings.geofencing.detectionRadius}米
                </label>
                <input
                  type="range"
                  min="10"
                  max="200"
                  step="10"
                  value={settings.geofencing.detectionRadius}
                  onChange={(e) => updateSetting('geofencing', 'detectionRadius', parseInt(e.target.value))}
                  disabled={!settings.geofencing.enabled}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  最小停留时间: {settings.geofencing.minStayDuration}秒
                </label>
                <input
                  type="range"
                  min="30"
                  max="300"
                  step="30"
                  value={settings.geofencing.minStayDuration}
                  onChange={(e) => updateSetting('geofencing', 'minStayDuration', parseInt(e.target.value))}
                  disabled={!settings.geofencing.enabled}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  每日最大奖励次数: {settings.geofencing.maxDailyRewards}
                </label>
                <input
                  type="range"
                  min="1"
                  max="50"
                  step="1"
                  value={settings.geofencing.maxDailyRewards}
                  onChange={(e) => updateSetting('geofencing', 'maxDailyRewards', parseInt(e.target.value))}
                  disabled={!settings.geofencing.enabled}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed"
                />
              </div>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.geofencing.autoCheckin}
                  onChange={(e) => updateSetting('geofencing', 'autoCheckin', e.target.checked)}
                  disabled={!settings.geofencing.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">自动签到</span>
              </label>
            </div>
          </div>
        )}

        {/* 通知设置 */}
        {activeTab === 'notifications' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-gray-900">通知设置</h3>
                <p className="text-sm text-gray-600">配置各种通知和提醒</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.notifications.enabled}
                  onChange={(e) => updateSetting('notifications', 'enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>

            <div className="space-y-3">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.notifications.rewardNotifications}
                  onChange={(e) => updateSetting('notifications', 'rewardNotifications', e.target.checked)}
                  disabled={!settings.notifications.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">奖励通知</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.notifications.geofenceEntry}
                  onChange={(e) => updateSetting('notifications', 'geofenceEntry', e.target.checked)}
                  disabled={!settings.notifications.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">进入地理围栏通知</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.notifications.geofenceExit}
                  onChange={(e) => updateSetting('notifications', 'geofenceExit', e.target.checked)}
                  disabled={!settings.notifications.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">离开地理围栏通知</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.notifications.dailySummary}
                  onChange={(e) => updateSetting('notifications', 'dailySummary', e.target.checked)}
                  disabled={!settings.notifications.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">每日总结</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.notifications.sound}
                  onChange={(e) => updateSetting('notifications', 'sound', e.target.checked)}
                  disabled={!settings.notifications.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">声音提醒</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.notifications.vibration}
                  onChange={(e) => updateSetting('notifications', 'vibration', e.target.checked)}
                  disabled={!settings.notifications.enabled}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">震动提醒</span>
              </label>
            </div>
          </div>
        )}

        {/* 隐私设置 */}
        {activeTab === 'privacy' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900">隐私设置</h3>
              <p className="text-sm text-gray-600">管理您的隐私和数据安全</p>
            </div>

            <div className="space-y-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.privacy.shareLocation}
                  onChange={(e) => updateSetting('privacy', 'shareLocation', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">允许分享位置信息</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.privacy.anonymousMode}
                  onChange={(e) => updateSetting('privacy', 'anonymousMode', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">匿名模式</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.privacy.allowAnalytics}
                  onChange={(e) => updateSetting('privacy', 'allowAnalytics', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">允许数据分析</span>
              </label>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  数据保留期: {settings.privacy.dataRetention}天
                </label>
                <input
                  type="range"
                  min="7"
                  max="365"
                  step="7"
                  value={settings.privacy.dataRetention}
                  onChange={(e) => updateSetting('privacy', 'dataRetention', parseInt(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                />
                <p className="text-xs text-gray-500 mt-1">位置数据将在{settings.privacy.dataRetention}天后自动删除</p>
              </div>
            </div>
          </div>
        )}

        {/* 性能设置 */}
        {activeTab === 'performance' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900">性能设置</h3>
              <p className="text-sm text-gray-600">优化应用性能和数据使用</p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  缓存大小: {settings.performance.cacheSize}MB
                </label>
                <input
                  type="range"
                  min="10"
                  max="200"
                  step="10"
                  value={settings.performance.cacheSize}
                  onChange={(e) => updateSetting('performance', 'cacheSize', parseInt(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                />
              </div>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.performance.offlineMode}
                  onChange={(e) => updateSetting('performance', 'offlineMode', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">离线模式</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.performance.dataCompression}
                  onChange={(e) => updateSetting('performance', 'dataCompression', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">数据压缩</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={settings.performance.lowDataMode}
                  onChange={(e) => updateSetting('performance', 'lowDataMode', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">低数据模式</span>
              </label>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default LBSSettings;