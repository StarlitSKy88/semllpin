import {  } from 'antd';
import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Settings,
  User,
  Bell,
  Shield,
  Palette,
  Globe,
  Database,
  Save,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  Search,
  Wifi,
  WifiOff,
  HelpCircle,
  FileText,
  Star
} from 'lucide-react';
import { LoadingButton } from './InteractionFeedback';
import { toast } from 'sonner';
import { useMobile } from '../hooks/useMobile';
import { useNetworkStatus } from '../hooks/useNetworkStatus';
import { LoadingState } from './EmptyState';

interface SettingSection {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  settings: Setting[];
}

type SettingValue = string | number | boolean | null;

interface Setting {
  id: string;
  type: 'toggle' | 'select' | 'input' | 'slider' | 'color' | 'file' | 'button';
  label: string;
  description?: string;
  value: SettingValue;
  options?: { label: string; value: SettingValue }[];
  min?: number;
  max?: number;
  step?: number;
  accept?: string;
  action?: () => void;
  disabled?: boolean;
  warning?: string;
  premium?: boolean;
}

interface AdvancedSettingsProps {
  onSettingChange?: (sectionId: string, settingId: string, value: SettingValue) => void;
  className?: string;
}

const AdvancedSettings: React.FC<AdvancedSettingsProps> = ({
  onSettingChange,
  className = ''
}) => {
  const [activeSection, setActiveSection] = useState<string>('profile');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['profile']));
  const [settings, setSettings] = useState<Record<string, SettingValue>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [pendingChanges, setPendingChanges] = useState<Set<string>>(new Set());
  
  const { isMobile } = useMobile();
  const { isOnline } = useNetworkStatus();

  // 设置配置
  const settingSections: SettingSection[] = [
    {
      id: 'profile',
      title: '个人资料',
      description: '管理您的个人信息和账户设置',
      icon: User,
      settings: [
        {
          id: 'displayName',
          type: 'input',
          label: '显示名称',
          description: '其他用户看到的您的名称',
          value: settings.displayName || ''
        },
        {
          id: 'bio',
          type: 'input',
          label: '个人简介',
          description: '简短介绍您自己',
          value: settings.bio || ''
        },
        {
          id: 'avatar',
          type: 'file',
          label: '头像',
          description: '上传您的头像图片',
          value: settings.avatar || '',
          accept: 'image/*'
        },
        {
          id: 'profileVisibility',
          type: 'select',
          label: '资料可见性',
          description: '控制谁可以查看您的资料',
          value: settings.profileVisibility || 'public',
          options: [
            { label: '公开', value: 'public' },
            { label: '仅关注者', value: 'followers' },
            { label: '私密', value: 'private' }
          ]
        },
        {
          id: 'showLocation',
          type: 'toggle',
          label: '显示位置信息',
          description: '在您的资料中显示位置',
          value: settings.showLocation || false
        }
      ]
    },
    {
      id: 'notifications',
      title: '通知设置',
      description: '管理您接收通知的方式和时间',
      icon: Bell,
      settings: [
        {
          id: 'pushNotifications',
          type: 'toggle',
          label: '推送通知',
          description: '接收应用推送通知',
          value: settings.pushNotifications || true
        },
        {
          id: 'emailNotifications',
          type: 'toggle',
          label: '邮件通知',
          description: '接收邮件通知',
          value: settings.emailNotifications || true
        },
        {
          id: 'notificationSound',
          type: 'toggle',
          label: '通知声音',
          description: '播放通知声音',
          value: settings.notificationSound || true
        },
        {
          id: 'vibration',
          type: 'toggle',
          label: '振动',
          description: '通知时振动',
          value: settings.vibration || true
        },
        {
          id: 'quietHours',
          type: 'toggle',
          label: '免打扰时间',
          description: '在指定时间段内静音通知',
          value: settings.quietHours || false
        },
        {
          id: 'notificationTypes',
          type: 'select',
          label: '通知类型',
          description: '选择要接收的通知类型',
          value: settings.notificationTypes || 'all',
          options: [
            { label: '全部', value: 'all' },
            { label: '仅重要', value: 'important' },
            { label: '仅提及', value: 'mentions' },
            { label: '关闭', value: 'none' }
          ]
        }
      ]
    },
    {
      id: 'privacy',
      title: '隐私安全',
      description: '保护您的隐私和账户安全',
      icon: Shield,
      settings: [
        {
          id: 'twoFactorAuth',
          type: 'toggle',
          label: '双重认证',
          description: '为您的账户添加额外安全层',
          value: settings.twoFactorAuth || false
        },
        {
          id: 'loginAlerts',
          type: 'toggle',
          label: '登录提醒',
          description: '新设备登录时发送提醒',
          value: settings.loginAlerts || true
        },
        {
          id: 'dataSharing',
          type: 'toggle',
          label: '数据共享',
          description: '允许与第三方服务共享数据',
          value: settings.dataSharing || false,
          warning: '关闭可能影响某些功能'
        },
        {
          id: 'analyticsTracking',
          type: 'toggle',
          label: '分析跟踪',
          description: '帮助改进应用体验',
          value: settings.analyticsTracking || true
        },
        {
          id: 'locationTracking',
          type: 'toggle',
          label: '位置跟踪',
          description: '允许应用访问您的位置',
          value: settings.locationTracking || false
        },
        {
          id: 'changePassword',
          type: 'button',
          label: '更改密码',
          description: '更新您的账户密码',
          value: null,
          action: () => toast.info('密码更改功能开发中')
        }
      ]
    },
    {
      id: 'appearance',
      title: '外观主题',
      description: '自定义应用的外观和感觉',
      icon: Palette,
      settings: [
        {
          id: 'theme',
          type: 'select',
          label: '主题模式',
          description: '选择应用主题',
          value: settings.theme || 'system',
          options: [
            { label: '跟随系统', value: 'system' },
            { label: '浅色模式', value: 'light' },
            { label: '深色模式', value: 'dark' }
          ]
        },
        {
          id: 'accentColor',
          type: 'color',
          label: '主题色',
          description: '选择应用主题色',
          value: settings.accentColor || '#3B82F6'
        },
        {
          id: 'fontSize',
          type: 'slider',
          label: '字体大小',
          description: '调整界面字体大小',
          value: settings.fontSize || 14,
          min: 12,
          max: 20,
          step: 1
        },
        {
          id: 'animations',
          type: 'toggle',
          label: '动画效果',
          description: '启用界面动画',
          value: settings.animations || true
        },
        {
          id: 'compactMode',
          type: 'toggle',
          label: '紧凑模式',
          description: '使用更紧凑的界面布局',
          value: settings.compactMode || false
        }
      ]
    },
    {
      id: 'language',
      title: '语言地区',
      description: '设置语言和地区偏好',
      icon: Globe,
      settings: [
        {
          id: 'language',
          type: 'select',
          label: '界面语言',
          description: '选择应用界面语言',
          value: settings.language || 'zh-CN',
          options: [
            { label: '简体中文', value: 'zh-CN' },
            { label: '繁體中文', value: 'zh-TW' },
            { label: 'English', value: 'en-US' },
            { label: '日本語', value: 'ja-JP' },
            { label: '한국어', value: 'ko-KR' }
          ]
        },
        {
          id: 'timezone',
          type: 'select',
          label: '时区',
          description: '选择您的时区',
          value: settings.timezone || 'Asia/Shanghai',
          options: [
            { label: '北京时间 (UTC+8)', value: 'Asia/Shanghai' },
            { label: '东京时间 (UTC+9)', value: 'Asia/Tokyo' },
            { label: '纽约时间 (UTC-5)', value: 'America/New_York' },
            { label: '伦敦时间 (UTC+0)', value: 'Europe/London' }
          ]
        },
        {
          id: 'dateFormat',
          type: 'select',
          label: '日期格式',
          description: '选择日期显示格式',
          value: settings.dateFormat || 'YYYY-MM-DD',
          options: [
            { label: '2024-01-01', value: 'YYYY-MM-DD' },
            { label: '01/01/2024', value: 'MM/DD/YYYY' },
            { label: '01-01-2024', value: 'DD-MM-YYYY' }
          ]
        },
        {
          id: 'numberFormat',
          type: 'select',
          label: '数字格式',
          description: '选择数字显示格式',
          value: settings.numberFormat || 'comma',
          options: [
            { label: '1,234.56', value: 'comma' },
            { label: '1 234,56', value: 'space' },
            { label: '1.234,56', value: 'dot' }
          ]
        }
      ]
    },
    {
      id: 'data',
      title: '数据管理',
      description: '管理您的数据和存储',
      icon: Database,
      settings: [
        {
          id: 'autoBackup',
          type: 'toggle',
          label: '自动备份',
          description: '自动备份您的数据',
          value: settings.autoBackup || true
        },
        {
          id: 'syncData',
          type: 'toggle',
          label: '数据同步',
          description: '在设备间同步数据',
          value: settings.syncData || true
        },
        {
          id: 'cacheSize',
          type: 'slider',
          label: '缓存大小 (MB)',
          description: '设置本地缓存大小',
          value: settings.cacheSize || 100,
          min: 50,
          max: 500,
          step: 50
        },
        {
          id: 'exportData',
          type: 'button',
          label: '导出数据',
          description: '下载您的所有数据',
          value: null,
          action: () => handleExportData()
        },
        {
          id: 'clearCache',
          type: 'button',
          label: '清除缓存',
          description: '清除本地缓存数据',
          value: null,
          action: () => handleClearCache(),
          warning: '这将清除所有本地缓存'
        },
        {
          id: 'deleteAccount',
          type: 'button',
          label: '删除账户',
          description: '永久删除您的账户',
          value: null,
          action: () => handleDeleteAccount(),
          warning: '此操作不可撤销'
        }
      ]
    }
  ];

  useEffect(() => {
    const loadSettings = async () => {
      setIsLoading(true);
      try {
        // 模拟从服务器加载设置
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const defaultSettings = {
          displayName: '气味探索者',
          bio: '热爱发现和分享各种有趣的气味',
          profileVisibility: 'public',
          showLocation: false,
          pushNotifications: true,
          emailNotifications: true,
          notificationSound: true,
          vibration: true,
          quietHours: false,
          notificationTypes: 'all',
          twoFactorAuth: false,
          loginAlerts: true,
          dataSharing: false,
          analyticsTracking: true,
          locationTracking: false,
          theme: 'system',
          accentColor: '#3B82F6',
          fontSize: 14,
          animations: true,
          compactMode: false,
          language: 'zh-CN',
          timezone: 'Asia/Shanghai',
          dateFormat: 'YYYY-MM-DD',
          numberFormat: 'comma',
          autoBackup: true,
          syncData: true,
          cacheSize: 100
        };
        
        setSettings(defaultSettings);
      } catch {
      toast.error('加载设置失败');
      } finally {
        setIsLoading(false);
      }
    };

    loadSettings();
  }, []);

  const handleSettingChange = (sectionId: string, settingId: string, value: SettingValue) => {
    setSettings(prev => ({
      ...prev,
      [settingId]: value
    }));
    
    setPendingChanges(prev => new Set([...prev, `${sectionId}.${settingId}`]));
    
    if (onSettingChange) {
      onSettingChange(sectionId, settingId, value);
    }
  };

  const handleSaveSettings = async () => {
    setIsSaving(true);
    try {
      // 模拟保存到服务器
      await new Promise(resolve => setTimeout(resolve, 1500));
      setPendingChanges(new Set());
      toast.success('设置已保存');
    } catch {
      toast.error('保存失败');
    } finally {
      setIsSaving(false);
    }
  };

  const handleExportData = async () => {
    try {
      toast.info('正在准备数据导出...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // 模拟数据导出
      const data = {
        settings,
        exportDate: new Date().toISOString(),
        version: '1.0.0'
      };
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `smellpin-data-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast.success('数据导出成功');
    } catch {
      toast.error('导出失败');
    }
  };

  const handleClearCache = async () => {
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      toast.success('缓存已清除');
    } catch {
      toast.error('清除失败');
    }
  };

  const handleDeleteAccount = () => {
    toast.warning('账户删除功能需要额外验证');
  };

  const toggleSection = (sectionId: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(sectionId)) {
        newSet.delete(sectionId);
      } else {
        newSet.add(sectionId);
      }
      return newSet;
    });
  };

  const renderSetting = (sectionId: string, setting: Setting) => {
    const settingKey = `${sectionId}.${setting.id}`;
    const hasChanges = pendingChanges.has(settingKey);

    const renderInput = () => {
      switch (setting.type) {
        case 'toggle':
          return (
            <div className="flex items-center">
              <button
                onClick={() => handleSettingChange(sectionId, setting.id, !setting.value)}
                disabled={setting.disabled}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  setting.value ? 'bg-blue-600' : 'bg-gray-200'
                } ${setting.disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    setting.value ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          );
        
        case 'select':
          return (
            <select
              value={String(setting.value ?? '')}
              onChange={(e) => handleSettingChange(sectionId, setting.id, e.target.value)}
              disabled={setting.disabled}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
            >
              {setting.options?.map(option => (
                <option key={String(option.value ?? '')} value={String(option.value ?? '')}>
                  {option.label}
                </option>
              ))}
            </select>
          );
        
        case 'input':
          return (
            <input
              type="text"
              value={String(setting.value ?? '')}
              onChange={(e) => handleSettingChange(sectionId, setting.id, e.target.value)}
              disabled={setting.disabled}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
              placeholder={setting.label}
            />
          );
        
        case 'slider':
          return (
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={setting.min}
                max={setting.max}
                step={setting.step}
                value={String(setting.value ?? '')}
                onChange={(e) => handleSettingChange(sectionId, setting.id, Number(e.target.value))}
                disabled={setting.disabled}
                className="flex-1 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:opacity-50"
              />
              <span className="text-sm text-gray-600 min-w-[3rem] text-right">
                {setting.value}{setting.id === 'fontSize' ? 'px' : ''}
              </span>
            </div>
          );
        
        case 'color':
          return (
            <div className="flex items-center gap-2">
              <input
                type="color"
                value={String(setting.value ?? '')}
                onChange={(e) => handleSettingChange(sectionId, setting.id, e.target.value)}
                disabled={setting.disabled}
                className="w-10 h-10 border border-gray-300 rounded-lg cursor-pointer disabled:opacity-50"
              />
              <span className="text-sm text-gray-600">{setting.value}</span>
            </div>
          );
        
        case 'file':
          return (
            <div className="flex items-center gap-2">
              <input
                type="file"
                accept={setting.accept}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    handleSettingChange(sectionId, setting.id, file.name);
                  }
                }}
                disabled={setting.disabled}
                className="text-sm text-gray-600 file:mr-2 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-sm file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 disabled:opacity-50"
              />
            </div>
          );
        
        case 'button':
          return (
            <LoadingButton
              onClick={setting.action}
              disabled={setting.disabled}
              className={`px-4 py-2 rounded-lg text-sm transition-colors ${
                setting.warning
                  ? 'bg-red-600 text-white hover:bg-red-700'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              } disabled:opacity-50`}
            >
              {setting.label}
            </LoadingButton>
          );
        
        default:
          return null;
      }
    };

    return (
      <motion.div
        key={setting.id}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={`p-4 border border-gray-200 rounded-lg ${
          hasChanges ? 'bg-blue-50 border-blue-200' : 'bg-white'
        }`}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="text-sm font-medium text-gray-800">{setting.label}</h4>
              {setting.premium && (
                <span className="px-2 py-0.5 bg-yellow-100 text-yellow-800 text-xs rounded-full">
                  <Star className="w-3 h-3 inline mr-1" />
                  高级
                </span>
              )}
              {hasChanges && (
                <span className="w-2 h-2 bg-blue-500 rounded-full" />
              )}
            </div>
            {setting.description && (
              <p className="text-xs text-gray-600 mb-2">{setting.description}</p>
            )}
            {setting.warning && (
              <div className="flex items-center gap-1 text-xs text-amber-600 mb-2">
                <AlertTriangle className="w-3 h-3" />
                <span>{setting.warning}</span>
              </div>
            )}
          </div>
          
          <div className="flex-shrink-0">
            {renderInput()}
          </div>
        </div>
      </motion.div>
    );
  };

  const filteredSections = settingSections.filter(section => {
    if (!searchQuery) return true;
    
    const query = searchQuery.toLowerCase();
    return (
      section.title.toLowerCase().includes(query) ||
      section.description.toLowerCase().includes(query) ||
      section.settings.some(setting => 
        setting.label.toLowerCase().includes(query) ||
        setting.description?.toLowerCase().includes(query)
      )
    );
  });

  if (isLoading) {
    return (
      <div className={`w-full ${className}`}>
        <LoadingState message="加载设置中..." />
      </div>
    );
  }

  return (
    <div className={`w-full max-w-4xl mx-auto space-y-6 ${className}`}>
      {/* 头部 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-800">高级设置</h1>
            <p className="text-gray-600 mt-1">自定义您的应用体验</p>
          </div>
          
          <div className="flex items-center gap-2">
            {pendingChanges.size > 0 && (
              <div className="flex items-center gap-2 text-sm text-blue-600">
                <span>{pendingChanges.size} 项更改</span>
                <LoadingButton
                  onClick={handleSaveSettings}
                  loading={isSaving}
                  className="flex items-center gap-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Save className="w-4 h-4" />
                  保存更改
                </LoadingButton>
              </div>
            )}
            
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-1 px-3 py-2 text-gray-600 hover:text-gray-800 transition-colors"
            >
              <Settings className="w-4 h-4" />
              {showAdvanced ? '隐藏高级' : '显示高级'}
            </button>
          </div>
        </div>
        
        {/* 搜索 */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="搜索设置..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
      </div>
      
      {/* 设置导航 */}
      {!isMobile && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex flex-wrap gap-2">
            {filteredSections.map(section => {
              const IconComponent = section.icon;
              return (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
                    activeSection === section.id
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-600 hover:bg-gray-100'
                  }`}
                >
                  <IconComponent className="w-4 h-4" />
                  {section.title}
                </button>
              );
            })}
          </div>
        </div>
      )}
      
      {/* 设置内容 */}
      <div className="space-y-6">
        {filteredSections.map(section => {
          const IconComponent = section.icon;
          const isExpanded = expandedSections.has(section.id);
          const isActive = activeSection === section.id;
          
          if (!isMobile && !isActive) return null;
          
          return (
            <motion.div
              key={section.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden"
            >
              <button
                onClick={() => toggleSection(section.id)}
                className="w-full p-6 text-left hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <IconComponent className="w-5 h-5 text-blue-600" />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-gray-800">{section.title}</h2>
                      <p className="text-sm text-gray-600">{section.description}</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {pendingChanges.size > 0 && Array.from(pendingChanges).some(change => change.startsWith(section.id)) && (
                      <span className="w-2 h-2 bg-blue-500 rounded-full" />
                    )}
                    {isExpanded ? (
                      <ChevronDown className="w-5 h-5 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-5 h-5 text-gray-400" />
                    )}
                  </div>
                </div>
              </button>
              
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="border-t border-gray-100"
                  >
                    <div className="p-6 space-y-4">
                      {section.settings
                        .filter(setting => showAdvanced || !setting.premium)
                        .map(setting => renderSetting(section.id, setting))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          );
        })}
      </div>
      
      {/* 底部信息 */}
      <div className="bg-gray-50 rounded-lg p-4">
        <div className="flex items-center justify-between text-sm text-gray-600">
          <div className="flex items-center gap-4">
            <span>版本 1.0.0</span>
            <span>•</span>
            <button className="flex items-center gap-1 hover:text-gray-800 transition-colors">
              <HelpCircle className="w-4 h-4" />
              帮助中心
            </button>
            <button className="flex items-center gap-1 hover:text-gray-800 transition-colors">
              <FileText className="w-4 h-4" />
              隐私政策
            </button>
          </div>
          
          <div className="flex items-center gap-2">
            {isOnline ? (
              <div className="flex items-center gap-1 text-green-600">
                <Wifi className="w-4 h-4" />
                <span>已连接</span>
              </div>
            ) : (
              <div className="flex items-center gap-1 text-red-600">
                <WifiOff className="w-4 h-4" />
                <span>离线</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdvancedSettings;