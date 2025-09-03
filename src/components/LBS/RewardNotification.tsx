/**
 * 奖励通知组件
 * 显示实时奖励获得通知和动画效果
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useState, useEffect } from 'react';
import { Award, Star, MapPin, Clock, X } from 'lucide-react';
import { useLBSStore } from '../../stores/lbsStore';

interface RewardNotificationData {
  id: string;
  type: 'discovery' | 'checkin' | 'stay' | 'social';
  amount: number;
  geofenceName: string;
  timestamp: string;
  breakdown?: {
    baseAmount: number;
    timeDecayFactor: number;
    isFirstDiscoverer: boolean;
    bonusMultiplier: number;
  };
}

interface NotificationProps {
  notification: RewardNotificationData;
  onClose: () => void;
  isVisible: boolean;
}

const RewardNotificationItem: React.FC<NotificationProps> = ({ 
  notification, 
  onClose, 
  isVisible 
}) => {
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    if (isVisible) {
      setIsAnimating(true);
      // 自动关闭通知
      const timer = setTimeout(() => {
        onClose();
      }, 5000);
      return () => clearTimeout(timer);
    }
    // 如果条件不满足，明确返回undefined
    return undefined;
  }, [isVisible, onClose]);

  const getRewardTypeInfo = (type: string) => {
    switch (type) {
      case 'discovery':
        return {
          icon: Star,
          label: '首次发现',
          color: 'text-yellow-500',
          bgColor: 'bg-yellow-50',
          borderColor: 'border-yellow-200'
        };
      case 'checkin':
        return {
          icon: MapPin,
          label: '签到奖励',
          color: 'text-blue-500',
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200'
        };
      case 'stay':
        return {
          icon: Clock,
          label: '停留奖励',
          color: 'text-green-500',
          bgColor: 'bg-green-50',
          borderColor: 'border-green-200'
        };
      case 'social':
        return {
          icon: Award,
          label: '社交奖励',
          color: 'text-purple-500',
          bgColor: 'bg-purple-50',
          borderColor: 'border-purple-200'
        };
      default:
        return {
          icon: Award,
          label: '奖励',
          color: 'text-gray-500',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200'
        };
    }
  };

  const typeInfo = getRewardTypeInfo(notification.type);
  const IconComponent = typeInfo.icon;

  return (
    <div
      className={`
        transform transition-all duration-500 ease-out
        ${isVisible && isAnimating 
          ? 'translate-x-0 opacity-100 scale-100' 
          : 'translate-x-full opacity-0 scale-95'
        }
        ${typeInfo.bgColor} ${typeInfo.borderColor}
        border rounded-lg shadow-lg p-4 mb-3 relative overflow-hidden
      `}
    >
      {/* 背景动画效果 */}
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-20 transform -skew-x-12 animate-pulse"></div>
      
      {/* 关闭按钮 */}
      <button
        onClick={onClose}
        className="absolute top-2 right-2 text-gray-400 hover:text-gray-600 transition-colors"
      >
        <X className="h-4 w-4" />
      </button>

      <div className="flex items-start space-x-3">
        {/* 奖励图标 */}
        <div className={`flex-shrink-0 ${typeInfo.color}`}>
          <IconComponent className="h-6 w-6" />
        </div>

        {/* 奖励内容 */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center space-x-2">
            <h4 className="text-lg font-bold text-gray-900">
              +{notification.amount} 分
            </h4>
            <span className={`text-sm font-medium ${typeInfo.color}`}>
              {typeInfo.label}
            </span>
          </div>
          
          <p className="text-sm text-gray-700 mt-1">
            在 <span className="font-medium">{notification.geofenceName}</span> 获得奖励
          </p>
          
          <p className="text-xs text-gray-500 mt-1">
            {new Date(notification.timestamp).toLocaleTimeString()}
          </p>

          {/* 奖励详情 */}
          {notification.breakdown && (
            <div className="mt-2 text-xs text-gray-600 space-y-1">
              <div className="flex justify-between">
                <span>基础奖励:</span>
                <span>{notification.breakdown.baseAmount} 分</span>
              </div>
              
              {notification.breakdown.timeDecayFactor !== 1 && (
                <div className="flex justify-between">
                  <span>时间衰减:</span>
                  <span>×{notification.breakdown.timeDecayFactor.toFixed(2)}</span>
                </div>
              )}
              
              {notification.breakdown.isFirstDiscoverer && (
                <div className="flex justify-between text-yellow-600">
                  <span>首次发现奖励:</span>
                  <span>×2.0</span>
                </div>
              )}
              
              {notification.breakdown.bonusMultiplier !== 1 && (
                <div className="flex justify-between text-green-600">
                  <span>额外奖励:</span>
                  <span>×{notification.breakdown.bonusMultiplier}</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 进度条动画 */}
      <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-200">
        <div 
          className={`h-full ${typeInfo.color.replace('text-', 'bg-')} transition-all duration-5000 ease-linear`}
          style={{
            width: isVisible ? '0%' : '100%',
            transition: isVisible ? 'width 5s linear' : 'none'
          }}
        ></div>
      </div>
    </div>
  );
};

const RewardNotification: React.FC = () => {
  const { recentRewards } = useLBSStore();
  const [notifications, setNotifications] = useState<RewardNotificationData[]>([]);
  const [visibleNotifications, setVisibleNotifications] = useState<Set<string>>(new Set());

  // 监听新奖励并创建通知
  useEffect(() => {
    if (recentRewards.length > 0) {
      const latestReward = recentRewards[0];
      if (!latestReward) return;
      
      const notificationId = `${latestReward.id}_${Date.now()}`;
      
      // 检查是否已经显示过这个奖励的通知
      const existingNotification = notifications.find(
        n => n.id.startsWith(latestReward.id)
      );
      
      if (!existingNotification) {
        const newNotification: RewardNotificationData = {
          id: notificationId,
          type: 'reward' as any,
          amount: latestReward.finalPoints || 0,
          geofenceName: latestReward.geofenceName || '未知位置',
          timestamp: latestReward.timestamp || new Date().toISOString(),
          breakdown: latestReward.metadata
        };

        setNotifications(prev => [newNotification, ...prev.slice(0, 4)]); // 最多保留5个通知
        setVisibleNotifications(prev => new Set([...prev, notificationId]));
      }
    }
    // 此useEffect不需要返回清理函数，但需要明确返回undefined
    return undefined;
  }, [recentRewards, notifications]);

  // 关闭通知
  const closeNotification = (notificationId: string) => {
    setVisibleNotifications(prev => {
      const newSet = new Set(prev);
      newSet.delete(notificationId);
      return newSet;
    });

    // 延迟移除通知以允许动画完成
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== notificationId));
    }, 500);
  };

  // 清除所有通知
  const clearAllNotifications = () => {
    setVisibleNotifications(new Set());
    setTimeout(() => {
      setNotifications([]);
    }, 500);
  };

  if (notifications.length === 0) {
    return null;
  }

  return (
    <div className="fixed top-4 right-4 z-50 w-80 max-w-sm">
      {/* 清除所有按钮 */}
      {notifications.length > 1 && (
        <div className="mb-2 flex justify-end">
          <button
            onClick={clearAllNotifications}
            className="text-xs text-gray-500 hover:text-gray-700 bg-white rounded px-2 py-1 shadow-sm border"
          >
            清除所有
          </button>
        </div>
      )}

      {/* 通知列表 */}
      <div className="space-y-2">
        {notifications.map((notification) => (
          <RewardNotificationItem
            key={notification.id}
            notification={notification}
            onClose={() => closeNotification(notification.id)}
            isVisible={visibleNotifications.has(notification.id)}
          />
        ))}
      </div>
    </div>
  );
};

export default RewardNotification;