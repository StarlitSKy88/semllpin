import React, { useState, useEffect, useCallback } from 'react';
import { Gift, Star, Zap, Trophy, Coins } from 'lucide-react';

interface RewardData {
  id: string;
  type: 'discovery' | 'first_time' | 'combo' | 'special';
  amount: number;
  title: string;
  description?: string;
  multiplier?: number;
  annotationTitle?: string;
}

export interface RewardNotificationProps {
  reward: RewardData | null;
  onClose: () => void;
  duration?: number;
}

const RewardNotification: React.FC<RewardNotificationProps> = ({
  reward,
  onClose,
  duration = 4000
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);

  const handleClose = useCallback(() => {
    setIsAnimating(false);
    setTimeout(() => {
      setIsVisible(false);
      onClose();
    }, 300);
  }, [onClose]);

  useEffect(() => {
    if (reward) {
      setIsVisible(true);
      setIsAnimating(true);
      
      // 自动关闭
      const timer = setTimeout(() => {
        handleClose();
      }, duration);

      return () => clearTimeout(timer);
    }
  }, [reward, duration, handleClose]);

  if (!reward || !isVisible) return null;

  const getRewardIcon = (type: string) => {
    switch (type) {
      case 'discovery':
        return <Zap className="w-8 h-8 text-yellow-400" />;
      case 'first_time':
        return <Star className="w-8 h-8 text-blue-400" />;
      case 'combo':
        return <Trophy className="w-8 h-8 text-purple-400" />;
      case 'special':
        return <Gift className="w-8 h-8 text-red-400" />;
      default:
        return <Coins className="w-8 h-8 text-green-400" />;
    }
  };

  const getRewardColor = (type: string) => {
    switch (type) {
      case 'discovery':
        return 'from-yellow-400 to-orange-500';
      case 'first_time':
        return 'from-blue-400 to-indigo-500';
      case 'combo':
        return 'from-purple-400 to-pink-500';
      case 'special':
        return 'from-red-400 to-rose-500';
      default:
        return 'from-green-400 to-emerald-500';
    }
  };

  const getRewardTitle = (type: string) => {
    switch (type) {
      case 'discovery':
        return '🎯 发现奖励!';
      case 'first_time':
        return '⭐ 首次发现!';
      case 'combo':
        return '🏆 连击奖励!';
      case 'special':
        return '🎁 特殊奖励!';
      default:
        return '💰 获得奖励!';
    }
  };

  return (
    <>
      {/* 背景遮罩 */}
      <div 
        className={`fixed inset-0 bg-black bg-opacity-50 z-50 transition-opacity duration-300 ${
          isAnimating ? 'opacity-100' : 'opacity-0'
        }`}
        onClick={handleClose}
      />
      
      {/* 奖励通知卡片 */}
      <div 
        className={`fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-50 transition-all duration-500 ${
          isAnimating 
            ? 'scale-100 opacity-100 rotate-0' 
            : 'scale-75 opacity-0 rotate-12'
        }`}
      >
        <div className="bg-white rounded-2xl shadow-2xl p-6 max-w-sm mx-4 relative overflow-hidden">
          {/* 背景装饰 */}
          <div className={`absolute inset-0 bg-gradient-to-br ${getRewardColor(reward.type)} opacity-10`} />
          
          {/* 闪光效果 */}
          <div className="absolute -top-2 -right-2 w-16 h-16 bg-gradient-to-br from-white to-transparent opacity-20 rounded-full animate-ping" />
          <div className="absolute -bottom-2 -left-2 w-12 h-12 bg-gradient-to-br from-white to-transparent opacity-20 rounded-full animate-ping animation-delay-1000" />
          
          {/* 内容区域 */}
          <div className="relative z-10">
            {/* 图标和标题 */}
            <div className="text-center mb-4">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-white rounded-full shadow-lg mb-3 animate-bounce">
                {getRewardIcon(reward.type)}
              </div>
              <h3 className="text-xl font-bold text-gray-900 mb-1">
                {getRewardTitle(reward.type)}
              </h3>
              <p className="text-sm text-gray-600">
                {reward.title}
              </p>
            </div>
            
            {/* 奖励金额 */}
            <div className="text-center mb-4">
              <div className={`inline-flex items-center px-4 py-2 bg-gradient-to-r ${getRewardColor(reward.type)} rounded-full text-white font-bold text-lg shadow-lg`}>
                <Coins className="w-5 h-5 mr-2" />
                +{reward.amount}
                {reward.multiplier && reward.multiplier > 1 && (
                  <span className="ml-2 text-sm opacity-90">
                    (x{reward.multiplier})
                  </span>
                )}
              </div>
            </div>
            
            {/* 描述信息 */}
            {reward.description && (
              <div className="text-center mb-4">
                <p className="text-sm text-gray-600">
                  {reward.description}
                </p>
              </div>
            )}
            
            {/* 标注信息 */}
            {reward.annotationTitle && (
              <div className="bg-gray-50 rounded-lg p-3 mb-4">
                <p className="text-xs text-gray-500 mb-1">发现的标注</p>
                <p className="text-sm font-medium text-gray-900">
                  📍 {reward.annotationTitle}
                </p>
              </div>
            )}
            
            {/* 关闭按钮 */}
            <div className="text-center">
              <button
                onClick={handleClose}
                className="px-6 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors duration-200 font-medium"
              >
                太棒了！
              </button>
            </div>
          </div>
          
          {/* 装饰性星星 */}
          <div className="absolute top-4 left-4 text-yellow-400 animate-pulse">
            ⭐
          </div>
          <div className="absolute top-6 right-6 text-yellow-400 animate-pulse animation-delay-500">
            ✨
          </div>
          <div className="absolute bottom-4 left-6 text-yellow-400 animate-pulse animation-delay-1000">
            💫
          </div>
          <div className="absolute bottom-6 right-4 text-yellow-400 animate-pulse animation-delay-1500">
            ⭐
          </div>
        </div>
      </div>
      
      {/* 粒子效果 */}
      <div className="fixed inset-0 pointer-events-none z-40">
        {[...Array(12)].map((_, i) => (
          <div
            key={i}
            className={`absolute w-2 h-2 bg-yellow-400 rounded-full animate-ping ${
              isAnimating ? 'opacity-100' : 'opacity-0'
            }`}
            style={{
              left: `${20 + (i * 7)}%`,
              top: `${30 + (i % 3) * 20}%`,
              animationDelay: `${i * 100}ms`,
              animationDuration: '2s'
            }}
          />
        ))}
      </div>
      
      <style>{`
        .animation-delay-500 {
          animation-delay: 0.5s;
        }
        .animation-delay-1000 {
          animation-delay: 1s;
        }
        .animation-delay-1500 {
          animation-delay: 1.5s;
        }
        
        @keyframes float {
          0%, 100% {
            transform: translateY(0px);
          }
          50% {
            transform: translateY(-10px);
          }
        }
        
        .animate-float {
          animation: float 3s ease-in-out infinite;
        }
      `}</style>
    </>
  );
};

export default RewardNotification;