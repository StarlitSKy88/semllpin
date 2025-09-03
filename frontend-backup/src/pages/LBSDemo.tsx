import React, { useState, useEffect } from 'react';
import { MapPin, Radar, History } from 'lucide-react';
import {
  LBSRewardTracker,
  RewardNotification,
  DistanceIndicator,
  LBSMap,
  RewardHistory,
  type NearbyAnnotation
} from '../components/LBS';
import { useAuthStore } from '../stores/authStore';
import useNotificationStore from '../stores/notificationStore';
import { useNavigate } from 'react-router-dom';

const LBSDemo: React.FC = () => {
  const { user } = useAuthStore();
  const { addNotification } = useNotificationStore();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'tracker' | 'map' | 'history'>('tracker');
  const [currentReward, setCurrentReward] = useState<{
    id: string;
    type: 'discovery';
    amount: number;
    title: string;
    annotationTitle: string;
  } | null>(null);
  // const [selectedAnnotation, setSelectedAnnotation] = useState<NearbyAnnotation | null>(null);

  // 处理奖励获得
  const handleRewardEarned = (annotation: NearbyAnnotation) => {
    const reward = {
      id: annotation.id,
      type: 'discovery' as const,
      amount: annotation.reward,
      title: annotation.title,
      annotationTitle: annotation.title
    };
    setCurrentReward(reward);
    addNotification({
      type: 'success',
      title: '🎉 恭喜获得奖励!',
      message: `在「${annotation.title}」获得 ${annotation.reward} 积分奖励！`
    });
  };

  // 处理标注选择
  const handleAnnotationSelect = (annotation: NearbyAnnotation) => {
    // setSelectedAnnotation(annotation); // 注释掉未定义的函数调用
    console.log('Annotation clicked:', annotation);
  };

  // 处理奖励领取
  const handleRewardClaim = (annotation: NearbyAnnotation) => {
    addNotification({
      type: 'success',
      title: '奖励领取成功',
      message: `成功领取「${annotation.title}」的奖励！`
    });
  };

  // 处理奖励通知关闭
  const handleRewardNotificationClose = () => {
    setCurrentReward(null);
  };

  // 标签页配置
  const tabs = [
    {
      id: 'tracker' as const,
      name: '雷达追踪',
      icon: Radar,
      description: '实时扫描附近的标注点'
    },
    {
      id: 'map' as const,
      name: 'LBS地图',
      icon: MapPin,
      description: '在地图上查看所有标注'
    },
    {
      id: 'history' as const,
      name: '奖励历史',
      icon: History,
      description: '查看您的奖励记录'
    }
  ];

  // 检查用户登录状态
  useEffect(() => {
    if (!user) {
      addNotification({
        type: 'warning',
        title: '请先登录',
        message: '登录后即可使用LBS奖励功能'
      });
    }
  }, [user, addNotification]);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* 页面头部 */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <div className="p-2 bg-blue-100 rounded-lg">
                <MapPin className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900">LBS奖励系统</h1>
                <p className="text-sm text-gray-500">基于位置的奖励追踪系统演示</p>
              </div>
            </div>
            
            {user && (
              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-900">{user.username}</p>
                  <p className="text-xs text-gray-500">积分: {user.points || 0}</p>
                </div>
                <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">
                    {user.username?.charAt(0).toUpperCase()}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* 标签页导航 */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span>{tab.name}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
      
      {/* 主要内容区域 */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!user ? (
          // 未登录状态
          <div className="bg-white rounded-xl shadow-lg p-12 text-center">
            <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-6">
              <MapPin className="w-10 h-10 text-gray-400" />
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-4">欢迎使用LBS奖励系统</h2>
            <p className="text-gray-600 mb-8 max-w-md mx-auto">
              通过地理位置发现附近的有趣标注，获得积分奖励。请先登录以开始使用。
            </p>
            <button
              onClick={() => {
                navigate('/login', { state: { from: '/lbs' } });
              }}
              className="inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 transition-colors"
            >
              立即登录
            </button>
          </div>
        ) : (
          // 已登录状态 - 显示对应标签页内容
          <div className="space-y-8">
            {activeTab === 'tracker' && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* 雷达追踪器 */}
                <div className="lg:col-span-2">
                  <LBSRewardTracker
                    onRewardFound={handleRewardEarned}
                    className="h-[600px]"
                  />
                </div>
                
                {/* 距离指示器 */}
                <div className="space-y-6">
                  <DistanceIndicator
                    userLocation={null}
                    annotations={[]}
                    onAnnotationSelect={handleAnnotationSelect}
                  />
                  
                  {/* 功能说明 */}
                  <div className="bg-blue-50 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-blue-900 mb-3">使用说明</h3>
                    <ul className="space-y-2 text-sm text-blue-800">
                      <li className="flex items-start space-x-2">
                        <span className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2 flex-shrink-0"></span>
                        <span>点击「开始扫描」按钮启动雷达</span>
                      </li>
                      <li className="flex items-start space-x-2">
                        <span className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2 flex-shrink-0"></span>
                        <span>靠近标注点50米内可获得奖励</span>
                      </li>
                      <li className="flex items-start space-x-2">
                        <span className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2 flex-shrink-0"></span>
                        <span>首次发现标注可获得额外奖励</span>
                      </li>
                      <li className="flex items-start space-x-2">
                        <span className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2 flex-shrink-0"></span>
                        <span>连续发现可获得连击奖励</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
            
            {activeTab === 'map' && (
              <div className="space-y-6">
                {/* 地图组件 */}
                <LBSMap
                  onAnnotationSelect={handleAnnotationSelect}
                  onRewardClaim={handleRewardClaim}
                  className="h-[600px]"
                />
                
                {/* 地图说明 */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-red-50 rounded-lg p-6">
                    <div className="flex items-center space-x-3 mb-3">
                      <span className="text-2xl">😈</span>
                      <h3 className="font-semibold text-red-900">恶搞标注</h3>
                    </div>
                    <p className="text-sm text-red-800">有趣的恶搞内容，通常奖励较高</p>
                  </div>
                  
                  <div className="bg-yellow-50 rounded-lg p-6">
                    <div className="flex items-center space-x-3 mb-3">
                      <span className="text-2xl">😂</span>
                      <h3 className="font-semibold text-yellow-900">搞笑标注</h3>
                    </div>
                    <p className="text-sm text-yellow-800">幽默搞笑的内容，适合分享</p>
                  </div>
                  
                  <div className="bg-purple-50 rounded-lg p-6">
                    <div className="flex items-center space-x-3 mb-3">
                      <span className="text-2xl">🤔</span>
                      <h3 className="font-semibold text-purple-900">奇怪标注</h3>
                    </div>
                    <p className="text-sm text-purple-800">奇特有趣的发现，值得探索</p>
                  </div>
                </div>
              </div>
            )}
            
            {activeTab === 'history' && (
              <RewardHistory />
            )}
          </div>
        )}
      </div>
      
      {/* 奖励通知 */}
      {currentReward && (
        <RewardNotification
          reward={currentReward}
          onClose={handleRewardNotificationClose}
        />
      )}
    </div>
  );
};

export default LBSDemo;