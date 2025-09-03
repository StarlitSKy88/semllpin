import React, { useState, useEffect } from 'react';
import { EnvironmentOutlined, UserOutlined, HeartOutlined, TrophyOutlined, ArrowRightOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';

const SimpleHome: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // 模拟数据加载
    const timer = setTimeout(() => {
      setLoading(false);
    }, 1000);

    // 检查登录状态
    const token = localStorage.getItem('token');
    setIsLoggedIn(!!token);

    return () => clearTimeout(timer);
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="loading"></div>
      </div>
    );
  }

  return (
    <div className="container py-8 lg:py-12 mt-4 lg:mt-8">
      {/* Hero Section */}
      <div className="text-center mb-12 sm:mb-16 lg:mb-20 animate-fade-in">
        <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-bold text-gray-900 mb-4 sm:mb-6 px-4 text-gradient animate-slide-in">
          欢迎来到 SmellPin
        </h1>
        <p className="text-base sm:text-lg lg:text-xl text-gray-600 mb-6 sm:mb-8 max-w-xl sm:max-w-2xl mx-auto px-4 text-secondary leading-relaxed animate-fade-in" style={{animationDelay: '0.2s'}}>
          发现身边的气味地图，分享你的嗅觉体验，与社区一起探索城市的味道
        </p>
        <div className="mt-8 animate-scale-in" style={{animationDelay: '0.4s'}}>
          <div className="inline-block p-1 bg-gradient-to-r from-primary-500 to-accent-500 rounded-full">
            <div className="bg-primary px-8 py-3 rounded-full">
              <span className="text-sm font-medium text-gradient">🌟 已有 1,234+ 用户加入探索</span>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Section */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-20">
        <div className="card text-center hover-lift animate-fade-in" style={{animationDelay: '0.6s'}}>
          <div className="w-12 h-12 bg-gradient-to-br from-success-400 to-success-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <EnvironmentOutlined className="text-white text-xl" />
          </div>
          <div className="text-3xl font-bold text-primary mb-2">1,234</div>
          <div className="text-sm text-secondary">总标注数</div>
        </div>
        
        <div className="card text-center hover-lift animate-fade-in" style={{animationDelay: '0.8s'}}>
          <div className="w-12 h-12 bg-gradient-to-br from-primary-400 to-primary-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <UserOutlined className="text-white text-xl" />
          </div>
          <div className="text-3xl font-bold text-primary mb-2">567</div>
          <div className="text-sm text-secondary">活跃用户</div>
        </div>
        
        <div className="card text-center hover-lift animate-fade-in" style={{animationDelay: '1.0s'}}>
          <div className="w-12 h-12 bg-gradient-to-br from-error-400 to-error-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <HeartOutlined className="text-white text-xl" />
          </div>
          <div className="text-3xl font-bold text-primary mb-2">8,901</div>
          <div className="text-sm text-secondary">获赞总数</div>
        </div>
        
        <div className="card text-center hover-lift animate-fade-in" style={{animationDelay: '1.2s'}}>
          <div className="w-12 h-12 bg-gradient-to-br from-accent-400 to-accent-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <TrophyOutlined className="text-white text-xl" />
          </div>
          <div className="text-3xl font-bold text-primary mb-2">23</div>
          <div className="text-sm text-secondary">今日新增</div>
        </div>
      </div>

      {/* Features Section */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-8 mb-12 sm:mb-16 lg:mb-20">
        <div className="card group cursor-pointer hover-lift animate-scale-in" style={{animationDelay: '1.4s'}} onClick={() => navigate('/map')}>
          <div className="h-48 bg-gradient-to-br from-primary-500 to-accent-500 rounded-xl mb-6 flex items-center justify-center relative overflow-hidden">
            <EnvironmentOutlined className="text-6xl text-white z-10 animate-bounce" style={{animationDelay: '2.0s'}} />
            <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/20"></div>
            <div className="absolute -top-4 -right-4 w-24 h-24 bg-white/10 rounded-full"></div>
            <div className="absolute -bottom-6 -left-6 w-32 h-32 bg-white/5 rounded-full"></div>
          </div>
          <h3 className="text-xl font-semibold mb-3 text-primary">气味地图</h3>
          <p className="text-secondary leading-relaxed mb-4">
            在地图上标记和发现各种气味点，从美食香气到自然芬芳，记录城市的嗅觉印记。
          </p>
          <div className="flex items-center text-primary-400 group-hover:text-primary-300 transition-colors">
            <span className="text-sm font-medium">立即探索</span>
            <ArrowRightOutlined className="ml-2 transform group-hover:translate-x-1 transition-transform" />
          </div>
        </div>
        
        <div className="card group cursor-pointer hover-lift animate-scale-in" style={{animationDelay: '1.6s'}}>
          <div className="h-48 bg-gradient-to-br from-error-500 to-warning-500 rounded-xl mb-6 flex items-center justify-center relative overflow-hidden">
            <HeartOutlined className="text-6xl text-white z-10 animate-bounce" style={{animationDelay: '2.2s'}} />
            <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/20"></div>
            <div className="absolute -top-4 -right-4 w-24 h-24 bg-white/10 rounded-full"></div>
            <div className="absolute -bottom-6 -left-6 w-32 h-32 bg-white/5 rounded-full"></div>
          </div>
          <h3 className="text-xl font-semibold mb-3 text-primary">社区互动</h3>
          <p className="text-secondary leading-relaxed mb-4">
            为喜欢的气味点点赞，分享你的嗅觉体验，与其他用户交流发现。
          </p>
          <div className="flex items-center text-primary-400 group-hover:text-primary-300 transition-colors">
            <span className="text-sm font-medium">加入社区</span>
            <ArrowRightOutlined className="ml-2 transform group-hover:translate-x-1 transition-transform" />
          </div>
        </div>
        
        <div className="card group cursor-pointer hover-lift animate-scale-in" style={{animationDelay: '1.8s'}}>
          <div className="h-48 bg-gradient-to-br from-success-500 to-primary-500 rounded-xl mb-6 flex items-center justify-center relative overflow-hidden">
            <TrophyOutlined className="text-6xl text-white z-10 animate-bounce" style={{animationDelay: '2.4s'}} />
            <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/20"></div>
            <div className="absolute -top-4 -right-4 w-24 h-24 bg-white/10 rounded-full"></div>
            <div className="absolute -bottom-6 -left-6 w-32 h-32 bg-white/5 rounded-full"></div>
          </div>
          <h3 className="text-xl font-semibold mb-3 text-primary">成就系统</h3>
          <p className="text-secondary leading-relaxed mb-4">
            完成各种挑战，解锁成就徽章，成为气味探索的专家。
          </p>
          <div className="flex items-center text-primary-400 group-hover:text-primary-300 transition-colors">
            <span className="text-sm font-medium">查看成就</span>
            <ArrowRightOutlined className="ml-2 transform group-hover:translate-x-1 transition-transform" />
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="card text-center bg-gradient-to-br from-primary-900/50 to-accent-900/50 border-primary-500/30 animate-fade-in" style={{animationDelay: '2.0s'}}>
        <div className="max-w-2xl mx-auto">
          <h2 className="text-3xl font-bold mb-4 text-gradient">
            准备开始你的气味之旅？
          </h2>
          <p className="text-lg text-secondary mb-8 leading-relaxed">
            {isLoggedIn 
              ? '立即前往地图，开始探索和标记你发现的有趣气味！' 
              : '注册账号，加入我们的气味探索社区，开始你的嗅觉冒险！'
            }
          </p>
          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center px-4">
            {isLoggedIn ? (
              <button 
                className="btn btn-primary text-lg px-8 py-4 hover-glow"
                onClick={() => navigate('/map')}
              >
                <EnvironmentOutlined className="mr-2" />
                前往地图
                <ArrowRightOutlined className="ml-2" />
              </button>
            ) : (
              <>
                <button 
                  className="btn btn-primary text-lg px-8 py-4 hover-glow"
                  onClick={() => navigate('/register')}
                >
                  立即注册
                  <ArrowRightOutlined className="ml-2" />
                </button>
                <button 
                  className="btn btn-secondary text-lg px-8 py-4 hover-scale"
                  onClick={() => navigate('/login')}
                >
                  已有账号？登录
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SimpleHome;