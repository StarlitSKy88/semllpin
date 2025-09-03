import React, { useState, useEffect } from 'react';
import { UserOutlined, LogoutOutlined, HomeOutlined, EnvironmentOutlined, MenuOutlined } from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';

const SimpleNavigation: React.FC = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('username');
    if (token && user) {
      setIsLoggedIn(true);
      setUsername(user);
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIsLoggedIn(false);
    setUsername('');
    navigate('/');
  };

  const isActive = (path: string) => location.pathname === path;

  return (
    <>
      <nav className="nav fixed top-0 left-0 right-0 z-[9999] animate-slide-in bg-glass/90 backdrop-blur-xl border-b border-primary-500/20 shadow-lg">
        <div className="container flex items-center justify-between py-4 max-w-7xl">
          {/* Logo/Brand */}
          <div 
            className="nav-brand cursor-pointer text-2xl font-bold hover-scale"
            onClick={() => navigate('/')}
          >
            <span className="animate-bounce" style={{animationDelay: '0.5s'}}>🗺️</span>
            <span className="truncate">SmellPin</span>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden lg:flex items-center gap-6 xl:gap-8">
            <a 
              href="#" 
              className={`nav-link hover-lift ${isActive('/') ? 'active' : ''}`}
              onClick={(e) => { e.preventDefault(); navigate('/'); }}
            >
              <HomeOutlined className="mr-2" />
              首页
            </a>
            <a 
              href="#" 
              className={`nav-link hover-lift ${isActive('/map') ? 'active' : ''}`}
              onClick={(e) => { e.preventDefault(); navigate('/map'); }}
            >
              <EnvironmentOutlined className="mr-2" />
              地图
            </a>
          </div>

          {/* Desktop Auth Buttons */}
          <div className="hidden lg:flex items-center gap-3 xl:gap-4">
            {isLoggedIn ? (
              <div className="flex items-center gap-4 animate-fade-in">
                <div className="flex items-center gap-2 text-sm text-secondary">
                  <div className="w-8 h-8 bg-gradient-to-br from-primary-400 to-accent-400 rounded-full flex items-center justify-center">
                    <UserOutlined className="text-white text-xs" />
                  </div>
                  <span>{username}</span>
                </div>
                <button 
                  className="btn btn-ghost text-sm hover-scale"
                  onClick={handleLogout}
                >
                  <LogoutOutlined className="mr-1" />
                  退出
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-3 animate-fade-in">
                <button 
                  className="btn btn-secondary hover-lift"
                  onClick={() => navigate('/login')}
                >
                  登录
                </button>
                <button 
                  className="btn btn-primary hover-glow"
                  onClick={() => navigate('/register')}
                >
                  注册
                </button>
              </div>
            )}
          </div>

          {/* Mobile Menu Button */}
          <button 
            className="lg:hidden btn btn-ghost p-2 hover-scale"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            <MenuOutlined />
          </button>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="lg:hidden bg-glass/95 backdrop-blur-xl border-t border-primary-500/20 animate-slide-in shadow-lg">
            <div className="container py-4 space-y-4">
              <a 
                href="#" 
                className={`nav-link block hover-lift ${isActive('/') ? 'active' : ''}`}
                onClick={(e) => { 
                  e.preventDefault(); 
                  navigate('/'); 
                  setIsMobileMenuOpen(false);
                }}
              >
                <HomeOutlined className="mr-2" />
                首页
              </a>
              <a 
                href="#" 
                className={`nav-link block hover-lift ${isActive('/map') ? 'active' : ''}`}
                onClick={(e) => { 
                  e.preventDefault(); 
                  navigate('/map'); 
                  setIsMobileMenuOpen(false);
                }}
              >
                <EnvironmentOutlined className="mr-2" />
                地图
              </a>
              
              <div className="pt-4 border-t border-secondary">
                {isLoggedIn ? (
                  <div className="space-y-3 animate-fade-in">
                    <div className="flex items-center gap-2 text-sm text-secondary">
                      <div className="w-8 h-8 bg-gradient-to-br from-primary-400 to-accent-400 rounded-full flex items-center justify-center">
                        <UserOutlined className="text-white text-xs" />
                      </div>
                      <span>{username}</span>
                    </div>
                    <button 
                      className="btn btn-ghost w-full justify-start hover-scale"
                      onClick={() => {
                        handleLogout();
                        setIsMobileMenuOpen(false);
                      }}
                    >
                      <LogoutOutlined className="mr-2" />
                      退出登录
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3 animate-fade-in">
                    <button 
                      className="btn btn-secondary w-full hover-lift"
                      onClick={() => {
                        navigate('/login');
                        setIsMobileMenuOpen(false);
                      }}
                    >
                      登录
                    </button>
                    <button 
                      className="btn btn-primary w-full hover-glow"
                      onClick={() => {
                        navigate('/register');
                        setIsMobileMenuOpen(false);
                      }}
                    >
                      注册
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </nav>
      
      {/* Spacer for fixed navigation */}
      <div className="h-20 lg:h-24"></div>
    </>
  );
};

export default SimpleNavigation;