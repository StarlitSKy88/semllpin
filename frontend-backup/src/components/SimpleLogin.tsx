import React, { useState } from 'react';
import { UserOutlined, LockOutlined, EyeInvisibleOutlined, EyeTwoTone, ArrowRightOutlined } from '@ant-design/icons';
import { useNavigate, Link } from 'react-router-dom';

interface LoginForm {
  username: string;
  password: string;
}

const SimpleLogin: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState<LoginForm>({ username: '', password: '' });
  const [errors, setErrors] = useState<Partial<LoginForm>>({});
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const validateForm = (): boolean => {
    const newErrors: Partial<LoginForm> = {};
    
    if (!formData.username) {
      newErrors.username = '请输入用户名';
    } else if (formData.username.length < 3) {
      newErrors.username = '用户名至少3个字符';
    }
    
    if (!formData.password) {
      newErrors.password = '请输入密码';
    } else if (formData.password.length < 6) {
      newErrors.password = '密码至少6个字符';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setLoading(true);
    try {
      // 模拟登录验证
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // 简单的模拟验证
      if (formData.username === 'admin' && formData.password === 'password') {
        localStorage.setItem('token', 'mock-jwt-token');
        localStorage.setItem('user', JSON.stringify({
          id: 1,
          username: formData.username,
          email: 'admin@example.com'
        }));
        
        // 显示成功消息
        const successToast = document.createElement('div');
        successToast.className = 'fixed top-4 right-4 bg-success-500 text-white px-6 py-3 rounded-lg shadow-lg z-[10001]';
        successToast.textContent = '登录成功！';
        document.body.appendChild(successToast);
        setTimeout(() => document.body.removeChild(successToast), 3000);
        
        navigate('/');
      } else {
        // 显示错误消息
        const errorToast = document.createElement('div');
        errorToast.className = 'fixed top-4 right-4 bg-error-500 text-white px-6 py-3 rounded-lg shadow-lg z-[10001]';
        errorToast.textContent = '用户名或密码错误';
        document.body.appendChild(errorToast);
        setTimeout(() => document.body.removeChild(errorToast), 3000);
      }
    } catch (_error) {
      const errorToast = document.createElement('div');
      errorToast.className = 'fixed top-4 right-4 bg-error-500 text-white px-6 py-3 rounded-lg shadow-lg z-[10001]';
      errorToast.textContent = '登录失败，请重试';
      document.body.appendChild(errorToast);
      setTimeout(() => document.body.removeChild(errorToast), 3000);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field: keyof LoginForm, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }));
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-900 via-accent-900 to-primary-800 relative overflow-hidden p-3 sm:p-4 lg:p-6">
      {/* Background decorations */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-accent-500/10 rounded-full blur-3xl"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-primary-500/5 to-accent-500/5 rounded-full blur-3xl"></div>
      </div>

      <div className="relative z-10 w-full max-w-sm sm:max-w-md lg:max-w-lg xl:max-w-xl mx-4 animate-scale-in">
        {/* Logo and title */}
        <div className="text-center mb-8 lg:mb-12 animate-fade-in">
          <div className="inline-block p-3 lg:p-4 bg-gradient-to-br from-primary-500 to-accent-500 rounded-2xl mb-4 lg:mb-6">
            <div className="w-12 h-12 lg:w-16 lg:h-16 bg-white rounded-xl flex items-center justify-center">
              <span className="text-2xl lg:text-3xl font-bold text-gradient">S</span>
            </div>
          </div>
          <h1 className="text-2xl sm:text-3xl lg:text-4xl xl:text-5xl font-bold text-white mb-2 lg:mb-4 animate-slide-in">欢迎回来</h1>
          <p className="text-xs sm:text-sm text-primary-200 lg:text-lg animate-fade-in" style={{animationDelay: '0.2s'}}>登录到 SmellPin 继续你的气味探索之旅</p>
        </div>

        {/* Login form */}
        <div className="card bg-surface/80 backdrop-blur-xl border-primary-500/20 lg:p-12">
          <form onSubmit={handleSubmit} className="space-y-4 sm:space-y-6 lg:space-y-8">
            {/* Username field */}
            <div className="animate-fade-in space-y-3 sm:-space-y-px" style={{animationDelay: '0.4s'}}>
              <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">
                用户名
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 lg:pl-4 flex items-center pointer-events-none">
                  <UserOutlined className="text-primary-400 text-base lg:text-lg" />
                </div>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => handleInputChange('username', e.target.value)}
                  className={`form-input pl-10 lg:pl-12 hover-lift text-sm sm:text-base lg:text-lg py-2.5 sm:py-3 lg:py-4 rounded-md sm:rounded-t-md ${errors.username ? 'border-error-500 focus:border-error-500' : ''}`}
                  placeholder="请输入用户名"
                />
              </div>
              {errors.username && (
                <p className="mt-1 text-sm lg:text-base text-error-400">{errors.username}</p>
              )}
            </div>

            {/* Password field */}
            <div className="animate-fade-in" style={{animationDelay: '0.6s'}}>
              <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">
                密码
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 lg:pl-4 flex items-center pointer-events-none">
                  <LockOutlined className="text-primary-400 text-base lg:text-lg" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={(e) => handleInputChange('password', e.target.value)}
                  className={`form-input pl-10 lg:pl-12 pr-10 lg:pr-12 hover-lift text-sm sm:text-base lg:text-lg py-2.5 sm:py-3 lg:py-4 rounded-md sm:rounded-b-md ${errors.password ? 'border-error-500 focus:border-error-500' : ''}`}
                  placeholder="请输入密码"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 lg:pr-4 flex items-center text-primary-400 hover:text-primary-300 hover-scale"
                >
                  {showPassword ? <EyeTwoTone className="text-base lg:text-lg" /> : <EyeInvisibleOutlined className="text-base lg:text-lg" />}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1 text-sm lg:text-base text-error-400">{errors.password}</p>
              )}
            </div>

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary w-full text-lg lg:text-xl py-3 lg:py-4 relative overflow-hidden group hover-glow animate-fade-in"
              style={{animationDelay: '0.8s'}}
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <div className="loading w-5 h-5 lg:w-6 lg:h-6 mr-2"></div>
                  登录中...
                </div>
              ) : (
                <>
                  登录
                  <ArrowRightOutlined className="ml-2 lg:ml-3 transform group-hover:translate-x-1 transition-transform text-base lg:text-lg" />
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="relative my-6 lg:my-8">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border"></div>
            </div>
            <div className="relative flex justify-center text-sm lg:text-base">
              <span className="px-2 lg:px-4 bg-surface text-secondary">或</span>
            </div>
          </div>

          {/* Register link */}
          <div className="text-center animate-fade-in" style={{animationDelay: '1.0s'}}>
            <p className="text-secondary mb-2 lg:mb-3 text-base lg:text-lg">还没有账号？</p>
            <Link 
              to="/register" 
              className="text-primary-400 hover:text-primary-300 font-medium transition-all duration-300 hover-scale text-base lg:text-lg"
            >
              立即注册 →
            </Link>
          </div>
        </div>

        {/* Test account info */}
        <div className="mt-6 lg:mt-8 p-4 lg:p-6 bg-primary-900/30 backdrop-blur-sm rounded-xl border border-primary-500/20">
          <p className="text-xs lg:text-sm text-primary-200 mb-2 lg:mb-3">
            <strong>测试账号：</strong>
          </p>
          <div className="text-xs lg:text-sm text-primary-300 space-y-1 lg:space-y-2">
            <div>用户名：admin</div>
            <div>密码：password</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SimpleLogin;