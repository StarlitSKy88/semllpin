import React, { useState } from 'react';

import { useNavigate, Link } from 'react-router-dom';
import { toast } from 'sonner';

interface RegisterForm {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

interface FormErrors {
  username?: string;
  email?: string;
  password?: string;
  confirmPassword?: string;
}

const SimpleRegister: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [formData, setFormData] = useState<RegisterForm>({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState<FormErrors>({});
  const navigate = useNavigate();

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};
    
    if (!formData.username.trim()) {
      newErrors.username = '请输入用户名';
    } else if (formData.username.length < 3) {
      newErrors.username = '用户名至少3个字符';
    }
    
    if (!formData.email.trim()) {
      newErrors.email = '请输入邮箱';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = '请输入有效的邮箱地址';
    }
    
    if (!formData.password) {
      newErrors.password = '请输入密码';
    } else if (formData.password.length < 6) {
      newErrors.password = '密码至少6位字符';
    }
    
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = '请确认密码';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = '两次输入的密码不一致';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };



  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    try {
      // 模拟注册API调用
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      toast.success('注册成功！');
      // 存储简单的登录状态
      localStorage.setItem('isLoggedIn', 'true');
      localStorage.setItem('userEmail', formData.email);
      localStorage.setItem('username', formData.username);
      navigate('/');
    } catch (_error) {
      toast.error('注册失败，请重试');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center p-4">
      <div className="glass-card w-full max-w-md lg:max-w-lg xl:max-w-xl p-8 lg:p-12 rounded-2xl backdrop-blur-sm border border-white/20 animate-scale-in">
        <div className="text-center mb-8 lg:mb-12 animate-fade-in">
          <h1 className="text-3xl lg:text-4xl xl:text-5xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-2 lg:mb-4 animate-slide-in">
            创建账户
          </h1>
          <p className="text-gray-600 lg:text-lg animate-fade-in" style={{animationDelay: '0.2s'}}>加入 SmellPin 社区</p>
        </div>
          
        <form onSubmit={handleSubmit} className="space-y-6 lg:space-y-8">
          <div className="animate-fade-in" style={{animationDelay: '0.4s'}}>
            <label htmlFor="username" className="block text-sm lg:text-base font-medium text-gray-700 mb-2 lg:mb-3">
              用户名
            </label>
            <input
              type="text"
              id="username"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              className="w-full px-4 py-3 lg:px-6 lg:py-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/80 backdrop-blur-sm hover-lift text-base lg:text-lg"
              placeholder="请输入用户名"
              required
            />
            {errors.username && (
              <p className="mt-1 text-sm lg:text-base text-red-600 animate-fade-in">{errors.username}</p>
            )}
          </div>

          <div className="animate-fade-in" style={{animationDelay: '0.6s'}}>
            <label htmlFor="email" className="block text-sm lg:text-base font-medium text-gray-700 mb-2 lg:mb-3">
              邮箱
            </label>
            <input
              type="email"
              id="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="w-full px-4 py-3 lg:px-6 lg:py-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/80 backdrop-blur-sm hover-lift text-base lg:text-lg"
              placeholder="请输入邮箱地址"
              required
            />
            {errors.email && (
              <p className="mt-1 text-sm lg:text-base text-red-600 animate-fade-in">{errors.email}</p>
            )}
          </div>

          <div className="animate-fade-in" style={{animationDelay: '0.8s'}}>
            <label htmlFor="password" className="block text-sm lg:text-base font-medium text-gray-700 mb-2 lg:mb-3">
              密码
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                className="w-full px-4 py-3 lg:px-6 lg:py-4 pr-12 lg:pr-16 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/80 backdrop-blur-sm hover-lift text-base lg:text-lg"
                placeholder="请输入密码"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 lg:right-6 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700 transition-all duration-300 hover-scale text-lg lg:text-xl"
              >
                {showPassword ? '🙈' : '👁️'}
              </button>
            </div>
            {errors.password && (
              <p className="mt-1 text-sm lg:text-base text-red-600 animate-fade-in">{errors.password}</p>
            )}
          </div>

          <div className="animate-fade-in" style={{animationDelay: '1.0s'}}>
            <label htmlFor="confirmPassword" className="block text-sm lg:text-base font-medium text-gray-700 mb-2 lg:mb-3">
              确认密码
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                id="confirmPassword"
                value={formData.confirmPassword}
                onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                className="w-full px-4 py-3 lg:px-6 lg:py-4 pr-12 lg:pr-16 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/80 backdrop-blur-sm hover-lift text-base lg:text-lg"
                placeholder="请再次输入密码"
                required
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 lg:right-6 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700 transition-all duration-300 hover-scale text-lg lg:text-xl"
              >
                {showConfirmPassword ? '🙈' : '👁️'}
              </button>
            </div>
            {errors.confirmPassword && (
              <p className="mt-1 text-sm lg:text-base text-red-600 animate-fade-in">{errors.confirmPassword}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full btn-primary py-3 lg:py-4 text-lg lg:text-xl font-semibold disabled:opacity-50 disabled:cursor-not-allowed hover-glow animate-fade-in"
            style={{animationDelay: '1.2s'}}
          >
            {loading ? '注册中...' : '注册'}
          </button>
        </form>

        <div className="mt-6 lg:mt-8 text-center animate-fade-in" style={{animationDelay: '1.4s'}}>
          <p className="text-gray-600 text-base lg:text-lg">
            已有账户？{' '}
            <Link to="/login" className="text-blue-600 hover:text-blue-700 font-medium transition-all duration-300 hover-scale">
              立即登录
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default SimpleRegister;