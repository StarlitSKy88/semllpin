import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import type { User, AuthState, AuthContextType } from '../types/auth-types';
import { validateToken, mockLogin, mockRegister, mockUpdateProfile } from '../utils/auth-utils';
import { AuthContext } from '../contexts/AuthContext';

// 认证提供者组件
export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isLoading: true,
    isAuthenticated: false,
  });

  // 安全的localStorage访问函数
  const getStoredToken = () => {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        return localStorage.getItem('auth_token');
      }
    } catch (error) {
      console.warn('localStorage access failed:', error);
    }
    return null;
  };

  const setStoredToken = (token: string) => {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.setItem('auth_token', token);
      }
    } catch (error) {
      console.warn('localStorage write failed:', error);
    }
  };

  const removeStoredToken = () => {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.removeItem('auth_token');
      }
    } catch (error) {
      console.warn('localStorage remove failed:', error);
    }
  };

  // 初始化认证状态
  useEffect(() => {
    const initAuth = async () => {
      try {
        // 检查本地存储的token
        const token = getStoredToken();
        if (token) {
          // 验证token并获取用户信息
          const user = await validateToken(token);
          if (user) {
            setAuthState({
              user,
              isLoading: false,
              isAuthenticated: true,
            });
            return;
          }
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        removeStoredToken();
      }
      
      setAuthState({
        user: null,
        isLoading: false,
        isAuthenticated: false,
      });
    };

    initAuth();
  }, []);

  // 登录函数
  const login = async (email: string, password: string) => {
    try {
      setAuthState(prev => ({ ...prev, isLoading: true }));
      
      // 模拟API调用
      const response = await mockLogin(email, password);
      const { user, token } = response;
      
      // 保存token
      setStoredToken(token);
      
      setAuthState({
        user,
        isLoading: false,
        isAuthenticated: true,
      });
    } catch (error) {
      setAuthState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  // 登出函数
  const logout = () => {
    removeStoredToken();
    setAuthState({
      user: null,
      isLoading: false,
      isAuthenticated: false,
    });
  };

  // 注册函数
  const register = async (email: string, password: string, name: string) => {
    try {
      setAuthState(prev => ({ ...prev, isLoading: true }));
      
      // 模拟API调用
      const response = await mockRegister(email, password, name);
      const { user, token } = response;
      
      // 保存token
      setStoredToken(token);
      
      setAuthState({
        user,
        isLoading: false,
        isAuthenticated: true,
      });
    } catch (error) {
      setAuthState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  // 更新用户资料
  const updateProfile = async (data: Partial<User>) => {
    if (!authState.user) throw new Error('User not authenticated');
    
    // 模拟API调用
    const updatedUser = await mockUpdateProfile(authState.user.id, data);
    
    setAuthState(prev => ({
      ...prev,
      user: updatedUser,
    }));
  };

  const value: AuthContextType = {
    ...authState,
    login,
    logout,
    register,
    updateProfile,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};