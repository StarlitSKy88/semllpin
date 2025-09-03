/**
 * 认证状态管理
 * 使用Zustand管理用户认证相关状态
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  username: string;
  avatar?: string;
  university?: string;
  graduation_year?: number;
  level: number;
  points: number;
  role: string;
  created_at: string;
  updated_at: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  error: string | null;
  isAuthenticated: boolean;
}

interface AuthActions {
  // 登录
  login: (email: string, password: string) => Promise<void>;
  // 注册
  register: (email: string, password: string, username: string) => Promise<void>;
  // 登出
  logout: () => void;
  // 检查认证状态
  checkAuth: () => Promise<void>;
  // 更新用户信息
  updateProfile: (data: Partial<User>) => Promise<void>;
  // 刷新token
  refreshToken: () => Promise<void>;
  // 设置加载状态
  setLoading: (loading: boolean) => void;
  // 设置错误
  setError: (error: string | null) => void;
  // 清除错误
  clearError: () => void;
}

type AuthStore = AuthState & AuthActions;

const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:3001/api';

export const useAuthStore = create<AuthStore>()(persist(
  (set, get) => ({
    // 初始状态
    user: null,
    token: null,
    isLoading: false,
    error: null,
    isAuthenticated: false,

    // 登录
    login: async (email: string, password: string) => {
      set({ isLoading: true, error: null });

      try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.message || '登录失败');
        }

        const { user, token } = data.data;

        set({
          user,
          token,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });

        // 存储token到localStorage
        localStorage.setItem('auth_token', token);
      } catch (error: any) {
        set({
          error: error.message || '登录失败',
          isLoading: false,
          isAuthenticated: false,
        });
        throw error;
      }
    },

    // 注册
    register: async (email: string, password: string, username: string) => {
      set({ isLoading: true, error: null });

      try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email, password, username }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.message || '注册失败');
        }

        const { user, token } = data.data;

        set({
          user,
          token,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });

        // 存储token到localStorage
        localStorage.setItem('auth_token', token);
      } catch (error: any) {
        set({
          error: error.message || '注册失败',
          isLoading: false,
          isAuthenticated: false,
        });
        throw error;
      }
    },

    // 登出
    logout: () => {
      set({
        user: null,
        token: null,
        isAuthenticated: false,
        error: null,
      });

      // 清除localStorage
      localStorage.removeItem('auth_token');
    },

    // 检查认证状态
    checkAuth: async () => {
      const token = localStorage.getItem('auth_token');

      if (!token) {
        set({ isAuthenticated: false, user: null, token: null });
        return;
      }

      set({ isLoading: true });

      try {
        const response = await fetch(`${API_BASE_URL}/auth/me`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          throw new Error('Token验证失败');
        }

        const data = await response.json();
        const user = data.data;

        set({
          user,
          token,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
      } catch (error: any) {
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          isLoading: false,
          error: error.message || '认证失败',
        });

        // 清除无效token
        localStorage.removeItem('auth_token');
      }
    },

    // 更新用户信息
    updateProfile: async (data: Partial<User>) => {
      const { token } = get();

      if (!token) {
        throw new Error('未登录');
      }

      set({ isLoading: true, error: null });

      try {
        const response = await fetch(`${API_BASE_URL}/auth/profile`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify(data),
        });

        const responseData = await response.json();

        if (!response.ok) {
          throw new Error(responseData.message || '更新失败');
        }

        const updatedUser = responseData.data;

        set({
          user: updatedUser,
          isLoading: false,
          error: null,
        });
      } catch (error: any) {
        set({
          error: error.message || '更新失败',
          isLoading: false,
        });
        throw error;
      }
    },

    // 刷新token
    refreshToken: async () => {
      const { token } = get();

      if (!token) {
        throw new Error('未登录');
      }

      try {
        const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.message || 'Token刷新失败');
        }

        const { token: newToken } = data.data;

        set({ token: newToken });
        localStorage.setItem('auth_token', newToken);
      } catch (error: any) {
        // Token刷新失败，登出用户
        get().logout();
        throw error;
      }
    },

    // 设置加载状态
    setLoading: (loading: boolean) => {
      set({ isLoading: loading });
    },

    // 设置错误
    setError: (error: string | null) => {
      set({ error });
    },

    // 清除错误
    clearError: () => {
      set({ error: null });
    },
  }),
  {
    name: 'auth-storage',
    partialize: (state) => ({
      token: state.token,
      user: state.user,
      isAuthenticated: state.isAuthenticated,
    }),
  },
));

export default useAuthStore;
