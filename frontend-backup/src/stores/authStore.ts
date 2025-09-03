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
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, username: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<void>;
  refreshToken: () => Promise<void>;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
}

type AuthStore = AuthState & AuthActions;

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

// 安全的localStorage访问
const getStoredToken = (): string | null => {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return localStorage.getItem('auth_token');
    }
  } catch (error) {
    console.warn('无法访问localStorage:', error);
  }
  return null;
};

// 安全的localStorage设置
const setStoredToken = (token: string): void => {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.setItem('auth_token', token);
    }
  } catch (error) {
    console.warn('无法设置localStorage:', error);
  }
};

// 安全的localStorage移除
const removeStoredToken = (): void => {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('auth_token');
    }
  } catch (error) {
    console.warn('无法移除localStorage:', error);
  }
};

export const useAuthStore = create<AuthStore>()(persist(
  (set, get) => {
    // 安全获取初始token
    const initialToken = getStoredToken();
    
    // 防止重复调用的标记
    let isCheckingAuth = false;
    let lastCheckTime = 0;
    const CHECK_INTERVAL = 5000; // 5秒内不重复检查
    
    return {
      // 初始状态 - 添加安全检查
      user: null,
      token: initialToken,
      isLoading: false,
      error: null,
      isAuthenticated: !!initialToken,

    // 登录
    login: async (email: string, password: string) => {
      // 防止重复登录
      const currentState = get();
      if (currentState.isLoading) {
        console.log('login: 正在处理中，跳过重复请求');
        return;
      }
      
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

        setStoredToken(token);
        
        // 重置检查时间，允许后续检查
        lastCheckTime = 0;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : '登录失败';
        set({
          error: errorMessage,
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

        setStoredToken(token);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : '注册失败';
        set({
          error: errorMessage,
          isLoading: false,
          isAuthenticated: false,
        });
        throw error;
      }
    },

    // 登出
    logout: () => {
      // 重置所有标记
      isCheckingAuth = false;
      lastCheckTime = 0;
      
      set({
        user: null,
        token: null,
        isAuthenticated: false,
        error: null,
        isLoading: false,
      });
      
      removeStoredToken();
    },

    // 检查认证状态 - 添加防重复调用逻辑
    checkAuth: async () => {
      const now = Date.now();
      
      // 防止重复调用
      if (isCheckingAuth || (now - lastCheckTime < CHECK_INTERVAL)) {
        console.log('checkAuth: 跳过重复调用');
        return;
      }
      
      isCheckingAuth = true;
      lastCheckTime = now;
      
      try {
        const token = getStoredToken();
        
        if (!token) {
          set({ isAuthenticated: false, user: null, token: null, isLoading: false });
          return;
        }

        // 只有在状态真正需要更新时才设置loading
        const currentState = get();
        if (!currentState.isLoading) {
          set({ isLoading: true });
        }
        
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
        
        // 检查状态是否真的需要更新
        const state = get();
        const needsUpdate = !state.user || 
                           state.user.id !== user.id || 
                           state.token !== token || 
                           !state.isAuthenticated;
        
        if (needsUpdate) {
          set({
            user,
            token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } else {
          set({ isLoading: false });
        }
      } catch (error: unknown) {
        console.error('checkAuth error:', error);
        const errorMessage = error instanceof Error ? error.message : '认证失败';
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          isLoading: false,
          error: errorMessage,
        });
        removeStoredToken();
      } finally {
        isCheckingAuth = false;
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

        const result = await response.json();

        if (!response.ok) {
          throw new Error(result.message || '更新失败');
        }

        const updatedUser = result.data;
        
        set({
          user: updatedUser,
          isLoading: false,
          error: null,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : '更新失败';
        set({
          error: errorMessage,
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
        setStoredToken(newToken);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Token刷新失败';
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: errorMessage,
        });
        removeStoredToken();
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
  };
  },
  {
    name: 'auth-storage',
    partialize: (state) => ({
      user: state.user,
      token: state.token,
      isAuthenticated: state.isAuthenticated,
    }),
  }
));