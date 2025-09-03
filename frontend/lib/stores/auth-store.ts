import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User, authApi } from '../services/api';

interface AuthState {
  // 状态
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // 操作
  login: (phone: string, code: string) => Promise<void>;
  register: (phone: string, code: string, username: string) => Promise<void>;
  emailLogin: (email: string, password: string) => Promise<void>;
  emailRegister: (email: string, password: string, username: string) => Promise<void>;
  logout: () => void;
  getCurrentUser: () => Promise<void>;
  clearError: () => void;
  setLoading: (loading: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      // 初始状态
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      // 登录
      login: async (phone: string, code: string) => {
        try {
          set({ isLoading: true, error: null });
          const response = await authApi.login(phone, code);
          const { token, user } = response.data;
          
          // 保存token到localStorage
          localStorage.setItem('auth_token', token);
          localStorage.setItem('user_info', JSON.stringify(user));
          
          set({
            user,
            token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || '登录失败',
          });
          throw error;
        }
      },

      // 注册
      register: async (phone: string, code: string, username: string) => {
        try {
          set({ isLoading: true, error: null });
          const response = await authApi.register(phone, code, username);
          const { token, user } = response.data;
          
          // 保存token到localStorage
          localStorage.setItem('auth_token', token);
          localStorage.setItem('user_info', JSON.stringify(user));
          
          set({
            user,
            token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || '注册失败',
          });
          throw error;
        }
      },

      // 邮箱登录
      emailLogin: async (email: string, password: string) => {
        try {
          set({ isLoading: true, error: null });
          const response = await authApi.emailLogin(email, password);
          const { tokens, user } = response.data;
          const token = tokens.accessToken;
          
          // 保存token到localStorage
          localStorage.setItem('auth_token', token);
          localStorage.setItem('refresh_token', tokens.refreshToken);
          localStorage.setItem('user_info', JSON.stringify(user));
          
          set({
            user,
            token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || '邮箱登录失败',
          });
          throw error;
        }
      },

      // 邮箱注册
      emailRegister: async (email: string, password: string, username: string) => {
        try {
          set({ isLoading: true, error: null });
          const response = await authApi.emailRegister(email, password, username);
          const { tokens, user } = response.data;
          const token = tokens.accessToken;
          
          // 保存token到localStorage
          localStorage.setItem('auth_token', token);
          localStorage.setItem('refresh_token', tokens.refreshToken);
          localStorage.setItem('user_info', JSON.stringify(user));
          
          set({
            user,
            token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || '邮箱注册失败',
          });
          throw error;
        }
      },

      // 登出
      logout: () => {
        // 清除本地存储
        localStorage.removeItem('auth_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user_info');
        
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
        });
      },

      // 获取当前用户信息
      getCurrentUser: async () => {
        try {
          set({ isLoading: true, error: null });
          const response = await authApi.getCurrentUser();
          const user = response.data;
          
          set({
            user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || '获取用户信息失败',
          });
          // 如果获取用户信息失败，可能是token过期，执行登出
          get().logout();
        }
      },

      // 清除错误
      clearError: () => {
        set({ error: null });
      },

      // 设置加载状态
      setLoading: (loading: boolean) => {
        set({ isLoading: loading });
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);

// 初始化认证状态
export const initializeAuth = () => {
  const token = localStorage.getItem('auth_token');
  const userInfo = localStorage.getItem('user_info');
  
  if (token && userInfo) {
    try {
      const user = JSON.parse(userInfo);
      useAuthStore.setState({
        user,
        token,
        isAuthenticated: true,
      });
      
      // 验证token是否有效
      useAuthStore.getState().getCurrentUser();
    } catch (error) {
      // 如果解析失败，清除存储
      useAuthStore.getState().logout();
    }
  }
};