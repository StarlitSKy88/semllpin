import axios from 'axios';

// API基础配置
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:3002/api/v1';

// 创建axios实例
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 请求拦截器 - 添加认证token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器 - 处理错误
apiClient.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Token过期，清除本地存储并跳转到登录页
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user_info');
      window.location.href = '/auth/login';
    }
    return Promise.reject(error.response?.data || error.message);
  }
);

// API响应类型定义
export interface ApiResponse<T = any> {
  success: boolean;
  code?: number;
  message: string;
  data: T;
  timestamp?: string;
  requestId?: string;
}

// 通用API错误类型
export interface ApiError {
  code: number;
  message: string;
  error?: {
    code: string;
    details: any;
  };
}

export default apiClient;