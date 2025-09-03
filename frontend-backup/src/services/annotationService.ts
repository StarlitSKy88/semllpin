import type { Pin } from '../types/map';

// 重新导出Pin类型供其他组件使用
export type { Pin } from '../types/map';

// API base URL - 从环境变量获取
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8787';

// 开发环境调试
if (import.meta.env.VITE_NODE_ENV === 'development') {
  console.log('API Base URL:', API_BASE_URL);
}

// 标注创建请求接口
export interface CreateAnnotationRequest {
  content: string;
  location: {
    latitude: number;
    longitude: number;
    address?: string;
    place_name?: string;
  };
  media_urls?: string[];
  tags?: string[];
  visibility?: 'public' | 'friends' | 'private';
  smell_intensity?: number;
  smell_category?: string;
}

// 标注响应接口
export interface AnnotationResponse {
  success: boolean;
  data?: Pin;
  message?: string;
  error?: string;
}

// 获取认证token的函数
function getAuthToken(): string | null {
  // 从localStorage获取token，优先使用'token'，兼容'auth_token'
  return localStorage.getItem('token') || localStorage.getItem('auth_token');
}

// 创建标注
export async function createAnnotation(data: CreateAnnotationRequest): Promise<AnnotationResponse> {
  try {
    const token = getAuthToken();
    
    if (!token) {
      throw new Error('用户未登录');
    }

    const response = await fetch(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(data)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.message || '创建标注失败');
    }

    return result;
  } catch (error) {
    console.error('创建标注错误:', error);
    throw error;
  }
}

// 获取标注列表
export async function getAnnotations(params?: {
  page?: number;
  limit?: number;
  latitude?: number;
  longitude?: number;
  radius?: number;
  user_id?: string;
  tags?: string[];
  smell_category?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}): Promise<{
  success: boolean;
  data: Pin[];
  pagination?: {
    page: number;
    limit: number;
    has_more: boolean;
  };
  error?: string;
}> {
  try {
    const searchParams = new URLSearchParams();
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          if (Array.isArray(value)) {
            searchParams.append(key, value.join(','));
          } else {
            searchParams.append(key, value.toString());
          }
        }
      });
    }

    const response = await fetch(`${API_BASE_URL}/annotations?${searchParams}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.message || '获取标注失败');
    }

    return result;
  } catch (error) {
    console.error('获取标注错误:', error);
    throw error;
  }
}

// 获取单个标注详情
export async function getAnnotationById(id: string): Promise<AnnotationResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/annotations/${id}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.message || '获取标注详情失败');
    }

    return result;
  } catch (error) {
    console.error('获取标注详情错误:', error);
    throw error;
  }
}

// 点赞/取消点赞标注
export async function toggleAnnotationLike(id: string): Promise<{
  success: boolean;
  data?: {
    liked: boolean;
    likes_count: number;
  };
  error?: string;
}> {
  try {
    const token = getAuthToken();
    
    if (!token) {
      throw new Error('用户未登录');
    }

    const response = await fetch(`${API_BASE_URL}/annotations/${id}/like`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.message || '操作失败');
    }

    return result;
  } catch (error) {
    console.error('点赞操作错误:', error);
    throw error;
  }
}

// 删除标注
export async function deleteAnnotation(id: string): Promise<{
  success: boolean;
  message?: string;
  error?: string;
}> {
  try {
    const token = getAuthToken();
    
    if (!token) {
      throw new Error('用户未登录');
    }

    const response = await fetch(`${API_BASE_URL}/annotations/${id}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.message || '删除标注失败');
    }

    return result;
  } catch (error) {
    console.error('删除标注错误:', error);
    throw error;
  }
}

// 更新标注
export async function updateAnnotation(id: string, data: Partial<CreateAnnotationRequest>): Promise<AnnotationResponse> {
  try {
    const token = getAuthToken();
    
    if (!token) {
      throw new Error('用户未登录');
    }

    const response = await fetch(`${API_BASE_URL}/annotations/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(data)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.message || '更新标注失败');
    }

    return result;
  } catch (error) {
    console.error('更新标注错误:', error);
    throw error;
  }
}