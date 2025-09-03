import { apiClient, ApiResponse } from '../api';

// 用户相关类型定义
export interface User {
  id: string;
  username: string;
  email?: string;
  phone?: string;
  avatar?: string;
  level: number;
  points: number;
  role: 'user' | 'admin' | 'moderator';
  createdAt: string;
  updatedAt: string;
}

// 标注相关类型定义
export interface Annotation {
  id: string;
  title: string;
  description: string;
  latitude: number;
  longitude: number;
  authorId: string;
  author?: User;
  rewardAmount: number;
  smell_type?: string;
  smell_intensity?: number;
  images?: string[];
  status: 'pending' | 'approved' | 'rejected';
  createdAt: string;
  updatedAt: string;
  likesCount?: number;
  commentsCount?: number;
  isLiked?: boolean;
}

// 评论相关类型定义
export interface Comment {
  id: string;
  content: string;
  authorId: string;
  author?: User;
  annotationId: string;
  parentId?: string;
  replies?: Comment[];
  createdAt: string;
  updatedAt: string;
}

// LBS奖励相关类型定义
export interface LBSReward {
  id: string;
  userId: string;
  annotationId: string;
  amount: number;
  latitude: number;
  longitude: number;
  claimedAt: string;
}

// 钱包相关类型定义
export interface Wallet {
  id: string;
  userId: string;
  balance: number;
  totalEarned: number;
  totalSpent: number;
  updatedAt: string;
}

// 认证API
export const authApi = {
  // 发送验证码
  sendCode: (phone: string, type: 'login' | 'register' = 'login') =>
    apiClient.post<ApiResponse>('/auth/send-code', { phone, type }),

  // 手机号登录
  login: (phone: string, code: string) =>
    apiClient.post<ApiResponse<{ token: string; user: User }>>('/auth/login', { phone, code }),

  // 手机号注册
  register: (phone: string, code: string, username: string) =>
    apiClient.post<ApiResponse<{ token: string; user: User }>>('/auth/register', { phone, code, username }),

  // 邮箱登录
  emailLogin: (email: string, password: string) =>
    apiClient.post<ApiResponse<{ tokens: { accessToken: string; refreshToken: string }; user: User }>>('/auth/login', { email, password }),

  // 邮箱注册
  emailRegister: (email: string, password: string, username: string) =>
    apiClient.post<ApiResponse<{ tokens: { accessToken: string; refreshToken: string }; user: User }>>('/auth/register', { email, password, username }),

  // 获取当前用户信息
  getCurrentUser: () =>
    apiClient.get<ApiResponse<User>>('/auth/profile/me'),

  // 更新用户信息
  updateProfile: (data: { username?: string; email?: string; avatar?: string }) =>
    apiClient.put<ApiResponse<User>>('/auth/profile', data),

  // 修改密码
  changePassword: (currentPassword: string, newPassword: string) =>
    apiClient.post<ApiResponse>('/auth/change-password', { currentPassword, newPassword }),

  // 登出
  logout: () =>
    apiClient.post<ApiResponse>('/auth/logout'),
};

// 标注API
export const annotationApi = {
  // 获取地图标注
  getMapAnnotations: (bounds?: { north: number; south: number; east: number; west: number }) =>
    apiClient.get<ApiResponse<Annotation[]>>('/annotations/map', { params: bounds }),

  // 获取附近标注
  getNearbyAnnotations: (latitude: number, longitude: number, radius: number = 1000) =>
    apiClient.get<ApiResponse<Annotation[]>>('/annotations/nearby', {
      params: { latitude, longitude, radius }
    }),

  // 获取标注详情
  getAnnotation: (id: string) =>
    apiClient.get<ApiResponse<Annotation>>(`/annotations/${id}`),

  // 创建标注
  createAnnotation: (data: {
    title: string;
    description: string;
    latitude: number;
    longitude: number;
    rewardAmount: number;
    smell_type?: string;
    smell_intensity?: number;
    images?: string[];
  }) =>
    apiClient.post<ApiResponse<Annotation>>('/annotations', data),

  // 更新标注
  updateAnnotation: (id: string, data: Partial<Annotation>) =>
    apiClient.put<ApiResponse<Annotation>>(`/annotations/${id}`, data),

  // 删除标注
  deleteAnnotation: (id: string) =>
    apiClient.delete<ApiResponse>(`/annotations/${id}`),

  // 点赞标注
  likeAnnotation: (id: string) =>
    apiClient.post<ApiResponse>(`/annotations/${id}/like`),

  // 取消点赞
  unlikeAnnotation: (id: string) =>
    apiClient.delete<ApiResponse>(`/annotations/${id}/like`),

  // 获取我的标注
  getMyAnnotations: () =>
    apiClient.get<ApiResponse<Annotation[]>>('/annotations/user/me'),
};

// 评论API
export const commentApi = {
  // 获取标注评论
  getAnnotationComments: (annotationId: string, page: number = 1, limit: number = 20) =>
    apiClient.get<ApiResponse<{ comments: Comment[]; total: number; page: number; limit: number }>>(
      `/comments/annotation/${annotationId}`,
      { params: { page, limit } }
    ),

  // 创建评论
  createComment: (data: {
    content: string;
    annotationId: string;
    parentId?: string;
  }) =>
    apiClient.post<ApiResponse<Comment>>('/comments', data),

  // 更新评论
  updateComment: (id: string, content: string) =>
    apiClient.put<ApiResponse<Comment>>(`/comments/${id}`, { content }),

  // 删除评论
  deleteComment: (id: string) =>
    apiClient.delete<ApiResponse>(`/comments/${id}`),
};

// LBS奖励API
export const lbsApi = {
  // 上报位置并检查奖励
  reportLocation: (latitude: number, longitude: number) =>
    apiClient.post<ApiResponse<LBSReward[]>>('/lbs/report-location', { latitude, longitude }),

  // 领取奖励
  claimReward: (annotationId: string, latitude: number, longitude: number) =>
    apiClient.post<ApiResponse<LBSReward>>('/lbs/claim-reward', { annotationId, latitude, longitude }),

  // 获取我的奖励记录
  getMyRewards: (page: number = 1, limit: number = 20) =>
    apiClient.get<ApiResponse<{ rewards: LBSReward[]; total: number; page: number; limit: number }>>(
      '/lbs/rewards/me',
      { params: { page, limit } }
    ),
};

// 钱包API
export const walletApi = {
  // 获取钱包信息
  getWallet: () =>
    apiClient.get<ApiResponse<Wallet>>('/wallet'),

  // 充值
  recharge: (amount: number, paymentMethod: string) =>
    apiClient.post<ApiResponse<{ paymentUrl: string }>>('/wallet/recharge', { amount, paymentMethod }),

  // 提现
  withdraw: (amount: number, account: string) =>
    apiClient.post<ApiResponse>('/wallet/withdraw', { amount, account }),

  // 获取交易记录
  getTransactions: (page: number = 1, limit: number = 20) =>
    apiClient.get<ApiResponse<any[]>>('/wallet/transactions', { params: { page, limit } }),
};

// 文件上传API
export const uploadApi = {
  // 上传图片
  uploadImage: (file: File) => {
    const formData = new FormData();
    formData.append('image', file);
    return apiClient.post<ApiResponse<{ url: string }>>('/upload/image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },

  // 批量上传图片
  uploadImages: (files: File[]) => {
    const formData = new FormData();
    files.forEach((file, index) => {
      formData.append(`images`, file);
    });
    return apiClient.post<ApiResponse<{ urls: string[] }>>('/upload/images', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
};

// 地理编码API
export const geocodingApi = {
  // 地址转坐标
  geocode: (address: string) =>
    apiClient.get<ApiResponse<{ latitude: number; longitude: number; address: string }>>(
      '/geocoding/geocode',
      { params: { address } }
    ),

  // 坐标转地址
  reverseGeocode: (latitude: number, longitude: number) =>
    apiClient.get<ApiResponse<{ address: string; components: any }>>(
      '/geocoding/reverse',
      { params: { latitude, longitude } }
    ),
};