import type { User } from '../types/auth-types';

// 模拟API函数
export const validateToken = async (token: string): Promise<User | null> => {
  // 模拟token验证
  await new Promise(resolve => setTimeout(resolve, 500));
  
  if (token === 'valid_token') {
    return {
      id: '1',
      email: 'user@example.com',
      name: 'Test User',
      avatar: 'https://via.placeholder.com/40',
    };
  }
  
  return null;
};

export const mockLogin = async (email: string, password: string) => {
  // 模拟登录API
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  if (email === 'admin@smellpin.com' && password === 'password') {
    return {
      user: {
        id: '1',
        email,
        name: 'Admin User',
        avatar: 'https://via.placeholder.com/40',
      },
      token: 'valid_token',
    };
  }
  
  throw new Error('Invalid credentials');
};

export const mockRegister = async (email: string, _password: string, name: string) => {
  // 模拟注册API
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  return {
    user: {
      id: Date.now().toString(),
      email,
      name,
      avatar: 'https://via.placeholder.com/40',
    },
    token: 'valid_token',
  };
};

export const mockUpdateProfile = async (userId: string, data: Partial<User>): Promise<User> => {
  // 模拟更新用户资料API
  await new Promise(resolve => setTimeout(resolve, 500));
  
  return {
    id: userId,
    email: data.email || 'user@example.com',
    name: data.name || 'Updated User',
    avatar: data.avatar || 'https://via.placeholder.com/40',
  };
};