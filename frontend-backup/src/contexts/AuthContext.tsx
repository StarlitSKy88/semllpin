import { createContext } from 'react';
import type { AuthContextType } from '../types/auth-types';

// 创建认证上下文
export const AuthContext = createContext<AuthContextType | undefined>(undefined);