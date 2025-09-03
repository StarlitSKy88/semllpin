'use client';

import { useEffect } from 'react';
import { initializeAuth } from '@/lib/stores/auth-store';

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  useEffect(() => {
    // 初始化认证状态
    initializeAuth();
  }, []);

  return <>{children}</>;
}