'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { useState } from 'react';

interface QueryProviderProps {
  children: React.ReactNode;
}

export function QueryProvider({ children }: QueryProviderProps) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // 默认缓存时间：5分钟
            staleTime: 5 * 60 * 1000,
            // 默认垃圾回收时间：10分钟
            gcTime: 10 * 60 * 1000,
            // 重试次数
            retry: (failureCount, error: any) => {
              // 401错误不重试（认证失败）
              if (error?.response?.status === 401) {
                return false;
              }
              // 其他错误最多重试2次
              return failureCount < 2;
            },
            // 重试延迟
            retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
            // 窗口重新获得焦点时重新获取数据
            refetchOnWindowFocus: false,
            // 网络重连时重新获取数据
            refetchOnReconnect: true,
          },
          mutations: {
            // 默认重试次数
            retry: 1,
            // 重试延迟
            retryDelay: 1000,
          },
        },
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {/* 开发环境下显示React Query开发工具 */}
      {process.env.NODE_ENV === 'development' && (
        <ReactQueryDevtools 
          initialIsOpen={false} 
          position="bottom-right"
          buttonPosition="bottom-right"
        />
      )}
    </QueryClientProvider>
  );
}