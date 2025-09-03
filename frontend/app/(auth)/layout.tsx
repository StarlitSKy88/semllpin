'use client';

import { Suspense } from 'react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { redirect } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { isAuthenticated } = useAuthStore();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // 等待组件挂载以避免hydration错误
  if (!mounted) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white/20"></div>
      </div>
    );
  }

  // 如果用户已登录，重定向到主页
  if (isAuthenticated) {
    redirect('/');
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] flex flex-col">
      {/* 背景装饰 */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-transparent to-purple-500/5 pointer-events-none" />
      <div className="absolute inset-0 bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))] pointer-events-none" />
      
      {/* 主内容区域 */}
      <div className="flex-1 flex items-center justify-center p-4 relative z-10">
        <div className="w-full max-w-md">
          <Suspense fallback={
            <div className="bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl">
              <div className="animate-pulse space-y-6">
                <div className="h-8 bg-white/10 rounded"></div>
                <div className="space-y-4">
                  <div className="h-12 bg-white/10 rounded"></div>
                  <div className="h-12 bg-white/10 rounded"></div>
                </div>
                <div className="h-12 bg-white/10 rounded"></div>
              </div>
            </div>
          }>
            {children}
          </Suspense>
        </div>
      </div>
      
      {/* 底部链接 */}
      <div className="text-center p-6 text-white/60 text-sm relative z-10">
        <p>SmellPin - 全球气味标注平台</p>
      </div>
    </div>
  );
}