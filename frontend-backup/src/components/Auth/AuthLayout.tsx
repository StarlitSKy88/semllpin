import React from 'react';
import { BrandSection } from './BrandSection';

interface AuthLayoutProps {
  children: React.ReactNode;
}

/**
 * 通用认证页面布局
 *  - 大屏：左侧品牌，右侧表单
 *  - 小屏：上下排列，保留背景渐变
 */
const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-purple-200 to-orange-50">
      {/* 桌面视图 */}
      <div className="hidden lg:flex min-h-screen">
        <BrandSection className="flex-1" />
        <div className="flex-1 flex items-center justify-center p-8">
          {children}
        </div>
      </div>

      {/* 移动视图 */}
      <div className="lg:hidden flex flex-col items-center justify-center min-h-screen p-4 space-y-4">
        <BrandSection className="w-full max-h-64" />
        {children}
      </div>
    </div>
  );
};

export default AuthLayout;