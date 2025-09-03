import React, { Suspense, lazy } from 'react';
import { PageLoading } from './LoadingSkeleton';
import ErrorBoundary from './common/ErrorBoundary';
import { createLazyRoute } from '../utils/lazyRouteUtils';

interface LazyRouteProps {
  importFunc: () => Promise<{ default: React.ComponentType<Record<string, unknown>> }>;
  fallback?: React.ReactNode;
  errorFallback?: React.ReactNode;
  loadingTip?: string;
}

// 创建懒加载路由的高阶组件已移动到 ../utils/lazyRouteUtils.ts

// 通用懒加载路由组件
export const LazyRoute: React.FC<LazyRouteProps> = ({
  importFunc,
  fallback,
  errorFallback,
  loadingTip = '页面加载中...'
}) => {
  const LazyComponent = lazy(importFunc);
  
  return (
    <ErrorBoundary fallback={errorFallback}>
      <Suspense fallback={fallback || <PageLoading tip={loadingTip} />}>
        <LazyComponent />
      </Suspense>
    </ErrorBoundary>
  );
};

// 预定义的懒加载页面组件
export const LazyHomePage = createLazyRoute(
  () => import('../pages/HomePage'),
  { loadingTip: '首页加载中...' }
);

// AboutPage and ContactPage are not available, commenting out
// export const LazyAboutPage = createLazyRoute(
//   () => import('../pages/AboutPage'),
//   { loadingTip: '关于页面加载中...' }
// );

// export const LazyContactPage = createLazyRoute(
//   () => import('../pages/ContactPage'),
//   { loadingTip: '联系页面加载中...' }
// );

export const LazyProfilePage = createLazyRoute(
  () => import('../pages/ProfilePage'),
  { loadingTip: '个人资料加载中...' }
);

export const LazySettingsPage = createLazyRoute(
  () => import('../pages/Settings'),
  { loadingTip: '设置页面加载中...' }
);

// 路由预加载功能已移动到 ../utils/routePreload.ts

export default LazyRoute;