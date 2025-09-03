import React, { Suspense, lazy } from 'react';
import { PageLoading } from '../components/LoadingSkeleton';
import ErrorBoundary from '../components/common/ErrorBoundary';

// 创建懒加载路由的高阶组件
export const createLazyRoute = (
  importFunc: () => Promise<{ default: React.ComponentType<Record<string, unknown>> }>,
  options: {
    fallback?: React.ReactNode;
    errorFallback?: React.ReactNode;
    loadingTip?: string;
  } = {}
) => {
  const LazyComponent = lazy(importFunc);
  
  return (props: Record<string, unknown>) => (
    <ErrorBoundary fallback={options.errorFallback}>
      <Suspense 
        fallback={options.fallback || <PageLoading tip={options.loadingTip} />}
      >
        <LazyComponent {...props} />
      </Suspense>
    </ErrorBoundary>
  );
};