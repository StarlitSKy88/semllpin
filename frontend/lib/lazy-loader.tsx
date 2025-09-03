'use client';

import { lazy, Suspense, ComponentType, ReactNode } from 'react';
import { Skeleton } from '@/components/ui/skeleton';

interface LazyLoaderProps {
  children?: ReactNode;
  fallback?: ReactNode;
  className?: string;
}

const defaultFallback = (
  <div className="flex flex-col space-y-3 p-4">
    <Skeleton className="h-[125px] w-full rounded-xl" />
    <div className="space-y-2">
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-3/4" />
    </div>
  </div>
);

export function createLazyComponent<T = {}>(
  importFn: () => Promise<{ default: ComponentType<T> }>,
  fallback?: ReactNode
) {
  const LazyComponent = lazy(importFn);
  
  return function WrappedLazyComponent(props: T & LazyLoaderProps) {
    const { children, fallback: customFallback, className, ...restProps } = props as any;
    
    return (
      <Suspense fallback={customFallback || fallback || defaultFallback}>
        <div className={className}>
          <LazyComponent {...restProps}>
            {children}
          </LazyComponent>
        </div>
      </Suspense>
    );
  };
}

export const LazyInteractiveMap = createLazyComponent(
  () => import('@/components/map/interactive-map'),
  <div className="w-full h-96 bg-muted animate-pulse rounded-lg flex items-center justify-center">
    <span className="text-muted-foreground">加载地图中...</span>
  </div>
);

export const LazyEnhancedInteractiveMap = createLazyComponent(
  () => import('@/components/map/enhanced-interactive-map'),
  <div className="w-full h-96 bg-muted animate-pulse rounded-lg flex items-center justify-center">
    <span className="text-muted-foreground">加载增强地图中...</span>
  </div>
);

export const LazyPaymentModal = createLazyComponent(
  () => import('@/components/payment/payment-modal'),
  <div className="h-64 bg-muted animate-pulse rounded-lg" />
);

export const LazyWalletPage = createLazyComponent(
  () => import('@/components/wallet/wallet-page'),
  <div className="space-y-4">
    <Skeleton className="h-8 w-48" />
    <Skeleton className="h-32 w-full" />
    <Skeleton className="h-24 w-full" />
  </div>
);

export const LazyAdminAnalytics = createLazyComponent(
  () => import('@/components/admin/analytics-charts'),
  <div className="grid gap-4">
    <Skeleton className="h-64 w-full" />
    <div className="grid grid-cols-2 gap-4">
      <Skeleton className="h-32" />
      <Skeleton className="h-32" />
    </div>
  </div>
);

export const LazyUserManagement = createLazyComponent(
  () => import('@/components/admin/user-management'),
  <div className="space-y-4">
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-8 w-full" />
  </div>
);

export const LazyAnnotationReview = createLazyComponent(
  () => import('@/components/admin/annotation-review'),
  <div className="space-y-4">
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-8 w-full" />
  </div>
);

export const LazyScene = createLazyComponent(
  () => import('@/components/scene'),
  <div className="w-full h-screen bg-gradient-to-b from-background to-muted animate-pulse" />
);

export const LazyCyberspaceScene = createLazyComponent(
  () => import('@/components/project/cyberscape-scene'),
  <div className="w-full h-screen bg-gradient-to-b from-blue-900 to-purple-900 animate-pulse" />
);

export const LazyEtherealScene = createLazyComponent(
  () => import('@/components/project/ethereal-scene'),
  <div className="w-full h-screen bg-gradient-to-b from-pink-900 to-purple-900 animate-pulse" />
);

export const LazyQuantumScene = createLazyComponent(
  () => import('@/components/project/quantum-scene'),
  <div className="w-full h-screen bg-gradient-to-b from-green-900 to-teal-900 animate-pulse" />
);

export const LazyGlowScene = createLazyComponent(
  () => import('@/components/glow-scene'),
  <div className="w-full h-screen bg-gradient-to-b from-background to-muted animate-pulse" />
);

export const LazyPortfolio = createLazyComponent(
  () => import('@/components/portfolio'),
  <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
    <Skeleton className="h-64 rounded-lg" />
    <Skeleton className="h-64 rounded-lg" />
    <Skeleton className="h-64 rounded-lg" />
  </div>
);

export const LazyNotificationCenter = createLazyComponent(
  () => import('@/components/notifications/notification-center'),
  <div className="w-80 bg-background border rounded-lg shadow-lg">
    <Skeleton className="h-12 w-full rounded-t-lg" />
    <div className="p-4 space-y-3">
      <Skeleton className="h-6 w-full" />
      <Skeleton className="h-6 w-3/4" />
    </div>
  </div>
);

export const LazyCommentList = createLazyComponent(
  () => import('@/components/comments/comment-list'),
  <div className="space-y-4">
    <Skeleton className="h-20 w-full" />
    <Skeleton className="h-20 w-full" />
    <Skeleton className="h-20 w-full" />
  </div>
);

export const LazySearchResults = createLazyComponent(
  () => import('@/components/search/search-results'),
  <div className="space-y-4">
    <Skeleton className="h-6 w-48" />
    <Skeleton className="h-32 w-full" />
    <Skeleton className="h-32 w-full" />
  </div>
);

export const LazyAdvancedFilter = createLazyComponent(
  () => import('@/components/search/advanced-filter'),
  <div className="space-y-4 p-4">
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-8 w-full" />
  </div>
);

export const LazyLocationTracker = createLazyComponent(
  () => import('@/components/lbs/location-tracker'),
  <div className="h-16 bg-muted animate-pulse rounded-lg" />
);

export const LazyNearbyAnnotations = createLazyComponent(
  () => import('@/components/lbs/nearby-annotations'),
  <div className="space-y-3">
    <Skeleton className="h-16 w-full" />
    <Skeleton className="h-16 w-full" />
    <Skeleton className="h-16 w-full" />
  </div>
);

export const LazyRewardDiscoveryAnimation = createLazyComponent(
  () => import('@/components/lbs/reward-discovery-animation'),
  <div className="fixed inset-0 bg-background/80 backdrop-blur-sm animate-pulse" />
);

export const LazyGamifiedAchievementSystem = createLazyComponent(
  () => import('@/components/achievements/gamified-achievement-system'),
  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
    <Skeleton className="h-32 rounded-lg" />
    <Skeleton className="h-32 rounded-lg" />
    <Skeleton className="h-32 rounded-lg" />
  </div>
);

export const LazySmartCreationFlow = createLazyComponent(
  () => import('@/components/annotation/smart-creation-flow'),
  <div className="max-w-lg mx-auto space-y-4">
    <Skeleton className="h-8 w-full" />
    <Skeleton className="h-32 w-full" />
    <Skeleton className="h-12 w-full" />
  </div>
);