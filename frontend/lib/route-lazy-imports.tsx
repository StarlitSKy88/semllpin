'use client';

import dynamic from 'next/dynamic';
import { Skeleton } from '@/components/ui/skeleton';

const PageSkeleton = () => (
  <div className="container mx-auto px-4 py-8 space-y-6">
    <Skeleton className="h-12 w-3/4" />
    <Skeleton className="h-4 w-full" />
    <Skeleton className="h-4 w-5/6" />
    <Skeleton className="h-64 w-full" />
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <Skeleton className="h-32" />
      <Skeleton className="h-32" />
      <Skeleton className="h-32" />
    </div>
  </div>
);

const MapSkeleton = () => (
  <div className="w-full h-screen bg-muted animate-pulse flex items-center justify-center">
    <div className="text-center space-y-2">
      <div className="w-8 h-8 bg-primary rounded-full animate-bounce mx-auto" />
      <p className="text-muted-foreground">加载地图中...</p>
    </div>
  </div>
);

const AdminSkeleton = () => (
  <div className="container mx-auto px-4 py-8">
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-10 w-32" />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
      </div>
      <Skeleton className="h-96 w-full" />
    </div>
  </div>
);

const ProfileSkeleton = () => (
  <div className="container mx-auto px-4 py-8 space-y-6">
    <div className="flex items-start space-x-6">
      <Skeleton className="h-24 w-24 rounded-full" />
      <div className="space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-4 w-40" />
      </div>
    </div>
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <Skeleton className="h-32" />
      <Skeleton className="h-32" />
      <Skeleton className="h-32" />
    </div>
    <Skeleton className="h-64 w-full" />
  </div>
);

export const LazyMapPage = dynamic(
  () => import('@/app/map/page').then(mod => ({ default: mod.default })),
  {
    loading: MapSkeleton,
    ssr: false,
  }
);

export const LazyAdminPage = dynamic(
  () => import('@/app/admin/page').then(mod => ({ default: mod.default })),
  {
    loading: AdminSkeleton,
    ssr: false,
  }
);

export const LazyProfilePage = dynamic(
  () => import('@/app/profile/page').then(mod => ({ default: mod.default })),
  {
    loading: ProfileSkeleton,
    ssr: true,
  }
);

export const LazyProfileSettingsPage = dynamic(
  () => import('@/app/profile/settings/page').then(mod => ({ default: mod.default })),
  {
    loading: ProfileSkeleton,
    ssr: true,
  }
);

export const LazyProfileWalletPage = dynamic(
  () => import('@/app/profile/wallet/page').then(mod => ({ default: mod.default })),
  {
    loading: ProfileSkeleton,
    ssr: false,
  }
);

export const LazyProfileAnnotationsPage = dynamic(
  () => import('@/app/profile/annotations/page').then(mod => ({ default: mod.default })),
  {
    loading: ProfileSkeleton,
    ssr: true,
  }
);

export const LazyAboutPage = dynamic(
  () => import('@/app/about/page').then(mod => ({ default: mod.default })),
  {
    loading: PageSkeleton,
    ssr: true,
  }
);

export const LazyBlogPage = dynamic(
  () => import('@/app/blog/page').then(mod => ({ default: mod.default })),
  {
    loading: PageSkeleton,
    ssr: true,
  }
);

export const LazyContactPage = dynamic(
  () => import('@/app/contact/page').then(mod => ({ default: mod.default })),
  {
    loading: PageSkeleton,
    ssr: true,
  }
);

export const LazySettingsPage = dynamic(
  () => import('@/app/settings/page').then(mod => ({ default: mod.default })),
  {
    loading: ProfileSkeleton,
    ssr: true,
  }
);

// Portfolio pages with specific skeletons
export const LazyPortfolioCyberspaceProject = dynamic(
  () => import('@/app/portfolio/project-cyberscape/page').then(mod => ({ default: mod.default })),
  {
    loading: () => (
      <div className="w-full h-screen bg-gradient-to-b from-blue-900 to-purple-900 animate-pulse flex items-center justify-center">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-blue-400 rounded-full animate-pulse mx-auto" />
          <p className="text-blue-200">加载Cyberscape项目...</p>
        </div>
      </div>
    ),
    ssr: false,
  }
);

export const LazyPortfolioEtherealThreadsProject = dynamic(
  () => import('@/app/portfolio/ethereal-threads/page').then(mod => ({ default: mod.default })),
  {
    loading: () => (
      <div className="w-full h-screen bg-gradient-to-b from-pink-900 to-purple-900 animate-pulse flex items-center justify-center">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-pink-400 rounded-full animate-pulse mx-auto" />
          <p className="text-pink-200">加载Ethereal Threads项目...</p>
        </div>
      </div>
    ),
    ssr: false,
  }
);

export const LazyPortfolioQuantumLeapProject = dynamic(
  () => import('@/app/portfolio/quantum-leap/page').then(mod => ({ default: mod.default })),
  {
    loading: () => (
      <div className="w-full h-screen bg-gradient-to-b from-green-900 to-teal-900 animate-pulse flex items-center justify-center">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-green-400 rounded-full animate-pulse mx-auto" />
          <p className="text-green-200">加载Quantum Leap项目...</p>
        </div>
      </div>
    ),
    ssr: false,
  }
);

// Auth pages with minimal skeletons since they should load quickly
export const LazyLoginPage = dynamic(
  () => import('@/app/(auth)/login/page').then(mod => ({ default: mod.default })),
  {
    loading: () => (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-full max-w-md space-y-4">
          <Skeleton className="h-8 w-32 mx-auto" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </div>
    ),
    ssr: true,
  }
);

export const LazyRegisterPage = dynamic(
  () => import('@/app/(auth)/register/page').then(mod => ({ default: mod.default })),
  {
    loading: () => (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-full max-w-md space-y-4">
          <Skeleton className="h-8 w-32 mx-auto" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </div>
    ),
    ssr: true,
  }
);

export const LazyBlogPostPage = dynamic(
  () => import('@/app/blog/[slug]/page').then(mod => ({ default: mod.default })),
  {
    loading: () => (
      <div className="container mx-auto px-4 py-8 space-y-6 max-w-4xl">
        <Skeleton className="h-12 w-3/4" />
        <div className="flex items-center space-x-4">
          <Skeleton className="h-6 w-6 rounded-full" />
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-4 w-24" />
        </div>
        <Skeleton className="h-64 w-full" />
        <div className="space-y-3">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
          <Skeleton className="h-4 w-4/5" />
        </div>
      </div>
    ),
    ssr: true,
  }
);