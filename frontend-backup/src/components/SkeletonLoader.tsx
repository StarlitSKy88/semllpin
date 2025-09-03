import React from 'react';
import { clsx } from 'clsx';

interface SkeletonProps {
  className?: string;
  width?: string | number;
  height?: string | number;
  variant?: 'text' | 'rectangular' | 'circular' | 'rounded';
  animation?: 'pulse' | 'wave' | 'none';
  lines?: number;
  spacing?: string;
}

export function Skeleton({
  className = '',
  width,
  height,
  variant = 'text',
  animation = 'pulse',
  lines = 1,
  spacing = '0.5rem'
}: SkeletonProps) {
  const baseClasses = clsx(
    'bg-gradient-to-r from-gray-200 via-gray-300 to-gray-200 dark:from-gray-700 dark:via-gray-600 dark:to-gray-700',
    {
      // 动画效果
      'animate-pulse': animation === 'pulse',
      'animate-shimmer': animation === 'wave',
      // 变体样式
      'rounded-none': variant === 'rectangular',
      'rounded-full': variant === 'circular',
      'rounded-md': variant === 'rounded',
      'rounded-sm': variant === 'text'
    },
    className
  );

  const style: React.CSSProperties = {
    width: width || (variant === 'text' ? '100%' : '40px'),
    height: height || (variant === 'text' ? '1em' : '40px'),
    ...(variant === 'text' && { minHeight: '1em' })
  };

  if (lines > 1) {
    return (
      <div className="space-y-2" style={{ gap: spacing }}>
        {Array.from({ length: lines }, (_, index) => (
          <div
            key={`item-${index}`}
            className={clsx(baseClasses, {
              'w-3/4': index === lines - 1 && variant === 'text' // 最后一行稍短
            })}
            style={{
              ...style,
              width: index === lines - 1 && variant === 'text' ? '75%' : style.width
            }}
          />
        ))}
      </div>
    );
  }

  return <div className={baseClasses} style={style} />;
}

// 卡片骨架屏
interface SkeletonCardProps {
  className?: string;
  showAvatar?: boolean;
  showImage?: boolean;
  lines?: number;
  actions?: number;
}

export function SkeletonCard({
  className = '',
  showAvatar = false,
  showImage = false,
  lines = 3,
  actions = 0
}: SkeletonCardProps) {
  return (
    <div className={clsx('p-4 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800', className)}>
      {/* 头部区域 */}
      {showAvatar && (
        <div className="flex items-center space-x-3 mb-4">
          <Skeleton variant="circular" width={40} height={40} />
          <div className="flex-1">
            <Skeleton width="60%" height="1.2em" className="mb-2" />
            <Skeleton width="40%" height="1em" />
          </div>
        </div>
      )}

      {/* 图片区域 */}
      {showImage && (
        <Skeleton 
          variant="rounded" 
          width="100%" 
          height={200} 
          className="mb-4" 
        />
      )}

      {/* 内容区域 */}
      <div className="space-y-2 mb-4">
        <Skeleton lines={lines} />
      </div>

      {/* 操作区域 */}
      {actions > 0 && (
        <div className="flex space-x-2">
          {Array.from({ length: actions }, (_, index) => (
            <Skeleton 
              key={`item-${index}`}
              variant="rounded" 
              width={80} 
              height={32} 
            />
          ))}
        </div>
      )}
    </div>
  );
}

// 列表项骨架屏
interface SkeletonListItemProps {
  className?: string;
  showAvatar?: boolean;
  showThumbnail?: boolean;
  showMeta?: boolean;
}

export function SkeletonListItem({
  className = '',
  showAvatar = true,
  showThumbnail = false,
  showMeta = true
}: SkeletonListItemProps) {
  return (
    <div className={clsx('flex items-center space-x-3 p-3', className)}>
      {/* 头像或缩略图 */}
      {showAvatar && (
        <Skeleton variant="circular" width={48} height={48} />
      )}
      {showThumbnail && (
        <Skeleton variant="rounded" width={64} height={48} />
      )}

      {/* 内容区域 */}
      <div className="flex-1 min-w-0">
        <Skeleton width="70%" height="1.2em" className="mb-2" />
        <Skeleton width="50%" height="1em" className="mb-1" />
        {showMeta && (
          <Skeleton width="30%" height="0.9em" />
        )}
      </div>

      {/* 右侧操作 */}
      <div className="flex-shrink-0">
        <Skeleton variant="rounded" width={24} height={24} />
      </div>
    </div>
  );
}

// 表格骨架屏
interface SkeletonTableProps {
  className?: string;
  rows?: number;
  columns?: number;
  showHeader?: boolean;
}

export function SkeletonTable({
  className = '',
  rows = 5,
  columns = 4,
  showHeader = true
}: SkeletonTableProps) {
  return (
    <div className={clsx('w-full', className)}>
      {/* 表头 */}
      {showHeader && (
        <div className="grid gap-4 p-4 border-b border-gray-200 dark:border-gray-700" 
             style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
          {Array.from({ length: columns }, (_, index) => (
            <Skeleton key={`item-${index}`} width="80%" height="1.2em" />
          ))}
        </div>
      )}

      {/* 表格行 */}
      {Array.from({ length: rows }, (_, rowIndex) => (
        <div 
          key={rowIndex}
          className="grid gap-4 p-4 border-b border-gray-100 dark:border-gray-800"
          style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}
        >
          {Array.from({ length: columns }, (_, colIndex) => (
            <Skeleton 
              key={colIndex} 
              width={colIndex === 0 ? '90%' : '70%'} 
              height="1em" 
            />
          ))}
        </div>
      ))}
    </div>
  );
}

// 导航骨架屏
export function SkeletonNavigation({ className = '' }: { className?: string }) {
  return (
    <nav className={clsx('flex items-center justify-between p-4', className)}>
      {/* Logo */}
      <Skeleton width={120} height={32} variant="rounded" />

      {/* 导航菜单 */}
      <div className="hidden md:flex space-x-6">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={`item-${index}`} width={80} height="1.2em" />
        ))}
      </div>

      {/* 用户区域 */}
      <div className="flex items-center space-x-3">
        <Skeleton variant="circular" width={32} height={32} />
        <Skeleton width={60} height="1em" className="hidden sm:block" />
      </div>
    </nav>
  );
}

// 页面骨架屏
interface SkeletonPageProps {
  className?: string;
  showNavigation?: boolean;
  showSidebar?: boolean;
  showFooter?: boolean;
}

export function SkeletonPage({
  className = '',
  showNavigation = true,
  showSidebar = false,
  showFooter = true
}: SkeletonPageProps) {
  return (
    <div className={clsx('min-h-screen bg-gray-50 dark:bg-gray-900', className)}>
      {/* 导航栏 */}
      {showNavigation && (
        <SkeletonNavigation className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700" />
      )}

      <div className="flex">
        {/* 侧边栏 */}
        {showSidebar && (
          <aside className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 p-4">
            <div className="space-y-4">
              {Array.from({ length: 6 }, (_, index) => (
                <div key={`item-${index}`} className="flex items-center space-x-3">
                  <Skeleton variant="rounded" width={20} height={20} />
                  <Skeleton width="70%" height="1em" />
                </div>
              ))}
            </div>
          </aside>
        )}

        {/* 主内容区域 */}
        <main className="flex-1 p-6">
          {/* 页面标题 */}
          <div className="mb-6">
            <Skeleton width="30%" height="2em" className="mb-2" />
            <Skeleton width="60%" height="1.2em" />
          </div>

          {/* 内容卡片 */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }, (_, index) => (
              <SkeletonCard 
                key={`item-${index}`}
                showImage={index % 2 === 0}
                showAvatar={index % 3 === 0}
                lines={3}
                actions={2}
              />
            ))}
          </div>
        </main>
      </div>

      {/* 页脚 */}
      {showFooter && (
        <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 p-6">
          <div className="grid gap-4 md:grid-cols-3">
            {Array.from({ length: 3 }, (_, index) => (
              <div key={`item-${index}`} className="space-y-2">
                <Skeleton width="60%" height="1.2em" className="mb-3" />
                <Skeleton lines={4} />
              </div>
            ))}
          </div>
        </footer>
      )}
    </div>
  );
}

// 统计卡片骨架屏
export function SkeletonStatsCard({ className = '' }: { className?: string }) {
  return (
    <div className={clsx('p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700', className)}>
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <Skeleton width="60%" height="1em" className="mb-2" />
          <Skeleton width="40%" height="2em" className="mb-1" />
          <Skeleton width="30%" height="0.9em" />
        </div>
        <Skeleton variant="rounded" width={48} height={48} />
      </div>
    </div>
  );
}

// 图表骨架屏
export function SkeletonChart({ className = '', height = 300 }: { className?: string; height?: number }) {
  return (
    <div className={clsx('p-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700', className)}>
      {/* 图表标题 */}
      <div className="mb-4">
        <Skeleton width="40%" height="1.5em" className="mb-2" />
        <Skeleton width="60%" height="1em" />
      </div>

      {/* 图表区域 */}
      <div className="relative" style={{ height }}>
        <Skeleton 
          variant="rounded" 
          width="100%" 
          height="100%" 
          className="absolute inset-0" 
        />
        
        {/* 模拟图表元素 */}
        <div className="absolute inset-4 flex items-end justify-between">
          {Array.from({ length: 8 }, (_, index) => (
            <Skeleton 
              key={`item-${index}`}
              variant="rectangular"
              width={20}
              height={Math.random() * 60 + 20}
              className="opacity-30"
            />
          ))}
        </div>
      </div>

      {/* 图例 */}
      <div className="flex justify-center space-x-4 mt-4">
        {Array.from({ length: 3 }, (_, index) => (
          <div key={`item-${index}`} className="flex items-center space-x-2">
            <Skeleton variant="circular" width={12} height={12} />
            <Skeleton width={60} height="1em" />
          </div>
        ))}
      </div>
    </div>
  );
}