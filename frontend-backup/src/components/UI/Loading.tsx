/**
 * 现代化加载组件
 * 基于设计令牌系统的统一加载状态实现
 */

import React from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';

export interface LoadingProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  variant?: 'spinner' | 'dots' | 'pulse' | 'bars' | 'ring' | 'wave';
  color?: 'primary' | 'secondary' | 'gray' | 'white';
  text?: string;
  overlay?: boolean;
  className?: string;
}

const Loading: React.FC<LoadingProps> = ({
  size = 'md',
  variant = 'spinner',
  color = 'primary',
  text,
  overlay = false,
  className,
}) => {
  useTheme();

  // 尺寸样式
  const sizeStyles = {
    xs: {
      container: 'w-4 h-4',
      text: 'text-xs mt-1',
      dot: 'w-1 h-1',
      bar: 'w-1 h-3',
    },
    sm: {
      container: 'w-6 h-6',
      text: 'text-sm mt-2',
      dot: 'w-1.5 h-1.5',
      bar: 'w-1 h-4',
    },
    md: {
      container: 'w-8 h-8',
      text: 'text-base mt-3',
      dot: 'w-2 h-2',
      bar: 'w-1 h-5',
    },
    lg: {
      container: 'w-12 h-12',
      text: 'text-lg mt-4',
      dot: 'w-3 h-3',
      bar: 'w-1.5 h-6',
    },
    xl: {
      container: 'w-16 h-16',
      text: 'text-xl mt-5',
      dot: 'w-4 h-4',
      bar: 'w-2 h-8',
    },
  };

  // 颜色样式
  const colorStyles = {
    primary: 'text-pomegranate-500',
    secondary: 'text-floral-500',
    gray: 'text-gray-500',
    white: 'text-white',
  };

  // 渲染旋转器
  const renderSpinner = () => (
    <div
      className={cn(
        'animate-spin rounded-full border-2 border-current border-t-transparent',
        sizeStyles[size].container,
        colorStyles[color]
      )}
      role="status"
      aria-label="加载中"
    />
  );

  // 渲染点状加载
  const renderDots = () => (
    <div className="flex space-x-1" role="status" aria-label="加载中">
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className={cn(
            'rounded-full bg-current animate-pulse',
            sizeStyles[size].dot,
            colorStyles[color]
          )}
          style={{
            animationDelay: `${i * 0.2}s`,
            animationDuration: '1s',
          }}
        />
      ))}
    </div>
  );

  // 渲染脉冲加载
  const renderPulse = () => (
    <div
      className={cn(
        'rounded-full bg-current animate-pulse',
        sizeStyles[size].container,
        colorStyles[color]
      )}
      role="status"
      aria-label="加载中"
    />
  );

  // 渲染条状加载
  const renderBars = () => (
    <div className="flex items-end space-x-1" role="status" aria-label="加载中">
      {[0, 1, 2, 3].map((i) => (
        <div
          key={i}
          className={cn(
            'bg-current animate-pulse',
            sizeStyles[size].bar,
            colorStyles[color]
          )}
          style={{
            animationDelay: `${i * 0.15}s`,
            animationDuration: '0.8s',
          }}
        />
      ))}
    </div>
  );

  // 渲染环形加载
  const renderRing = () => (
    <div className="relative" role="status" aria-label="加载中">
      <div
        className={cn(
          'rounded-full border-2 border-floral-200 dark:border-pomegranate-700',
          sizeStyles[size].container
        )}
      />
      <div
        className={cn(
          'absolute top-0 left-0 rounded-full border-2 border-transparent border-t-current animate-spin',
          sizeStyles[size].container,
          colorStyles[color]
        )}
      />
    </div>
  );

  // 渲染波浪加载
  const renderWave = () => (
    <div className="flex items-center space-x-1" role="status" aria-label="加载中">
      {[0, 1, 2, 3, 4].map((i) => (
        <div
          key={i}
          className={cn(
            'rounded-full bg-current',
            sizeStyles[size].dot,
            colorStyles[color]
          )}
          style={{
            animation: `wave 1.4s ease-in-out ${i * 0.1}s infinite`,
          }}
        />
      ))}
      <style>{`
        @keyframes wave {
          0%, 60%, 100% {
            transform: initial;
          }
          30% {
            transform: translateY(-15px);
          }
        }
      `}</style>
    </div>
  );

  // 根据变体渲染不同的加载动画
  const renderLoader = () => {
    switch (variant) {
      case 'dots':
        return renderDots();
      case 'pulse':
        return renderPulse();
      case 'bars':
        return renderBars();
      case 'ring':
        return renderRing();
      case 'wave':
        return renderWave();
      default:
        return renderSpinner();
    }
  };

  const content = (
    <div
      className={cn(
        'flex flex-col items-center justify-center',
        overlay && [
          'fixed inset-0 z-50',
          'bg-white/80 dark:bg-pomegranate-900/80',
          'backdrop-blur-sm',
        ],
        className
      )}
    >
      {renderLoader()}
      {text && (
        <div
          className={cn(
            'font-medium text-center',
            sizeStyles[size].text,
            colorStyles[color]
          )}
        >
          {text}
        </div>
      )}
    </div>
  );

  return content;
};

// 页面加载组件
export interface PageLoadingProps {
  title?: string;
  description?: string;
  size?: LoadingProps['size'];
  variant?: LoadingProps['variant'];
}

export const PageLoading: React.FC<PageLoadingProps> = ({
  title = '加载中...',
  description,
  size = 'lg',
  variant = 'spinner',
}) => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-floral-50 dark:bg-pomegranate-900">
      <div className="text-center space-y-4">
        <Loading size={size} variant={variant} color="primary" />
        <div className="space-y-2">
          <h2 className="text-xl font-semibold text-pomegranate-900 dark:text-floral-100">
            {title}
          </h2>
          {description && (
            <p className="text-pomegranate-500 dark:text-floral-400">
              {description}
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

// 内容加载组件
export interface ContentLoadingProps {
  lines?: number;
  avatar?: boolean;
  className?: string;
}

export const ContentLoading: React.FC<ContentLoadingProps> = ({
  lines = 3,
  avatar = false,
  className,
}) => {
  return (
    <div className={cn('animate-pulse space-y-4', className)}>
      {avatar && (
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-floral-300 dark:bg-pomegranate-600 rounded-full" />
          <div className="space-y-2 flex-1">
            <div className="h-4 bg-floral-300 dark:bg-pomegranate-600 rounded w-1/4" />
            <div className="h-3 bg-floral-300 dark:bg-pomegranate-600 rounded w-1/3" />
          </div>
        </div>
      )}
      <div className="space-y-3">
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className={cn(
              'h-4 bg-floral-300 dark:bg-pomegranate-600 rounded',
              i === lines - 1 ? 'w-2/3' : 'w-full'
            )}
          />
        ))}
      </div>
    </div>
  );
};

// 表格加载组件
export interface TableLoadingProps {
  rows?: number;
  columns?: number;
  className?: string;
}

export const TableLoading: React.FC<TableLoadingProps> = ({
  rows = 5,
  columns = 4,
  className,
}) => {
  return (
    <div className={cn('animate-pulse space-y-4', className)}>
      {/* 表头 */}
      <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
        {Array.from({ length: columns }).map((_, i) => (
          <div key={i} className="h-4 bg-floral-300 dark:bg-pomegranate-600 rounded" />
        ))}
      </div>
      
      {/* 表格行 */}
      <div className="space-y-3">
        {Array.from({ length: rows }).map((_, rowIndex) => (
          <div
            key={rowIndex}
            className="grid gap-4"
            style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}
          >
            {Array.from({ length: columns }).map((_, colIndex) => (
              <div
                key={colIndex}
                className="h-4 bg-floral-200 dark:bg-pomegranate-700 rounded"
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

// 卡片加载组件
export interface CardLoadingProps {
  hasImage?: boolean;
  hasAvatar?: boolean;
  className?: string;
}

export const CardLoading: React.FC<CardLoadingProps> = ({
  hasImage = false,
  hasAvatar = false,
  className,
}) => {
  return (
    <div className={cn('animate-pulse space-y-4 p-6 bg-white dark:bg-pomegranate-800 rounded-lg', className)}>
      {/* 图片 */}
      {hasImage && (
        <div className="w-full h-48 bg-floral-300 dark:bg-pomegranate-600 rounded" />
      )}
      
      {/* 头部 */}
      <div className="flex items-center space-x-3">
        {hasAvatar && (
          <div className="w-10 h-10 bg-floral-300 dark:bg-pomegranate-600 rounded-full" />
        )}
        <div className="space-y-2 flex-1">
          <div className="h-4 bg-floral-300 dark:bg-pomegranate-600 rounded w-3/4" />
          <div className="h-3 bg-floral-300 dark:bg-pomegranate-600 rounded w-1/2" />
        </div>
      </div>
      
      {/* 内容 */}
      <div className="space-y-3">
        <div className="h-4 bg-floral-200 dark:bg-pomegranate-700 rounded" />
        <div className="h-4 bg-floral-200 dark:bg-pomegranate-700 rounded" />
        <div className="h-4 bg-floral-200 dark:bg-pomegranate-700 rounded w-2/3" />
      </div>
    </div>
  );
};

export default Loading;