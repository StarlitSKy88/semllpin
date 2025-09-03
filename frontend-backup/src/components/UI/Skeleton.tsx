import React from 'react';
import { clsx } from 'clsx';

interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'circular' | 'rectangular' | 'rounded';
  width?: string | number;
  height?: string | number;
  animation?: 'pulse' | 'wave' | 'none';
  lines?: number; // For text variant
}

const Skeleton: React.FC<SkeletonProps> = ({
  className,
  variant = 'rectangular',
  width,
  height,
  animation = 'pulse',
  lines = 1,
}) => {
  const baseClasses = 'bg-floral-200 dark:bg-pomegranate-800/30';
  
  const animationClasses = {
    pulse: 'animate-pulse',
    wave: 'animate-wave',
    none: '',
  };

  const variantClasses = {
    text: 'h-4 rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-none',
    rounded: 'rounded-md',
  };

  const style: React.CSSProperties = {
    width: width || (variant === 'text' ? '100%' : undefined),
    height: height || (variant === 'circular' ? width : undefined),
  };

  if (variant === 'text' && lines > 1) {
    return (
      <div className={clsx('space-y-2', className)}>
        {Array.from({ length: lines }).map((_, index) => (
          <div
            key={`item-${index}`}
            className={clsx(
              baseClasses,
              variantClasses.text,
              animationClasses[animation],
              index === lines - 1 ? 'w-3/4' : 'w-full'
            )}
            style={{
              width: index === lines - 1 ? '75%' : '100%',
              height: height || '1rem',
            }}
          />
        ))}
      </div>
    );
  }

  return (
    <div
      className={clsx(
        baseClasses,
        variantClasses[variant],
        animationClasses[animation],
        className
      )}
      style={style}
      role="status"
      aria-label="Loading..."
    />
  );
};

// Skeleton组合组件
const SkeletonCard: React.FC<{ className?: string }> = ({ className }) => (
  <div className={clsx('p-6 space-y-4', className)}>
    <Skeleton variant="circular" width={64} height={64} className="mx-auto" />
    <Skeleton variant="text" lines={2} className="text-center" />
    <Skeleton variant="rectangular" height={40} className="rounded-md" />
  </div>
);

const SkeletonStatistic: React.FC<{ className?: string }> = ({ className }) => (
  <div className={clsx('text-center space-y-2', className)}>
    <Skeleton variant="text" height={20} width="60%" className="mx-auto" />
    <Skeleton variant="text" height={32} width="80%" className="mx-auto" />
    <Skeleton variant="text" height={16} width="40%" className="mx-auto" />
  </div>
);

const SkeletonAvatar: React.FC<{ size?: number; className?: string }> = ({ 
  size = 40, 
  className 
}) => (
  <Skeleton 
    variant="circular" 
    width={size} 
    height={size} 
    className={className} 
  />
);

const SkeletonButton: React.FC<{ className?: string; width?: string | number }> = ({ 
  className, 
  width = 120 
}) => (
  <Skeleton 
    variant="rounded" 
    width={width} 
    height={44} 
    className={className} 
  />
);

export { 
  Skeleton, 
  SkeletonCard, 
  SkeletonStatistic, 
  SkeletonAvatar, 
  SkeletonButton 
};
export default Skeleton;