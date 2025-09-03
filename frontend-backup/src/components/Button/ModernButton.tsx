import React from 'react';
import { cn } from '../../utils/cn';

interface ModernButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'success' | 'warning';
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  loading?: boolean;
  icon?: React.ReactNode;
  children: React.ReactNode;
  fullWidth?: boolean;
  rounded?: 'none' | 'sm' | 'md' | 'lg' | 'xl' | 'full';
}

export const ModernButton: React.FC<ModernButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  children,
  className,
  disabled,
  fullWidth = false,
  rounded = 'lg',
  ...props
}) => {
  // 基础样式 - 使用设计令牌
  const baseClasses = [
    'inline-flex items-center justify-center',
    'font-medium transition-all duration-200',
    'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-background-primary',
    'disabled:opacity-50 disabled:cursor-not-allowed',
    'active:scale-95 transform',
    'relative overflow-hidden',
    // 触摸设备优化
    'touch:min-h-11 touch:min-w-11', // 44px最小触摸目标
    // 可访问性
    'focus-visible:ring-2 focus-visible:ring-border-focus',
    // 响应式
    fullWidth ? 'w-full' : 'w-auto',
  ].join(' ');
  
  // 变体样式 - 基于设计令牌
  const variants = {
    primary: [
      'bg-gradient-to-r from-interactive-primary to-accent-500',
      'hover:from-interactive-primary-hover hover:to-accent-600',
      'active:from-interactive-primary-active active:to-accent-700',
      'text-text-inverse shadow-lg hover:shadow-glow-primary',
      'focus:ring-interactive-primary',
    ].join(' '),
    
    secondary: [
      'bg-interactive-secondary border border-border-primary',
      'hover:bg-interactive-secondary-hover hover:border-border-secondary',
      'active:bg-interactive-secondary-active',
      'text-text-primary shadow-sm hover:shadow-md',
      'focus:ring-interactive-secondary',
    ].join(' '),
    
    outline: [
      'border-2 border-interactive-primary bg-transparent',
      'text-interactive-primary hover:bg-interactive-primary hover:text-text-inverse',
      'active:bg-interactive-primary-active active:text-text-inverse',
      'focus:ring-interactive-primary',
    ].join(' '),
    
    ghost: [
      'bg-transparent text-text-secondary',
      'hover:bg-background-secondary hover:text-text-primary',
      'active:bg-background-tertiary',
      'focus:ring-border-primary',
    ].join(' '),
    
    danger: [
      'bg-gradient-to-r from-error-500 to-error-600',
      'hover:from-error-600 hover:to-error-700',
      'active:from-error-700 active:to-error-800',
      'text-text-inverse shadow-lg hover:shadow-glow-error',
      'focus:ring-error-500',
    ].join(' '),
    
    success: [
      'bg-gradient-to-r from-success-500 to-success-600',
      'hover:from-success-600 hover:to-success-700',
      'active:from-success-700 active:to-success-800',
      'text-text-inverse shadow-lg hover:shadow-glow-success',
      'focus:ring-success-500',
    ].join(' '),
    
    warning: [
      'bg-gradient-to-r from-warning-500 to-warning-600',
      'hover:from-warning-600 hover:to-warning-700',
      'active:from-warning-700 active:to-warning-800',
      'text-text-inverse shadow-lg hover:shadow-glow-warning',
      'focus:ring-warning-500',
    ].join(' '),
  };
  
  // 尺寸样式 - 响应式设计
  const sizes = {
    xs: 'px-2 py-1 text-xs gap-1 min-h-6',
    sm: 'px-3 py-1.5 text-sm gap-1.5 min-h-8 sm:px-4 sm:py-2',
    md: 'px-4 py-2 text-base gap-2 min-h-10 sm:px-6 sm:py-2.5',
    lg: 'px-6 py-3 text-lg gap-2.5 min-h-12 sm:px-8 sm:py-3.5',
    xl: 'px-8 py-4 text-xl gap-3 min-h-14 sm:px-10 sm:py-4.5',
  };
  
  // 圆角样式
  const roundedClasses = {
    none: 'rounded-none',
    sm: 'rounded-sm',
    md: 'rounded-md',
    lg: 'rounded-lg',
    xl: 'rounded-xl',
    full: 'rounded-full',
  };

  return (
    <button
      className={cn(
        baseClasses,
        variants[variant],
        sizes[size],
        roundedClasses[rounded],
        loading && 'cursor-wait pointer-events-none',
        // 减少动画偏好支持
        'reduced-motion:transition-none reduced-motion:transform-none',
        className
      )}
      disabled={disabled || loading}
      // 可访问性属性
      aria-disabled={disabled || loading}
      aria-busy={loading}
      {...props}
    >
      {/* 加载状态 */}
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-inherit rounded-inherit">
          <svg 
            className="animate-spin h-4 w-4 sm:h-5 sm:w-5" 
            fill="none" 
            viewBox="0 0 24 24"
            aria-hidden
          >
            <circle 
              className="opacity-25" 
              cx="12" 
              cy="12" 
              r="10" 
              stroke="currentColor" 
              strokeWidth="4"
            />
            <path 
              className="opacity-75" 
              fill="currentColor" 
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        </div>
      )}
      
      {/* 按钮内容 */}
      <div className={cn(
        'flex items-center justify-center gap-inherit',
        loading && 'opacity-0'
      )}>
        {icon && (
          <span 
            className="flex-shrink-0" 
            aria-hidden
          >
            {icon}
          </span>
        )}
        <span className="truncate">{children}</span>
      </div>
      
      {/* 涟漪效果 */}
      <div className="absolute inset-0 rounded-inherit opacity-0 hover:opacity-10 active:opacity-20 bg-white transition-opacity duration-200 pointer-events-none" />
    </button>
  );
};