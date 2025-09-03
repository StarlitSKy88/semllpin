import React from 'react';
import { cn } from '../../utils/cn';

interface ModernCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  variant?: 'default' | 'glass' | 'elevated' | 'outlined' | 'gradient' | 'minimal';
  hoverable?: boolean;
  padding?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  rounded?: 'none' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '3xl';
  interactive?: boolean;
  loading?: boolean;
  header?: React.ReactNode;
  footer?: React.ReactNode;
}

export const ModernCard: React.FC<ModernCardProps> = ({
  children,
  className,
  variant = 'default',
  hoverable = true,
  padding = 'md',
  rounded = 'xl',
  interactive = false,
  loading = false,
  header,
  footer,
  onClick,
  ...props
}) => {
  // 基础样式 - 使用设计令牌
  const baseClasses = [
    'relative overflow-hidden',
    'transition-all duration-300 ease-out-expo',
    'border border-border-primary',
    // 可访问性
    'focus-visible:ring-2 focus-visible:ring-border-focus focus-visible:ring-offset-2',
    // 触摸设备优化
    interactive && 'touch:min-h-11',
    // 响应式
    'w-full',
  ].join(' ');
  
  // 变体样式 - 基于设计令牌
  const variants = {
    default: [
      'bg-background-secondary/90 backdrop-blur-sm',
      'shadow-lg shadow-neutral-950/50',
      'border-border-primary',
      hoverable && 'hover:shadow-xl hover:shadow-neutral-950/60 hover:-translate-y-1 hover:scale-[1.02]',
    ].join(' '),
    
    glass: [
      'bg-background-glass backdrop-blur-md',
      'border-border-primary/20',
      'shadow-glass',
      hoverable && 'hover:bg-background-glass hover:shadow-glass-lg hover:-translate-y-1',
    ].join(' '),
    
    elevated: [
      'bg-background-secondary',
      'shadow-2xl shadow-neutral-950/80',
      'border-border-secondary',
      hoverable && 'hover:shadow-glow hover:-translate-y-2 hover:scale-[1.01]',
    ].join(' '),
    
    outlined: [
      'bg-transparent border-2 border-border-primary',
      'hover:border-border-secondary',
      hoverable && 'hover:bg-background-secondary/50 hover:-translate-y-1',
    ].join(' '),
    
    gradient: [
      'bg-gradient-to-br from-background-secondary via-background-tertiary to-background-secondary',
      'border-border-primary',
      'shadow-lg shadow-neutral-950/50',
      hoverable && 'hover:shadow-glow-primary hover:-translate-y-1 hover:scale-[1.02]',
    ].join(' '),
    
    minimal: [
      'bg-background-primary border-border-primary/50',
      'shadow-sm',
      hoverable && 'hover:bg-background-secondary hover:shadow-md hover:-translate-y-0.5',
    ].join(' '),
  };
  
  // 内边距样式 - 响应式设计
  const paddingClasses = {
    none: 'p-0',
    xs: 'p-2 sm:p-3',
    sm: 'p-3 sm:p-4',
    md: 'p-4 sm:p-6',
    lg: 'p-6 sm:p-8',
    xl: 'p-8 sm:p-10',
  };
  
  // 圆角样式
  const roundedClasses = {
    none: 'rounded-none',
    sm: 'rounded-sm',
    md: 'rounded-md',
    lg: 'rounded-lg',
    xl: 'rounded-xl',
    '2xl': 'rounded-2xl',
    '3xl': 'rounded-3xl',
  };
  
  // 交互样式
  const interactiveClasses = [
    interactive && 'cursor-pointer',
    interactive && 'active:scale-95',
    // 键盘导航支持
    interactive && 'focus:outline-none tabindex-0',
  ].filter(Boolean).join(' ');

  return (
    <div
      className={cn(
        baseClasses,
        variants[variant],
        paddingClasses[padding],
        roundedClasses[rounded],
        interactiveClasses,
        loading && 'pointer-events-none',
        // 减少动画偏好支持
        'reduced-motion:transition-none reduced-motion:transform-none',
        className
      )}
      onClick={interactive ? onClick : undefined}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-disabled={loading}
      {...props}
    >
      {/* 加载状态覆盖层 */}
      {loading && (
        <div className="absolute inset-0 bg-background-secondary/80 backdrop-blur-sm flex items-center justify-center z-50 rounded-inherit">
          <div className="flex flex-col items-center gap-3">
            <svg 
              className="animate-spin h-6 w-6 text-interactive-primary" 
              fill="none" 
              viewBox="0 0 24 24"
              aria-hidden={true}
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
            <span className="text-sm text-text-secondary">加载中...</span>
          </div>
        </div>
      )}
      
      {/* 卡片头部 */}
      {header && (
        <div className="border-b border-border-primary pb-4 mb-4 last:border-b-0 last:pb-0 last:mb-0">
          {header}
        </div>
      )}
      
      {/* 卡片内容 */}
      <div className={cn(
        'relative z-10',
        loading && 'opacity-50'
      )}>
        {children}
      </div>
      
      {/* 卡片底部 */}
      {footer && (
        <div className="border-t border-border-primary pt-4 mt-4 first:border-t-0 first:pt-0 first:mt-0">
          {footer}
        </div>
      )}
      
      {/* 悬停效果光晕 */}
      {hoverable && (
        <div className="absolute inset-0 rounded-inherit opacity-0 hover:opacity-5 bg-gradient-to-br from-interactive-primary via-transparent to-accent-500 transition-opacity duration-300 pointer-events-none" />
      )}
      
      {/* 交互涟漪效果 */}
      {interactive && (
        <div className="absolute inset-0 rounded-inherit opacity-0 active:opacity-10 bg-interactive-primary transition-opacity duration-150 pointer-events-none" />
      )}
    </div>
  );
};