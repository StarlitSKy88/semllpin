/**
 * 现代化卡片组件
 * 基于设计令牌系统的统一卡片实现
 */

import React, { forwardRef, useId, useCallback } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useAnnouncer, useKeyboardNavigation } from '../../hooks/useAccessibility';

export interface CardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, keyof AccessibilityProps>, AccessibilityProps {
  variant?: 'default' | 'elevated' | 'outlined' | 'glass' | 'gradient';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  rounded?: 'none' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full';
  shadow?: 'none' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  border?: boolean;
  hoverable?: boolean;
  loading?: boolean;
  interactive?: boolean;
  children?: React.ReactNode;
}

const Card = forwardRef<HTMLDivElement, CardProps>((
  {
    className,
    variant = 'default',
    size = 'md',
    rounded = 'lg',
    shadow = 'md',
    border = false,
    hoverable = false,
    loading = false,
    interactive = false,
    children,
    ...props
  },
  ref
) => {
  useTheme();
  const cardId = useId();
  
  // 无障碍功能hooks
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([], {
    orientation: 'vertical',
    loop: false
  });

  // 事件处理函数
  const handleClick = useCallback((event: React.MouseEvent<HTMLDivElement>) => {
    if (interactive && props.onClick) {
      announce('卡片已激活');
      props.onClick(event);
    }
  }, [interactive, props.onClick, announce]);

  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    if (interactive) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        if (props.onClick) {
          announce('卡片已激活');
          props.onClick(event as any);
        }
      }
      handleKeyDown(event as any);
    }
    if (props.onKeyDown) {
      props.onKeyDown(event);
    }
  }, [interactive, props.onClick, props.onKeyDown, announce, handleKeyDown]);

  // 基础样式
  const baseStyles = [
    'relative overflow-hidden',
    'transition-all duration-300 ease-out',
    loading && 'animate-pulse',
  ];

  // 尺寸样式 - 石榴主题
  const sizeStyles = {
    sm: 'p-4',
    md: 'p-6',
    lg: 'p-8',
    xl: 'p-10',
  };

  // 圆角样式
  const roundedStyles = {
    none: 'rounded-none',
    sm: 'rounded-sm',
    md: 'rounded-md',
    lg: 'rounded-lg',
    xl: 'rounded-xl',
    '2xl': 'rounded-2xl',
    full: 'rounded-full',
  };

  // 阴影样式
  const shadowStyles = {
    none: 'shadow-none',
    sm: 'shadow-sm',
    md: 'shadow-md',
    lg: 'shadow-lg',
    xl: 'shadow-xl',
    '2xl': 'shadow-2xl',
  };

  // 变体样式 - 石榴主题
  const variantStyles = {
    default: [
      'bg-gradient-to-br from-white to-floral-50/50 dark:from-pomegranate-900 dark:to-floral-900/50',
      'text-pomegranate-800 dark:text-pomegranate-100',
      'shadow-lg shadow-pomegranate-200/30 dark:shadow-pomegranate-800/30',
      'border border-pomegranate-200/40 dark:border-pomegranate-700/40',
    ],
    elevated: [
      'bg-gradient-to-br from-white to-floral-50/70 dark:from-pomegranate-900 dark:to-floral-900/70',
      'text-pomegranate-800 dark:text-pomegranate-100',
      'shadow-xl shadow-pomegranate-300/40 hover:shadow-2xl hover:shadow-pomegranate-400/50',
      'transform hover:-translate-y-2 hover:scale-[1.03] transition-all duration-300',
      'border border-pomegranate-300/50 dark:border-pomegranate-600/50',
      'hover:border-pomegranate-400/70 dark:hover:border-pomegranate-500/70',
    ],
    outlined: [
      'bg-transparent hover:bg-gradient-to-br hover:from-pomegranate-50/30 hover:to-floral-50/30',
      'dark:hover:from-pomegranate-900/20 dark:hover:to-floral-900/20',
      'text-pomegranate-700 dark:text-pomegranate-300',
      'border-2 border-pomegranate-400 dark:border-pomegranate-500',
      'shadow-none hover:shadow-lg hover:shadow-pomegranate-200/40',
    ],
    glass: [
      'bg-white/20 backdrop-blur-lg dark:bg-pomegranate-900/20',
      'text-pomegranate-800 dark:text-pomegranate-200',
      'border border-pomegranate-200/50 dark:border-pomegranate-600/50',
      'shadow-lg shadow-pomegranate-300/20 dark:shadow-pomegranate-800/20',
      'hover:bg-white/30 dark:hover:bg-pomegranate-900/30',
    ],
    gradient: [
      'bg-gradient-to-br from-pomegranate-100 via-floral-100 to-pomegranate-200',
      'dark:from-pomegranate-800 dark:via-floral-800 dark:to-pomegranate-700',
      'text-pomegranate-800 dark:text-pomegranate-100',
      'shadow-xl shadow-floral-300/40 dark:shadow-floral-800/40',
      'border border-floral-300/60 dark:border-floral-600/60',
      'hover:shadow-2xl hover:shadow-floral-400/50',
    ],
  };

  // 边框样式
  const borderStyles = border ? [
    'border border-pomegranate-200 dark:border-pomegranate-700',
  ] : [];

  // 悬停样式
  const hoverStyles = hoverable ? [
    'hover:shadow-xl hover:shadow-pomegranate-300/50 hover:-translate-y-1',
    'cursor-pointer transition-all duration-300',
  ] : [];

  // 交互样式 - 石榴主题
  const interactiveStyles = interactive ? [
    'cursor-pointer',
    'hover:bg-gradient-to-br hover:from-pomegranate-50/40 hover:to-floral-50/40',
    'dark:hover:from-pomegranate-900/30 dark:hover:to-floral-900/30',
    'active:scale-[0.98] transition-transform duration-150',
    'focus:outline-none focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
    'dark:focus:ring-offset-pomegranate-900',
  ] : [];

  // 加载样式 - 石榴主题
  const loadingStyles = loading ? [
    'pointer-events-none',
    'select-none',
    'opacity-70',
    'filter blur-sm',
  ] : [];

  return (
    <div
      ref={ref}
      id={props.id || cardId}
      className={cn(
        baseStyles,
        sizeStyles[size],
        roundedStyles[rounded],
        variant !== 'outlined' && variant !== 'glass' && shadowStyles[shadow],
        variantStyles[variant],
        borderStyles,
        hoverStyles,
        interactiveStyles,
        loadingStyles,
        className
      )}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-busy={loading}
      aria-label={props['aria-label']}
      onClick={interactive ? handleClick : props.onClick}
      onKeyDown={handleKeyDownEvent}
      {...(interactive ? {} : props)}
    >
      {/* 加载覆盖层 */}
      {loading && (
        <div className="absolute inset-0 bg-white/60 dark:bg-pomegranate-900/60 backdrop-blur-sm flex items-center justify-center z-10">
          <div className="animate-spin rounded-full h-8 w-8 border-2 border-pomegranate-300 border-t-pomegranate-600 dark:border-pomegranate-600 dark:border-t-pomegranate-300" />
        </div>
      )}
      
      {/* 渐变覆盖层 */}
      {variant === 'gradient' && (
        <div className="absolute inset-0 bg-gradient-to-br from-pomegranate-500/10 to-floral-500/10 dark:from-pomegranate-400/5 dark:to-floral-400/5 pointer-events-none" />
      )}
      
      {/* 内容 */}
      <div className="relative z-0">
        {children}
      </div>
    </div>
  );
});

Card.displayName = 'Card';

// 卡片头部组件
export interface CardHeaderProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  action?: React.ReactNode;
  avatar?: React.ReactNode;
  size?: 'sm' | 'md' | 'lg';
}

export const CardHeader = forwardRef<HTMLDivElement, CardHeaderProps>((
  {
    className,
    title,
    subtitle,
    action,
    avatar,
    size = 'md',
    children,
    ...props
  },
  ref
) => {
  const sizeStyles = {
    sm: 'pb-3',
    md: 'pb-4',
    lg: 'pb-6',
  };

  const titleSizes = {
    sm: 'text-lg',
    md: 'text-xl',
    lg: 'text-2xl',
  };

  const subtitleSizes = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
  };

  return (
    <div
      ref={ref}
      className={cn(
        'flex items-start justify-between',
        sizeStyles[size],
        className
      )}
      {...props}
    >
      <div className="flex items-start space-x-3 flex-1 min-w-0">
        {/* 头像 */}
        {avatar && (
          <div className="flex-shrink-0">
            {avatar}
          </div>
        )}
        
        {/* 标题和副标题 */}
        <div className="flex-1 min-w-0">
          {title && (
            <h3 className={cn(
              'font-semibold text-pomegranate-800 dark:text-pomegranate-100 truncate',
              titleSizes[size]
            )}>
              {title}
            </h3>
          )}
          {subtitle && (
            <p className={cn(
              'text-pomegranate-600 dark:text-pomegranate-400 mt-1',
              subtitleSizes[size]
            )}>
              {subtitle}
            </p>
          )}
          {children}
        </div>
      </div>
      
      {/* 操作按钮 */}
      {action && (
        <div className="flex-shrink-0 ml-4">
          {action}
        </div>
      )}
    </div>
  );
});

CardHeader.displayName = 'CardHeader';

// 卡片内容组件
export interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: 'sm' | 'md' | 'lg';
}

export const CardContent = forwardRef<HTMLDivElement, CardContentProps>((
  {
    className,
    size = 'md',
    children,
    ...props
  },
  ref
) => {
  const sizeStyles = {
    sm: 'py-2',
    md: 'py-3',
    lg: 'py-4',
  };

  return (
    <div
      ref={ref}
      className={cn(
        'text-pomegranate-700 dark:text-pomegranate-300',
        sizeStyles[size],
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
});

CardContent.displayName = 'CardContent';

// 卡片底部组件
export interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: 'sm' | 'md' | 'lg';
  justify?: 'start' | 'center' | 'end' | 'between';
}

export const CardFooter = forwardRef<HTMLDivElement, CardFooterProps>((
  {
    className,
    size = 'md',
    justify = 'end',
    children,
    ...props
  },
  ref
) => {
  const sizeStyles = {
    sm: 'pt-3',
    md: 'pt-4',
    lg: 'pt-6',
  };

  const justifyStyles = {
    start: 'justify-start',
    center: 'justify-center',
    end: 'justify-end',
    between: 'justify-between',
  };

  return (
    <div
      ref={ref}
      className={cn(
        'flex items-center gap-3',
        sizeStyles[size],
        justifyStyles[justify],
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
});

CardFooter.displayName = 'CardFooter';

// 卡片分隔线组件
export const CardDivider = forwardRef<HTMLHRElement, React.HTMLAttributes<HTMLHRElement>>((
  { className, ...props },
  ref
) => {
  return (
    <hr
      ref={ref}
      className={cn(
        'my-4 border-0 border-t border-pomegranate-200 dark:border-pomegranate-700',
        className
      )}
      {...props}
    />
  );
});

CardDivider.displayName = 'CardDivider';

export default Card;