/**
 * 现代化输入框组件
 * 基于设计令牌系统的统一输入实现
 */

import React, { forwardRef, useState, useId, useCallback } from 'react';
import { Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';

export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size' | 'aria-atomic' | 'aria-current' | 'aria-describedby' | 'aria-expanded' | 'aria-label' | 'aria-labelledby' | 'aria-live' | 'aria-selected' | 'aria-disabled' | 'aria-hidden' | 'aria-invalid' | 'aria-required' | 'role'>, AccessibilityProps {
  label?: string;
  error?: string;
  success?: string;
  hint?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  loading?: boolean;
  clearable?: boolean;
  onClear?: () => void;
}

const Input = forwardRef<HTMLInputElement, InputProps>((
  {
    className,
    label,
    error,
    success,
    hint,
    size = 'md',
    variant = 'outline',
    type = 'text',
    leftIcon,
    rightIcon,
    loading = false,
    clearable = false,
    onClear,
    disabled,
    value,
    ...props
  },
  ref
) => {
  const inputId = useId();
  useId();
  useTheme();
  const [showPassword, setShowPassword] = useState(false);
  const [, setIsFocused] = useState(false);
  
  // 无障碍功能
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);

  const isPassword = type === 'password';
  const hasError = !!error;
  const hasSuccess = !!success && !hasError;
  const hasValue = value !== undefined && value !== '';

  // 基础容器样式
  const containerStyles = [
    'relative w-full',
  ];

  // 标签样式
  const labelStyles = [
    'block text-sm font-medium mb-2',
    hasError ? 'text-red-600 dark:text-red-400' : 'text-gray-700 dark:text-gray-300',
  ];

  // 输入框尺寸
  const sizeStyles = {
    sm: 'h-9 px-3 text-sm',
    md: 'h-10 px-4 text-base',
    lg: 'h-12 px-5 text-lg',
  };

  // 输入框变体样式 - 石榴主题
  const variantStyles = {
    default: [
      'border border-pomegranate-300 bg-white/90',
      'focus:border-pomegranate-500 focus:ring-2 focus:ring-pomegranate-200',
      'hover:border-pomegranate-400',
      'backdrop-blur-sm',
      'transition-all duration-300',
    ],
    filled: [
      'border-0 bg-pomegranate-50/80',
      'focus:bg-white/95 focus:ring-2 focus:ring-pomegranate-300',
      'hover:bg-pomegranate-50/90',
      'backdrop-blur-sm',
    ],
    outline: [
      'border-2 border-pomegranate-400 bg-transparent',
      'focus:border-pomegranate-600 focus:ring-0',
      'hover:border-pomegranate-500',
      'hover:bg-pomegranate-50/20',
    ],
  };

  // 状态样式 - 石榴主题
  const stateStyles = {
    error: [
      'border-error-500 focus:border-error-500 focus:ring-error-200',
      'bg-error-50/50',
      'text-error-700',
    ],
    success: [
      'border-leaf-500 focus:border-leaf-500 focus:ring-leaf-200',
      'bg-leaf-50/50',
      'text-leaf-700',
    ],
    disabled: [
      'opacity-50 cursor-not-allowed bg-neutral-100/50',
      'border-neutral-300',
      'text-neutral-500',
    ],
  };

  // 输入框基础样式 - 石榴主题
  const inputStyles = [
    'w-full rounded-md transition-all duration-300',
    'placeholder:text-pomegranate-400/70',
    'text-text-primary',
    'focus:outline-none',
    'selection:bg-pomegranate-200 selection:text-pomegranate-800',
    leftIcon && 'pl-10',
    (rightIcon || isPassword || clearable || loading) && 'pr-10',
  ];

  // 图标容器样式 - 石榴主题
  const iconContainerStyles = [
    'absolute top-1/2 transform -translate-y-1/2',
    'flex items-center justify-center',
    'text-pomegranate-500',
    'transition-colors duration-200',
  ];

  // 左图标样式
  const leftIconStyles = [
    ...iconContainerStyles,
    'left-3',
  ];

  // 右图标样式
  const rightIconStyles = [
    ...iconContainerStyles,
    'right-3',
  ];

  // 消息样式 - 石榴主题
  const messageStyles = [
    'mt-2 text-sm flex items-center gap-1',
    'transition-all duration-200',
  ];

  // 渲染图标
  const renderIcon = (icon: React.ReactNode, size: number = 18) => {
    if (React.isValidElement(icon)) {
      return React.cloneElement(icon as React.ReactElement<any>, {
        size,
        className: cn('flex-shrink-0', icon.props.className),
      });
    }
    return icon;
  };

  // 处理清除
  const handleClear = useCallback(() => {
    if (onClear) {
      onClear();
      announce('输入内容已清除');
    }
  }, [onClear, announce]);

  // 切换密码显示
  const togglePasswordVisibility = useCallback(() => {
    setShowPassword(!showPassword);
    announce(showPassword ? '密码已隐藏' : '密码已显示');
  }, [showPassword, announce]);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    // 处理特殊键盘事件
    if (e.key === 'Escape' && clearable && hasValue) {
      e.preventDefault();
      handleClear();
    }
    
    // 调用通用键盘导航处理
    handleKeyDown(e.nativeEvent);
    
    // 调用原始的onKeyDown处理器
    props.onKeyDown?.(e);
  }, [clearable, hasValue, handleClear, handleKeyDown, props]);

  // 处理焦点事件
  const handleFocus = useCallback((e: React.FocusEvent<HTMLInputElement>) => {
    setIsFocused(true);
    if (label) {
      announce(`正在编辑 ${label}`);
    }
    props.onFocus?.(e);
  }, [label, announce, props]);

  // 处理失焦事件
  const handleBlur = useCallback((e: React.FocusEvent<HTMLInputElement>) => {
    setIsFocused(false);
    props.onBlur?.(e);
  }, [props]);

  // 获取输入框类型
  const getInputType = () => {
    if (isPassword) {
      return showPassword ? 'text' : 'password';
    }
    return type;
  };

  // 渲染右侧图标
  const renderRightIcon = () => {
    if (loading) {
      return (
        <div className="animate-spin rounded-full h-4 w-4 border-2 border-pomegranate-300 border-t-pomegranate-600" />
      );
    }

    if (isPassword) {
      return (
        <button
          type="button"
          onClick={togglePasswordVisibility}
          className="hover:text-pomegranate-600 dark:hover:text-pomegranate-400 transition-colors"
          aria-label={showPassword ? '隐藏密码' : '显示密码'}
          tabIndex={-1}
        >
          {showPassword ? renderIcon(<EyeOff aria-hidden="true" />) : renderIcon(<Eye aria-hidden="true" />)}
        </button>
      );
    }

    if (clearable && hasValue) {
      return (
        <button
          type="button"
          onClick={handleClear}
          className="hover:text-pomegranate-600 dark:hover:text-pomegranate-400 transition-colors"
          aria-label="清除输入内容"
          tabIndex={-1}
        >
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
            <path
              fillRule="evenodd"
              d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
              clipRule="evenodd"
            />
          </svg>
        </button>
      );
    }

    if (rightIcon) {
      return renderIcon(rightIcon);
    }

    return null;
  };

  return (
    <div className={cn(containerStyles, className)}>
      {/* 标签 */}
      {label && (
        <label 
          htmlFor={props.id || inputId}
          className={cn(labelStyles)}
        >
          {label}
        </label>
      )}

      {/* 输入框容器 */}
      <div className="relative">
        {/* 左图标 */}
        {leftIcon && (
          <div className={cn(leftIconStyles)} aria-hidden="true">
            {renderIcon(leftIcon)}
          </div>
        )}

        {/* 输入框 */}
        <input
          ref={ref}
          id={props.id || inputId}
          type={getInputType()}
          className={cn(
            inputStyles,
            sizeStyles[size],
            variantStyles[variant],
            hasError && stateStyles.error,
            hasSuccess && stateStyles.success,
            disabled && stateStyles.disabled
          )}
          disabled={disabled}
          value={value}
          aria-invalid={hasError ? 'true' : 'false'}
          aria-describedby={error || success || hint ? `${inputId}-message` : undefined}
          aria-required={props.required}
          aria-label={props['aria-label'] || label}
          onFocus={handleFocus}
          onBlur={handleBlur}
          onKeyDown={handleKeyDownEvent}
          {...props}
        />

        {/* 右图标 */}
        <div className={cn(rightIconStyles)} aria-hidden="true">
          {renderRightIcon()}
        </div>
      </div>

      {/* 错误消息 */}
      {hasError && (
        <div id={`${inputId}-message`} className={cn(messageStyles, 'text-red-600 dark:text-red-400')} role="alert">
          {renderIcon(<AlertCircle />, 16)}
          {error}
        </div>
      )}

      {/* 成功消息 */}
      {hasSuccess && (
        <div id={`${inputId}-message`} className={cn(messageStyles, 'text-green-600 dark:text-green-400')} role="status">
          {renderIcon(<CheckCircle />, 16)}
          {success}
        </div>
      )}

      {/* 提示消息 */}
      {hint && !hasError && !hasSuccess && (
        <div id={`${inputId}-message`} className={cn(messageStyles, 'text-gray-500 dark:text-gray-400')}>
          {hint}
        </div>
      )}
    </div>
  );
});

Input.displayName = 'Input';

// 文本域组件
export interface TextareaProps extends Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, 'size' | 'aria-atomic' | 'aria-current' | 'aria-describedby' | 'aria-expanded' | 'aria-label' | 'aria-labelledby' | 'aria-live' | 'aria-selected' | 'aria-disabled' | 'aria-hidden' | 'aria-invalid' | 'aria-required' | 'role'>, AccessibilityProps {
  label?: string;
  error?: string;
  success?: string;
  hint?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  resize?: 'none' | 'vertical' | 'horizontal' | 'both';
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>((
  {
    className,
    label,
    error,
    success,
    hint,
    size = 'md',
    variant = 'outline',
    resize = 'vertical',
    disabled,
    ...props
  },
  ref
) => {
  const textareaId = useId();
  const hasError = !!error;
  const hasSuccess = !!success && !hasError;
  
  // 无障碍功能
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);
  
  // 处理焦点事件
  const handleFocus = useCallback((e: React.FocusEvent<HTMLTextAreaElement>) => {
    if (label) {
      announce(`正在编辑 ${label}`);
    }
    props.onFocus?.(e);
  }, [label, announce, props]);
  
  // 处理键盘事件
  const handleKeyDownEvent = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // 调用通用键盘导航处理
    handleKeyDown(e.nativeEvent);
    
    // 调用原始的onKeyDown处理器
    props.onKeyDown?.(e);
  }, [handleKeyDown, props]);

  // 尺寸样式
  const sizeStyles = {
    sm: 'min-h-[80px] px-3 py-2 text-sm',
    md: 'min-h-[100px] px-4 py-3 text-base',
    lg: 'min-h-[120px] px-5 py-4 text-lg',
  };

  // 变体样式 - 石榴主题
  const variantStyles = {
    default: [
      'border border-pomegranate-300 bg-white/90',
      'focus:border-pomegranate-500 focus:ring-2 focus:ring-pomegranate-200',
      'hover:border-pomegranate-400',
      'backdrop-blur-sm',
      'transition-all duration-300',
    ],
    filled: [
      'border-0 bg-pomegranate-50/80',
      'focus:bg-white/95 focus:ring-2 focus:ring-pomegranate-300',
      'hover:bg-pomegranate-50/90',
      'backdrop-blur-sm',
    ],
    outline: [
      'border-2 border-pomegranate-400 bg-transparent',
      'focus:border-pomegranate-600 focus:ring-0',
      'hover:border-pomegranate-500',
      'hover:bg-pomegranate-50/20',
    ],
  };

  // 状态样式 - 石榴主题
  const stateStyles = {
    error: [
      'border-error-500 focus:border-error-500 focus:ring-error-200',
      'bg-error-50/50',
      'text-error-700',
    ],
    success: [
      'border-leaf-500 focus:border-leaf-500 focus:ring-leaf-200',
      'bg-leaf-50/50',
      'text-leaf-700',
    ],
    disabled: [
      'opacity-50 cursor-not-allowed bg-neutral-100/50',
      'border-neutral-300',
      'text-neutral-500',
    ],
  };

  // 调整大小样式
  const resizeStyles = {
    none: 'resize-none',
    vertical: 'resize-y',
    horizontal: 'resize-x',
    both: 'resize',
  };

  return (
    <div className="w-full">
      {/* 标签 */}
      {label && (
        <label 
          htmlFor={props.id || textareaId}
          className={cn(
            'block text-sm font-medium mb-2',
            hasError ? 'text-error-600' : 'text-pomegranate-700'
          )}
        >
          {label}
        </label>
      )}

      {/* 文本域 */}
      <textarea
        ref={ref}
        id={props.id || textareaId}
        className={cn(
          'w-full rounded-md transition-all duration-300',
          'placeholder:text-pomegranate-400/70',
          'text-text-primary',
          'focus:outline-none',
          'selection:bg-pomegranate-200 selection:text-pomegranate-800',
          sizeStyles[size],
          variantStyles[variant],
          resizeStyles[resize],
          hasError && stateStyles.error,
          hasSuccess && stateStyles.success,
          disabled && stateStyles.disabled,
          className
        )}
        disabled={disabled}
        aria-invalid={hasError ? 'true' : 'false'}
        aria-describedby={error || success || hint ? `${textareaId}-message` : undefined}
        aria-required={props.required}
        aria-label={props['aria-label'] || label}
        onFocus={handleFocus}
        onKeyDown={handleKeyDownEvent}
        {...props}
      />

      {/* 错误消息 */}
      {hasError && (
        <div id={`${textareaId}-message`} className="mt-2 text-sm flex items-center gap-1 text-error-600" role="alert">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {/* 成功消息 */}
      {hasSuccess && (
        <div id={`${textareaId}-message`} className="mt-2 text-sm flex items-center gap-1 text-leaf-600" role="status">
          <CheckCircle size={16} />
          {success}
        </div>
      )}

      {/* 提示消息 */}
      {hint && !hasError && !hasSuccess && (
        <div id={`${textareaId}-message`} className="mt-2 text-sm text-pomegranate-500">
          {hint}
        </div>
      )}
    </div>
  );
});

Textarea.displayName = 'Textarea';

export default Input;