/**
 * 现代化开关组件
 * 支持完整的无障碍功能和键盘导航
 */

import React, { forwardRef, useId, useCallback } from 'react';
import { cn } from '../../utils/cn';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';

export interface SwitchProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size' | 'aria-atomic' | 'aria-current' | 'aria-describedby' | 'aria-expanded' | 'aria-label' | 'aria-labelledby' | 'aria-live' | 'aria-selected' | 'aria-disabled' | 'aria-hidden' | 'aria-invalid' | 'aria-required' | 'role'>, AccessibilityProps {
  label?: string;
  description?: string;
  error?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  labelPosition?: 'left' | 'right';
  thumbIcon?: React.ReactNode;
  checkedThumbIcon?: React.ReactNode;
  loading?: boolean;
  onCheckedChange?: (checked: boolean) => void;
}

const Switch = forwardRef<HTMLInputElement, SwitchProps>((
  {
    className,
    label,
    description,
    error,
    size = 'md',
    variant = 'default',
    labelPosition = 'right',
    thumbIcon,
    checkedThumbIcon,
    loading = false,
    checked,
    disabled,
    onCheckedChange,
    onChange,
    ...props
  },
  ref
) => {
  const switchId = useId();
  const descriptionId = useId();
  const errorId = useId();

  
  // 无障碍功能
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);

  const hasError = !!error;
  const isChecked = checked || false;
  const isDisabled = disabled || loading;

  // 尺寸样式
  const sizeStyles = {
    sm: {
      track: 'h-5 w-9',
      thumb: 'h-4 w-4',
      translate: 'translate-x-4',
      label: 'text-sm',
      description: 'text-xs'
    },
    md: {
      track: 'h-6 w-11',
      thumb: 'h-5 w-5',
      translate: 'translate-x-5',
      label: 'text-base',
      description: 'text-sm'
    },
    lg: {
      track: 'h-7 w-14',
      thumb: 'h-6 w-6',
      translate: 'translate-x-7',
      label: 'text-lg',
      description: 'text-base'
    }
  };

  // 轨道样式
  const trackStyles = {
    default: {
      base: [
        'relative inline-flex items-center rounded-full transition-colors duration-200',
        'focus-within:ring-2 focus-within:ring-pomegranate-500 focus-within:ring-offset-2',
        'cursor-pointer'
      ],
      unchecked: [
        'bg-gray-200 dark:bg-gray-700'
      ],
      checked: [
        'bg-gradient-to-r from-pomegranate-600 to-pomegranate-700 dark:from-pomegranate-500 dark:to-pomegranate-600'
      ],
      disabled: [
        'opacity-50 cursor-not-allowed'
      ],
      error: [
        'ring-2 ring-red-500'
      ]
    },
    filled: {
      base: [
        'relative inline-flex items-center rounded-full transition-colors duration-200',
        'focus-within:ring-2 focus-within:ring-pomegranate-500 focus-within:ring-offset-2',
        'cursor-pointer'
      ],
      unchecked: [
        'bg-gradient-to-r from-floral-100 to-floral-200 dark:from-gray-600 dark:to-gray-700'
      ],
      checked: [
        'bg-gradient-to-r from-pomegranate-700 to-pomegranate-800 dark:from-pomegranate-400 dark:to-pomegranate-500'
      ],
      disabled: [
        'opacity-50 cursor-not-allowed'
      ],
      error: [
        'ring-2 ring-red-500'
      ]
    },
    outline: {
      base: [
        'relative inline-flex items-center rounded-full transition-all duration-200',
        'border-2 focus-within:ring-2 focus-within:ring-pomegranate-500 focus-within:ring-offset-2',
        'cursor-pointer'
      ],
      unchecked: [
        'border-pomegranate-300 bg-transparent dark:border-pomegranate-600'
      ],
      checked: [
        'border-pomegranate-600 bg-gradient-to-r from-pomegranate-600 to-pomegranate-700 dark:border-pomegranate-500 dark:from-pomegranate-500 dark:to-pomegranate-600'
      ],
      disabled: [
        'opacity-50 cursor-not-allowed'
      ],
      error: [
        'border-red-500 ring-2 ring-red-500'
      ]
    }
  };

  // 滑块样式
  const thumbStyles = {
    base: [
      'inline-block rounded-full bg-white shadow-lg transform transition-transform duration-200',
      'flex items-center justify-center'
    ],
    translate: isChecked ? sizeStyles[size].translate : 'translate-x-0.5'
  };

  // 处理变化事件
  const handleChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const newChecked = event.target.checked;
    
    // 调用原始onChange
    onChange?.(event);
    
    // 调用自定义onCheckedChange
    onCheckedChange?.(newChecked);
    
    // 无障碍公告
    const status = newChecked ? '已开启' : '已关闭';
    const labelText = label || '开关';
    announce(`${labelText} ${status}`);
  }, [onChange, onCheckedChange, announce, label]);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent<HTMLInputElement>) => {
    // 空格键切换状态
    if (event.key === ' ') {
      event.preventDefault();
      if (!isDisabled) {
        const newChecked = !isChecked;
        const syntheticEvent = {
          target: { checked: newChecked },
          currentTarget: { checked: newChecked }
        } as React.ChangeEvent<HTMLInputElement>;
        handleChange(syntheticEvent);
      }
    }
    
    // 其他键盘导航
    handleKeyDown(event.nativeEvent);
  }, [isChecked, isDisabled, handleChange, handleKeyDown]);

  const trackClasses = cn(
    sizeStyles[size].track,
    trackStyles[variant].base,
    isChecked ? trackStyles[variant].checked : trackStyles[variant].unchecked,
    isDisabled && trackStyles[variant].disabled,
    hasError && trackStyles[variant].error
  );

  const thumbClasses = cn(
    sizeStyles[size].thumb,
    thumbStyles.base,
    thumbStyles.translate
  );

  const labelClasses = cn(
    'font-medium cursor-pointer select-none',
    sizeStyles[size].label,
    hasError ? 'text-pomegranate-600 dark:text-pomegranate-400' : 'text-pomegranate-700 dark:text-pomegranate-300',
    isDisabled && 'text-pomegranate-400 cursor-not-allowed dark:text-pomegranate-500'
  );

  const descriptionClasses = cn(
    'mt-1',
    sizeStyles[size].description,
    hasError ? 'text-pomegranate-500 dark:text-pomegranate-400' : 'text-pomegranate-500 dark:text-pomegranate-400',
    isDisabled && 'text-pomegranate-400 dark:text-pomegranate-500'
  );

  const errorClasses = cn(
    'mt-1 text-pomegranate-600 dark:text-pomegranate-400',
    sizeStyles[size].description
  );

  const renderSwitch = () => (
    <div className={trackClasses}>
      <input
        ref={ref}
        id={switchId}
        type="checkbox"
        role="switch"
        className="sr-only"
        checked={isChecked}
        disabled={isDisabled}
        onChange={handleChange}
        onKeyDown={handleKeyDownEvent}
        aria-describedby={cn(
          description && descriptionId,
          error && errorId
        )}
        aria-invalid={hasError}
        aria-checked={isChecked}
        {...props}
      />
      
      {/* 滑块 */}
      <span className={thumbClasses} aria-hidden="true">
        {loading ? (
          <div className="w-3 h-3 border-2 border-gray-300 border-t-pomegranate-600 rounded-full animate-spin" />
        ) : (
          <>
            {isChecked && checkedThumbIcon ? checkedThumbIcon : thumbIcon}
          </>
        )}
      </span>
    </div>
  );

  const renderLabel = () => (
    <div className="flex-1">
      {label && (
        <label htmlFor={switchId} className={labelClasses}>
          {label}
        </label>
      )}
      {description && (
        <p id={descriptionId} className={descriptionClasses}>
          {description}
        </p>
      )}
      {error && (
        <p id={errorId} className={errorClasses} role="alert">
          {error}
        </p>
      )}
    </div>
  );

  return (
    <div className="flex items-start space-x-3">
      {labelPosition === 'left' && renderLabel()}
      {renderSwitch()}
      {labelPosition === 'right' && renderLabel()}
    </div>
  );
});

Switch.displayName = 'Switch';

export default Switch;