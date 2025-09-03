/**
 * 现代化复选框组件
 * 支持完整的无障碍功能和键盘导航
 */

import React, { forwardRef, useId, useCallback } from 'react';
import { Check, Minus } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size' | keyof AccessibilityProps>, AccessibilityProps {
  label?: string;
  description?: string;
  error?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  indeterminate?: boolean;
  labelPosition?: 'left' | 'right';
  onCheckedChange?: (checked: boolean) => void;
}

const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>((
  {
    className,
    label,
    description,
    error,
    size = 'md',
    variant = 'default',
    indeterminate = false,
    labelPosition = 'right',
    checked,
    disabled,
    onCheckedChange,
    onChange,
    ...props
  },
  ref
) => {
  const checkboxId = useId();
  const descriptionId = useId();
  const errorId = useId();
  useTheme();
  
  // 无障碍功能
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);

  const hasError = !!error;
  const isChecked = checked || false;

  // 尺寸样式
  const sizeStyles = {
    sm: {
      checkbox: 'h-4 w-4',
      icon: 'h-3 w-3',
      label: 'text-sm',
      description: 'text-xs'
    },
    md: {
      checkbox: 'h-5 w-5',
      icon: 'h-4 w-4',
      label: 'text-base',
      description: 'text-sm'
    },
    lg: {
      checkbox: 'h-6 w-6',
      icon: 'h-5 w-5',
      label: 'text-lg',
      description: 'text-base'
    }
  };

  // 复选框样式
  const checkboxStyles = {
    default: [
      'border-2 border-pomegranate-300 bg-white',
      'checked:bg-gradient-to-br checked:from-pomegranate-600 checked:to-pomegranate-700 checked:border-pomegranate-600',
      'focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
      'hover:border-pomegranate-400 hover:shadow-sm hover:shadow-pomegranate-200',
      'disabled:bg-gray-100 disabled:border-gray-300 disabled:cursor-not-allowed',
      'dark:border-pomegranate-600 dark:bg-gray-800',
      'dark:checked:from-pomegranate-500 dark:checked:to-pomegranate-600 dark:checked:border-pomegranate-500',
      'dark:hover:border-pomegranate-500 dark:hover:shadow-pomegranate-900/30',
      'dark:disabled:bg-gray-700 dark:disabled:border-gray-600'
    ],
    filled: [
      'border-0 bg-gradient-to-br from-floral-50 to-floral-100',
      'checked:bg-gradient-to-br checked:from-pomegranate-600 checked:to-pomegranate-700',
      'focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
      'hover:from-floral-100 hover:to-floral-200 hover:shadow-sm hover:shadow-pomegranate-200',
      'disabled:bg-gray-200 disabled:cursor-not-allowed',
      'dark:from-gray-700 dark:to-gray-800',
      'dark:checked:from-pomegranate-500 dark:checked:to-pomegranate-600',
      'dark:hover:from-gray-600 dark:hover:to-gray-700 dark:hover:shadow-pomegranate-900/30',
      'dark:disabled:bg-gray-600'
    ],
    outline: [
      'border-2 border-pomegranate-400 bg-transparent',
      'checked:bg-gradient-to-br checked:from-pomegranate-600 checked:to-pomegranate-700 checked:border-pomegranate-600',
      'focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
      'hover:border-pomegranate-500 hover:bg-pomegranate-50 hover:shadow-sm hover:shadow-pomegranate-200',
      'disabled:border-gray-300 disabled:cursor-not-allowed',
      'dark:border-pomegranate-500',
      'dark:checked:from-pomegranate-500 dark:checked:to-pomegranate-600 dark:checked:border-pomegranate-500',
      'dark:hover:border-pomegranate-400 dark:hover:bg-pomegranate-900/20 dark:hover:shadow-pomegranate-900/30',
      'dark:disabled:border-gray-600'
    ]
  };

  // 处理变化事件
  const handleChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const newChecked = event.target.checked;
    
    // 调用原始onChange
    onChange?.(event);
    
    // 调用自定义onCheckedChange
    onCheckedChange?.(newChecked);
    
    // 无障碍公告
    const status = newChecked ? '已选中' : '未选中';
    const labelText = label || '复选框';
    announce(`${labelText} ${status}`);
  }, [onChange, onCheckedChange, announce, label]);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent<HTMLInputElement>) => {
    // 空格键切换状态
    if (event.key === ' ') {
      event.preventDefault();
      if (!disabled) {
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
  }, [isChecked, disabled, handleChange, handleKeyDown]);

  const checkboxClasses = cn(
    'rounded transition-all duration-200 cursor-pointer',
    'focus:outline-none',
    sizeStyles[size].checkbox,
    checkboxStyles[variant],
    hasError && 'border-red-500 focus:ring-red-500 checked:from-red-600 checked:to-red-700',
    className
  );

  const labelClasses = cn(
    'font-medium cursor-pointer select-none',
    sizeStyles[size].label,
    hasError ? 'text-red-600 dark:text-red-400' : 'text-gray-700 dark:text-gray-300',
    disabled && 'text-gray-400 cursor-not-allowed dark:text-gray-500'
  );

  const descriptionClasses = cn(
    'mt-1',
    sizeStyles[size].description,
    hasError ? 'text-red-500 dark:text-red-400' : 'text-gray-500 dark:text-gray-400',
    disabled && 'text-gray-400 dark:text-gray-500'
  );

  const errorClasses = cn(
    'mt-1 text-red-600 dark:text-red-400',
    sizeStyles[size].description
  );

  const renderCheckbox = () => (
    <div className="relative inline-flex items-center">
      <input
        ref={ref}
        id={checkboxId}
        type="checkbox"
        className={checkboxClasses}
        checked={isChecked}
        disabled={disabled}
        onChange={handleChange}
        onKeyDown={handleKeyDownEvent}
        aria-describedby={cn(
          description && descriptionId,
          error && errorId
        )}
        aria-invalid={hasError}
        aria-checked={indeterminate ? 'mixed' : isChecked}
        {...props}
      />
      
      {/* 自定义图标 */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        {indeterminate ? (
          <Minus 
            className={cn(
              sizeStyles[size].icon,
              'text-white transition-opacity duration-200',
              isChecked ? 'opacity-100' : 'opacity-0'
            )}
            aria-hidden="true"
          />
        ) : (
          <Check 
            className={cn(
              sizeStyles[size].icon,
              'text-white transition-opacity duration-200',
              isChecked ? 'opacity-100' : 'opacity-0'
            )}
            aria-hidden="true"
          />
        )}
      </div>
    </div>
  );

  const renderLabel = () => (
    <div className="flex-1">
      {label && (
        <label htmlFor={checkboxId} className={labelClasses}>
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
      {renderCheckbox()}
      {labelPosition === 'right' && renderLabel()}
    </div>
  );
});

Checkbox.displayName = 'Checkbox';

export default Checkbox;