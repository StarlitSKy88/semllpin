/**
 * 现代化单选按钮组件
 * 支持完整的无障碍功能和键盘导航
 */

import React, { forwardRef, useId, useCallback, createContext, useContext } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';

// Radio Group Context
interface RadioGroupContextValue {
  value?: string;
  name?: string;
  disabled?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  onChange?: (value: string) => void;
}

const RadioGroupContext = createContext<RadioGroupContextValue | undefined>(undefined);

const useRadioGroup = () => {
  const context = useContext(RadioGroupContext);
  if (!context) {
    throw new Error('Radio must be used within a RadioGroup');
  }
  return context;
};

// Radio Group Props
export interface RadioGroupProps extends AccessibilityProps {
  value?: string;
  defaultValue?: string;
  name?: string;
  disabled?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  orientation?: 'horizontal' | 'vertical';
  className?: string;
  children: React.ReactNode;
  onChange?: (value: string) => void;
}

// Radio Group Component
export const RadioGroup = forwardRef<HTMLDivElement, RadioGroupProps>((
  {
    value,
    defaultValue,
    name,
    disabled = false,
    size = 'md',
    variant = 'default',
    orientation = 'vertical',
    className,
    children,
    onChange,
    ...props
  },
  ref
) => {
  const groupId = useId();
  const { handleKeyDown } = useKeyboardNavigation([]);
  
  const [internalValue, setInternalValue] = React.useState(defaultValue || '');
  const currentValue = value !== undefined ? value : internalValue;

  const { announce } = useAnnouncer();
  
  const handleValueChange = useCallback((newValue: string) => {
    if (value === undefined) {
      setInternalValue(newValue);
    }
    onChange?.(newValue);
    announce(`已选择 ${newValue}`);
  }, [value, onChange, announce]);

  const contextValue: RadioGroupContextValue = {
    value: currentValue,
    name: name || groupId,
    disabled,
    size,
    variant,
    onChange: handleValueChange
  };

  const groupClasses = cn(
    'flex',
    orientation === 'horizontal' ? 'flex-row space-x-4' : 'flex-col space-y-3',
    className
  );

  return (
    <RadioGroupContext.Provider value={contextValue}>
      <div
        ref={ref}
        className={groupClasses}
        role="radiogroup"
        onKeyDown={(e) => handleKeyDown(e.nativeEvent)}
        {...props}
      >
        {children}
      </div>
    </RadioGroupContext.Provider>
  );
});

RadioGroup.displayName = 'RadioGroup';

// Radio Props
export interface RadioProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size' | 'aria-atomic' | 'aria-current' | 'aria-describedby' | 'aria-expanded' | 'aria-label' | 'aria-labelledby' | 'aria-live' | 'aria-selected' | 'aria-disabled' | 'aria-hidden' | 'aria-invalid' | 'aria-required' | 'role'>, AccessibilityProps {
  value: string;
  label?: string;
  description?: string;
  error?: string;
  labelPosition?: 'left' | 'right';
}

// Radio Component
const Radio = forwardRef<HTMLInputElement, RadioProps>((
  {
    value,
    className,
    label,
    description,
    error,
    labelPosition = 'right',
    disabled: propDisabled,
    ...props
  },
  ref
) => {
  const radioId = useId();
  const descriptionId = useId();
  const errorId = useId();
  useTheme();
  
  const {
    value: groupValue,
    name,
    disabled: groupDisabled,
    size = 'md',
    variant = 'default',
    onChange
  } = useRadioGroup();
  
  // 无障碍功能
  useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);

  const disabled = propDisabled || groupDisabled;
  const isChecked = groupValue === value;
  const hasError = !!error;

  // 尺寸样式
  const sizeStyles = {
    sm: {
      radio: 'h-4 w-4',
      dot: 'h-2 w-2',
      label: 'text-sm',
      description: 'text-xs'
    },
    md: {
      radio: 'h-5 w-5',
      dot: 'h-2.5 w-2.5',
      label: 'text-base',
      description: 'text-sm'
    },
    lg: {
      radio: 'h-6 w-6',
      dot: 'h-3 w-3',
      label: 'text-lg',
      description: 'text-base'
    }
  };

  // 单选按钮样式
  const radioStyles = {
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
    if (!disabled && event.target.checked) {
      onChange?.(value);
    }
  }, [disabled, onChange, value]);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent<HTMLInputElement>) => {
    // 空格键或回车键选择
    if (event.key === ' ' || event.key === 'Enter') {
      event.preventDefault();
      if (!disabled) {
        onChange?.(value);
      }
    }
    
    // 其他键盘导航
    handleKeyDown(event.nativeEvent);
  }, [disabled, onChange, value, handleKeyDown]);

  const radioClasses = cn(
    'rounded-full transition-all duration-200 cursor-pointer',
    'focus:outline-none',
    sizeStyles[size].radio,
    radioStyles[variant],
    hasError && 'border-pomegranate-500 focus:ring-pomegranate-500 checked:from-pomegranate-600 checked:to-pomegranate-700',
    className
  );

  const labelClasses = cn(
    'font-medium cursor-pointer select-none',
    sizeStyles[size].label,
    hasError ? 'text-pomegranate-600 dark:text-pomegranate-400' : 'text-pomegranate-700 dark:text-pomegranate-300',
    disabled && 'text-pomegranate-400 cursor-not-allowed dark:text-pomegranate-500'
  );

  const descriptionClasses = cn(
    'mt-1',
    sizeStyles[size].description,
    hasError ? 'text-pomegranate-500 dark:text-pomegranate-400' : 'text-pomegranate-500 dark:text-pomegranate-400',
    disabled && 'text-pomegranate-400 dark:text-pomegranate-500'
  );

  const errorClasses = cn(
    'mt-1 text-pomegranate-600 dark:text-pomegranate-400',
    sizeStyles[size].description
  );

  const renderRadio = () => (
    <div className="relative inline-flex items-center">
      <input
        ref={ref}
        id={radioId}
        type="radio"
        name={name}
        value={value}
        className={radioClasses}
        checked={isChecked}
        disabled={disabled}
        onChange={handleChange}
        onKeyDown={handleKeyDownEvent}
        aria-describedby={cn(
          description && descriptionId,
          error && errorId
        )}
        aria-invalid={hasError}
        {...props}
      />
      
      {/* 自定义圆点 */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div 
          className={cn(
            'rounded-full bg-white transition-all duration-200',
            sizeStyles[size].dot,
            isChecked ? 'opacity-100 scale-100' : 'opacity-0 scale-50'
          )}
          aria-hidden="true"
        />
      </div>
    </div>
  );

  const renderLabel = () => (
    <div className="flex-1">
      {label && (
        <label htmlFor={radioId} className={labelClasses}>
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
      {renderRadio()}
      {labelPosition === 'right' && renderLabel()}
    </div>
  );
});

Radio.displayName = 'Radio';

export default Radio;
// RadioGroup is already exported above