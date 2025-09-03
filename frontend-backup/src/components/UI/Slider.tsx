/**
 * 现代化滑块组件
 * 支持完整的无障碍功能和键盘导航
 */

import React, { forwardRef, useId, useCallback, useRef, useState } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';

export interface SliderProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size' | 'aria-atomic' | 'aria-current' | 'aria-describedby' | 'aria-expanded' | 'aria-label' | 'aria-labelledby' | 'aria-live' | 'aria-selected' | 'aria-disabled' | 'aria-hidden' | 'aria-invalid' | 'aria-required' | 'role'>, AccessibilityProps {
  label?: string;
  description?: string;
  error?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'gradient';
  orientation?: 'horizontal' | 'vertical';
  showValue?: boolean;
  showTicks?: boolean;
  showTooltip?: boolean;
  formatValue?: (value: number) => string;
  marks?: Array<{ value: number; label?: string }>;
  thumbIcon?: React.ReactNode;
  onValueChange?: (value: number) => void;
  onValueCommit?: (value: number) => void;
}

const Slider = forwardRef<HTMLInputElement, SliderProps>((
  {
    className,
    label,
    description,
    error,
    size = 'md',
    variant = 'default',
    orientation = 'horizontal',
    showValue = false,
    showTicks = false,
    showTooltip = false,
    formatValue = (value) => value.toString(),
    marks = [],
    thumbIcon,
    min = 0,
    max = 100,
    step = 1,
    value,
    defaultValue,
    disabled,
    onValueChange,
    onValueCommit,
    onChange,
    onMouseUp,
    onTouchEnd,
    ...props
  },
  ref
) => {
  const sliderId = useId();
  const descriptionId = useId();
  const errorId = useId();
  const trackRef = useRef<HTMLDivElement>(null);
  useTheme();
  
  // 内部状态
  const [internalValue, setInternalValue] = useState(value ?? defaultValue ?? min);
  const [isDragging, setIsDragging] = useState(false);
  const [showTooltipState, setShowTooltipState] = useState(false);
  
  // 无障碍功能
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);

  const currentValue = value ?? internalValue;
  const hasError = !!error;
  const isDisabled = disabled;
  const isVertical = orientation === 'vertical';

  // 计算百分比
  const percentage = ((Number(currentValue) - Number(min)) / (Number(max) - Number(min))) * 100;

  // 尺寸样式
  const sizeStyles = {
    sm: {
      track: isVertical ? 'w-1 h-32' : 'h-1 w-full',
      thumb: 'h-4 w-4',
      label: 'text-sm',
      description: 'text-xs',
      value: 'text-xs'
    },
    md: {
      track: isVertical ? 'w-2 h-40' : 'h-2 w-full',
      thumb: 'h-5 w-5',
      label: 'text-base',
      description: 'text-sm',
      value: 'text-sm'
    },
    lg: {
      track: isVertical ? 'w-3 h-48' : 'h-3 w-full',
      thumb: 'h-6 w-6',
      label: 'text-lg',
      description: 'text-base',
      value: 'text-base'
    }
  };

  // 轨道样式
  const trackStyles = {
    default: {
      base: [
        'relative rounded-full cursor-pointer',
        'bg-floral-200 dark:bg-pomegranate-800/30'
      ],
      filled: [
        'bg-gradient-to-r from-pomegranate-600 to-pomegranate-700 dark:from-pomegranate-500 dark:to-pomegranate-600'
      ]
    },
    filled: {
      base: [
        'relative rounded-full cursor-pointer',
        'bg-gradient-to-r from-floral-100 to-floral-200 dark:from-pomegranate-800/20 dark:to-pomegranate-700/30'
      ],
      filled: [
        'bg-gradient-to-r from-pomegranate-700 to-pomegranate-800 dark:from-pomegranate-400 dark:to-pomegranate-500'
      ]
    },
    gradient: {
      base: [
        'relative rounded-full cursor-pointer',
        'bg-gradient-to-r from-floral-200 to-floral-300 dark:from-pomegranate-800/30 dark:to-pomegranate-700/40'
      ],
      filled: [
        'bg-gradient-to-r from-pomegranate-500 via-pomegranate-600 to-pomegranate-700 dark:from-pomegranate-400 dark:via-pomegranate-500 dark:to-pomegranate-600'
      ]
    }
  };

  // 滑块样式
  const thumbStyles = {
    base: [
      'absolute rounded-full bg-white shadow-lg border-2 border-pomegranate-600',
      'transform -translate-x-1/2 -translate-y-1/2 cursor-grab active:cursor-grabbing',
      'transition-all duration-150 hover:scale-110 hover:shadow-pomegranate-200',
      'focus:outline-none focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
      'flex items-center justify-center'
    ],
    disabled: [
      'opacity-50 cursor-not-allowed'
    ],
    dragging: [
      'scale-110 shadow-xl shadow-pomegranate-300'
    ]
  };

  // 更新值
  const updateValue = useCallback((newValue: number) => {
    const clampedValue = Math.max(Number(min), Math.min(Number(max), newValue));
    const steppedValue = Math.round(clampedValue / Number(step)) * Number(step);
    
    setInternalValue(steppedValue);
    onValueChange?.(steppedValue);
    
    // 创建合成事件
    const syntheticEvent = {
      target: { value: steppedValue.toString() },
      currentTarget: { value: steppedValue.toString() }
    } as React.ChangeEvent<HTMLInputElement>;
    onChange?.(syntheticEvent);
  }, [min, max, step, onValueChange, onChange]);

  // 处理鼠标/触摸事件
  const handlePointerMove = useCallback((clientX: number, clientY: number) => {
    if (!trackRef.current || isDisabled) return;
    
    const rect = trackRef.current.getBoundingClientRect();
    let percentage: number;
    
    if (isVertical) {
      percentage = ((rect.bottom - clientY) / rect.height) * 100;
    } else {
      percentage = ((clientX - rect.left) / rect.width) * 100;
    }
    
    const newValue = Number(min) + (percentage / 100) * (Number(max) - Number(min));
    updateValue(newValue);
  }, [isVertical, min, max, updateValue, isDisabled]);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent<HTMLInputElement>) => {
    if (isDisabled) return;
    
    let newValue = currentValue;
    const largeStep = (Number(max) - Number(min)) / 10;
    
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowUp':
        event.preventDefault();
        newValue = Number(currentValue) + Number(step);
        break;
      case 'ArrowLeft':
      case 'ArrowDown':
        event.preventDefault();
        newValue = Number(currentValue) - Number(step);
        break;
      case 'PageUp':
        event.preventDefault();
        newValue = Number(currentValue) + largeStep;
        break;
      case 'PageDown':
        event.preventDefault();
        newValue = Number(currentValue) - largeStep;
        break;
      case 'Home':
        event.preventDefault();
        newValue = Number(min);
        break;
      case 'End':
        event.preventDefault();
        newValue = Number(max);
        break;
    }
    
    if (newValue !== currentValue) {
      updateValue(Number(newValue));
      announce(`滑块值: ${formatValue(Number(newValue))}`);
    }
    
    handleKeyDown(event.nativeEvent);
  }, [currentValue, step, min, max, updateValue, formatValue, announce, handleKeyDown, isDisabled]);

  // 处理值提交
  const handleValueCommit = useCallback(() => {
    onValueCommit?.(Number(currentValue));
    
    // 触发原始事件
    const syntheticEvent = {
      target: { value: Number(currentValue).toString() },
      currentTarget: { value: Number(currentValue).toString() }
    } as unknown as React.MouseEvent<HTMLInputElement>;
    onMouseUp?.(syntheticEvent);
  }, [currentValue, onValueCommit, onMouseUp]);

  // 鼠标事件处理
  const handleMouseDown = useCallback((event: React.MouseEvent) => {
    if (isDisabled) return;
    
    setIsDragging(true);
    setShowTooltipState(true);
    handlePointerMove(event.clientX, event.clientY);
    
    const handleMouseMove = (e: MouseEvent) => {
      handlePointerMove(e.clientX, e.clientY);
    };
    
    const handleMouseUp = () => {
      setIsDragging(false);
      setShowTooltipState(false);
      handleValueCommit();
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
    
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [isDisabled, handlePointerMove, handleValueCommit]);

  // 触摸事件处理
  const handleTouchStart = useCallback((event: React.TouchEvent) => {
    if (isDisabled) return;
    
    setIsDragging(true);
    setShowTooltipState(true);
    const touch = event.touches[0];
    handlePointerMove(touch.clientX, touch.clientY);
    
    const handleTouchMove = (e: TouchEvent) => {
      const touch = e.touches[0];
      handlePointerMove(touch.clientX, touch.clientY);
    };
    
    const handleTouchEnd = () => {
      setIsDragging(false);
      setShowTooltipState(false);
      handleValueCommit();
      
      // 触发原始事件
      const syntheticEvent = {
        target: { value: Number(currentValue).toString() },
        currentTarget: { value: Number(currentValue).toString() }
      } as unknown as React.TouchEvent<HTMLInputElement>;
      onTouchEnd?.(syntheticEvent);
      
      document.removeEventListener('touchmove', handleTouchMove);
      document.removeEventListener('touchend', handleTouchEnd);
    };
    
    document.addEventListener('touchmove', handleTouchMove);
    document.addEventListener('touchend', handleTouchEnd);
  }, [isDisabled, handlePointerMove, handleValueCommit, currentValue, onTouchEnd]);

  // 计算滑块位置
  const thumbPosition = isVertical
    ? { bottom: `${percentage}%`, left: '50%' }
    : { left: `${percentage}%`, top: '50%' };

  // 计算填充区域样式
  const filledStyle = isVertical
    ? { height: `${percentage}%` }
    : { width: `${percentage}%` };

  const trackClasses = cn(
    sizeStyles[size].track,
    trackStyles[variant].base,
    isDisabled && 'opacity-50 cursor-not-allowed'
  );

  const thumbClasses = cn(
    sizeStyles[size].thumb,
    thumbStyles.base,
    isDisabled && thumbStyles.disabled,
    isDragging && thumbStyles.dragging
  );

  const labelClasses = cn(
    'font-medium block mb-2',
    sizeStyles[size].label,
    hasError ? 'text-red-600 dark:text-red-400' : 'text-pomegranate-700 dark:text-pomegranate-300',
    isDisabled && 'text-gray-400 dark:text-gray-500'
  );

  const descriptionClasses = cn(
    'mt-1',
    sizeStyles[size].description,
    hasError ? 'text-red-500 dark:text-red-400' : 'text-pomegranate-600 dark:text-pomegranate-400',
    isDisabled && 'text-gray-400 dark:text-gray-500'
  );

  const errorClasses = cn(
    'mt-1 text-red-600 dark:text-red-400',
    sizeStyles[size].description
  );

  const valueClasses = cn(
    'font-medium',
    sizeStyles[size].value,
    'text-pomegranate-600 dark:text-pomegranate-400'
  );

  return (
    <div className={cn('w-full', isVertical && 'flex flex-col items-center')}>
      {/* 标签和值 */}
      {(label || showValue) && (
        <div className={cn('flex justify-between items-center mb-2', isVertical && 'flex-col space-y-1')}>
          {label && (
            <label htmlFor={sliderId} className={labelClasses}>
              {label}
            </label>
          )}
          {showValue && (
            <span className={valueClasses}>
              {formatValue(Number(currentValue))}
            </span>
          )}
        </div>
      )}

      {/* 滑块容器 */}
      <div className={cn('relative', isVertical ? 'flex justify-center' : 'w-full')}>
        {/* 轨道 */}
        <div
          ref={trackRef}
          className={trackClasses}
          onMouseDown={handleMouseDown}
          onTouchStart={handleTouchStart}
        >
          {/* 填充区域 */}
          <div
            className={cn(
              'absolute rounded-full',
              trackStyles[variant].filled,
              isVertical ? 'bottom-0 left-0 w-full' : 'top-0 left-0 h-full'
            )}
            style={filledStyle}
          />

          {/* 刻度标记 */}
          {showTicks && marks.map((mark) => {
            const markPercentage = ((mark.value - Number(min)) / (Number(max) - Number(min))) * 100;
            const markPosition = isVertical
              ? { bottom: `${markPercentage}%`, left: '50%' }
              : { left: `${markPercentage}%`, top: '50%' };
            
            return (
              <div
                key={mark.value}
                className="absolute w-1 h-1 bg-pomegranate-500 dark:bg-pomegranate-400 rounded-full transform -translate-x-1/2 -translate-y-1/2"
                style={markPosition}
              />
            );
          })}
        </div>

        {/* 滑块 */}
        <div
          className={thumbClasses}
          style={thumbPosition}
        >
          {thumbIcon}
        </div>

        {/* 工具提示 */}
        {(showTooltip || showTooltipState) && (
          <div
            className={cn(
              'absolute z-10 px-2 py-1 text-xs font-medium text-white bg-pomegranate-800 dark:bg-pomegranate-700 rounded shadow-lg',
              'transform -translate-x-1/2',
              isVertical ? '-translate-y-full -top-2 left-1/2' : '-translate-y-full -top-8'
            )}
            style={isVertical ? { bottom: `${percentage}%` } : { left: `${percentage}%` }}
          >
            {formatValue(Number(currentValue))}
            <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-2 border-r-2 border-t-2 border-transparent border-t-pomegranate-800 dark:border-t-pomegranate-700" />
          </div>
        )}

        {/* 隐藏的输入元素 */}
        <input
          ref={ref}
          id={sliderId}
          type="range"
          className="sr-only"
          min={min}
          max={max}
          step={step}
          value={Number(currentValue)}
          disabled={isDisabled}
          onKeyDown={handleKeyDownEvent}
          aria-describedby={cn(
            description && descriptionId,
            error && errorId
          )}
          aria-invalid={hasError}
          aria-orientation={orientation}
          aria-valuemin={Number(min)}
          aria-valuemax={Number(max)}
          aria-valuenow={Number(currentValue)}
          aria-valuetext={formatValue(Number(currentValue))}
          {...props}
        />
      </div>

      {/* 标记标签 */}
      {marks.length > 0 && (
        <div className={cn('relative mt-2', isVertical ? 'h-4 w-full' : 'w-full h-4')}>
          {marks.map((mark) => {
            if (!mark.label) return null;
            
            const markPercentage = ((mark.value - Number(min)) / (Number(max) - Number(min))) * 100;
            const markPosition = isVertical
              ? { bottom: `${markPercentage}%`, left: '50%' }
              : { left: `${markPercentage}%`, top: '0' };
            
            return (
              <div
                key={mark.value}
                className={cn(
                  'absolute text-xs text-pomegranate-600 dark:text-pomegranate-400 transform',
                  isVertical ? '-translate-x-1/2' : '-translate-x-1/2'
                )}
                style={markPosition}
              >
                {mark.label}
              </div>
            );
          })}
        </div>
      )}

      {/* 描述和错误 */}
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
});

Slider.displayName = 'Slider';

export default Slider;