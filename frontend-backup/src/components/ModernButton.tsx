import React, { useRef, useState } from 'react';
import { Button, type ButtonProps } from 'antd';
import { cn } from '../utils/cn';

interface ModernButtonProps extends Omit<ButtonProps, 'variant'> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost';
  gradient?: boolean;
  ariaLabel?: string;
  ariaDescribedBy?: string;
  fullWidth?: boolean;
}

const ModernButton: React.FC<ModernButtonProps> = ({
  variant = 'primary',
  gradient = false,
  className,
  children,
  ariaLabel,
  ariaDescribedBy,
  fullWidth = false,
  disabled,
  loading,
  onClick,
  ...props
}) => {
  const [isPressed, setIsPressed] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const getButtonClasses = () => {
    const baseClasses = cn(
      'relative overflow-hidden transition-all duration-300',
      'focus:outline-none focus:ring-2 focus:ring-offset-2',
      'min-h-[44px] min-w-[44px]', // 确保触摸目标大小
      'transform hover:scale-105 active:scale-95',
      'motion-reduce:transform-none motion-reduce:hover:scale-100 motion-reduce:active:scale-100',
      fullWidth && 'w-full'
    );
    
    const focusRingClasses = {
      primary: 'focus:ring-blue-500',
      secondary: 'focus:ring-gray-500',
      outline: 'focus:ring-blue-500',
      ghost: 'focus:ring-blue-500',
    };
    
    switch (variant) {
      case 'primary':
        return cn(
          baseClasses,
          focusRingClasses.primary,
          gradient
            ? 'bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 border-0 text-white shadow-lg hover:shadow-xl'
            : 'bg-blue-500 hover:bg-blue-600 border-blue-500 hover:border-blue-600 text-white shadow-lg hover:shadow-xl'
        );
      case 'secondary':
        return cn(
          baseClasses,
          focusRingClasses.secondary,
          'bg-gray-100 hover:bg-gray-200 border-gray-300 hover:border-gray-400 text-gray-700',
          'dark:bg-gray-700 dark:hover:bg-gray-600 dark:border-gray-600 dark:text-gray-200'
        );
      case 'outline':
        return cn(
          baseClasses,
          focusRingClasses.outline,
          'bg-transparent border-2 border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white'
        );
      case 'ghost':
        return cn(
          baseClasses,
          focusRingClasses.ghost,
          'bg-transparent border-0 text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20'
        );
      default:
        return baseClasses;
    }
  };

  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (disabled || loading) {
      e.preventDefault();
      return;
    }
    
    setIsPressed(true);
    setTimeout(() => setIsPressed(false), 150);
    
    if (onClick) {
      onClick(e);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setIsPressed(true);
    }
    
    if (props.onKeyDown) {
      props.onKeyDown(e);
    }
  };

  const handleKeyUp = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setIsPressed(false);
      
      // 触发点击事件
      if (!disabled && !loading) {
        const clickEvent = new MouseEvent('click', {
          bubbles: true,
          cancelable: true,
        });
        buttonRef.current?.dispatchEvent(clickEvent);
      }
    }
    
    if (props.onKeyUp) {
      props.onKeyUp(e);
    }
  };

  return (
    <Button
      {...props}
      ref={buttonRef}
      className={cn(getButtonClasses(), className)}
      disabled={disabled}
      loading={loading}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      onKeyUp={handleKeyUp}
      aria-label={ariaLabel}
      aria-describedby={ariaDescribedBy}
      aria-pressed={isPressed}
      role="button"
      tabIndex={disabled ? -1 : 0}
    >
      {children}
      {loading && (
        <span className="sr-only" aria-live="polite">
          加载中...
        </span>
      )}
    </Button>
  );
};

export { ModernButton };
export default ModernButton;