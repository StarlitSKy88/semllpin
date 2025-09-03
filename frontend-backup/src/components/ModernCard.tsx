import React, { useRef, useState } from 'react';
import { Card, type CardProps } from 'antd';
import { cn } from '../utils/cn';

interface ModernCardProps extends Omit<CardProps, 'variant'> {
  variant?: 'default' | 'elevated' | 'outlined' | 'glass';
  hover?: boolean;
  hoverable?: boolean; // 兼容旧用法，避免传递到 DOM
  interactive?: boolean;
  ariaLabel?: string;
  ariaDescribedBy?: string;
  role?: string;
  as?: 'div' | 'article' | 'section' | 'aside';
}

const ModernCard: React.FC<ModernCardProps> = ({
  variant = 'default',
  hover,
  hoverable,
  interactive = false,
  className,
  children,
  ariaLabel,
  ariaDescribedBy,
  role,
  as = 'div',
  onClick,
  ...props
}) => {
  const [isFocused, setIsFocused] = useState(false);
  const [isPressed, setIsPressed] = useState(false);
  const cardRef = useRef<HTMLDivElement>(null);

  // 统一处理 hover / hoverable，默认开启悬停效果
  const effectiveHover = typeof hover === 'boolean' ? hover : (typeof hoverable === 'boolean' ? hoverable : true);

  const getCardClasses = () => {
    const baseClasses = cn(
      'transition-all duration-300',
      'motion-reduce:transition-none motion-reduce:hover:transform-none',
      interactive && [
        'cursor-pointer',
        'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
        'active:scale-[0.98]',
        'motion-reduce:active:scale-100'
      ]
    );
    
    const hoverClasses = effectiveHover ? cn(
      'hover:shadow-lg hover:-translate-y-1',
      'motion-reduce:hover:translate-y-0'
    ) : '';
    
    const interactiveClasses = interactive ? cn(
      isFocused && 'ring-2 ring-blue-500 ring-offset-2',
      isPressed && 'scale-[0.98] motion-reduce:scale-100'
    ) : '';
    
    switch (variant) {
      case 'elevated':
        return cn(
          baseClasses,
          hoverClasses,
          interactiveClasses,
          'shadow-lg border-0 bg-white dark:bg-gray-800'
        );
      case 'outlined':
        return cn(
          baseClasses,
          hoverClasses,
          interactiveClasses,
          'border-2 border-gray-200 dark:border-gray-700 shadow-none bg-white dark:bg-gray-800'
        );
      case 'glass':
        return cn(
          baseClasses,
          hoverClasses,
          interactiveClasses,
          'backdrop-blur-md bg-white/80 dark:bg-gray-800/80 border border-white/20 shadow-xl'
        );
      default:
        return cn(
          baseClasses,
          hoverClasses,
          interactiveClasses,
          'shadow-md border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'
        );
    }
  };

  const handleClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!interactive) return;
    
    setIsPressed(true);
    setTimeout(() => setIsPressed(false), 150);
    
    if (onClick) {
      onClick(e);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!interactive) return;
    
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setIsPressed(true);
    }
  };

  const handleKeyUp = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!interactive) return;
    
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setIsPressed(false);
      
      // 触发点击事件
      const clickEvent = new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
      });
      cardRef.current?.dispatchEvent(clickEvent);
    }
  };

  const handleFocus = () => {
    if (interactive) {
      setIsFocused(true);
    }
  };

  const handleBlur = () => {
    if (interactive) {
      setIsFocused(false);
    }
  };

  // 从 props 中拿出 title，避免将其落到外层容器属性
  const { title, ...restProps } = props;
  const cardProps = {
    ...restProps,
    ref: cardRef,
    className: cn(getCardClasses(), className),
    onClick: handleClick,
    onKeyDown: handleKeyDown,
    onKeyUp: handleKeyUp,
    onFocus: handleFocus,
    onBlur: handleBlur,
    'aria-label': ariaLabel,
    'aria-describedby': ariaDescribedBy,
    role: role || (interactive ? 'button' : undefined),
    tabIndex: interactive ? 0 : undefined,
  } as React.HTMLAttributes<HTMLDivElement> & { ref: React.Ref<HTMLDivElement> };

  // 根据 as 属性渲染不同的语义化标签
  if (as === 'article') {
    return (
      <article {...cardProps}>
        <Card variant="borderless" className="bg-transparent shadow-none" title={title}>
          {children}
        </Card>
      </article>
    );
  }

  if (as === 'section') {
    return (
      <section {...cardProps}>
        <Card variant="borderless" className="bg-transparent shadow-none" title={title}>
          {children}
        </Card>
      </section>
    );
  }

  if (as === 'aside') {
    return (
      <aside {...cardProps}>
        <Card variant="borderless" className="bg-transparent shadow-none" title={title}>
          {children}
        </Card>
      </aside>
    );
  }

  return (
    <Card
      {...cardProps}
      title={title}
    >
      {children}
    </Card>
  );
};

export { ModernCard };
export default ModernCard;