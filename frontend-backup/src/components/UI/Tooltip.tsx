/**
 * 现代化工具提示组件
 * 基于设计令牌系统的统一工具提示实现
 */

import React, { useState, useRef, useEffect, cloneElement, useCallback, useId } from 'react';
import { createPortal } from 'react-dom';
import { cn } from '../../utils/cn';

import { useAnnouncer, useKeyboardNavigation } from '../../hooks/useAccessibility';

// 位置类型
type TooltipPlacement = 
  | 'top' | 'top-start' | 'top-end'
  | 'bottom' | 'bottom-start' | 'bottom-end'
  | 'left' | 'left-start' | 'left-end'
  | 'right' | 'right-start' | 'right-end';

// 位置计算函数
const calculatePosition = (
  triggerRect: DOMRect,
  tooltipRect: DOMRect,
  placement: TooltipPlacement,
  offset: number
) => {
  const scrollX = window.pageXOffset;
  const scrollY = window.pageYOffset;
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  let top = 0;
  let left = 0;
  let arrowPosition = '';

  // 基础位置计算
  switch (placement) {
    case 'top':
    case 'top-start':
    case 'top-end':
      top = triggerRect.top + scrollY - tooltipRect.height - offset;
      arrowPosition = 'bottom';
      break;
    case 'bottom':
    case 'bottom-start':
    case 'bottom-end':
      top = triggerRect.bottom + scrollY + offset;
      arrowPosition = 'top';
      break;
    case 'left':
    case 'left-start':
    case 'left-end':
      left = triggerRect.left + scrollX - tooltipRect.width - offset;
      arrowPosition = 'right';
      break;
    case 'right':
    case 'right-start':
    case 'right-end':
      left = triggerRect.right + scrollX + offset;
      arrowPosition = 'left';
      break;
  }

  // 水平对齐
  switch (placement) {
    case 'top':
    case 'bottom':
      left = triggerRect.left + scrollX + (triggerRect.width - tooltipRect.width) / 2;
      break;
    case 'top-start':
    case 'bottom-start':
      left = triggerRect.left + scrollX;
      break;
    case 'top-end':
    case 'bottom-end':
      left = triggerRect.right + scrollX - tooltipRect.width;
      break;
    case 'left':
    case 'right':
      top = triggerRect.top + scrollY + (triggerRect.height - tooltipRect.height) / 2;
      break;
    case 'left-start':
    case 'right-start':
      top = triggerRect.top + scrollY;
      break;
    case 'left-end':
    case 'right-end':
      top = triggerRect.bottom + scrollY - tooltipRect.height;
      break;
  }

  // 边界检测和调整
  let adjustedPlacement = placement;
  
  // 水平边界检测
  if (left < scrollX + 8) {
    left = scrollX + 8;
  } else if (left + tooltipRect.width > viewportWidth + scrollX - 8) {
    left = viewportWidth + scrollX - tooltipRect.width - 8;
  }

  // 垂直边界检测
  if (top < scrollY + 8) {
    // 如果是顶部显示，改为底部
    if (placement.startsWith('top')) {
      top = triggerRect.bottom + scrollY + offset;
      arrowPosition = 'top';
      adjustedPlacement = placement.replace('top', 'bottom') as TooltipPlacement;
    } else {
      top = scrollY + 8;
    }
  } else if (top + tooltipRect.height > viewportHeight + scrollY - 8) {
    // 如果是底部显示，改为顶部
    if (placement.startsWith('bottom')) {
      top = triggerRect.top + scrollY - tooltipRect.height - offset;
      arrowPosition = 'bottom';
      adjustedPlacement = placement.replace('bottom', 'top') as TooltipPlacement;
    } else {
      top = viewportHeight + scrollY - tooltipRect.height - 8;
    }
  }

  return { top, left, arrowPosition, adjustedPlacement };
};

// 工具提示组件
export interface TooltipProps {
  content: React.ReactNode;
  placement?: TooltipPlacement;
  trigger?: 'hover' | 'click' | 'focus' | 'manual';
  delay?: number;
  offset?: number;
  arrow?: boolean;
  disabled?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  className?: string;
  contentClassName?: string;
  children: React.ReactElement;
}

const Tooltip: React.FC<TooltipProps> = ({
  content,
  placement = 'top',
  trigger = 'hover',
  delay = 0,
  offset = 8,
  arrow = true,
  disabled = false,
  open: controlledOpen,
  onOpenChange,
  className,
  contentClassName,
  children,
}) => {
  const [internalOpen, setInternalOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const [arrowPosition, setArrowPosition] = useState('');

  
  const triggerRef = useRef<HTMLElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<NodeJS.Timeout>();
  const delayTimeoutRef = useRef<NodeJS.Timeout>();
  
  // 无障碍功能
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);
  const tooltipId = useId();

  const isOpen = controlledOpen !== undefined ? controlledOpen : internalOpen;

  // 更新位置
  const updatePosition = () => {
    if (!triggerRef.current || !tooltipRef.current || !isOpen) return;

    const triggerRect = triggerRef.current.getBoundingClientRect();
    const tooltipRect = tooltipRef.current.getBoundingClientRect();
    
    const result = calculatePosition(triggerRect, tooltipRect, placement, offset);
    setPosition({ top: result.top, left: result.left });
    setArrowPosition(result.arrowPosition);
    // setActualPlacement(result.adjustedPlacement);
  };

  // 显示工具提示
  const showTooltip = useCallback(() => {
    if (disabled) return;
    
    if (delayTimeoutRef.current) {
      clearTimeout(delayTimeoutRef.current);
    }

    const show = () => {
      if (controlledOpen === undefined) {
        setInternalOpen(true);
      }
      onOpenChange?.(true);
      // 宣布tooltip显示
      if (typeof content === 'string') {
        announce(`工具提示显示: ${content}`);
      }
    };

    if (delay > 0) {
      delayTimeoutRef.current = setTimeout(show, delay);
    } else {
      show();
    }
  }, [disabled, controlledOpen, onOpenChange, delay, content, announce]);

  // 隐藏工具提示
  const hideTooltip = useCallback(() => {
    if (delayTimeoutRef.current) {
      clearTimeout(delayTimeoutRef.current);
    }

    if (controlledOpen === undefined) {
      setInternalOpen(false);
    }
    onOpenChange?.(false);
    // 宣布tooltip隐藏
    announce('工具提示已隐藏');
  }, [controlledOpen, onOpenChange, announce]);

  // 事件处理器
  const handleMouseEnter = () => {
    if (trigger === 'hover') {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      showTooltip();
    }
  };

  const handleMouseLeave = () => {
    if (trigger === 'hover') {
      timeoutRef.current = setTimeout(hideTooltip, 100);
    }
  };

  const handleClick = () => {
    if (trigger === 'click') {
      if (isOpen) {
        hideTooltip();
      } else {
        showTooltip();
      }
    }
  };

  const handleFocus = () => {
    if (trigger === 'focus') {
      showTooltip();
    }
  };

  const handleBlur = () => {
    if (trigger === 'focus') {
      hideTooltip();
    }
  };

  // 键盘事件处理
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent) => {
    if (event.key === 'Escape' && isOpen) {
      event.preventDefault();
      hideTooltip();
    }
    // 调用通用键盘导航处理
    handleKeyDown(event.nativeEvent);
  }, [isOpen, hideTooltip, handleKeyDown]);

  // 点击外部关闭
  useEffect(() => {
    if (!isOpen || trigger !== 'click') return;

    const handleClickOutside = (event: MouseEvent) => {
      if (
        triggerRef.current &&
        tooltipRef.current &&
        !triggerRef.current.contains(event.target as Node) &&
        !tooltipRef.current.contains(event.target as Node)
      ) {
        hideTooltip();
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        hideTooltip();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen, trigger]);

  // 更新位置
  useEffect(() => {
    if (isOpen) {
      // 延迟更新位置，确保DOM已渲染
      const timer = setTimeout(updatePosition, 0);
      
      window.addEventListener('scroll', updatePosition);
      window.addEventListener('resize', updatePosition);

      return () => {
        clearTimeout(timer);
        window.removeEventListener('scroll', updatePosition);
        window.removeEventListener('resize', updatePosition);
      };
    }
  }, [isOpen, placement, offset]);

  // 清理定时器
  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      if (delayTimeoutRef.current) {
        clearTimeout(delayTimeoutRef.current);
      }
    };
  }, []);

  // 克隆子元素并添加事件处理器
  const triggerElement = cloneElement(children, {
    ref: triggerRef,
    onMouseEnter: (e: React.MouseEvent) => {
      children.props.onMouseEnter?.(e);
      handleMouseEnter();
    },
    onMouseLeave: (e: React.MouseEvent) => {
      children.props.onMouseLeave?.(e);
      handleMouseLeave();
    },
    onClick: (e: React.MouseEvent) => {
      children.props.onClick?.(e);
      handleClick();
    },
    onFocus: (e: React.FocusEvent) => {
      children.props.onFocus?.(e);
      handleFocus();
    },
    onBlur: (e: React.FocusEvent) => {
      children.props.onBlur?.(e);
      handleBlur();
    },
    onKeyDown: (e: React.KeyboardEvent) => {
      children.props.onKeyDown?.(e);
      handleKeyDownEvent(e);
    },
    className: cn(children.props.className, className),
    'aria-describedby': isOpen ? tooltipId : undefined,
    'aria-expanded': trigger === 'click' ? isOpen : undefined,
  });

  // 箭头样式
  const arrowStyles = {
    top: 'bottom-0 left-1/2 transform -translate-x-1/2 translate-y-full border-l-transparent border-r-transparent border-b-transparent',
    bottom: 'top-0 left-1/2 transform -translate-x-1/2 -translate-y-full border-l-transparent border-r-transparent border-t-transparent',
    left: 'right-0 top-1/2 transform translate-x-full -translate-y-1/2 border-t-transparent border-b-transparent border-r-transparent',
    right: 'left-0 top-1/2 transform -translate-x-full -translate-y-1/2 border-t-transparent border-b-transparent border-l-transparent',
  };

  return (
    <>
      {triggerElement}
      
      {isOpen && content && createPortal(
        <div
          ref={tooltipRef}
          id={tooltipId}
          className={cn(
            'absolute z-50 px-3 py-2 text-sm font-medium text-white',
            'bg-gradient-to-br from-pomegranate-800 to-pomegranate-900 dark:from-pomegranate-700 dark:to-pomegranate-800',
            'border border-pomegranate-600/30 dark:border-pomegranate-500/30',
            'rounded-md shadow-xl shadow-pomegranate-900/40',
            'animate-in fade-in-0 zoom-in-95 duration-200',
            'max-w-xs break-words backdrop-blur-sm',
            contentClassName
          )}
          style={{
            top: position.top,
            left: position.left,
          }}
          role="tooltip"
          aria-live="polite"
          aria-atomic="true"
          onMouseEnter={() => {
            if (trigger === 'hover' && timeoutRef.current) {
              clearTimeout(timeoutRef.current);
            }
          }}
          onMouseLeave={() => {
            if (trigger === 'hover') {
              timeoutRef.current = setTimeout(hideTooltip, 100);
            }
          }}
        >
          {content}
          
          {/* 箭头 */}
          {arrow && arrowPosition && (
            <div
              className={cn(
                'absolute w-0 h-0 border-4',
                'border-pomegranate-800 dark:border-pomegranate-700',
                arrowStyles[arrowPosition as keyof typeof arrowStyles]
              )}
            />
          )}
        </div>,
        document.body
      )}
    </>
  );
};

// 便捷的工具提示组件
export interface SimpleTooltipProps {
  title: string;
  children: React.ReactElement;
  placement?: TooltipPlacement;
  className?: string;
}

export const SimpleTooltip: React.FC<SimpleTooltipProps> = ({
  title,
  children,
  placement = 'top',
  className,
}) => {
  return (
    <Tooltip
      content={title}
      placement={placement}
      className={className}
    >
      {children}
    </Tooltip>
  );
};

export default Tooltip;