/**
 * 现代化手风琴组件
 * 支持完整的无障碍功能和键盘导航
 */

import React, { useState, useCallback, useRef, useId } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useAnnouncer, useKeyboardNavigation } from '../../hooks/useAccessibility';

// 手风琴项接口
export interface AccordionItemData {
  id: string;
  title: string;
  content: React.ReactNode;
  disabled?: boolean;
  icon?: React.ReactNode;
}

// 手风琴组件属性
export interface AccordionProps {
  items: AccordionItemData[];
  type?: 'single' | 'multiple';
  defaultValue?: string | string[];
  value?: string | string[];
  onValueChange?: (value: string | string[]) => void;
  collapsible?: boolean;
  variant?: 'default' | 'bordered' | 'filled' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  animated?: boolean;
  className?: string;
}

// 手风琴项组件属性
export interface AccordionItemProps {
  item: AccordionItemData;
  isOpen: boolean;
  onToggle: () => void;
  variant: AccordionProps['variant'];
  size: AccordionProps['size'];
  animated: boolean;
  index: number;
  totalItems: number;
}

// 手风琴项组件
const AccordionItem: React.FC<AccordionItemProps> = ({
  item,
  isOpen,
  onToggle,
  variant = 'default',
  size = 'md',
  animated = true,
  index,
  totalItems
}) => {
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([]);
  
  const triggerId = useId();
  const contentId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent) => {
    switch (event.key) {
      case 'Enter':
      case ' ':
        event.preventDefault();
        onToggle();
        announce(`${item.title} ${isOpen ? '已收起' : '已展开'}`);
        break;
      case 'ArrowDown':
        event.preventDefault();
        const nextIndex = (index + 1) % totalItems;
        const nextTrigger = document.querySelector(`[data-accordion-trigger="${nextIndex}"]`) as HTMLElement;
        nextTrigger?.focus();
        break;
      case 'ArrowUp':
        event.preventDefault();
        const prevIndex = (index - 1 + totalItems) % totalItems;
        const prevTrigger = document.querySelector(`[data-accordion-trigger="${prevIndex}"]`) as HTMLElement;
        prevTrigger?.focus();
        break;
      case 'Home':
        event.preventDefault();
        const firstTrigger = document.querySelector(`[data-accordion-trigger="0"]`) as HTMLElement;
        firstTrigger?.focus();
        break;
      case 'End':
        event.preventDefault();
        const lastTrigger = document.querySelector(`[data-accordion-trigger="${totalItems - 1}"]`) as HTMLElement;
        lastTrigger?.focus();
        break;
      default:
        handleKeyDown(event.nativeEvent);
    }
  }, [index, totalItems, onToggle, isOpen, item.title, announce, handleKeyDown]);

  // 样式变体
  const variants = {
    default: {
      container: 'border-b border-pomegranate-200/30 last:border-b-0',
      trigger: 'hover:bg-gradient-to-r hover:from-floral-50 hover:to-pomegranate-50',
      content: 'bg-gradient-to-br from-floral-25 to-pomegranate-25'
    },
    bordered: {
      container: 'border border-pomegranate-300/40 rounded-lg mb-2 last:mb-0 shadow-sm',
      trigger: 'hover:bg-gradient-to-r hover:from-floral-50 hover:to-pomegranate-50 hover:border-pomegranate-400/50',
      content: 'bg-gradient-to-br from-floral-25 to-pomegranate-25'
    },
    filled: {
      container: 'bg-gradient-to-r from-floral-100 to-pomegranate-100 rounded-lg mb-2 last:mb-0 shadow-sm',
      trigger: 'hover:bg-gradient-to-r hover:from-floral-150 hover:to-pomegranate-150',
      content: 'bg-gradient-to-br from-floral-50 to-pomegranate-50'
    },
    ghost: {
      container: 'mb-2 last:mb-0',
      trigger: 'hover:bg-gradient-to-r hover:from-floral-50/50 hover:to-pomegranate-50/50 rounded-md',
      content: 'bg-transparent'
    }
  };

  // 尺寸样式
  const sizes = {
    sm: {
      trigger: 'px-3 py-2 text-sm',
      content: 'px-3 py-2 text-sm',
      icon: 'w-4 h-4'
    },
    md: {
      trigger: 'px-4 py-3 text-base',
      content: 'px-4 py-3 text-base',
      icon: 'w-5 h-5'
    },
    lg: {
      trigger: 'px-6 py-4 text-lg',
      content: 'px-6 py-4 text-base',
      icon: 'w-6 h-6'
    }
  };

  const variantStyles = variants[variant!];
  const sizeStyles = sizes[size!];

  return (
    <div className={cn('overflow-hidden', variantStyles.container)}>
      {/* 触发器 */}
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        className={cn(
          'w-full flex items-center justify-between text-left transition-all duration-200',
          'focus:outline-none focus:ring-2 focus:ring-pomegranate-400 focus:ring-offset-2',
          'disabled:opacity-50 disabled:cursor-not-allowed',
          variantStyles.trigger,
          sizeStyles.trigger
        )}
        aria-expanded={isOpen}
        aria-controls={contentId}
        aria-disabled={item.disabled}
        disabled={item.disabled}
        onClick={onToggle}
        onKeyDown={handleKeyDownEvent}
        data-accordion-trigger={index}
      >
        <div className="flex items-center gap-3">
          {item.icon && (
            <span className={cn('flex-shrink-0 text-pomegranate-600', sizeStyles.icon)}>
              {item.icon}
            </span>
          )}
          <span className="font-medium text-pomegranate-800">
            {item.title}
          </span>
        </div>
        
        <motion.div
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: animated ? 0.2 : 0 }}
          className={cn('flex-shrink-0 text-pomegranate-500', sizeStyles.icon)}
        >
          <ChevronDown />
        </motion.div>
      </button>

      {/* 内容区域 */}
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            id={contentId}
            role="region"
            aria-labelledby={triggerId}
            initial={animated ? { height: 0, opacity: 0 } : false}
            animate={animated ? { height: 'auto', opacity: 1 } : false}
            exit={animated ? { height: 0, opacity: 0 } : undefined}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className={cn(
              'border-t border-pomegranate-200/40',
              variantStyles.content,
              sizeStyles.content
            )}>
              <div className="text-pomegranate-700">
                {item.content}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// 主手风琴组件
const Accordion: React.FC<AccordionProps> = ({
  items,
  type = 'single',
  defaultValue,
  value: controlledValue,
  onValueChange,
  collapsible = true,
  variant = 'default',
  size = 'md',
  animated = true,
  className
}) => {
  const { announce } = useAnnouncer();
  
  // 内部状态管理
  const [internalValue, setInternalValue] = useState<string | string[]>(() => {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    return type === 'multiple' ? [] : '';
  });

  const value = controlledValue !== undefined ? controlledValue : internalValue;

  // 更新值的处理函数
  const updateValue = useCallback((newValue: string | string[]) => {
    if (controlledValue === undefined) {
      setInternalValue(newValue);
    }
    onValueChange?.(newValue);
  }, [controlledValue, onValueChange]);

  // 切换项的处理函数
  const handleToggle = useCallback((itemId: string) => {
    const item = items.find(item => item.id === itemId);
    if (!item || item.disabled) return;

    if (type === 'single') {
      const currentValue = value as string;
      const newValue = currentValue === itemId ? (collapsible ? '' : itemId) : itemId;
      updateValue(newValue);
      
      // 宣布状态变化
      const isOpening = newValue === itemId && currentValue !== itemId;
      const isClosing = newValue === '' && currentValue === itemId;
      if (isOpening) {
        announce(`${item.title} 已展开`);
      } else if (isClosing) {
        announce(`${item.title} 已收起`);
      }
    } else {
      const currentValue = value as string[];
      const isOpen = currentValue.includes(itemId);
      const newValue = isOpen
        ? currentValue.filter(id => id !== itemId)
        : [...currentValue, itemId];
      updateValue(newValue);
      
      // 宣布状态变化
      announce(`${item.title} ${isOpen ? '已收起' : '已展开'}`);
    }
  }, [type, value, collapsible, updateValue, items, announce]);

  // 检查项是否打开
  const isItemOpen = useCallback((itemId: string) => {
    if (type === 'single') {
      return value === itemId;
    }
    return (value as string[]).includes(itemId);
  }, [type, value]);

  return (
    <div 
      className={cn('w-full', className)}
      role="region"
      aria-label="手风琴面板"
    >
      {items.map((item, index) => (
        <AccordionItem
          key={item.id}
          item={item}
          isOpen={isItemOpen(item.id)}
          onToggle={() => handleToggle(item.id)}
          variant={variant}
          size={size}
          animated={animated}
          index={index}
          totalItems={items.length}
        />
      ))}
    </div>
  );
};

export default Accordion;