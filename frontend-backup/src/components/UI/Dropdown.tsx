/**
 * 现代化下拉菜单组件
 * 基于设计令牌系统的统一下拉菜单实现
 */

import React, { useState, useRef, useEffect, createContext, useContext, useId, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { Check } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useDropdownAccessibility, useAnnouncer, useKeyboardNavigation } from '../../hooks/useAccessibility';


// 下拉菜单上下文
interface DropdownContextType {
  isOpen: boolean;
  onToggle: () => void;
  onClose: () => void;
  triggerRef: React.RefObject<HTMLElement>;
  contentRef: React.RefObject<HTMLDivElement>;
  menuId: string;
  triggerId: string;
}

const DropdownContext = createContext<DropdownContextType | null>(null);

const useDropdownContext = () => {
  const context = useContext(DropdownContext);
  if (!context) {
    throw new Error('Dropdown components must be used within a Dropdown component');
  }
  return context;
};

// 位置计算函数
const calculatePosition = (
  triggerRect: DOMRect,
  contentRect: DOMRect,
  placement: string
) => {
  const scrollX = window.pageXOffset;
  const scrollY = window.pageYOffset;
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  let top = 0;
  let left = 0;

  switch (placement) {
    case 'bottom-start':
      top = triggerRect.bottom + scrollY;
      left = triggerRect.left + scrollX;
      break;
    case 'bottom-end':
      top = triggerRect.bottom + scrollY;
      left = triggerRect.right + scrollX - contentRect.width;
      break;
    case 'top-start':
      top = triggerRect.top + scrollY - contentRect.height;
      left = triggerRect.left + scrollX;
      break;
    case 'top-end':
      top = triggerRect.top + scrollY - contentRect.height;
      left = triggerRect.right + scrollX - contentRect.width;
      break;
    case 'right-start':
      top = triggerRect.top + scrollY;
      left = triggerRect.right + scrollX;
      break;
    case 'left-start':
      top = triggerRect.top + scrollY;
      left = triggerRect.left + scrollX - contentRect.width;
      break;
    default: // bottom-start
      top = triggerRect.bottom + scrollY;
      left = triggerRect.left + scrollX;
  }

  // 边界检测和调整
  if (left + contentRect.width > viewportWidth + scrollX) {
    left = viewportWidth + scrollX - contentRect.width - 8;
  }
  if (left < scrollX) {
    left = scrollX + 8;
  }
  if (top + contentRect.height > viewportHeight + scrollY) {
    top = triggerRect.top + scrollY - contentRect.height - 8;
  }
  if (top < scrollY) {
    top = scrollY + 8;
  }

  return { top, left };
};

// 下拉菜单主组件
export interface DropdownProps extends AccessibilityProps {
  trigger?: 'click' | 'hover' | 'contextMenu';
  placement?: 'bottom-start' | 'bottom-end' | 'top-start' | 'top-end' | 'right-start' | 'left-start';
  disabled?: boolean;
  _arrow?: boolean;
  offset?: number;
  onOpenChange?: (open: boolean) => void;
  className?: string;
  children: React.ReactNode;
}

const Dropdown: React.FC<DropdownProps> = ({
  trigger = 'click',
  placement = 'bottom-start',
  disabled = false,
  // _arrow = true,
  offset = 4,
  onOpenChange,
  className,
  children,
  // ..._accessibilityProps
}) => {
  useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const triggerRef = useRef<HTMLElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const hoverTimeoutRef = useRef<NodeJS.Timeout>();
  const menuId = useId();
  const triggerId = useId();
  
  // 使用无障碍功能钩子
  const { setOnClose } = useDropdownAccessibility(isOpen);
  const { announce } = useAnnouncer();
  const { handleKeyDown } = useKeyboardNavigation([], {
    orientation: 'vertical',
    loop: true
  });
  
  // 设置关闭回调
  useEffect(() => {
    setOnClose(() => handleClose);
  }, [setOnClose]);

  // 更新位置
  const updatePosition = () => {
    if (!triggerRef.current || !contentRef.current) return;

    const triggerRect = triggerRef.current.getBoundingClientRect();
    const contentRect = contentRef.current.getBoundingClientRect();
    
    const newPosition = calculatePosition(triggerRect, contentRect, placement);
    setPosition(newPosition);
  };

  // 打开下拉菜单
  const handleOpen = useCallback(() => {
    if (disabled) return;
    setIsOpen(true);
    onOpenChange?.(true);
    announce('下拉菜单已打开');
  }, [disabled, onOpenChange, announce]);

  // 关闭下拉菜单
  const handleClose = useCallback(() => {
    setIsOpen(false);
    onOpenChange?.(false);
    announce('下拉菜单已关闭');
  }, [onOpenChange, announce]);

  // 切换下拉菜单
  const handleToggle = useCallback(() => {
    if (isOpen) {
      handleClose();
    } else {
      handleOpen();
    }
  }, [isOpen, handleClose, handleOpen]);

  // 鼠标悬停处理
  const handleMouseEnter = useCallback(() => {
    if (trigger === 'hover') {
      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current);
      }
      handleOpen();
    }
  }, [trigger, handleOpen]);

  const handleMouseLeave = useCallback(() => {
    if (trigger === 'hover') {
      hoverTimeoutRef.current = setTimeout(() => {
        handleClose();
      }, 100);
    }
  }, [trigger, handleClose]);

  // 右键菜单处理
  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    if (trigger === 'contextMenu') {
      e.preventDefault();
      handleOpen();
    }
  }, [trigger, handleOpen]);

  // 键盘事件处理
  const handleKeyDownEvent = useCallback((e: React.KeyboardEvent) => {
    handleKeyDown(e as any);
    
    if (e.key === 'Escape' && isOpen) {
      handleClose();
    }
  }, [handleKeyDown, isOpen, handleClose]);

  // 点击外部关闭
  useEffect(() => {
    if (!isOpen) return;

    const handleClickOutside = (event: MouseEvent) => {
      if (
        triggerRef.current &&
        contentRef.current &&
        !triggerRef.current.contains(event.target as Node) &&
        !contentRef.current.contains(event.target as Node)
      ) {
        handleClose();
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        handleClose();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscape);
    window.addEventListener('scroll', updatePosition);
    window.addEventListener('resize', updatePosition);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
      window.removeEventListener('scroll', updatePosition);
      window.removeEventListener('resize', updatePosition);
    };
  }, [isOpen]);

  // 更新位置
  useEffect(() => {
    if (isOpen) {
      updatePosition();
    }
  }, [isOpen, placement]);

  const contextValue: DropdownContextType = {
    isOpen,
    onToggle: handleToggle,
    onClose: handleClose,
    triggerRef,
    contentRef,
    menuId,
    triggerId,
  };

  return (
    <DropdownContext.Provider value={contextValue}>
      <div
        className={cn('relative inline-block', className)}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        onContextMenu={handleContextMenu}
        onKeyDown={handleKeyDownEvent}
      >
        {children}
        
        {/* Portal 渲染下拉内容 */}
        {isOpen && createPortal(
          <div
            ref={contentRef}
            className="fixed z-50"
            style={{
              top: position.top + offset,
              left: position.left,
            }}
          >
            {React.Children.map(children, (child) => {
              if (React.isValidElement(child) && child.type === DropdownContent) {
                return child;
              }
              return null;
            })}
          </div>,
          document.body
        )}
      </div>
    </DropdownContext.Provider>
  );
};

// 触发器组件
export interface DropdownTriggerProps {
  asChild?: boolean;
  className?: string;
  children: React.ReactNode;
}

const DropdownTrigger: React.FC<DropdownTriggerProps> = ({
  asChild = false,
  className,
  children,
}) => {
  const { onToggle, triggerRef, isOpen, menuId, triggerId } = useDropdownContext();

  if (asChild && React.isValidElement(children)) {
    return React.cloneElement(children, {
      id: triggerId,
      onClick: onToggle,
      className: cn(children.props.className, className),
      'aria-expanded': isOpen,
      'aria-haspopup': 'menu',
      'aria-controls': isOpen ? menuId : undefined,
    } as any);
  }

  return (
    <button
      ref={triggerRef as React.RefObject<HTMLButtonElement>}
      id={triggerId}
      className={cn(
        'inline-flex items-center justify-center gap-2',
        'px-3 py-2 text-sm font-medium',
        'bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600',
        'rounded-md shadow-sm',
        'hover:bg-gray-50 dark:hover:bg-gray-700',
        'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
        'dark:focus:ring-offset-gray-900',
        'transition-colors duration-200',
        className
      )}
      onClick={onToggle}
      aria-expanded={isOpen}
      aria-haspopup="menu"
      aria-controls={isOpen ? menuId : undefined}
    >
      {children}
    </button>
  );
};

// 下拉内容组件
export interface DropdownContentProps {
  className?: string;
  _sideOffset?: number;
  children: React.ReactNode;
}

const DropdownContent: React.FC<DropdownContentProps> = ({
  className,
  // _sideOffset = 4,
  children,
}) => {
  const { menuId, triggerId } = useDropdownContext();

  return (
    <div
      id={menuId}
      className={cn(
        'min-w-[8rem] overflow-hidden rounded-md border',
        'bg-gradient-to-br from-white to-floral-50 dark:from-gray-800 dark:to-gray-900',
        'border-pomegranate-200/50 dark:border-pomegranate-700/50',
        'shadow-xl shadow-pomegranate-900/20 dark:shadow-pomegranate-900/40',
        'backdrop-blur-sm',
        'animate-in fade-in-0 zoom-in-95 duration-200',
        'data-[side=bottom]:slide-in-from-top-2',
        'data-[side=left]:slide-in-from-right-2',
        'data-[side=right]:slide-in-from-left-2',
        'data-[side=top]:slide-in-from-bottom-2',
        className
      )}
      role="menu"
      aria-labelledby={triggerId}
    >
      {children}
    </div>
  );
};

// 下拉菜单项组件
export interface DropdownItemProps {
  disabled?: boolean;
  destructive?: boolean;
  icon?: React.ReactNode;
  shortcut?: string;
  onSelect?: () => void;
  className?: string;
  children: React.ReactNode;
}

const DropdownItem: React.FC<DropdownItemProps> = ({
  disabled = false,
  destructive = false,
  icon,
  shortcut,
  onSelect,
  className,
  children,
}) => {
  const { onClose } = useDropdownContext();

  const handleSelect = () => {
    if (disabled) return;
    onSelect?.();
    onClose();
  };

  return (
    <button
      className={cn(
        'relative flex w-full cursor-pointer select-none items-center',
        'rounded-sm px-2 py-1.5 text-sm outline-none',
        'transition-all duration-200',
        {
          'text-red-600 dark:text-red-400 focus:bg-gradient-to-r focus:from-red-50 focus:to-red-100 dark:focus:bg-red-900/20 hover:bg-gradient-to-r hover:from-red-50 hover:to-red-100': destructive && !disabled,
          'text-gray-900 dark:text-gray-100 focus:bg-gradient-to-r focus:from-pomegranate-50 focus:to-floral-100 dark:focus:bg-gradient-to-r dark:focus:from-pomegranate-900/30 dark:focus:to-pomegranate-800/30 hover:bg-gradient-to-r hover:from-pomegranate-50 hover:to-floral-100 dark:hover:bg-gradient-to-r dark:hover:from-pomegranate-900/30 dark:hover:to-pomegranate-800/30': !destructive && !disabled,
          'text-gray-400 dark:text-gray-600 cursor-not-allowed': disabled,
        },
        className
      )}
      onClick={handleSelect}
      disabled={disabled}
      role="menuitem"
    >
      {icon && (
        <span className="mr-2 h-4 w-4 flex-shrink-0" aria-hidden="true">
          {icon}
        </span>
      )}
      
      <span className="flex-1 text-left">{children}</span>
      
      {shortcut && (
        <span className="ml-auto text-xs tracking-widest text-gray-400 dark:text-gray-500" aria-label={`快捷键 ${shortcut}`}>
          {shortcut}
        </span>
      )}
    </button>
  );
};

// 下拉菜单分隔符
export interface DropdownSeparatorProps {
  className?: string;
}

const DropdownSeparator: React.FC<DropdownSeparatorProps> = ({ className }) => {
  return (
    <div
      className={cn(
        '-mx-1 my-1 h-px bg-gradient-to-r from-transparent via-pomegranate-200 to-transparent dark:via-pomegranate-700',
        className
      )}
      role="separator"
    />
  );
};

// 下拉菜单标签
export interface DropdownLabelProps {
  className?: string;
  children: React.ReactNode;
}

const DropdownLabel: React.FC<DropdownLabelProps> = ({ className, children }) => {
  return (
    <div
      className={cn(
        'px-2 py-1.5 text-sm font-semibold text-pomegranate-800 dark:text-pomegranate-200',
        className
      )}
    >
      {children}
    </div>
  );
};

// 复选框菜单项
export interface DropdownCheckboxItemProps extends Omit<DropdownItemProps, 'onSelect'> {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
}

const DropdownCheckboxItem: React.FC<DropdownCheckboxItemProps> = ({
  checked = false,
  onCheckedChange,
  children,
  ...props
}) => {
  const handleSelect = () => {
    onCheckedChange?.(!checked);
  };

  return (
    <DropdownItem {...props} onSelect={handleSelect}>
      <span className="mr-2 h-4 w-4 flex items-center justify-center" aria-hidden="true">
        {checked && <Check className="h-3 w-3" />}
      </span>
      <span className="sr-only">{checked ? '已选中' : '未选中'}</span>
      {children}
    </DropdownItem>
  );
};

// 单选菜单项
export interface DropdownRadioItemProps extends Omit<DropdownItemProps, 'onSelect'> {
  value: string;
  checked?: boolean;
  onSelect?: (value: string) => void;
}

const DropdownRadioItem: React.FC<DropdownRadioItemProps> = ({
  value,
  checked = false,
  onSelect,
  children,
  ...props
}) => {
  const handleSelect = () => {
    onSelect?.(value);
  };

  return (
    <DropdownItem {...props} onSelect={handleSelect}>
      <span className="mr-2 h-4 w-4 flex items-center justify-center" aria-hidden="true">
        {checked && (
          <div className="h-2 w-2 rounded-full bg-current" />
        )}
      </span>
      <span className="sr-only">{checked ? '已选中' : '未选中'}</span>
      {children}
    </DropdownItem>
  );
};

// 复合组件类型定义
type DropdownComponent = React.FC<DropdownProps> & {
  Trigger: typeof DropdownTrigger;
  Content: typeof DropdownContent;
  Item: typeof DropdownItem;
  Separator: typeof DropdownSeparator;
  Label: typeof DropdownLabel;
  CheckboxItem: typeof DropdownCheckboxItem;
  RadioItem: typeof DropdownRadioItem;
};

// 复合组件
const DropdownWithSubComponents = Dropdown as DropdownComponent;
DropdownWithSubComponents.Trigger = DropdownTrigger;
DropdownWithSubComponents.Content = DropdownContent;
DropdownWithSubComponents.Item = DropdownItem;
DropdownWithSubComponents.Separator = DropdownSeparator;
DropdownWithSubComponents.Label = DropdownLabel;
DropdownWithSubComponents.CheckboxItem = DropdownCheckboxItem;
DropdownWithSubComponents.RadioItem = DropdownRadioItem;

export default DropdownWithSubComponents;