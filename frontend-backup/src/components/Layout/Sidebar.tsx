/**
 * 现代化侧边栏组件
 * 支持响应式设计、多种布局模式和交互状态
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import Button from '../UI/Button';
import { ChevronLeftIcon, ChevronRightIcon, XMarkIcon } from '@heroicons/react/24/outline';

// 侧边栏上下文
interface SidebarContextType {
  isOpen: boolean;
  isCollapsed: boolean;
  isMobile: boolean;
  toggle: () => void;
  open: () => void;
  close: () => void;
  collapse: () => void;
  expand: () => void;
}

const SidebarContext = createContext<SidebarContextType | undefined>(undefined);

export const useSidebar = () => {
  const context = useContext(SidebarContext);
  if (!context) {
    throw new Error('useSidebar must be used within a SidebarProvider');
  }
  return context;
};

// 侧边栏主组件属性
export interface SidebarProps {
  // 基础配置
  side?: 'left' | 'right';
  variant?: 'default' | 'floating' | 'bordered' | 'minimal';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  
  // 状态控制
  defaultOpen?: boolean;
  defaultCollapsed?: boolean;
  open?: boolean;
  collapsed?: boolean;
  onOpenChange?: (open: boolean) => void;
  onCollapsedChange?: (collapsed: boolean) => void;
  
  // 响应式配置
  collapsible?: boolean;
  mobileBreakpoint?: number;
  overlay?: boolean;
  
  // 样式配置
  className?: string;
  children: React.ReactNode;
}

interface SidebarComponent extends React.FC<SidebarProps> {
  Header: React.FC<SidebarHeaderProps>;
  Content: React.FC<SidebarContentProps>;
  Footer: React.FC<SidebarFooterProps>;
  Toggle: React.FC<SidebarToggleProps>;
  NavItem: React.FC<SidebarNavItemProps>;
  NavGroup: React.FC<SidebarNavGroupProps>;
  Separator: React.FC<SidebarSeparatorProps>;
}

const Sidebar: SidebarComponent = ({
  side = 'left',
  variant = 'default',
  size = 'md',
  defaultOpen = true,
  defaultCollapsed = false,
  open: controlledOpen,
  collapsed: controlledCollapsed,
  onOpenChange,
  onCollapsedChange,
  // collapsible = true,
  mobileBreakpoint = 768,
  overlay = true,
  className,
  children,
}) => {
  useTheme();
  const [internalOpen, setInternalOpen] = useState(defaultOpen);
  const [internalCollapsed, setInternalCollapsed] = useState(defaultCollapsed);
  const [isMobile, setIsMobile] = useState(false);

  // 状态管理
  const isOpen = controlledOpen !== undefined ? controlledOpen : internalOpen;
  const isCollapsed = controlledCollapsed !== undefined ? controlledCollapsed : internalCollapsed;

  // 响应式检测
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < mobileBreakpoint);
    };

    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, [mobileBreakpoint]);

  // 移动端自动关闭
  useEffect(() => {
    if (isMobile && isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isMobile, isOpen]);

  // 控制函数
  const toggle = () => {
    const newOpen = !isOpen;
    setInternalOpen(newOpen);
    onOpenChange?.(newOpen);
  };

  const open = () => {
    setInternalOpen(true);
    onOpenChange?.(true);
  };

  const close = () => {
    setInternalOpen(false);
    onOpenChange?.(false);
  };

  const collapse = () => {
    const newCollapsed = true;
    setInternalCollapsed(newCollapsed);
    onCollapsedChange?.(newCollapsed);
  };

  const expand = () => {
    const newCollapsed = false;
    setInternalCollapsed(newCollapsed);
    onCollapsedChange?.(newCollapsed);
  };

  // 样式类名
  const sidebarClasses = cn(
    // 基础样式
    'fixed top-0 z-40 h-full transition-all duration-300 ease-in-out',
    'bg-gradient-to-b from-floral-50 to-pomegranate-50 dark:from-pomegranate-900 dark:to-floral-900',
    
    // 位置
    side === 'left' ? 'left-0' : 'right-0',
    
    // 尺寸
    {
      'w-16': isCollapsed && size === 'sm',
      'w-20': isCollapsed && size === 'md',
      'w-24': isCollapsed && size === 'lg',
      'w-28': isCollapsed && size === 'xl',
      'w-48': !isCollapsed && size === 'sm',
      'w-56': !isCollapsed && size === 'md',
      'w-64': !isCollapsed && size === 'lg',
      'w-72': !isCollapsed && size === 'xl',
    },
    
    // 变体样式
    {
      'border-r border-pomegranate-200 dark:border-pomegranate-700': variant === 'default' || variant === 'bordered',
      'shadow-lg shadow-pomegranate-300/50 dark:shadow-pomegranate-700/50': variant === 'floating',
      'border-none shadow-none': variant === 'minimal',
    },
    
    // 显示状态
    {
      'translate-x-0': isOpen,
      '-translate-x-full': !isOpen && side === 'left',
      'translate-x-full': !isOpen && side === 'right',
    },
    
    // 移动端样式
    {
      'md:translate-x-0': !isMobile,
    },
    
    className
  );

  // 遮罩层样式
  const overlayClasses = cn(
    'fixed inset-0 z-30 bg-gradient-to-br from-pomegranate-900/60 to-floral-900/60 backdrop-blur-sm transition-opacity duration-300',
    {
      'opacity-100 pointer-events-auto': isMobile && isOpen && overlay,
      'opacity-0 pointer-events-none': !isMobile || !isOpen || !overlay,
    }
  );

  const contextValue: SidebarContextType = {
    isOpen,
    isCollapsed,
    isMobile,
    toggle,
    open,
    close,
    collapse,
    expand,
  };

  return (
    <SidebarContext.Provider value={contextValue}>
      {/* 遮罩层 */}
      {overlay && (
        <div
          className={overlayClasses}
          onClick={close}
          aria-hidden="true"
        />
      )}
      
      {/* 侧边栏 */}
      <aside className={sidebarClasses} role="complementary">
        {children}
      </aside>
    </SidebarContext.Provider>
  );
};

// 侧边栏头部组件
export interface SidebarHeaderProps {
  className?: string;
  children: React.ReactNode;
}

const SidebarHeader: React.FC<SidebarHeaderProps> = ({ className, children }) => {
  const { isCollapsed } = useSidebar();
  
  return (
    <div className={cn(
      'flex items-center justify-between p-4 border-b border-pomegranate-200 dark:border-pomegranate-700 bg-gradient-to-r from-floral-100/50 to-pomegranate-100/50 dark:from-pomegranate-800/50 dark:to-floral-800/50',
      {
        'px-2': isCollapsed,
      },
      className
    )}>
      {children}
    </div>
  );
};

// 侧边栏内容组件
export interface SidebarContentProps {
  className?: string;
  children: React.ReactNode;
}

const SidebarContent: React.FC<SidebarContentProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'flex-1 overflow-y-auto p-4',
      className
    )}>
      {children}
    </div>
  );
};

// 侧边栏底部组件
export interface SidebarFooterProps {
  className?: string;
  children: React.ReactNode;
}

const SidebarFooter: React.FC<SidebarFooterProps> = ({ className, children }) => {
  const { isCollapsed } = useSidebar();
  
  return (
    <div className={cn(
      'p-4 border-t border-pomegranate-200 dark:border-pomegranate-700 bg-gradient-to-r from-floral-100/50 to-pomegranate-100/50 dark:from-pomegranate-800/50 dark:to-floral-800/50',
      {
        'px-2': isCollapsed,
      },
      className
    )}>
      {children}
    </div>
  );
};

// 侧边栏切换按钮
export interface SidebarToggleProps {
  variant?: 'collapse' | 'close';
  className?: string;
}

const SidebarToggle: React.FC<SidebarToggleProps> = ({ 
  variant = 'collapse',
  className 
}) => {
  const { isCollapsed, isMobile, toggle, collapse, expand, close } = useSidebar();
  
  const handleClick = () => {
    if (variant === 'close' || isMobile) {
      if (isMobile) {
        close();
      } else {
        toggle();
      }
    } else {
      isCollapsed ? expand() : collapse();
    }
  };
  
  const getIcon = () => {
    if (variant === 'close' || isMobile) {
      return <XMarkIcon className="w-5 h-5" />;
    }
    return isCollapsed ? 
      <ChevronRightIcon className="w-5 h-5" /> : 
      <ChevronLeftIcon className="w-5 h-5" />;
  };
  
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={handleClick}
      className={cn('p-2', className)}
      aria-label={variant === 'close' ? '关闭侧边栏' : (isCollapsed ? '展开侧边栏' : '收起侧边栏')}
    >
      {getIcon()}
    </Button>
  );
};

// 侧边栏导航项组件
export interface SidebarNavItemProps {
  icon?: React.ReactNode;
  label: string;
  active?: boolean;
  disabled?: boolean;
  badge?: string | number;
  href?: string;
  onClick?: () => void;
  className?: string;
}

const SidebarNavItem: React.FC<SidebarNavItemProps> = ({
  icon,
  label,
  active = false,
  disabled = false,
  badge,
  href,
  onClick,
  className,
}) => {
  const { isCollapsed } = useSidebar();
  
  const itemClasses = cn(
    'flex items-center w-full p-3 rounded-lg transition-all duration-200',
    'hover:bg-gradient-to-r hover:from-floral-100 hover:to-pomegranate-100 dark:hover:from-pomegranate-800 dark:hover:to-floral-800',
    {
      'bg-gradient-to-r from-pomegranate-100 to-floral-100 text-pomegranate-700 dark:from-pomegranate-800 dark:to-floral-800 dark:text-pomegranate-300 shadow-sm': active,
      'text-pomegranate-600 dark:text-pomegranate-400': !active && !disabled,
      'text-pomegranate-400 dark:text-pomegranate-600 cursor-not-allowed opacity-50': disabled,
      'justify-center': isCollapsed,
      'cursor-pointer': !disabled,
    },
    className
  );
  
  const content = (
    <>
      {icon && (
        <span className={cn(
          'flex-shrink-0',
          {
            'mr-3': !isCollapsed,
          }
        )}>
          {icon}
        </span>
      )}
      
      {!isCollapsed && (
        <>
          <span className="flex-1 truncate">{label}</span>
          {badge && (
            <span className="ml-2 px-2 py-1 text-xs bg-gradient-to-r from-pomegranate-200 to-floral-200 dark:from-pomegranate-700 dark:to-floral-700 text-pomegranate-700 dark:text-pomegranate-300 rounded-full">
              {badge}
            </span>
          )}
        </>
      )}
    </>
  );
  
  if (href) {
    return (
      <a
        href={href}
        className={itemClasses}
        onClick={disabled ? undefined : onClick}
        aria-label={isCollapsed ? label : undefined}
        title={isCollapsed ? label : undefined}
      >
        {content}
      </a>
    );
  }
  
  return (
    <button
      className={itemClasses}
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      aria-label={isCollapsed ? label : undefined}
      title={isCollapsed ? label : undefined}
    >
      {content}
    </button>
  );
};

// 侧边栏导航组
export interface SidebarNavGroupProps {
  title?: string;
  className?: string;
  children: React.ReactNode;
}

const SidebarNavGroup: React.FC<SidebarNavGroupProps> = ({
  title,
  className,
  children,
}) => {
  const { isCollapsed } = useSidebar();
  
  return (
    <div className={cn('mb-6', className)}>
      {title && !isCollapsed && (
        <h3 className="mb-2 px-3 text-xs font-semibold text-pomegranate-500 dark:text-pomegranate-400 uppercase tracking-wider">
          {title}
        </h3>
      )}
      <nav className="space-y-1">
        {children}
      </nav>
    </div>
  );
};

// 侧边栏分隔符
export interface SidebarSeparatorProps {
  className?: string;
}

const SidebarSeparator: React.FC<SidebarSeparatorProps> = ({ className }) => {
  return (
    <hr className={cn(
      'my-4 border-pomegranate-200 dark:border-pomegranate-700',
      className
    )} />
  );
};

// 复合组件
Sidebar.Header = SidebarHeader;
Sidebar.Content = SidebarContent;
Sidebar.Footer = SidebarFooter;
Sidebar.Toggle = SidebarToggle;
Sidebar.NavItem = SidebarNavItem;
Sidebar.NavGroup = SidebarNavGroup;
Sidebar.Separator = SidebarSeparator;

export default Sidebar;

// 导出上下文
export { SidebarContext };