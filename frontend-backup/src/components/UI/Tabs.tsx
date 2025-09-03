/**
 * 现代化标签页组件
 * 基于设计令牌系统的统一标签页实现
 */

import React, { useState, useRef, useEffect, createContext, useContext, useCallback } from 'react';
import { cn } from '../../utils/cn';

import { useAnnouncer, useKeyboardNavigation } from '../../hooks/useAccessibility';

// 标签页上下文
interface TabsContextType {
  activeKey: string;
  onChange: (key: string) => void;
  variant: 'line' | 'card' | 'pill' | 'segment';
  size: 'sm' | 'md' | 'lg';
  disabled?: boolean;
}

const TabsContext = createContext<TabsContextType | null>(null);

const useTabsContext = () => {
  const context = useContext(TabsContext);
  if (!context) {
    throw new Error('Tab components must be used within a Tabs component');
  }
  return context;
};

// 标签页主组件
export interface TabsProps {
  activeKey?: string;
  defaultActiveKey?: string;
  onChange?: (key: string) => void;
  variant?: 'line' | 'card' | 'pill' | 'segment';
  size?: 'sm' | 'md' | 'lg';
  position?: 'top' | 'bottom' | 'left' | 'right';
  centered?: boolean;
  animated?: boolean;
  disabled?: boolean;
  className?: string;
  children: React.ReactNode;
}

interface TabsComponent extends React.FC<TabsProps> {
  List: React.FC<TabListProps>;
  Tab: React.FC<TabProps>;
  Panel: React.FC<TabPanelProps>;
  Content: React.FC<TabContentProps>;
}

const Tabs: TabsComponent = ({
  activeKey,
  defaultActiveKey,
  onChange,
  variant = 'line',
  size = 'md',
  position = 'top',
  // centered = false,
  // animated = true,
  disabled = false,
  className,
  children,
}) => {

  const [internalActiveKey, setInternalActiveKey] = useState(
    activeKey || defaultActiveKey || ''
  );
  
  const currentActiveKey = activeKey !== undefined ? activeKey : internalActiveKey;

  const handleChange = (key: string) => {
    if (disabled) return;
    
    if (activeKey === undefined) {
      setInternalActiveKey(key);
    }
    onChange?.(key);
  };

  const contextValue: TabsContextType = {
    activeKey: currentActiveKey,
    onChange: handleChange,
    variant,
    size,
    disabled,
  };

  const isVertical = position === 'left' || position === 'right';

  return (
    <TabsContext.Provider value={contextValue}>
      <div
        className={cn(
          'tabs-container',
          {
            'flex': isVertical,
            'flex-col': !isVertical,
            'flex-row-reverse': position === 'right',
            'flex-col-reverse': position === 'bottom',
          },
          className
        )}
      >
        {children}
      </div>
    </TabsContext.Provider>
  );
};

// 标签页列表组件
export interface TabListProps {
  className?: string;
  children: React.ReactNode;
}

const TabList: React.FC<TabListProps> = ({ className, children }) => {
  const { variant, size } = useTabsContext();
  const [indicatorStyle, setIndicatorStyle] = useState<React.CSSProperties>({});
  const tabListRef = useRef<HTMLDivElement>(null);
  const { announce } = useAnnouncer();
  useKeyboardNavigation([], {
    orientation: 'horizontal',
    loop: true,
  });

  // 更新指示器位置
  const updateIndicator = () => {
    if (!tabListRef.current || variant !== 'line') return;

    const activeTab = tabListRef.current.querySelector('[data-active="true"]') as HTMLElement;
    if (activeTab) {
      const { offsetLeft, offsetWidth } = activeTab;
      setIndicatorStyle({
        left: offsetLeft,
        width: offsetWidth,
      });
    }
  };

  // 键盘事件处理
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent) => {
    const tabs = Array.from(tabListRef.current?.querySelectorAll('[role="tab"]') || []) as HTMLElement[];
    const currentIndex = tabs.findIndex(tab => tab.getAttribute('aria-selected') === 'true');
    
    let newIndex = currentIndex;
    
    switch (event.key) {
      case 'ArrowLeft':
        event.preventDefault();
        newIndex = currentIndex > 0 ? currentIndex - 1 : tabs.length - 1;
        break;
      case 'ArrowRight':
        event.preventDefault();
        newIndex = currentIndex < tabs.length - 1 ? currentIndex + 1 : 0;
        break;
      case 'Home':
        event.preventDefault();
        newIndex = 0;
        break;
      case 'End':
        event.preventDefault();
        newIndex = tabs.length - 1;
        break;
      default:
        return;
    }
    
    if (newIndex !== currentIndex && tabs[newIndex]) {
      tabs[newIndex].click();
      tabs[newIndex].focus();
      announce(`已切换到 ${tabs[newIndex].textContent || ''} 标签页`);
    }
  }, [announce]);

  useEffect(() => {
    updateIndicator();
    window.addEventListener('resize', updateIndicator);
    return () => window.removeEventListener('resize', updateIndicator);
  }, [children]);

  const sizeStyles = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
  };

  const variantStyles = {
    line: 'border-b border-pomegranate-200 dark:border-pomegranate-700',
    card: 'bg-floral-50 dark:bg-pomegranate-900/20 rounded-lg p-1',
    pill: 'bg-floral-100 dark:bg-pomegranate-900/20 rounded-full p-1',
    segment: 'bg-floral-100 dark:bg-pomegranate-900/20 rounded-lg p-1 border border-pomegranate-200 dark:border-pomegranate-700',
  };

  return (
    <div
      ref={tabListRef}
      className={cn(
        'relative flex',
        sizeStyles[size],
        variantStyles[variant],
        className
      )}
      role="tablist"
      onKeyDown={handleKeyDownEvent}
    >
      {children}
      
      {/* 线条指示器 */}
      {variant === 'line' && (
        <div
          className="absolute bottom-0 h-0.5 bg-pomegranate-500 dark:bg-pomegranate-400 transition-all duration-300 ease-out"
          style={indicatorStyle}
        />
      )}
    </div>
  );
};

// 标签页项组件
export interface TabProps {
  key: string;
  title: React.ReactNode;
  disabled?: boolean;
  icon?: React.ReactNode;
  closable?: boolean;
  onClose?: () => void;
  className?: string;
}

const Tab: React.FC<TabProps> = ({
  key: tabKey,
  title,
  disabled = false,
  icon,
  closable = false,
  onClose,
  className,
}) => {
  const { activeKey, onChange, variant, size, disabled: tabsDisabled } = useTabsContext();
  const isActive = activeKey === tabKey;
  const isDisabled = disabled || tabsDisabled;

  const { announce } = useAnnouncer();

  const handleClick = useCallback(() => {
    if (isDisabled) return;
    onChange(tabKey);
    announce(`已激活 ${typeof title === 'string' ? title : '标签页'}`);
  }, [isDisabled, onChange, tabKey, announce, title]);

  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handleClick();
    }
  }, [handleClick]);

  const handleClose = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    onClose?.();
    announce('标签页已关闭');
  }, [onClose, announce]);

  const sizeStyles = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };

  const baseStyles = cn(
    'relative flex items-center gap-2 font-medium transition-all duration-200',
    'focus:outline-none focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
    'dark:focus:ring-offset-pomegranate-900',
    sizeStyles[size],
    {
      'cursor-pointer': !isDisabled,
      'cursor-not-allowed opacity-50': isDisabled,
    }
  );

  const variantStyles = {
    line: cn(
      'border-b-2 border-transparent hover:text-pomegranate-600 dark:hover:text-pomegranate-400',
      {
        'text-pomegranate-600 dark:text-pomegranate-400 border-pomegranate-500 dark:border-pomegranate-400': isActive,
        'text-pomegranate-600/70 dark:text-pomegranate-400/70': !isActive && !isDisabled,
      }
    ),
    card: cn(
      'rounded-md hover:bg-floral-50 dark:hover:bg-pomegranate-800/20',
      {
        'bg-floral-50 dark:bg-pomegranate-800/20 shadow-sm text-pomegranate-700 dark:text-pomegranate-300': isActive,
        'text-pomegranate-600/70 dark:text-pomegranate-400/70': !isActive && !isDisabled,
      }
    ),
    pill: cn(
      'rounded-full hover:bg-floral-50 dark:hover:bg-pomegranate-800/20',
      {
        'bg-floral-50 dark:bg-pomegranate-800/20 shadow-sm text-pomegranate-700 dark:text-pomegranate-300': isActive,
        'text-pomegranate-600/70 dark:text-pomegranate-400/70': !isActive && !isDisabled,
      }
    ),
    segment: cn(
      'rounded-md hover:bg-floral-50 dark:hover:bg-pomegranate-800/20',
      {
        'bg-floral-50 dark:bg-pomegranate-800/20 shadow-sm text-pomegranate-700 dark:text-pomegranate-300': isActive,
        'text-pomegranate-600/70 dark:text-pomegranate-400/70': !isActive && !isDisabled,
      }
    ),
  };

  return (
    <button
      className={cn(baseStyles, variantStyles[variant], className)}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      disabled={isDisabled}
      role="tab"
      aria-selected={isActive}
      aria-disabled={isDisabled}
      aria-controls={`panel-${tabKey}`}
      data-active={isActive}
      tabIndex={isActive ? 0 : -1}
      id={`tab-${tabKey}`}
    >
      {icon && (
        <span className="flex-shrink-0">
          {icon}
        </span>
      )}
      
      <span className="truncate">{title}</span>
      
      {closable && (
        <button
          className="ml-1 p-0.5 rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
          onClick={handleClose}
          aria-label="关闭标签页"
        >
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </button>
  );
};

// 标签页面板组件
export interface TabPanelProps {
  key: string;
  className?: string;
  children: React.ReactNode;
}

const TabPanel: React.FC<TabPanelProps> = ({
  key: panelKey,
  className,
  children,
}) => {
  const { activeKey } = useTabsContext();
  const isActive = activeKey === panelKey;

  if (!isActive) return null;

  return (
    <div
      className={cn(
        'tab-panel',
        'animate-in fade-in-0 duration-200',
        className
      )}
      role="tabpanel"
      aria-hidden={!isActive}
      aria-labelledby={`tab-${panelKey}`}
      tabIndex={0}
      id={`panel-${panelKey}`}
    >
      {children}
    </div>
  );
};

// 标签页内容容器
export interface TabContentProps {
  className?: string;
  children: React.ReactNode;
}

const TabContent: React.FC<TabContentProps> = ({ className, children }) => {
  return (
    <div className={cn('tab-content flex-1', className)}>
      {children}
    </div>
  );
};

// 复合组件
Tabs.List = TabList;
Tabs.Tab = Tab;
Tabs.Panel = TabPanel;
Tabs.Content = TabContent;

// 便捷的标签页项接口
export interface TabItem {
  key: string;
  title: React.ReactNode;
  content: React.ReactNode;
  disabled?: boolean;
  icon?: React.ReactNode;
  closable?: boolean;
}

// 简化的标签页组件
export interface SimpleTabsProps extends Omit<TabsProps, 'children'> {
  items: TabItem[];
  onTabClose?: (key: string) => void;
}

export const SimpleTabs: React.FC<SimpleTabsProps> = ({
  items,
  onTabClose,
  ...tabsProps
}) => {
  return (
    <Tabs {...tabsProps}>
      <Tabs.List>
        {items.map((item) => (
          <Tabs.Tab
            key={item.key}
            title={item.title}
            disabled={item.disabled}
            icon={item.icon}
            closable={item.closable}
            onClose={() => onTabClose?.(item.key)}
          />
        ))}
      </Tabs.List>
      
      <Tabs.Content>
        {items.map((item) => (
          <Tabs.Panel key={item.key}>
            {item.content}
          </Tabs.Panel>
        ))}
      </Tabs.Content>
    </Tabs>
  );
};

export default Tabs;