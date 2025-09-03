/**
 * 现代化页面布局组件
 * 整合头部、侧边栏、主内容和底部的完整布局解决方案
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import Container from './Container';

// 页面布局上下文
interface PageLayoutContextType {
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  isMobile: boolean;
  toggleSidebar: () => void;
  openSidebar: () => void;
  closeSidebar: () => void;
  collapseSidebar: () => void;
  expandSidebar: () => void;
}

const PageLayoutContext = createContext<PageLayoutContextType | undefined>(undefined);

export const usePageLayout = () => {
  const context = useContext(PageLayoutContext);
  if (!context) {
    throw new Error('usePageLayout must be used within a PageLayoutProvider');
  }
  return context;
};

// 页面布局主组件属性
export interface PageLayoutProps {
  // 布局类型
  layout?: 'default' | 'sidebar' | 'navbar-only' | 'full';
  
  // 导航栏配置
  navbar?: {
    variant?: 'default' | 'floating' | 'bordered' | 'minimal';
    position?: 'static' | 'fixed' | 'sticky';
    transparent?: boolean;
    blur?: boolean;
    shadow?: boolean;
  };
  
  // 侧边栏配置
  sidebar?: {
    side?: 'left' | 'right';
    variant?: 'default' | 'floating' | 'bordered' | 'minimal';
    size?: 'sm' | 'md' | 'lg' | 'xl';
    defaultOpen?: boolean;
    defaultCollapsed?: boolean;
    collapsible?: boolean;
    overlay?: boolean;
  };
  
  // 主内容配置
  main?: {
    container?: boolean;
    containerSize?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full';
    padding?: 'none' | 'sm' | 'md' | 'lg' | 'xl';
  };
  
  // 底部配置
  footer?: {
    sticky?: boolean;
    container?: boolean;
  };
  
  // 响应式配置
  mobileBreakpoint?: number;
  
  // 样式
  className?: string;
  children: React.ReactNode;
}

// 定义复合组件类型
interface PageLayoutComponent extends React.FC<PageLayoutProps> {
  Header: React.FC<PageHeaderProps>;
  Content: React.FC<PageContentProps>;
  Aside: React.FC<PageAsideProps>;
  Toolbar: React.FC<PageToolbarProps>;
  Footer: React.FC<PageFooterProps>;
}

const PageLayout: PageLayoutComponent = ({
  layout = 'default',
  navbar = {},
  sidebar = {},
  main = {},
  footer = {},
  mobileBreakpoint = 768,
  className,
  children,
}) => {
  useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(sidebar.defaultOpen ?? true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(sidebar.defaultCollapsed ?? false);
  const [isMobile, setIsMobile] = useState(false);

  // 响应式检测
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < mobileBreakpoint);
    };

    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, [mobileBreakpoint]);

  // 移动端自动关闭侧边栏
  useEffect(() => {
    if (isMobile) {
      setSidebarOpen(false);
    } else {
      setSidebarOpen(sidebar.defaultOpen ?? true);
    }
  }, [isMobile, sidebar.defaultOpen]);

  // 侧边栏控制函数
  const toggleSidebar = () => setSidebarOpen(!sidebarOpen);
  const openSidebar = () => setSidebarOpen(true);
  const closeSidebar = () => setSidebarOpen(false);
  const collapseSidebar = () => setSidebarCollapsed(true);
  const expandSidebar = () => setSidebarCollapsed(false);

  // 计算主内容区域的样式
  const getMainContentStyles = () => {
    const hasNavbar = layout !== 'full';
    const hasSidebar = layout === 'sidebar';
    const sidebarWidth = getSidebarWidth();
    
    return {
      paddingTop: hasNavbar && navbar.position === 'fixed' ? '4rem' : '0',
      marginLeft: hasSidebar && sidebarOpen && !isMobile ? sidebarWidth : '0',
      transition: 'margin-left 0.3s ease-in-out',
    };
  };

  // 获取侧边栏宽度
  const getSidebarWidth = () => {
    if (sidebarCollapsed) {
      switch (sidebar.size) {
        case 'sm': return '4rem';
        case 'md': return '5rem';
        case 'lg': return '6rem';
        case 'xl': return '7rem';
        default: return '5rem';
      }
    } else {
      switch (sidebar.size) {
        case 'sm': return '12rem';
        case 'md': return '14rem';
        case 'lg': return '16rem';
        case 'xl': return '18rem';
        default: return '14rem';
      }
    }
  };

  const contextValue: PageLayoutContextType = {
    sidebarOpen,
    sidebarCollapsed,
    isMobile,
    toggleSidebar,
    openSidebar,
    closeSidebar,
    collapseSidebar,
    expandSidebar,
  };

  return (
    <PageLayoutContext.Provider value={contextValue}>
      <div className={cn(
        'min-h-screen bg-gray-50 dark:bg-gray-900',
        className
      )}>
        {/* 导航栏 */}
        {layout !== 'full' && (
          <Navbar
            variant={navbar.variant}
            position={navbar.position}
            transparent={navbar.transparent}
            blur={navbar.blur}
            shadow={navbar.shadow}
            mobileBreakpoint={mobileBreakpoint}
          >
            {children}
          </Navbar>
        )}

        {/* 侧边栏 */}
        {layout === 'sidebar' && (
          <Sidebar
            side={sidebar.side}
            variant={sidebar.variant}
            size={sidebar.size}
            open={sidebarOpen}
            collapsed={sidebarCollapsed}
            onOpenChange={setSidebarOpen}
            onCollapsedChange={setSidebarCollapsed}
            collapsible={sidebar.collapsible}
            overlay={sidebar.overlay}
            mobileBreakpoint={mobileBreakpoint}
          >
            {children}
          </Sidebar>
        )}

        {/* 主内容区域 */}
        <main
          className="flex-1 transition-all duration-300 ease-in-out"
          style={getMainContentStyles()}
        >
          {main.container ? (
            <Container
              size={main.containerSize}
              padding={main.padding}
            >
              {children}
            </Container>
          ) : (
            <div className={cn({
              'p-4': main.padding === 'sm',
              'p-6': main.padding === 'md',
              'p-8': main.padding === 'lg',
              'p-12': main.padding === 'xl',
            })}>
              {children}
            </div>
          )}
        </main>

        {/* 底部 */}
        {footer && (
          <footer className={cn(
            'bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700',
            {
              'sticky bottom-0': footer.sticky,
            }
          )}>
            {footer.container ? (
              <Container>
                {children}
              </Container>
            ) : (
              children
            )}
          </footer>
        )}
      </div>
    </PageLayoutContext.Provider>
  );
};

// 页面头部组件
export interface PageHeaderProps {
  title?: string;
  subtitle?: string;
  breadcrumb?: React.ReactNode;
  actions?: React.ReactNode;
  tabs?: React.ReactNode;
  className?: string;
  children?: React.ReactNode;
}

const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  breadcrumb,
  actions,
  tabs,
  className,
  children,
}) => {
  return (
    <div className={cn(
      'bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700',
      className
    )}>
      <div className="px-4 sm:px-6 lg:px-8">
        {/* 面包屑 */}
        {breadcrumb && (
          <div className="py-3">
            {breadcrumb}
          </div>
        )}
        
        {/* 标题和操作 */}
        <div className="flex items-center justify-between py-6">
          <div className="flex-1 min-w-0">
            {title && (
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white truncate">
                {title}
              </h1>
            )}
            {subtitle && (
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {subtitle}
              </p>
            )}
          </div>
          
          {actions && (
            <div className="flex items-center space-x-3">
              {actions}
            </div>
          )}
        </div>
        
        {/* 标签页 */}
        {tabs && (
          <div className="-mb-px">
            {tabs}
          </div>
        )}
        
        {/* 自定义内容 */}
        {children}
      </div>
    </div>
  );
};

// 页面内容组件
export interface PageContentProps {
  className?: string;
  children: React.ReactNode;
}

const PageContent: React.FC<PageContentProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'flex-1 p-4 sm:p-6 lg:p-8',
      className
    )}>
      {children}
    </div>
  );
};

// 页面侧边内容组件
export interface PageAsideProps {
  side?: 'left' | 'right';
  width?: 'sm' | 'md' | 'lg';
  className?: string;
  children: React.ReactNode;
}

const PageAside: React.FC<PageAsideProps> = ({
  side = 'right',
  width = 'md',
  className,
  children,
}) => {
  return (
    <aside className={cn(
      'flex-shrink-0 bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700',
      {
        'border-r': side === 'left',
        'border-l': side === 'right',
        'w-64': width === 'sm',
        'w-80': width === 'md',
        'w-96': width === 'lg',
      },
      className
    )}>
      <div className="p-4 sm:p-6">
        {children}
      </div>
    </aside>
  );
};

// 页面工具栏组件
export interface PageToolbarProps {
  className?: string;
  children: React.ReactNode;
}

const PageToolbar: React.FC<PageToolbarProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800',
      'border-b border-gray-200 dark:border-gray-700',
      className
    )}>
      {children}
    </div>
  );
};

// 页面底部组件
export interface PageFooterProps {
  className?: string;
  children: React.ReactNode;
}

const PageFooter: React.FC<PageFooterProps> = ({ className, children }) => {
  return (
    <footer className={cn(
      'bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700',
      'p-4 sm:p-6 lg:p-8',
      className
    )}>
      {children}
    </footer>
  );
};

// 复合组件
PageLayout.Header = PageHeader;
PageLayout.Content = PageContent;
PageLayout.Aside = PageAside;
PageLayout.Toolbar = PageToolbar;
PageLayout.Footer = PageFooter;

export default PageLayout;

// 导出上下文
export { PageLayoutContext };