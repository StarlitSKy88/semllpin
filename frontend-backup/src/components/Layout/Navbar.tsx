/**
 * 现代化导航栏组件
 * 支持响应式设计、多种布局模式和交互状态
 */

import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import Button from '../UI/Button';
import Dropdown from '../UI/Dropdown';
import { Bars3Icon, XMarkIcon, ChevronDownIcon } from '@heroicons/react/24/outline';

// 导航栏上下文
interface NavbarContextType {
  isMobileMenuOpen: boolean;
  toggleMobileMenu: () => void;
  closeMobileMenu: () => void;
}

const NavbarContext = createContext<NavbarContextType | undefined>(undefined);

export const useNavbar = () => {
  const context = useContext(NavbarContext);
  if (!context) {
    throw new Error('useNavbar must be used within a NavbarProvider');
  }
  return context;
};

// 导航栏主组件属性
export interface NavbarProps {
  // 基础配置
  variant?: 'default' | 'floating' | 'bordered' | 'minimal';
  size?: 'sm' | 'md' | 'lg';
  position?: 'static' | 'fixed' | 'sticky';
  
  // 样式配置
  transparent?: boolean;
  blur?: boolean;
  shadow?: boolean;
  
  // 响应式配置
  mobileBreakpoint?: number;
  
  // 样式
  className?: string;
  children: React.ReactNode;
}

// 定义复合组件类型
interface NavbarComponent extends React.FC<NavbarProps> {
  Container: React.FC<NavbarContainerProps>;
  Content: React.FC<NavbarContentProps>;
  Brand: React.FC<NavbarBrandProps>;
  Menu: React.FC<NavbarMenuProps>;
  MobileMenu: React.FC<NavbarMobileMenuProps>;
  MenuToggle: React.FC<NavbarMenuToggleProps>;
  Link: React.FC<NavbarLinkProps>;
  Dropdown: React.FC<NavbarDropdownProps>;
  Actions: React.FC<NavbarActionsProps>;
  Separator: React.FC<NavbarSeparatorProps>;
}

const Navbar: NavbarComponent = ({
  variant = 'default',
  // size = 'md',
  position = 'static',
  transparent = false,
  blur = false,
  shadow = true,
  // mobileBreakpoint = 768,
  className,
  children,
}) => {
  useTheme();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const navRef = useRef<HTMLElement>(null);

  // 滚动检测
  useEffect(() => {
    if (position === 'fixed' || position === 'sticky') {
      const handleScroll = () => {
        setIsScrolled(window.scrollY > 0);
      };

      window.addEventListener('scroll', handleScroll);
      return () => window.removeEventListener('scroll', handleScroll);
    }
  }, [position]);

  // 移动端菜单控制
  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const closeMobileMenu = () => {
    setIsMobileMenuOpen(false);
  };

  // 点击外部关闭移动端菜单
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(event.target as Node)) {
        closeMobileMenu();
      }
    };

    if (isMobileMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isMobileMenuOpen]);

  // 样式类名
  const navbarClasses = cn(
    // 基础样式
    'w-full transition-all duration-300 ease-in-out z-50',
    
    // 位置
    {
      'relative': position === 'static',
      'fixed top-0 left-0 right-0': position === 'fixed',
      'sticky top-0': position === 'sticky',
    },
    
    // 背景
    {
      'bg-gradient-to-r from-floral-50 to-pomegranate-50 dark:from-pomegranate-900 dark:to-floral-900': !transparent,
      'bg-gradient-to-r from-floral-50/80 to-pomegranate-50/80 dark:from-pomegranate-900/80 dark:to-floral-900/80': transparent && !isScrolled,
      'bg-gradient-to-r from-floral-50/95 to-pomegranate-50/95 dark:from-pomegranate-900/95 dark:to-floral-900/95': transparent && isScrolled,
      'backdrop-blur-md': blur,
    },
    
    // 变体样式
    {
      'border-b border-pomegranate-200 dark:border-pomegranate-700': variant === 'default' || variant === 'bordered',
      'shadow-sm shadow-pomegranate-200/50 dark:shadow-pomegranate-800/50': shadow && (variant === 'default' || isScrolled),
      'shadow-lg shadow-pomegranate-300/50 dark:shadow-pomegranate-700/50': variant === 'floating',
      'border-none shadow-none': variant === 'minimal',
    },
    
    className
  );

  const contextValue: NavbarContextType = {
    isMobileMenuOpen,
    toggleMobileMenu,
    closeMobileMenu,
  };

  return (
    <NavbarContext.Provider value={contextValue}>
      <nav ref={navRef} className={navbarClasses} role="navigation">
        {children}
      </nav>
    </NavbarContext.Provider>
  );
};

// 导航栏容器
export interface NavbarContainerProps {
  className?: string;
  children: React.ReactNode;
}

const NavbarContainer: React.FC<NavbarContainerProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8',
      className
    )}>
      {children}
    </div>
  );
};

// 导航栏内容
export interface NavbarContentProps {
  className?: string;
  children: React.ReactNode;
}

const NavbarContent: React.FC<NavbarContentProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'flex items-center justify-between h-16',
      className
    )}>
      {children}
    </div>
  );
};

// 导航栏品牌/Logo
export interface NavbarBrandProps {
  href?: string;
  onClick?: () => void;
  className?: string;
  children: React.ReactNode;
}

const NavbarBrand: React.FC<NavbarBrandProps> = ({
  href,
  onClick,
  className,
  children,
}) => {
  const { closeMobileMenu } = useNavbar();
  
  const handleClick = () => {
    onClick?.();
    closeMobileMenu();
  };
  
  const brandClasses = cn(
    'flex items-center space-x-2 text-xl font-bold text-pomegranate-900 dark:text-pomegranate-100',
    'hover:text-pomegranate-600 dark:hover:text-pomegranate-400 transition-all duration-300 hover:scale-105',
    className
  );
  
  if (href) {
    return (
      <a href={href} className={brandClasses} onClick={handleClick}>
        {children}
      </a>
    );
  }
  
  return (
    <button className={brandClasses} onClick={handleClick}>
      {children}
    </button>
  );
};

// 导航栏菜单
export interface NavbarMenuProps {
  className?: string;
  children: React.ReactNode;
}

const NavbarMenu: React.FC<NavbarMenuProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'hidden md:flex md:items-center md:space-x-8',
      className
    )}>
      {children}
    </div>
  );
};

// 导航栏移动端菜单
export interface NavbarMobileMenuProps {
  className?: string;
  children: React.ReactNode;
}

const NavbarMobileMenu: React.FC<NavbarMobileMenuProps> = ({ className, children }) => {
  const { isMobileMenuOpen } = useNavbar();
  
  return (
    <div className={cn(
      'md:hidden transition-all duration-300 ease-in-out overflow-hidden',
      {
        'max-h-96 opacity-100': isMobileMenuOpen,
        'max-h-0 opacity-0': !isMobileMenuOpen,
      },
      className
    )}>
      <div className="px-2 pt-2 pb-3 space-y-1 bg-gradient-to-r from-floral-100 to-pomegranate-100 dark:from-pomegranate-800 dark:to-floral-800 border-t border-pomegranate-200 dark:border-pomegranate-700">
        {children}
      </div>
    </div>
  );
};

// 导航栏菜单切换按钮
export interface NavbarMenuToggleProps {
  className?: string;
}

const NavbarMenuToggle: React.FC<NavbarMenuToggleProps> = ({ className }) => {
  const { isMobileMenuOpen, toggleMobileMenu } = useNavbar();
  
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn('md:hidden p-2', className)}
      onClick={toggleMobileMenu}
      aria-label="切换菜单"
    >
      {isMobileMenuOpen ? (
        <XMarkIcon className="w-6 h-6" />
      ) : (
        <Bars3Icon className="w-6 h-6" />
      )}
    </Button>
  );
};

// 导航栏链接
export interface NavbarLinkProps {
  href?: string;
  active?: boolean;
  disabled?: boolean;
  mobile?: boolean;
  onClick?: () => void;
  className?: string;
  children: React.ReactNode;
}

const NavbarLink: React.FC<NavbarLinkProps> = ({
  href,
  active = false,
  disabled = false,
  mobile = false,
  onClick,
  className,
  children,
}) => {
  const { closeMobileMenu } = useNavbar();
  
  const handleClick = () => {
    if (!disabled) {
      onClick?.();
      if (mobile) {
        closeMobileMenu();
      }
    }
  };
  
  const linkClasses = cn(
    'transition-colors duration-200',
    {
      // 桌面端样式
      'text-pomegranate-700 dark:text-pomegranate-300 hover:text-pomegranate-600 dark:hover:text-pomegranate-400': !mobile && !active && !disabled,
      'text-pomegranate-600 dark:text-pomegranate-400 font-medium': !mobile && active,
      
      // 移动端样式
      'block px-3 py-2 rounded-md text-base font-medium': mobile,
      'text-pomegranate-700 dark:text-pomegranate-300 hover:text-pomegranate-600 dark:hover:text-pomegranate-400 hover:bg-floral-100 dark:hover:bg-pomegranate-700': mobile && !active && !disabled,
      'text-pomegranate-600 dark:text-pomegranate-400 bg-floral-50 dark:bg-pomegranate-900/20': mobile && active,
      
      // 通用样式
      'text-pomegranate-400 dark:text-pomegranate-600 cursor-not-allowed': disabled,
      'cursor-pointer': !disabled,
    },
    className
  );
  
  if (href) {
    return (
      <a
        href={href}
        className={linkClasses}
        onClick={handleClick}
      >
        {children}
      </a>
    );
  }
  
  return (
    <button
      className={linkClasses}
      onClick={handleClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
};

// 导航栏下拉菜单
export interface NavbarDropdownProps {
  label: string;
  mobile?: boolean;
  className?: string;
  children: React.ReactNode;
}

const NavbarDropdown: React.FC<NavbarDropdownProps> = ({
  label,
  mobile = false,
  className,
  children,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  
  if (mobile) {
    return (
      <div className={className}>
        <button
          className="flex items-center justify-between w-full px-3 py-2 rounded-md text-base font-medium text-pomegranate-700 dark:text-pomegranate-300 hover:text-pomegranate-600 dark:hover:text-pomegranate-400 hover:bg-floral-100 dark:hover:bg-pomegranate-700"
          onClick={() => setIsOpen(!isOpen)}
        >
          {label}
          <ChevronDownIcon className={cn(
            'w-4 h-4 transition-transform duration-200',
            { 'rotate-180': isOpen }
          )} />
        </button>
        {isOpen && (
          <div className="mt-1 ml-4 space-y-1">
            {children}
          </div>
        )}
      </div>
    );
  }
  
  return (
    <Dropdown>
      <Dropdown.Trigger>
        <button className={cn(
          'flex items-center space-x-1 text-pomegranate-700 dark:text-pomegranate-300',
          'hover:text-pomegranate-600 dark:hover:text-pomegranate-400 transition-colors duration-200',
          className
        )}>
          <span>{label}</span>
          <ChevronDownIcon className="w-4 h-4" />
        </button>
      </Dropdown.Trigger>
      <Dropdown.Content>
        {children}
      </Dropdown.Content>
    </Dropdown>
  );
};

// 导航栏操作区域
export interface NavbarActionsProps {
  className?: string;
  children: React.ReactNode;
}

const NavbarActions: React.FC<NavbarActionsProps> = ({ className, children }) => {
  return (
    <div className={cn(
      'flex items-center space-x-4',
      className
    )}>
      {children}
    </div>
  );
};

// 导航栏分隔符
export interface NavbarSeparatorProps {
  mobile?: boolean;
  className?: string;
}

const NavbarSeparator: React.FC<NavbarSeparatorProps> = ({ mobile = false, className }) => {
  if (mobile) {
    return (
      <hr className={cn(
        'my-2 border-pomegranate-200 dark:border-pomegranate-700',
        className
      )} />
    );
  }
  
  return (
    <div className={cn(
      'h-6 w-px bg-pomegranate-200 dark:bg-pomegranate-700',
      className
    )} />
  );
};

// 复合组件
Navbar.Container = NavbarContainer;
Navbar.Content = NavbarContent;
Navbar.Brand = NavbarBrand;
Navbar.Menu = NavbarMenu;
Navbar.MobileMenu = NavbarMobileMenu;
Navbar.MenuToggle = NavbarMenuToggle;
Navbar.Link = NavbarLink;
Navbar.Dropdown = NavbarDropdown;
Navbar.Actions = NavbarActions;
Navbar.Separator = NavbarSeparator;

export default Navbar;

// 导出上下文
export { NavbarContext };