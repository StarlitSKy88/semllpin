import React, { useEffect, useRef, useState, createContext, useContext } from 'react';
import { cn } from '../utils/cn';

// 可访问性上下文
interface AccessibilityContextType {
  announceToScreenReader: (message: string, priority?: 'polite' | 'assertive') => void;
  focusElement: (selector: string) => void;
  isHighContrast: boolean;
  isReducedMotion: boolean;
  fontSize: 'small' | 'medium' | 'large';
  setFontSize: (size: 'small' | 'medium' | 'large') => void;
}

const AccessibilityContext = createContext<AccessibilityContextType | null>(null);

// 屏幕阅读器公告组件
interface ScreenReaderAnnouncerProps {
  children?: React.ReactNode;
}

export const ScreenReaderAnnouncer: React.FC<ScreenReaderAnnouncerProps> = ({ children }) => {
  const [politeMessage] = useState('');
  const [assertiveMessage] = useState('');

  // const announceToScreenReader = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
  //   if (priority === 'assertive') {
  //     setAssertiveMessage(message);
  //     setTimeout(() => setAssertiveMessage(''), 1000);
  //   } else {
  //     setPoliteMessage(message);
  //     setTimeout(() => setPoliteMessage(''), 1000);
  //   }
  // };

  return (
    <>
      {/* 屏幕阅读器公告区域 */}
      <div
        aria-live="polite"
        aria-atomic={true}
        className="sr-only"
        role="status"
      >
        {politeMessage}
      </div>
      <div
        aria-live="assertive"
        aria-atomic={true}
        className="sr-only"
        role="alert"
      >
        {assertiveMessage}
      </div>
      {children}
    </>
  );
};

// 跳转链接组件
interface SkipLinkProps {
  href: string;
  children: React.ReactNode;
}

export const SkipLink: React.FC<SkipLinkProps> = ({ href, children }) => {
  return (
    <a
      href={href}
      className={cn(
        'absolute left-0 top-0 z-50 px-4 py-2 bg-blue-600 text-white',
        'transform -translate-y-full focus:translate-y-0',
        'transition-transform duration-200',
        'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'
      )}
    >
      {children}
    </a>
  );
};

// 焦点陷阱组件
interface FocusTrapProps {
  active: boolean;
  children: React.ReactNode;
  onEscape?: () => void;
}

export const FocusTrap: React.FC<FocusTrapProps> = ({ active, children, onEscape }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const firstFocusableRef = useRef<HTMLElement | null>(null);
  const lastFocusableRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!active || !containerRef.current) return;

    const container = containerRef.current;
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    ) as NodeListOf<HTMLElement>;

    if (focusableElements.length === 0) return;

    firstFocusableRef.current = focusableElements[0];
    lastFocusableRef.current = focusableElements[focusableElements.length - 1];

    // 聚焦第一个元素
    firstFocusableRef.current?.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && onEscape) {
        onEscape();
        return;
      }

      if (e.key === 'Tab') {
        if (e.shiftKey) {
          // Shift + Tab
          if (document.activeElement === firstFocusableRef.current) {
            e.preventDefault();
            lastFocusableRef.current?.focus();
          }
        } else {
          // Tab
          if (document.activeElement === lastFocusableRef.current) {
            e.preventDefault();
            firstFocusableRef.current?.focus();
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [active, onEscape]);

  return (
    <div ref={containerRef} className={active ? '' : 'pointer-events-none'}>
      {children}
    </div>
  );
};

// 可访问性提供者组件
interface AccessibilityProviderProps {
  children: React.ReactNode;
}

export const AccessibilityProvider: React.FC<AccessibilityProviderProps> = ({ children }) => {
  const [fontSize, setFontSize] = useState<'small' | 'medium' | 'large'>('medium');
  const [isHighContrast, setIsHighContrast] = useState(false);
  const [isReducedMotion, setIsReducedMotion] = useState(false);
  const announcerRef = useRef<{ announceToScreenReader: (message: string, priority?: 'polite' | 'assertive') => void } | null>(null);

  useEffect(() => {
    // 检测用户偏好
    const highContrastQuery = window.matchMedia('(prefers-contrast: high)');
    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

    setIsHighContrast(highContrastQuery.matches);
    setIsReducedMotion(reducedMotionQuery.matches);

    const handleHighContrastChange = (e: MediaQueryListEvent) => setIsHighContrast(e.matches);
    const handleReducedMotionChange = (e: MediaQueryListEvent) => setIsReducedMotion(e.matches);

    highContrastQuery.addEventListener('change', handleHighContrastChange);
    reducedMotionQuery.addEventListener('change', handleReducedMotionChange);

    return () => {
      highContrastQuery.removeEventListener('change', handleHighContrastChange);
      reducedMotionQuery.removeEventListener('change', handleReducedMotionChange);
    };
  }, []);

  // 单独的useEffect处理字体大小变化
  useEffect(() => {
    const root = document.documentElement;
    switch (fontSize) {
      case 'small':
        root.style.fontSize = '14px';
        break;
      case 'large':
        root.style.fontSize = '18px';
        break;
      default:
        root.style.fontSize = '16px';
    }
  }, [fontSize]);

  const announceToScreenReader = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
    announcerRef.current?.announceToScreenReader(message, priority);
  };

  const focusElement = (selector: string) => {
    const element = document.querySelector(selector) as HTMLElement;
    if (element) {
      element.focus();
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const contextValue: AccessibilityContextType = {
    announceToScreenReader,
    focusElement,
    isHighContrast,
    isReducedMotion,
    fontSize,
    setFontSize,
  };

  return (
    <AccessibilityContext.Provider value={contextValue}>
      <ScreenReaderAnnouncer>
        <div
          className={cn(
            isHighContrast && 'high-contrast',
            isReducedMotion && 'reduce-motion'
          )}
        >
          {children}
        </div>
      </ScreenReaderAnnouncer>
    </AccessibilityContext.Provider>
  );
};

// 导出AccessibilityContext供工具函数使用
export { AccessibilityContext };

// 可访问性按钮组件
interface AccessibleButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  children: React.ReactNode;
}

export const AccessibleButton: React.FC<AccessibleButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled,
  children,
  className,
  ...props
}) => {
  const context = useContext(AccessibilityContext);
  if (!context) {
    throw new Error('AccessibleButton must be used within AccessibilityProvider');
  }
  const { announceToScreenReader } = context;

  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (loading || disabled) return;
    
    if (props.onClick) {
      props.onClick(e);
    }
    
    // 向屏幕阅读器公告按钮被点击
    announceToScreenReader(`按钮 ${typeof children === 'string' ? children : '操作'} 已执行`);
  };

  const getButtonClasses = () => {
    const baseClasses = cn(
      'relative inline-flex items-center justify-center font-medium rounded-lg',
      'transition-all duration-200 ease-in-out',
      'focus:outline-none focus:ring-2 focus:ring-offset-2',
      'disabled:opacity-50 disabled:cursor-not-allowed',
      'min-h-[44px] min-w-[44px]', // 确保触摸目标大小
      {
        'px-3 py-2 text-sm': size === 'sm',
        'px-4 py-2 text-base': size === 'md',
        'px-6 py-3 text-lg': size === 'lg',
      }
    );

    const variantClasses = {
      primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
      secondary: 'bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-500',
      outline: 'border-2 border-blue-600 text-blue-600 hover:bg-blue-50 focus:ring-blue-500',
      ghost: 'text-blue-600 hover:bg-blue-50 focus:ring-blue-500',
    };

    return cn(baseClasses, variantClasses[variant], className);
  };

  return (
    <button
      {...props}
      className={getButtonClasses()}
      disabled={disabled || loading}
      aria-disabled={disabled || loading}
      aria-busy={loading}
      onClick={handleClick}
    >
      {loading && (
        <span className="mr-2 animate-spin" aria-hidden={true}>
          ⟳
        </span>
      )}
      {children}
      {loading && <span className="sr-only">加载中...</span>}
    </button>
  );
};