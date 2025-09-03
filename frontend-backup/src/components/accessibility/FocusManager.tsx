import React, { useEffect, useRef, useCallback } from 'react';

interface FocusManagerProps {
  children: React.ReactNode;
  autoFocus?: boolean;
  restoreFocus?: boolean;
  trapFocus?: boolean;
  className?: string;
}

/**
 * 焦点管理组件 - 提供键盘导航和焦点陷阱功能
 * 支持自动聚焦、焦点恢复和焦点陷阱
 */
export const FocusManager: React.FC<FocusManagerProps> = ({
  children,
  autoFocus = false,
  restoreFocus = false,
  trapFocus = false,
  className = ''
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<Element | null>(null);

  // 获取所有可聚焦元素
  const getFocusableElements = useCallback(() => {
    if (!containerRef.current) return [];
    
    const focusableSelectors = [
      'a[href]',
      'button:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])',
      '[contenteditable="true"]'
    ].join(', ');
    
    return Array.from(
      containerRef.current.querySelectorAll(focusableSelectors)
    ) as HTMLElement[];
  }, []);

  // 处理Tab键导航
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (!trapFocus || event.key !== 'Tab') return;
    
    const focusableElements = getFocusableElements();
    if (focusableElements.length === 0) return;
    
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    
    if (event.shiftKey) {
      // Shift + Tab
      if (document.activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
      }
    } else {
      // Tab
      if (document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    }
  }, [trapFocus, getFocusableElements]);

  useEffect(() => {
    // 保存当前聚焦元素
    if (restoreFocus) {
      previousActiveElement.current = document.activeElement;
    }

    // 自动聚焦到第一个可聚焦元素
    if (autoFocus) {
      const focusableElements = getFocusableElements();
      if (focusableElements.length > 0) {
        focusableElements[0].focus();
      }
    }

    // 添加键盘事件监听
    if (trapFocus) {
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      // 清理事件监听
      if (trapFocus) {
        document.removeEventListener('keydown', handleKeyDown);
      }

      // 恢复之前的焦点
      if (restoreFocus && previousActiveElement.current) {
        (previousActiveElement.current as HTMLElement).focus();
      }
    };
  }, [autoFocus, restoreFocus, trapFocus, handleKeyDown, getFocusableElements]);

  return (
    <div ref={containerRef} className={className}>
      {children}
    </div>
  );
};

/**
 * 焦点陷阱组件 - 专门用于模态框等需要陷阱焦点的场景
 */
export const FocusTrap: React.FC<{
  children: React.ReactNode;
  active?: boolean;
  className?: string;
}> = ({ children, active = true, className = '' }) => {
  return (
    <FocusManager
      autoFocus={active}
      restoreFocus={active}
      trapFocus={active}
      className={className}
    >
      {children}
    </FocusManager>
  );
};

/**
 * 跳转链接组件 - 提供快速导航到页面主要区域的功能
 */
export const SkipLinks: React.FC = () => {
  const skipLinkStyle = {
    position: 'absolute' as const,
    left: '-9999px',
    top: '0',
    zIndex: 9999,
    padding: '8px 16px',
    backgroundColor: '#000',
    color: '#fff',
    textDecoration: 'none',
    borderRadius: '0 0 4px 4px',
    fontSize: '14px',
    fontWeight: 'bold',
    transition: 'left 0.3s ease'
  };

  const skipLinkFocusStyle = {
    ...skipLinkStyle,
    left: '0'
  };

  return (
    <div className="skip-links">
      <a
        href="#main-content"
        style={skipLinkStyle}
        onFocus={(e) => {
          Object.assign(e.target.style, skipLinkFocusStyle);
        }}
        onBlur={(e) => {
          Object.assign(e.target.style, skipLinkStyle);
        }}
      >
        跳转到主要内容
      </a>
      <a
        href="#navigation"
        style={skipLinkStyle}
        onFocus={(e) => {
          Object.assign(e.target.style, skipLinkFocusStyle);
        }}
        onBlur={(e) => {
          Object.assign(e.target.style, skipLinkStyle);
        }}
      >
        跳转到导航菜单
      </a>
    </div>
  );
};

export default FocusManager;