/**
 * SmellPin无障碍性支持Hook
 * 提供键盘导航、屏幕阅读器支持和ARIA属性管理
 */

'use client';

import { useEffect, useRef, useCallback, useState } from 'react';

interface UseAccessibilityOptions {
  // 焦点管理
  autoFocus?: boolean;
  trapFocus?: boolean;
  restoreFocus?: boolean;
  
  // 键盘导航
  enableKeyboard?: boolean;
  escapeToClose?: boolean;
  arrowNavigation?: boolean;
  
  // 屏幕阅读器
  announceChanges?: boolean;
  liveRegion?: 'polite' | 'assertive' | 'off';
  
  // ARIA属性
  ariaLabel?: string;
  ariaLabelledBy?: string;
  ariaDescribedBy?: string;
  role?: string;
}

interface UseAccessibilityReturn {
  // 引用
  containerRef: React.RefObject<HTMLElement>;
  focusedElementRef: React.RefObject<HTMLElement>;
  
  // 焦点管理
  focusFirst: () => void;
  focusLast: () => void;
  focusNext: () => void;
  focusPrevious: () => void;
  
  // 键盘处理
  keyboardProps: React.HTMLAttributes<HTMLElement>;
  
  // ARIA属性
  ariaProps: React.AriaAttributes & React.HTMLAttributes<HTMLElement>;
  
  // 屏幕阅读器公告
  announce: (message: string, priority?: 'polite' | 'assertive') => void;
}

export function useAccessibility(options: UseAccessibilityOptions = {}): UseAccessibilityReturn {
  const {
    autoFocus = false,
    trapFocus = false,
    restoreFocus = false,
    enableKeyboard = true,
    escapeToClose = false,
    arrowNavigation = false,
    announceChanges = false,
    liveRegion = 'polite',
    ariaLabel,
    ariaLabelledBy,
    ariaDescribedBy,
    role
  } = options;

  const containerRef = useRef<HTMLElement>(null);
  const focusedElementRef = useRef<HTMLElement>(null);
  const previousFocusRef = useRef<Element | null>(null);
  const [focusableElements, setFocusableElements] = useState<HTMLElement[]>([]);
  const [currentFocusIndex, setCurrentFocusIndex] = useState(-1);

  // 获取可聚焦元素的选择器
  const focusableSelector = `
    a[href]:not([disabled]),
    button:not([disabled]),
    textarea:not([disabled]),
    input:not([disabled]),
    select:not([disabled]),
    [tabindex]:not([tabindex="-1"]):not([disabled]),
    [contenteditable="true"]
  `;

  // 更新可聚焦元素列表
  const updateFocusableElements = useCallback(() => {
    if (!containerRef.current) return;

    const elements = Array.from(
      containerRef.current.querySelectorAll<HTMLElement>(focusableSelector)
    ).filter(element => {
      return element.offsetParent !== null && // 元素可见
             !element.hasAttribute('hidden') &&
             element.tabIndex !== -1;
    });

    setFocusableElements(elements);
  }, []);

  // 焦点管理函数
  const focusFirst = useCallback(() => {
    if (focusableElements.length > 0) {
      const firstElement = focusableElements[0];
      firstElement.focus();
      setCurrentFocusIndex(0);
      focusedElementRef.current = firstElement;
    }
  }, [focusableElements]);

  const focusLast = useCallback(() => {
    if (focusableElements.length > 0) {
      const lastElement = focusableElements[focusableElements.length - 1];
      lastElement.focus();
      setCurrentFocusIndex(focusableElements.length - 1);
      focusedElementRef.current = lastElement;
    }
  }, [focusableElements]);

  const focusNext = useCallback(() => {
    if (focusableElements.length === 0) return;
    
    const nextIndex = (currentFocusIndex + 1) % focusableElements.length;
    const nextElement = focusableElements[nextIndex];
    nextElement.focus();
    setCurrentFocusIndex(nextIndex);
    focusedElementRef.current = nextElement;
  }, [focusableElements, currentFocusIndex]);

  const focusPrevious = useCallback(() => {
    if (focusableElements.length === 0) return;
    
    const prevIndex = currentFocusIndex <= 0 ? focusableElements.length - 1 : currentFocusIndex - 1;
    const prevElement = focusableElements[prevIndex];
    prevElement.focus();
    setCurrentFocusIndex(prevIndex);
    focusedElementRef.current = prevElement;
  }, [focusableElements, currentFocusIndex]);

  // 键盘事件处理
  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    if (!enableKeyboard) return;

    switch (event.key) {
      case 'Escape':
        if (escapeToClose) {
          // 触发关闭回调（需要从外部传入）
          event.preventDefault();
        }
        break;

      case 'Tab':
        if (trapFocus && focusableElements.length > 0) {
          event.preventDefault();
          if (event.shiftKey) {
            focusPrevious();
          } else {
            focusNext();
          }
        }
        break;

      case 'ArrowDown':
      case 'ArrowRight':
        if (arrowNavigation) {
          event.preventDefault();
          focusNext();
        }
        break;

      case 'ArrowUp':
      case 'ArrowLeft':
        if (arrowNavigation) {
          event.preventDefault();
          focusPrevious();
        }
        break;

      case 'Home':
        if (arrowNavigation) {
          event.preventDefault();
          focusFirst();
        }
        break;

      case 'End':
        if (arrowNavigation) {
          event.preventDefault();
          focusLast();
        }
        break;
    }
  }, [
    enableKeyboard,
    escapeToClose,
    trapFocus,
    arrowNavigation,
    focusableElements,
    focusNext,
    focusPrevious,
    focusFirst,
    focusLast
  ]);

  // 屏幕阅读器公告
  const announce = useCallback((message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', priority);
    announcement.setAttribute('aria-atomic', 'true');
    announcement.setAttribute('class', 'sr-only');
    announcement.textContent = message;

    document.body.appendChild(announcement);

    // 短暂延迟后移除元素
    setTimeout(() => {
      document.body.removeChild(announcement);
    }, 1000);
  }, []);

  // 初始化效果
  useEffect(() => {
    updateFocusableElements();

    // 保存之前的焦点元素
    if (restoreFocus) {
      previousFocusRef.current = document.activeElement;
    }

    // 自动聚焦
    if (autoFocus) {
      setTimeout(() => focusFirst(), 0);
    }

    // 清理函数
    return () => {
      if (restoreFocus && previousFocusRef.current) {
        (previousFocusRef.current as HTMLElement).focus?.();
      }
    };
  }, [autoFocus, restoreFocus, focusFirst, updateFocusableElements]);

  // 监听DOM变化以更新可聚焦元素
  useEffect(() => {
    if (!containerRef.current) return;

    const observer = new MutationObserver(updateFocusableElements);
    observer.observe(containerRef.current, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['disabled', 'hidden', 'tabindex']
    });

    return () => observer.disconnect();
  }, [updateFocusableElements]);

  // 构建键盘属性
  const keyboardProps: React.HTMLAttributes<HTMLElement> = {
    onKeyDown: handleKeyDown,
    tabIndex: trapFocus ? -1 : undefined
  };

  // 构建ARIA属性
  const ariaProps: React.AriaAttributes & React.HTMLAttributes<HTMLElement> = {
    role,
    'aria-label': ariaLabel,
    'aria-labelledby': ariaLabelledBy,
    'aria-describedby': ariaDescribedBy,
    'aria-live': announceChanges ? liveRegion : undefined
  };

  return {
    containerRef,
    focusedElementRef,
    focusFirst,
    focusLast,
    focusNext,
    focusPrevious,
    keyboardProps,
    ariaProps,
    announce
  };
}

// 屏幕阅读器专用类名
export const srOnlyClass = "sr-only absolute w-px h-px p-0 -m-px overflow-hidden whitespace-nowrap border-0";

// 跳转到内容的链接组件
export function SkipToContent({ href = "#main-content" }: { href?: string }) {
  return (
    <a
      href={href}
      className={`
        ${srOnlyClass}
        focus:not-sr-only 
        focus:absolute 
        focus:top-4 
        focus:left-4 
        focus:z-50 
        focus:px-4 
        focus:py-2 
        focus:bg-primary 
        focus:text-primary-foreground 
        focus:rounded-md 
        focus:shadow-lg
        transition-all
      `}
    >
      跳转到主要内容
    </a>
  );
}

// 焦点陷阱组件
interface FocusTrapProps {
  children: React.ReactNode;
  enabled?: boolean;
  autoFocus?: boolean;
  restoreFocus?: boolean;
}

export function FocusTrap({ 
  children, 
  enabled = true, 
  autoFocus = true, 
  restoreFocus = true 
}: FocusTrapProps) {
  const { containerRef, keyboardProps } = useAccessibility({
    trapFocus: enabled,
    autoFocus,
    restoreFocus,
    enableKeyboard: enabled
  });

  return (
    <div ref={containerRef} {...keyboardProps}>
      {children}
    </div>
  );
}

// 实时区域组件
interface LiveRegionProps {
  children: React.ReactNode;
  priority?: 'polite' | 'assertive';
  atomic?: boolean;
  relevant?: string;
}

export function LiveRegion({ 
  children, 
  priority = 'polite', 
  atomic = true,
  relevant = 'additions text'
}: LiveRegionProps) {
  return (
    <div
      aria-live={priority}
      aria-atomic={atomic}
      aria-relevant={relevant}
      className={srOnlyClass}
    >
      {children}
    </div>
  );
}