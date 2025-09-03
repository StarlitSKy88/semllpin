/**
 * 无障碍功能React钩子
 * 提供便捷的无障碍功能集成
 */

import { useEffect, useRef, useCallback, useState } from 'react';
import {
  FocusManager,
  announcer,
  AriaHelper,
  KeyboardNavigationHelper,
  KEYBOARD_KEYS,
  type UseAccessibilityOptions,
} from '../utils/accessibility';

/**
 * 焦点管理钩子
 */
export const useFocusManagement = (options: {
  trapFocus?: boolean;
  restoreFocus?: boolean;
  autoFocus?: boolean;
} = {}) => {
  const containerRef = useRef<HTMLElement>(null);
  const restoreFocusRef = useRef<() => void>();

  useEffect(() => {
    if (!containerRef.current) return;

    let cleanup: (() => void) | undefined;

    // 保存焦点
    if (options.restoreFocus) {
      restoreFocusRef.current = FocusManager.saveFocus();
    }

    // 自动聚焦
    if (options.autoFocus) {
      const firstElement = FocusManager.getFirstFocusableElement(containerRef.current);
      FocusManager.moveFocus(firstElement);
    }

    // 焦点陷阱
    if (options.trapFocus) {
      cleanup = FocusManager.trapFocus(containerRef.current);
    }

    return () => {
      cleanup?.();
      if (options.restoreFocus && restoreFocusRef.current) {
        restoreFocusRef.current();
      }
    };
  }, [options.trapFocus, options.restoreFocus, options.autoFocus]);

  return {
    containerRef,
    moveFocus: FocusManager.moveFocus,
    getFocusableElements: () => 
      containerRef.current ? FocusManager.getFocusableElements(containerRef.current) : [],
  };
};

/**
 * 屏幕阅读器公告钩子
 */
export const useAnnouncer = () => {
  const announce = useCallback((message: string, priority: 'assertive' | 'polite' = 'polite') => {
    if (priority === 'assertive') {
      announcer.announce(message);
    } else {
      announcer.announcePolite(message);
    }
  }, []);

  const clear = useCallback(() => {
    announcer.clear();
  }, []);

  return { announce, clear };
};

/**
 * 键盘导航钩子
 */
export const useKeyboardNavigation = <T extends HTMLElement>(
  items: T[],
  options: {
    orientation?: 'horizontal' | 'vertical' | 'both';
    loop?: boolean;
    defaultIndex?: number;
    onIndexChange?: (index: number) => void;
    enableTypeahead?: boolean;
    getItemText?: (item: T) => string;
  } = {}
) => {
  const {
    orientation = 'vertical',
    loop = true,
    defaultIndex = 0,
    onIndexChange,
    enableTypeahead = false,
    getItemText = (item) => item.textContent || '',
  } = options;

  const [currentIndex, setCurrentIndex] = useState(defaultIndex);

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    KeyboardNavigationHelper.handleArrowNavigation(
      event,
      items,
      currentIndex,
      {
        orientation,
        loop,
        onIndexChange: (index) => {
          setCurrentIndex(index);
          onIndexChange?.(index);
        },
      }
    );

    if (enableTypeahead) {
      KeyboardNavigationHelper.handleTypeahead(
        event,
        items,
        getItemText as (item: HTMLElement) => string,
        (index) => {
          setCurrentIndex(index);
          onIndexChange?.(index);
        }
      );
    }
  }, [items, currentIndex, orientation, loop, onIndexChange, enableTypeahead, getItemText]);

  const setIndex = useCallback((index: number) => {
    if (index >= 0 && index < items.length) {
      setCurrentIndex(index);
      items[index]?.focus();
      onIndexChange?.(index);
    }
  }, [items, onIndexChange]);

  return {
    currentIndex,
    setIndex,
    handleKeyDown,
  };
};

/**
 * ARIA属性管理钩子
 */
export const useAriaAttributes = () => {
  const generateId = useCallback((prefix?: string) => {
    return AriaHelper.generateId(prefix);
  }, []);

  const setLabel = useCallback((element: HTMLElement | null, label: string) => {
    if (element) {
      AriaHelper.setLabel(element, label);
    }
  }, []);

  const setDescription = useCallback((element: HTMLElement | null, description: string, descriptionId?: string) => {
    if (element) {
      return AriaHelper.setDescription(element, description, descriptionId);
    }
    return descriptionId || '';
  }, []);

  const setExpanded = useCallback((element: HTMLElement | null, expanded: boolean) => {
    if (element) {
      AriaHelper.setExpanded(element, expanded);
    }
  }, []);

  const setSelected = useCallback((element: HTMLElement | null, selected: boolean) => {
    if (element) {
      AriaHelper.setSelected(element, selected);
    }
  }, []);

  const setDisabled = useCallback((element: HTMLElement | null, disabled: boolean) => {
    if (element) {
      AriaHelper.setDisabled(element, disabled);
    }
  }, []);

  const setHidden = useCallback((element: HTMLElement | null, hidden: boolean) => {
    if (element) {
      AriaHelper.setHidden(element, hidden);
    }
  }, []);

  return {
    generateId,
    setLabel,
    setDescription,
    setExpanded,
    setSelected,
    setDisabled,
    setHidden,
  };
};

/**
 * 综合无障碍钩子
 */
export const useAccessibility = (options: UseAccessibilityOptions = {}) => {
  const {
    announceOnMount,
    announceOnUnmount,
    trapFocus = false,
    restoreFocus = false,
  } = options;

  const { announce } = useAnnouncer();
  const { containerRef, moveFocus, getFocusableElements } = useFocusManagement({
    trapFocus,
    restoreFocus,
  });
  const ariaHelpers = useAriaAttributes();

  // 挂载和卸载时的公告
  useEffect(() => {
    if (announceOnMount) {
      announce(announceOnMount, 'polite');
    }

    return () => {
      if (announceOnUnmount) {
        announce(announceOnUnmount, 'polite');
      }
    };
  }, [announceOnMount, announceOnUnmount, announce]);

  return {
    containerRef,
    announce,
    moveFocus,
    getFocusableElements,
    ...ariaHelpers,
  };
};

/**
 * 模态框无障碍钩子
 */
export const useModalAccessibility = (isOpen: boolean) => {
  const { containerRef, announce } = useAccessibility({
    trapFocus: isOpen,
    restoreFocus: true,
    announceOnMount: isOpen ? '模态框已打开' : undefined,
    announceOnUnmount: '模态框已关闭',
  });

  // ESC键关闭
  const [onClose, setOnClose] = useState<(() => void) | null>(null);

  useEffect(() => {
    if (!isOpen || !onClose) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === KEYBOARD_KEYS.ESCAPE) {
        event.preventDefault();
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // 阻止背景滚动
  useEffect(() => {
    if (isOpen) {
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      return () => {
        document.body.style.overflow = originalOverflow;
      };
    }
  }, [isOpen]);

  return {
    containerRef,
    announce,
    setOnClose,
  };
};

/**
 * 下拉菜单无障碍钩子
 */
export const useDropdownAccessibility = (isOpen: boolean) => {
  const menuRef = useRef<HTMLElement>(null);
  const triggerRef = useRef<HTMLElement>(null);
  const [onClose, setOnClose] = useState<(() => void) | null>(null);

  // 焦点管理
  useEffect(() => {
    if (isOpen && menuRef.current) {
      const firstItem = FocusManager.getFirstFocusableElement(menuRef.current);
      FocusManager.moveFocus(firstItem);
    }
  }, [isOpen]);

  // 键盘导航
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (!isOpen || !menuRef.current) return;

    const items = FocusManager.getFocusableElements(menuRef.current);
    const currentIndex = items.findIndex(item => item === document.activeElement);

    switch (event.key) {
      case KEYBOARD_KEYS.ESCAPE:
        event.preventDefault();
        onClose?.();
        FocusManager.moveFocus(triggerRef.current);
        break;
      case KEYBOARD_KEYS.TAB:
        event.preventDefault();
        onClose?.();
        break;
      case KEYBOARD_KEYS.ARROW_UP:
      case KEYBOARD_KEYS.ARROW_DOWN:
        KeyboardNavigationHelper.handleArrowNavigation(
          event,
          items,
          currentIndex,
          { orientation: 'vertical', loop: true }
        );
        break;
    }
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isOpen, handleKeyDown]);

  return {
    menuRef,
    triggerRef,
    setOnClose,
  };
};

/**
 * 标签页无障碍钩子
 */
export const useTabsAccessibility = (tabs: HTMLElement[], panels: HTMLElement[]) => {
  const [activeIndex, setActiveIndex] = useState(0);
  const { announce } = useAnnouncer();

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    KeyboardNavigationHelper.handleArrowNavigation(
      event,
      tabs,
      activeIndex,
      {
        orientation: 'horizontal',
        loop: true,
        onIndexChange: (index) => {
          setActiveIndex(index);
          announce(`已切换到 ${tabs[index]?.textContent || ''} 标签页`);
        },
      }
    );
  }, [tabs, activeIndex, announce]);

  // 设置ARIA属性
  useEffect(() => {
    tabs.forEach((tab, index) => {
      const panel = panels[index];
      if (tab && panel) {
        const tabId = AriaHelper.generateId('tab');
        const panelId = AriaHelper.generateId('panel');
        
        tab.setAttribute('id', tabId);
        tab.setAttribute('role', 'tab');
        tab.setAttribute('aria-controls', panelId);
        tab.setAttribute('aria-selected', (index === activeIndex).toString());
        tab.setAttribute('tabindex', index === activeIndex ? '0' : '-1');
        
        panel.setAttribute('id', panelId);
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', tabId);
        panel.setAttribute('tabindex', '0');
        
        if (index !== activeIndex) {
          panel.setAttribute('hidden', '');
        } else {
          panel.removeAttribute('hidden');
        }
      }
    });
  }, [tabs, panels, activeIndex]);

  return {
    activeIndex,
    setActiveIndex,
    handleKeyDown,
  };
};

/**
 * 表单无障碍钩子
 */
export const useFormAccessibility = () => {
  const { announce } = useAnnouncer();

  const announceError = useCallback((fieldName: string, error: string) => {
    announce(`${fieldName}字段错误：${error}`, 'assertive');
  }, [announce]);

  const announceSuccess = useCallback((message: string) => {
    announce(message, 'polite');
  }, [announce]);

  const setFieldError = useCallback((element: HTMLElement | null, error: string | null, errorId?: string) => {
    if (!element) return;

    if (error) {
      element.setAttribute('aria-invalid', 'true');
      if (errorId) {
        element.setAttribute('aria-describedby', errorId);
      }
    } else {
      element.removeAttribute('aria-invalid');
      element.removeAttribute('aria-describedby');
    }
  }, []);

  const setFieldRequired = useCallback((element: HTMLElement | null, required: boolean) => {
    if (!element) return;

    if (required) {
      element.setAttribute('aria-required', 'true');
    } else {
      element.removeAttribute('aria-required');
    }
  }, []);

  return {
    announceError,
    announceSuccess,
    setFieldError,
    setFieldRequired,
  };
};

/**
 * 实时状态更新钩子
 */
export const useLiveRegion = () => {
  const regionRef = useRef<HTMLElement>(null);
  const { announce } = useAnnouncer();

  const updateStatus = useCallback((message: string, priority: 'polite' | 'assertive' = 'polite') => {
    if (regionRef.current) {
      regionRef.current.textContent = message;
    } else {
      announce(message, priority);
    }
  }, [announce]);

  const clearStatus = useCallback(() => {
    if (regionRef.current) {
      regionRef.current.textContent = '';
    }
  }, []);

  return {
    regionRef,
    updateStatus,
    clearStatus,
  };
};