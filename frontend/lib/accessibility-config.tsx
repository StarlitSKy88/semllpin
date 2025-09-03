/**
 * SmellPin全局无障碍性配置
 * 统一管理ARIA标签、键盘导航和屏幕阅读器设置
 */

'use client';

import { createContext, useContext, useEffect, useState } from 'react';

// 无障碍性偏好设置
export interface AccessibilityPreferences {
  // 运动偏好
  reducedMotion: boolean;
  
  // 视觉偏好
  highContrast: boolean;
  largeText: boolean;
  
  // 交互偏好
  preferKeyboard: boolean;
  announceActions: boolean;
  
  // 焦点偏好
  visibleFocus: boolean;
  skipLinks: boolean;
  
  // 语言偏好
  language: 'zh-CN' | 'en-US';
  voiceRate: number; // 语音速率 0.5-2.0
}

const defaultPreferences: AccessibilityPreferences = {
  reducedMotion: false,
  highContrast: false,
  largeText: false,
  preferKeyboard: false,
  announceActions: true,
  visibleFocus: true,
  skipLinks: true,
  language: 'zh-CN',
  voiceRate: 1.0
};

// Context
const AccessibilityContext = createContext<{
  preferences: AccessibilityPreferences;
  updatePreferences: (updates: Partial<AccessibilityPreferences>) => void;
  announce: (message: string, priority?: 'polite' | 'assertive') => void;
  setFocusVisible: (visible: boolean) => void;
}>({
  preferences: defaultPreferences,
  updatePreferences: () => {},
  announce: () => {},
  setFocusVisible: () => {}
});

// Provider组件
interface AccessibilityProviderProps {
  children: React.ReactNode;
}

export function AccessibilityProvider({ children }: AccessibilityProviderProps) {
  const [preferences, setPreferences] = useState<AccessibilityPreferences>(defaultPreferences);
  const [focusVisible, setFocusVisible] = useState(false);

  // 从本地存储加载偏好设置
  useEffect(() => {
    const stored = localStorage.getItem('smellpin-accessibility-preferences');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        setPreferences({ ...defaultPreferences, ...parsed });
      } catch (error) {
        console.warn('Failed to parse accessibility preferences:', error);
      }
    }

    // 检测系统偏好
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const prefersHighContrast = window.matchMedia('(prefers-contrast: high)').matches;
    
    if (prefersReducedMotion || prefersHighContrast) {
      const systemPreferences = {
        reducedMotion: prefersReducedMotion,
        highContrast: prefersHighContrast
      };
      setPreferences(prev => ({ ...prev, ...systemPreferences }));
    }
  }, []);

  // 保存偏好设置到本地存储
  const updatePreferences = (updates: Partial<AccessibilityPreferences>) => {
    const newPreferences = { ...preferences, ...updates };
    setPreferences(newPreferences);
    localStorage.setItem('smellpin-accessibility-preferences', JSON.stringify(newPreferences));
  };

  // 屏幕阅读器公告
  const announce = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
    if (!preferences.announceActions) return;

    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', priority);
    announcement.setAttribute('aria-atomic', 'true');
    announcement.setAttribute('class', 'sr-only');
    announcement.textContent = message;

    document.body.appendChild(announcement);

    // 延迟移除
    setTimeout(() => {
      if (document.body.contains(announcement)) {
        document.body.removeChild(announcement);
      }
    }, 1000);
  };

  // 应用全局样式
  useEffect(() => {
    const root = document.documentElement;

    // 减少动画
    if (preferences.reducedMotion) {
      root.style.setProperty('--animation-duration', '0.01ms');
      root.style.setProperty('--transition-duration', '0.01ms');
      document.body.classList.add('reduce-motion');
    } else {
      root.style.removeProperty('--animation-duration');
      root.style.removeProperty('--transition-duration');
      document.body.classList.remove('reduce-motion');
    }

    // 高对比度
    if (preferences.highContrast) {
      document.body.classList.add('high-contrast');
    } else {
      document.body.classList.remove('high-contrast');
    }

    // 大字体
    if (preferences.largeText) {
      document.body.classList.add('large-text');
    } else {
      document.body.classList.remove('large-text');
    }

    // 可见焦点
    if (preferences.visibleFocus || focusVisible) {
      document.body.classList.add('visible-focus');
    } else {
      document.body.classList.remove('visible-focus');
    }

    // 键盘偏好
    if (preferences.preferKeyboard) {
      document.body.classList.add('prefer-keyboard');
    } else {
      document.body.classList.remove('prefer-keyboard');
    }
  }, [preferences, focusVisible]);

  // 监听键盘使用
  useEffect(() => {
    let keyboardUsed = false;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Tab') {
        keyboardUsed = true;
        setFocusVisible(true);
        document.body.classList.add('using-keyboard');
      }
    };

    const handleMouseDown = () => {
      if (keyboardUsed) {
        keyboardUsed = false;
        setFocusVisible(false);
        document.body.classList.remove('using-keyboard');
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleMouseDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleMouseDown);
    };
  }, []);

  return (
    <AccessibilityContext.Provider
      value={{
        preferences,
        updatePreferences,
        announce,
        setFocusVisible
      }}
    >
      {children}
    </AccessibilityContext.Provider>
  );
}

// Hook
export const useAccessibilityPreferences = () => {
  const context = useContext(AccessibilityContext);
  if (!context) {
    throw new Error('useAccessibilityPreferences must be used within AccessibilityProvider');
  }
  return context;
};

// 无障碍性检查工具
export const AccessibilityChecker = {
  // 检查颜色对比度
  checkColorContrast: (foreground: string, background: string): number => {
    // 简化的对比度计算
    const getLuminance = (color: string) => {
      const hex = color.replace('#', '');
      const r = parseInt(hex.substr(0, 2), 16) / 255;
      const g = parseInt(hex.substr(2, 2), 16) / 255;
      const b = parseInt(hex.substr(4, 2), 16) / 255;
      
      const toLinear = (c: number) => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
      
      return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
    };

    const l1 = getLuminance(foreground);
    const l2 = getLuminance(background);
    
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  },

  // 检查ARIA标签
  checkAriaLabels: (element: HTMLElement): string[] => {
    const issues: string[] = [];
    
    // 检查交互元素是否有可访问名称
    const interactiveElements = element.querySelectorAll('button, a, input, select, textarea');
    interactiveElements.forEach((el) => {
      const hasLabel = el.hasAttribute('aria-label') || 
                      el.hasAttribute('aria-labelledby') || 
                      el.querySelector('label') ||
                      el.textContent?.trim();
      
      if (!hasLabel) {
        issues.push(`交互元素缺少可访问名称: ${el.tagName}`);
      }
    });

    // 检查图片alt属性
    const images = element.querySelectorAll('img');
    images.forEach((img) => {
      if (!img.hasAttribute('alt')) {
        issues.push('图片缺少alt属性');
      }
    });

    return issues;
  },

  // 检查键盘可访问性
  checkKeyboardAccessibility: (element: HTMLElement): string[] => {
    const issues: string[] = [];
    
    const focusableElements = element.querySelectorAll(
      'a, button, input, textarea, select, [tabindex]:not([tabindex="-1"])'
    );
    
    focusableElements.forEach((el) => {
      const tabIndex = el.getAttribute('tabindex');
      if (tabIndex && parseInt(tabIndex) > 0) {
        issues.push('避免使用正数tabindex值');
      }
    });

    return issues;
  }
};

// 常用ARIA属性和角色
export const ARIA_ROLES = {
  // 地标角色
  BANNER: 'banner',
  MAIN: 'main',
  NAVIGATION: 'navigation',
  CONTENTINFO: 'contentinfo',
  COMPLEMENTARY: 'complementary',
  SEARCH: 'search',
  FORM: 'form',
  
  // 交互角色
  BUTTON: 'button',
  LINK: 'link',
  MENUITEM: 'menuitem',
  TAB: 'tab',
  TABPANEL: 'tabpanel',
  DIALOG: 'dialog',
  ALERTDIALOG: 'alertdialog',
  
  // 状态角色
  ALERT: 'alert',
  STATUS: 'status',
  LOG: 'log',
  MARQUEE: 'marquee',
  TIMER: 'timer'
} as const;

export const ARIA_PROPERTIES = {
  // 状态属性
  'aria-expanded': 'aria-expanded',
  'aria-selected': 'aria-selected',
  'aria-checked': 'aria-checked',
  'aria-disabled': 'aria-disabled',
  'aria-hidden': 'aria-hidden',
  'aria-pressed': 'aria-pressed',
  
  // 关系属性
  'aria-labelledby': 'aria-labelledby',
  'aria-describedby': 'aria-describedby',
  'aria-controls': 'aria-controls',
  'aria-owns': 'aria-owns',
  'aria-activedescendant': 'aria-activedescendant',
  
  // 实时区域属性
  'aria-live': 'aria-live',
  'aria-atomic': 'aria-atomic',
  'aria-relevant': 'aria-relevant',
  
  // 其他属性
  'aria-label': 'aria-label',
  'aria-required': 'aria-required',
  'aria-invalid': 'aria-invalid',
  'aria-level': 'aria-level'
} as const;

// CSS类名常量
export const ACCESSIBILITY_CLASSES = {
  SR_ONLY: 'sr-only',
  SKIP_LINK: 'skip-link',
  FOCUS_VISIBLE: 'focus-visible',
  HIGH_CONTRAST: 'high-contrast',
  LARGE_TEXT: 'large-text',
  REDUCE_MOTION: 'reduce-motion'
} as const;