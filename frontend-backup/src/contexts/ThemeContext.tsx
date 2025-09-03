/**
 * SmellPin 主题上下文
 * 提供主题管理和切换功能
 */

import React, { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { theme } from '../styles/theme';

// 主题模式类型
export type ThemeMode = 'light' | 'dark' | 'system';

// 主题上下文类型
interface ThemeContextType {
  mode: ThemeMode;
  actualMode: 'light' | 'dark';
  setMode: (mode: ThemeMode) => void;
  toggleMode: () => void;
  theme: typeof theme;
}

// 创建主题上下文
const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

// 主题提供者属性
interface ThemeProviderProps {
  children: ReactNode;
  defaultMode?: ThemeMode;
}

// 获取系统主题偏好
const getSystemTheme = (): 'light' | 'dark' => {
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

// 从本地存储获取保存的主题
const getSavedTheme = (): ThemeMode => {
  if (typeof window === 'undefined') return 'system';
  const saved = localStorage.getItem('smellpin-theme');
  return (saved as ThemeMode) || 'system';
};

// 主题提供者组件
export const ThemeProvider: React.FC<ThemeProviderProps> = ({
  children,
  defaultMode = 'system'
}) => {
  const [mode, setModeState] = useState<ThemeMode>(() => getSavedTheme() || defaultMode);
  const [systemTheme, setSystemTheme] = useState<'light' | 'dark'>(() => getSystemTheme());

  // 计算实际主题模式
  const actualMode = mode === 'system' ? systemTheme : mode;

  // 设置主题模式
  const setMode = (newMode: ThemeMode) => {
    setModeState(newMode);
    localStorage.setItem('smellpin-theme', newMode);
  };

  // 切换主题模式
  const toggleMode = () => {
    if (mode === 'light') {
      setMode('dark');
    } else if (mode === 'dark') {
      setMode('system');
    } else {
      setMode('light');
    }
  };

  // 监听系统主题变化
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      setSystemTheme(e.matches ? 'dark' : 'light');
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // 应用主题到文档
  useEffect(() => {
    if (typeof document === 'undefined') return;

    const root = document.documentElement;
    
    // 移除之前的主题类
    root.classList.remove('light', 'dark');
    
    // 添加当前主题类
    root.classList.add(actualMode);
    
    // 设置主题属性
    root.setAttribute('data-theme', actualMode);
    
    // 更新meta标签颜色
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (metaThemeColor) {
      const themeColor = actualMode === 'dark' 
        ? 'var(--color-gray-900)' 
        : 'var(--color-primary-500)';
      metaThemeColor.setAttribute('content', themeColor);
    }
  }, [actualMode]);

  const contextValue: ThemeContextType = {
    mode,
    actualMode,
    setMode,
    toggleMode,
    theme,
  };

  return (
    <ThemeContext.Provider value={contextValue}>
      {children}
    </ThemeContext.Provider>
  );
};

// 使用主题的Hook
export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

// 主题工具Hook
export const useThemeValue = (path: string): string => {
  const { theme } = useTheme();
  
  const keys = path.split('.');
  let value: any = theme;
  
  for (const key of keys) {
    value = value?.[key];
    if (value === undefined) {
      console.warn(`Theme value not found for path: ${path}`);
      return '';
    }
  }
  
  return value;
};

// 响应式断点Hook
export const useBreakpoint = () => {
  const [breakpoint, setBreakpoint] = useState<string>('xs');

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const updateBreakpoint = () => {
      const width = window.innerWidth;
      if (width >= 1536) setBreakpoint('2xl');
      else if (width >= 1280) setBreakpoint('xl');
      else if (width >= 1024) setBreakpoint('lg');
      else if (width >= 768) setBreakpoint('md');
      else if (width >= 640) setBreakpoint('sm');
      else setBreakpoint('xs');
    };

    updateBreakpoint();
    window.addEventListener('resize', updateBreakpoint);
    return () => window.removeEventListener('resize', updateBreakpoint);
  }, []);

  return breakpoint;
};

// 暗色模式检测Hook
export const useDarkMode = (): boolean => {
  const { actualMode } = useTheme();
  return actualMode === 'dark';
};

export default ThemeProvider;