import React, { useState, useEffect, useCallback } from 'react';
import { Button, Dropdown, Switch } from 'antd';
import { Sun, Moon, Monitor, Check, Palette, Contrast } from 'lucide-react';
import { cn } from '../utils/cn';
import type { Theme, ContrastMode, ThemeState } from '../types/theme';
import { STORAGE_KEY } from '../types/theme';

interface ThemeToggleProps {
  className?: string;
  size?: 'small' | 'middle' | 'large';
  showLabel?: boolean;
  showAdvanced?: boolean;
  onChange?: (themeState: ThemeState) => void;
}

const ThemeToggle: React.FC<ThemeToggleProps> = ({
  className,
  size = 'middle',
  showLabel = false,
  showAdvanced = false,
  onChange }) => {
  const [themeState, setThemeState] = useState<ThemeState>({
    theme: 'system',
    contrastMode: 'normal',
    reducedMotion: false,
    fontSize: 'medium' });

  const [systemTheme, setSystemTheme] = useState<'light' | 'dark'>('light');
  const [isOpen, setIsOpen] = useState(false);

  // 检测系统主题偏好
  const detectSystemTheme = useCallback(() => {
    if (typeof window !== 'undefined') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      setSystemTheme(mediaQuery.matches ? 'dark' : 'light');
      return mediaQuery.matches ? 'dark' : 'light';
    }
    return 'light';
  }, []);

  // 检测用户偏好设置
  const detectUserPreferences = useCallback(() => {
    if (typeof window !== 'undefined') {
      const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const highContrast = window.matchMedia('(prefers-contrast: high)').matches;
      
      return {
        reducedMotion,
        contrastMode: highContrast ? 'high' as ContrastMode : 'normal' as ContrastMode };
    }
    return {
      reducedMotion: false,
      contrastMode: 'normal' as ContrastMode };
  }, []);

  // 从本地存储加载主题设置
  const loadThemeFromStorage = useCallback(() => {
    if (typeof window !== 'undefined') {
      try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          const parsed = JSON.parse(stored) as Partial<ThemeState>;
          const userPrefs = detectUserPreferences();
          
          return {
            theme: parsed.theme || 'system',
            contrastMode: parsed.contrastMode || userPrefs.contrastMode,
            reducedMotion: parsed.reducedMotion ?? userPrefs.reducedMotion,
            fontSize: parsed.fontSize || 'medium' } as ThemeState;
        }
      } catch (error) {
        console.warn('Failed to load theme from storage:', error);
      }
    }
    
    const userPrefs = detectUserPreferences();
    return {
      theme: 'system' as Theme,
      contrastMode: userPrefs.contrastMode,
      reducedMotion: userPrefs.reducedMotion,
      fontSize: 'medium' as const };
  }, [detectUserPreferences]);

  // 保存主题设置到本地存储
  const saveThemeToStorage = useCallback((state: ThemeState) => {
    if (typeof window !== 'undefined') {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
      } catch (error) {
        console.warn('Failed to save theme to storage:', error);
      }
    }
  }, []);

  // 应用主题到DOM
  const applyTheme = useCallback((state: ThemeState) => {
    if (typeof window === 'undefined') return;

    const root = document.documentElement;
    const actualTheme = state.theme === 'system' ? systemTheme : state.theme;

    // 应用主题类
    root.classList.remove('light', 'dark');
    root.classList.add(actualTheme);

    // 应用对比度模式
    root.classList.toggle('high-contrast', state.contrastMode === 'high');

    // 应用动画偏好
    root.classList.toggle('reduce-motion', state.reducedMotion);

    // 应用字体大小
    root.classList.remove('font-small', 'font-medium', 'font-large');
    root.classList.add(`font-${state.fontSize}`);

    // 设置CSS变量
    root.style.setProperty('--theme-mode', actualTheme);
    root.style.setProperty('--contrast-mode', state.contrastMode);
    root.style.setProperty('--motion-mode', state.reducedMotion ? 'reduced' : 'normal');
    root.style.setProperty('--font-size-mode', state.fontSize);
  }, [systemTheme]);

  // 更新主题状态
  const updateThemeState = useCallback((newState: Partial<ThemeState>) => {
    const updatedState = { ...themeState, ...newState };
    setThemeState(updatedState);
    saveThemeToStorage(updatedState);
    applyTheme(updatedState);
    onChange?.(updatedState);
  }, [themeState, saveThemeToStorage, applyTheme, onChange]);

  // 初始化主题
  useEffect(() => {
    const initialSystemTheme = detectSystemTheme();
    const initialThemeState = loadThemeFromStorage();
    
    setSystemTheme(initialSystemTheme);
    setThemeState(initialThemeState);
    applyTheme(initialThemeState);
  }, [detectSystemTheme, loadThemeFromStorage, applyTheme]);

  // 监听系统主题变化
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      const newSystemTheme = e.matches ? 'dark' : 'light';
      setSystemTheme(newSystemTheme);
      
      // 如果当前使用系统主题，重新应用
      if (themeState.theme === 'system') {
        applyTheme(themeState);
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [themeState, applyTheme]);



  // 获取主题图标
  const getThemeIcon = (theme: Theme) => {
    switch (theme) {
      case 'light':
        return <Sun className="h-4 w-4" />;
      case 'dark':
        return <Moon className="h-4 w-4" />;
      case 'system':
        return <Monitor className="h-4 w-4" />;
    }
  };

  // 主题选项
  const themeOptions = [
    { key: 'light', label: '浅色模式', icon: <Sun className="h-4 w-4" /> },
    { key: 'dark', label: '深色模式', icon: <Moon className="h-4 w-4" /> },
    { key: 'system', label: '跟随系统', icon: <Monitor className="h-4 w-4" /> },
  ];

  // 字体大小选项
  const fontSizeOptions = [
    { key: 'small', label: '小号字体' },
    { key: 'medium', label: '标准字体' },
    { key: 'large', label: '大号字体' },
  ];

  // 下拉菜单内容
  const dropdownContent = (
    <div className="p-4 min-w-[280px]">
      {/* 主题选择 */}
      <div className="mb-4">
        <h4 className="text-sm font-medium mb-3 text-gray-700 dark:text-gray-300">
          主题模式
        </h4>
        <div className="grid grid-cols-1 gap-2">
          {themeOptions.map((option) => (
            <button
              key={option.key}
              onClick={() => updateThemeState({ theme: option.key as Theme })}
              className={cn(
                'flex items-center justify-between p-3 rounded-lg border transition-all',
                'hover:bg-gray-50 dark:hover:bg-gray-800',
                'focus:outline-none focus:ring-2 focus:ring-blue-500',
                themeState.theme === option.key
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-200 dark:border-gray-700'
              )}
              aria-pressed={themeState.theme === option.key}
            >
              <div className="flex items-center space-x-3">
                {option.icon}
                <span className="text-sm">{option.label}</span>
              </div>
              {themeState.theme === option.key && (
                <Check className="h-4 w-4 text-blue-500" />
              )}
            </button>
          ))}
        </div>
      </div>

      {showAdvanced && (
        <>
          <div className="my-4 border-t border-gray-200 dark:border-gray-700" />
          
          {/* 可访问性选项 */}
          <div className="space-y-4">
            <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
              可访问性选项
            </h4>
            
            {/* 高对比度模式 */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Contrast className="h-4 w-4" />
                <span className="text-sm">高对比度模式</span>
              </div>
              <Switch
                size="small"
                checked={themeState.contrastMode === 'high'}
                onChange={(checked) => 
                  updateThemeState({ contrastMode: checked ? 'high' : 'normal' })
                }
                aria-label="切换高对比度模式"
              />
            </div>
            
            {/* 减少动画 */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="text-sm">减少动画效果</span>
              </div>
              <Switch
                size="small"
                checked={themeState.reducedMotion}
                onChange={(checked) => 
                  updateThemeState({ reducedMotion: checked })
                }
                aria-label="切换动画减少模式"
              />
            </div>
            
            {/* 字体大小 */}
            <div>
              <div className="flex items-center space-x-2 mb-2">
                <Palette className="h-4 w-4" />
                <span className="text-sm">字体大小</span>
              </div>
              <div className="grid grid-cols-3 gap-1">
                {fontSizeOptions.map((option) => (
                  <button
                    key={option.key}
                    onClick={() => updateThemeState({ fontSize: option.key as 'small' | 'medium' | 'large' })}
                    className={cn(
                      'p-2 text-xs rounded border transition-all',
                      'hover:bg-gray-50 dark:hover:bg-gray-800',
                      'focus:outline-none focus:ring-1 focus:ring-blue-500',
                      themeState.fontSize === option.key
                        ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'
                        : 'border-gray-200 dark:border-gray-700'
                    )}
                    aria-pressed={themeState.fontSize === option.key}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );

  return (
    <Dropdown
      popupRender={() => dropdownContent}
      trigger={['click']}
      placement="bottomRight"
      open={isOpen}
      onOpenChange={setIsOpen}
      overlayClassName="theme-toggle-dropdown"
    >
      <Button
        className={cn(
          'flex items-center space-x-2',
          'focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
          className
        )}
        size={size}
        icon={getThemeIcon(themeState.theme)}
        aria-label={`当前主题: ${themeOptions.find(opt => opt.key === themeState.theme)?.label}, 点击切换主题`}
        aria-expanded={isOpen}
        aria-haspopup="menu"
      >
        {showLabel && (
          <span className="hidden sm:inline">
            {themeOptions.find(opt => opt.key === themeState.theme)?.label}
          </span>
        )}
      </Button>
    </Dropdown>
  );
};

export { ThemeToggle };
export default ThemeToggle;