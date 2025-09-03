/**
 * 主题切换组件
 * 提供明暗主题切换功能
 */

import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { useTheme, type ThemeMode } from '../../contexts/ThemeContext';
import { cn } from '../../utils/cn';

interface ThemeToggleProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'button' | 'dropdown' | 'icon';
  showLabel?: boolean;
}

const ThemeToggle: React.FC<ThemeToggleProps> = ({
  className,
  size = 'md',
  variant = 'button',
  showLabel = false,
}) => {
  const { mode, setMode } = useTheme();

  const sizeClasses = {
    sm: 'h-8 w-8 text-sm',
    md: 'h-10 w-10 text-base',
    lg: 'h-12 w-12 text-lg',
  };

  const iconSizes = {
    sm: 16,
    md: 20,
    lg: 24,
  };

  const getThemeIcon = (themeMode: ThemeMode) => {
    const iconSize = iconSizes[size];
    switch (themeMode) {
      case 'light':
        return <Sun size={iconSize} />;
      case 'dark':
        return <Moon size={iconSize} />;
      case 'system':
        return <Monitor size={iconSize} />;
      default:
        return <Sun size={iconSize} />;
    }
  };

  const getThemeLabel = (themeMode: ThemeMode) => {
    switch (themeMode) {
      case 'light':
        return '浅色模式';
      case 'dark':
        return '深色模式';
      case 'system':
        return '跟随系统';
      default:
        return '浅色模式';
    }
  };

  const handleToggle = () => {
    const modes: ThemeMode[] = ['light', 'dark', 'system'];
    const currentIndex = modes.indexOf(mode);
    const nextIndex = (currentIndex + 1) % modes.length;
    setMode(modes[nextIndex]);
  };

  if (variant === 'icon') {
    return (
      <button
        onClick={handleToggle}
        className={cn(
          'inline-flex items-center justify-center rounded-lg',
          'bg-floral-50 dark:bg-pomegranate-900/20 border border-pomegranate-200 dark:border-pomegranate-700',
          'text-pomegranate-700 dark:text-pomegranate-200',
          'hover:bg-floral-100 dark:hover:bg-pomegranate-800/30',
          'focus:outline-none focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
          'transition-all duration-200',
          sizeClasses[size],
          className
        )}
        title={getThemeLabel(mode)}
        aria-label={`切换到${getThemeLabel(mode)}`}
      >
        {getThemeIcon(mode)}
      </button>
    );
  }

  if (variant === 'dropdown') {
    return (
      <div className={cn('relative', className)}>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as ThemeMode)}
          className={cn(
            'appearance-none bg-floral-50 dark:bg-pomegranate-900/20',
            'border border-pomegranate-200 dark:border-pomegranate-700',
            'text-pomegranate-700 dark:text-pomegranate-200',
            'rounded-lg px-3 py-2 pr-8',
            'focus:outline-none focus:ring-2 focus:ring-pomegranate-500',
            'transition-colors duration-200',
            size === 'sm' && 'text-sm',
            size === 'lg' && 'text-lg'
          )}
        >
          <option value="light">浅色模式</option>
          <option value="dark">深色模式</option>
          <option value="system">跟随系统</option>
        </select>
        <div className="absolute inset-y-0 right-0 flex items-center pr-2 pointer-events-none">
          <svg className="w-4 h-4 text-pomegranate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>
    );
  }

  return (
    <button
      onClick={handleToggle}
      className={cn(
        'inline-flex items-center gap-2 px-4 py-2 rounded-lg',
        'bg-floral-50 dark:bg-pomegranate-900/20 border border-pomegranate-200 dark:border-pomegranate-700',
        'text-pomegranate-700 dark:text-pomegranate-200',
        'hover:bg-floral-100 dark:hover:bg-pomegranate-800/30',
        'focus:outline-none focus:ring-2 focus:ring-pomegranate-500 focus:ring-offset-2',
        'transition-all duration-200',
        size === 'sm' && 'text-sm px-3 py-1.5',
        size === 'lg' && 'text-lg px-6 py-3',
        className
      )}
      title={getThemeLabel(mode)}
      aria-label={`当前: ${getThemeLabel(mode)}，点击切换主题`}
    >
      {getThemeIcon(mode)}
      {showLabel && (
        <span className="font-medium">
          {getThemeLabel(mode)}
        </span>
      )}
    </button>
  );
};

// 主题状态指示器
export const ThemeIndicator: React.FC<{ className?: string }> = ({ className }) => {
  const { actualMode } = useTheme();
  
  return (
    <div className={cn(
      'inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs',
      'bg-floral-100 dark:bg-pomegranate-900/20 text-pomegranate-600 dark:text-pomegranate-400',
      className
    )}>
      <div className={cn(
        'w-2 h-2 rounded-full',
        actualMode === 'light' ? 'bg-floral-400' : 'bg-pomegranate-400'
      )} />
      <span>{actualMode === 'light' ? '浅色' : '深色'}</span>
    </div>
  );
};

export default ThemeToggle;