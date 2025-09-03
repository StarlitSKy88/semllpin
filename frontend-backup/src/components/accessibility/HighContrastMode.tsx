import React, { useEffect, useState } from 'react';
import { Button } from 'antd';
import { EyeOutlined } from '@ant-design/icons';
import { 
  applyHighContrastStyles, 
  detectSystemHighContrastPreference, 
  getStoredHighContrastPreference, 
  saveHighContrastPreference 
} from '../../utils/high-contrast-utils';
import { useHighContrast } from '../../hooks/useHighContrast';
import { HighContrastContext } from '../../contexts/HighContrastContext';

/**
 * 高对比度模式提供者组件
 */
export const HighContrastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isHighContrast, setIsHighContrast] = useState(false);

  // 从localStorage读取用户偏好
  useEffect(() => {
    const saved = getStoredHighContrastPreference();
    if (saved !== null) {
      setIsHighContrast(saved);
    } else {
      // 检测系统偏好
      const systemPreference = detectSystemHighContrastPreference();
      setIsHighContrast(systemPreference);
    }

    const mediaQuery = window.matchMedia('(prefers-contrast: high)');
    const handleChange = (e: MediaQueryListEvent) => {
      if (getStoredHighContrastPreference() === null) {
        setIsHighContrast(e.matches);
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // 应用高对比度样式
  useEffect(() => {
    applyHighContrastStyles(isHighContrast);
  }, [isHighContrast]);

  const toggleHighContrast = () => {
    const newValue = !isHighContrast;
    setIsHighContrast(newValue);
    saveHighContrastPreference(newValue);
  };

  return (
    <HighContrastContext.Provider value={{ isHighContrast, toggleHighContrast }}>
      {children}
    </HighContrastContext.Provider>
  );
};



/**
 * 高对比度切换按钮组件
 */
export const HighContrastToggle: React.FC<{
  className?: string;
  size?: 'small' | 'middle' | 'large';
}> = ({ className = '', size = 'middle' }) => {
  const { isHighContrast, toggleHighContrast } = useHighContrast();

  return (
    <Button
      type={isHighContrast ? 'primary' : 'default'}
      icon={<EyeOutlined />}
      onClick={toggleHighContrast}
      size={size}
      className={`high-contrast-toggle ${className}`}
      aria-label={isHighContrast ? '关闭高对比度模式' : '开启高对比度模式'}
      aria-pressed={isHighContrast}
      title={isHighContrast ? '关闭高对比度模式' : '开启高对比度模式'}
    >
      {isHighContrast ? '关闭高对比度' : '开启高对比度'}
    </Button>
  );
};

/**
 * 高对比度样式组件 - 注入CSS样式
 */
export const HighContrastStyles: React.FC = () => {
  return (
    <style>{`
      /* 高对比度模式样式 */
      .high-contrast {
        filter: contrast(150%) brightness(120%);
      }

      .high-contrast * {
        background-color: var(--high-contrast-bg, #000000) !important;
        color: var(--high-contrast-text, #ffffff) !important;
        border-color: var(--high-contrast-border, #ffffff) !important;
      }

      .high-contrast a {
        color: var(--high-contrast-link, #00ffff) !important;
        text-decoration: underline !important;
      }

      .high-contrast button {
        background-color: var(--high-contrast-button-bg, #000000) !important;
        color: var(--high-contrast-button, #ffffff) !important;
        border: 2px solid var(--high-contrast-border, #ffffff) !important;
      }

      .high-contrast button:hover,
      .high-contrast button:focus {
        background-color: var(--high-contrast-button, #ffffff) !important;
        color: var(--high-contrast-button-bg, #000000) !important;
      }

      .high-contrast *:focus {
        outline: 3px solid var(--high-contrast-focus, #ffff00) !important;
        outline-offset: 2px !important;
      }

      .high-contrast img {
        filter: contrast(150%) brightness(120%);
      }

      .high-contrast .ant-card {
        background-color: var(--high-contrast-bg, #000000) !important;
        border-color: var(--high-contrast-border, #ffffff) !important;
      }

      .high-contrast .ant-btn {
        background-color: var(--high-contrast-button-bg, #000000) !important;
        color: var(--high-contrast-button, #ffffff) !important;
        border-color: var(--high-contrast-border, #ffffff) !important;
      }

      .high-contrast .ant-btn:hover,
      .high-contrast .ant-btn:focus {
        background-color: var(--high-contrast-button, #ffffff) !important;
        color: var(--high-contrast-button-bg, #000000) !important;
      }

      /* 确保文本可读性 */
      .high-contrast .text-gray-600,
      .high-contrast .text-gray-500,
      .high-contrast .text-gray-400,
      .high-contrast .text-gray-300 {
        color: var(--high-contrast-text, #ffffff) !important;
      }

      /* 渐变背景在高对比度模式下的处理 */
      .high-contrast .bg-gradient-to-r,
      .high-contrast .bg-gradient-to-br,
      .high-contrast .bg-gradient-to-bl {
        background: var(--high-contrast-bg, #000000) !important;
      }

      /* 阴影在高对比度模式下的处理 */
      .high-contrast .shadow-lg,
      .high-contrast .shadow-md,
      .high-contrast .shadow-sm {
        box-shadow: 0 0 0 2px var(--high-contrast-border, #ffffff) !important;
      }
    `}</style>
  );
};