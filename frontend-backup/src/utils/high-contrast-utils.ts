/**
 * 高对比度模式工具函数
 */

/**
 * 应用高对比度样式到DOM
 */
export const applyHighContrastStyles = (isHighContrast: boolean) => {
  const root = document.documentElement;
  
  if (isHighContrast) {
    root.classList.add('high-contrast');
    // 添加高对比度CSS变量
    root.style.setProperty('--high-contrast-bg', '#000000');
    root.style.setProperty('--high-contrast-text', '#ffffff');
    root.style.setProperty('--high-contrast-border', '#ffffff');
    root.style.setProperty('--high-contrast-focus', '#ffff00');
    root.style.setProperty('--high-contrast-link', '#00ffff');
    root.style.setProperty('--high-contrast-button', '#ffffff');
    root.style.setProperty('--high-contrast-button-bg', '#000000');
  } else {
    root.classList.remove('high-contrast');
    // 移除高对比度CSS变量
    root.style.removeProperty('--high-contrast-bg');
    root.style.removeProperty('--high-contrast-text');
    root.style.removeProperty('--high-contrast-border');
    root.style.removeProperty('--high-contrast-focus');
    root.style.removeProperty('--high-contrast-link');
    root.style.removeProperty('--high-contrast-button');
    root.style.removeProperty('--high-contrast-button-bg');
  }
};

/**
 * 检测系统高对比度偏好
 */
export const detectSystemHighContrastPreference = (): boolean => {
  const mediaQuery = window.matchMedia('(prefers-contrast: high)');
  return mediaQuery.matches;
};

/**
 * 从localStorage获取高对比度偏好
 */
export const getStoredHighContrastPreference = (): boolean | null => {
  const saved = localStorage.getItem('high-contrast-mode');
  if (saved === 'true') return true;
  if (saved === 'false') return false;
  return null;
};

/**
 * 保存高对比度偏好到localStorage
 */
export const saveHighContrastPreference = (isHighContrast: boolean): void => {
  localStorage.setItem('high-contrast-mode', isHighContrast.toString());
};