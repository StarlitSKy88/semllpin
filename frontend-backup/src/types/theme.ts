// 主题相关类型定义
export type Theme = 'light' | 'dark' | 'system';
export type ContrastMode = 'normal' | 'high';

export interface ThemeState {
  theme: Theme;
  contrastMode: ContrastMode;
  reducedMotion: boolean;
  fontSize: 'small' | 'medium' | 'large';
}

// 存储键
export const STORAGE_KEY = 'app-theme-state';