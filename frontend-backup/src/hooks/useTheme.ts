import { useState, useEffect } from 'react';
import type { ThemeState } from '../types/theme';
import { STORAGE_KEY } from '../types/theme';

// Hook 用于在组件中使用主题状态
export const useTheme = () => {
  const [themeState, setThemeState] = useState<ThemeState>({
    theme: 'system',
    contrastMode: 'normal',
    reducedMotion: false,
    fontSize: 'medium'
  });

  useEffect(() => {
    if (typeof window !== 'undefined') {
      try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          setThemeState(JSON.parse(stored));
        }
      } catch (error) {
        console.warn('Failed to load theme from storage:', error);
      }
    }
  }, []);

  return themeState;
};