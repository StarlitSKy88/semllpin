import React from 'react';
import { ScreenReaderContext } from '../contexts/ScreenReaderContext';

/**
 * 屏幕阅读器上下文类型
 */
interface ScreenReaderContextType {
  announce: (message: string, priority?: 'polite' | 'assertive') => void;
  announceNavigation: (page: string) => void;
  announceLoading: (isLoading: boolean) => void;
  announceError: (error: string) => void;
  announceSuccess: (message: string) => void;
}

/**
 * 使用屏幕阅读器上下文的 Hook
 */
export const useScreenReader = (): ScreenReaderContextType => {
  const context = React.useContext(ScreenReaderContext);
  if (!context) {
    throw new Error('useScreenReader must be used within a ScreenReaderProvider');
  }
  return context;
};