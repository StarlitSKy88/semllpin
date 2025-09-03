import React from 'react';

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

export const ScreenReaderContext = React.createContext<ScreenReaderContextType | null>(null);