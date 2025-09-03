import React from 'react';

interface ScreenReaderContextType {
  announce: (message: string, priority?: 'polite' | 'assertive') => void;
  announceNavigation: (page: string) => void;
  announceLoading: (isLoading: boolean) => void;
  announceError: (error: string) => void;
  announceSuccess: (message: string) => void;
}

export const ScreenReaderContext = React.createContext<ScreenReaderContextType | null>(null);