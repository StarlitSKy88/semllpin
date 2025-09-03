import { useContext } from 'react';
import { HighContrastContext } from '../contexts/HighContrastContext';

/**
 * 使用高对比度模式的Hook
 */
export const useHighContrast = () => {
  const context = useContext(HighContrastContext);
  if (context === undefined) {
    throw new Error('useHighContrast must be used within a HighContrastProvider');
  }
  return context;
};