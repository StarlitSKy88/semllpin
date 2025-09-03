import { createContext } from 'react';

interface HighContrastContextType {
  isHighContrast: boolean;
  toggleHighContrast: () => void;
}

export const HighContrastContext = createContext<HighContrastContextType | undefined>(undefined);