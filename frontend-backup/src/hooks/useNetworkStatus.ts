import { useContext } from 'react';
import { NetworkContext } from '../contexts/NetworkContext';

// 网络状态Hook
export const useNetworkStatus = () => {
  const context = useContext(NetworkContext);
  if (!context) {
    throw new Error('useNetworkStatus must be used within NetworkProvider');
  }
  return context;
};