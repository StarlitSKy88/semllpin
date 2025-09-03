import { createContext } from 'react';

// 网络状态类型
export interface NetworkState {
  isOnline: boolean;
  isSlowConnection: boolean;
  connectionType: string;
  effectiveType: string;
}

// 网络状态上下文
export interface NetworkContextType extends NetworkState {
  retryConnection: () => void;
  dismissSlowConnectionWarning: () => void;
  showSlowConnectionWarning: boolean;
}

export const NetworkContext = createContext<NetworkContextType | undefined>(undefined);