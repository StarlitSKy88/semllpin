import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Wifi, WifiOff, AlertTriangle, RefreshCw, X } from 'lucide-react';
import { NetworkContext } from '../contexts/NetworkContext';
import type { NetworkContextType, NetworkState } from '../contexts/NetworkContext';
import { useNetworkStatus } from '../hooks/useNetworkStatus';

// 网络状态提供者组件
interface NetworkProviderProps {
  children: React.ReactNode;
}

export const NetworkProvider: React.FC<NetworkProviderProps> = ({ children }) => {
  const [networkState, setNetworkState] = useState<NetworkState>({
    isOnline: navigator.onLine,
    isSlowConnection: false,
    connectionType: 'unknown',
    effectiveType: 'unknown'
  });
  
  const [showSlowConnectionWarning, setShowSlowConnectionWarning] = useState(false);
  const [retryCount, setRetryCount] = useState(0);

  // 检测网络连接类型
  const getConnectionInfo = () => {
    interface ExtendedNavigator extends Navigator {
        connection?: {
          type?: string;
          effectiveType?: string;
          downlink?: number;
          rtt?: number;
          saveData?: boolean;
          addEventListener?: (type: string, listener: () => void) => void;
          removeEventListener?: (type: string, listener: () => void) => void;
        };
        mozConnection?: {
          type?: string;
          effectiveType?: string;
          downlink?: number;
          rtt?: number;
          saveData?: boolean;
          addEventListener?: (type: string, listener: () => void) => void;
          removeEventListener?: (type: string, listener: () => void) => void;
        };
        webkitConnection?: {
          type?: string;
          effectiveType?: string;
          downlink?: number;
          rtt?: number;
          saveData?: boolean;
          addEventListener?: (type: string, listener: () => void) => void;
          removeEventListener?: (type: string, listener: () => void) => void;
        };
      }
    
    const extendedNavigator = navigator as ExtendedNavigator;
    const connection = extendedNavigator.connection || 
                     extendedNavigator.mozConnection || 
                     extendedNavigator.webkitConnection;
    
    if (connection) {
      return {
        connectionType: connection.type || 'unknown',
        effectiveType: connection.effectiveType || 'unknown',
        isSlowConnection: connection.effectiveType === 'slow-2g' || 
                         connection.effectiveType === '2g' ||
                         (connection.downlink ?? 0) < 1
      };
    }
    
    return {
      connectionType: 'unknown',
      effectiveType: 'unknown',
      isSlowConnection: false
    };
  };

  // 更新网络状态
  const updateNetworkStatus = useCallback(() => {
    const connectionInfo = getConnectionInfo();
    setNetworkState(prev => ({
      ...prev,
      isOnline: navigator.onLine,
      ...connectionInfo
    }));

    // 显示慢连接警告
    if (connectionInfo.isSlowConnection && navigator.onLine) {
      setShowSlowConnectionWarning(true);
    }
  }, []);

  // 重试连接
  const retryConnection = () => {
    const newRetryCount = retryCount + 1;
    setRetryCount(newRetryCount);
    updateNetworkStatus();
    
    // 模拟网络检测
    fetch('/api/ping', { 
      method: 'HEAD',
      cache: 'no-cache'
    }).catch(() => {
      // 网络仍然不可用
      console.log(`Network still unavailable after ${newRetryCount} retries`);
    });
  };

  // 关闭慢连接警告
  const dismissSlowConnectionWarning = () => {
    setShowSlowConnectionWarning(false);
  };

  useEffect(() => {
    // 监听网络状态变化
    const handleOnline = () => {
      updateNetworkStatus();
    };

    const handleOffline = () => {
      updateNetworkStatus();
    };

    const handleConnectionChange = () => {
      updateNetworkStatus();
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    // 监听连接变化（如果支持）
    const connection = (navigator as Navigator & {
      connection?: {
        addEventListener?: (event: string, handler: () => void) => void;
        removeEventListener?: (event: string, handler: () => void) => void;
      };
    }).connection;
    if (connection) {
      connection?.addEventListener?.('change', handleConnectionChange);
    }

    // 初始化网络状态
    updateNetworkStatus();

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      connection?.removeEventListener?.('change', handleConnectionChange);
    };
  }, [updateNetworkStatus]);

  const contextValue: NetworkContextType = {
    ...networkState,
    retryConnection,
    dismissSlowConnectionWarning,
    showSlowConnectionWarning
  };

  return (
    <NetworkContext.Provider value={contextValue}>
      {children}
      <NetworkStatusIndicator />
      <SlowConnectionWarning />
    </NetworkContext.Provider>
  );
};

// 网络状态指示器
const NetworkStatusIndicator: React.FC = () => {
  const { isOnline, retryConnection } = useNetworkStatus();
  const [showOfflineMessage, setShowOfflineMessage] = useState(false);

  useEffect(() => {
    if (!isOnline) {
      setShowOfflineMessage(true);
    } else {
      // 延迟隐藏，让用户看到恢复消息
      const timer = setTimeout(() => {
        setShowOfflineMessage(false);
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [isOnline]);

  return (
    <AnimatePresence>
      {showOfflineMessage && (
        <motion.div
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -100, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className={`
            fixed top-4 left-1/2 transform -translate-x-1/2 z-50
            px-6 py-3 rounded-lg shadow-lg
            flex items-center space-x-3
            ${
              isOnline 
                ? 'bg-green-500 text-white' 
                : 'bg-red-500 text-white'
            }
          `}
          role="alert"
          aria-live="assertive"
        >
          {isOnline ? (
            <>
              <Wifi className="w-5 h-5" />
              <span className="font-medium">网络连接已恢复</span>
            </>
          ) : (
            <>
              <WifiOff className="w-5 h-5" />
              <span className="font-medium">网络连接已断开</span>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={retryConnection}
                className="ml-2 px-3 py-1 bg-white bg-opacity-20 rounded text-sm hover:bg-opacity-30 transition-all"
                aria-label="重试连接"
              >
                <RefreshCw className="w-4 h-4" />
              </motion.button>
            </>
          )}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// 慢连接警告
const SlowConnectionWarning: React.FC = () => {
  const { 
    isSlowConnection, 
    showSlowConnectionWarning, 
    dismissSlowConnectionWarning,
    effectiveType 
  } = useNetworkStatus();

  return (
    <AnimatePresence>
      {showSlowConnectionWarning && isSlowConnection && (
        <motion.div
          initial={{ y: 100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 100, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className="fixed bottom-4 left-4 right-4 md:left-auto md:right-4 md:w-96 z-50"
        >
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 shadow-lg">
            <div className="flex items-start">
              <AlertTriangle className="w-5 h-5 text-yellow-600 mt-0.5 mr-3 flex-shrink-0" />
              <div className="flex-1">
                <h4 className="text-sm font-medium text-yellow-800 mb-1">
                  网络连接较慢
                </h4>
                <p className="text-sm text-yellow-700">
                  检测到您的网络连接速度较慢（{effectiveType}），某些功能可能需要更长时间加载。
                </p>
              </div>
              <button
                onClick={dismissSlowConnectionWarning}
                className="ml-2 text-yellow-600 hover:text-yellow-800 transition-colors"
                aria-label="关闭警告"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// 网络状态徽章组件
interface NetworkBadgeProps {
  className?: string;
  showText?: boolean;
}

export const NetworkBadge: React.FC<NetworkBadgeProps> = ({ 
  className = '', 
  showText = false 
}) => {
  const { isOnline, effectiveType } = useNetworkStatus();

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      <div className={`w-2 h-2 rounded-full ${
        isOnline ? 'bg-green-500' : 'bg-red-500'
      }`} />
      {showText && (
        <span className={`text-sm ${
          isOnline ? 'text-green-600' : 'text-red-600'
        }`}>
          {isOnline ? `在线 (${effectiveType})` : '离线'}
        </span>
      )}
    </div>
  );
};

// 网络依赖组件包装器
interface NetworkDependentProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  requireOnline?: boolean;
}

export const NetworkDependent: React.FC<NetworkDependentProps> = ({
  children,
  fallback,
  requireOnline = true
}) => {
  const { isOnline } = useNetworkStatus();

  if (requireOnline && !isOnline) {
    return (
      <div className="text-center py-8">
        {fallback || (
          <div className="space-y-4">
            <WifiOff className="w-12 h-12 text-gray-400 mx-auto" />
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                需要网络连接
              </h3>
              <p className="text-gray-600">
                此功能需要网络连接才能使用，请检查您的网络设置。
              </p>
            </div>
          </div>
        )}
      </div>
    );
  }

  return <>{children}</>;
};

// 网络重试组件
interface NetworkRetryProps {
  onRetry: () => void;
  isRetrying?: boolean;
  error?: string;
  className?: string;
}

export const NetworkRetry: React.FC<NetworkRetryProps> = ({
  onRetry,
  isRetrying = false,
  error = '网络请求失败',
  className = ''
}) => {
  return (
    <div className={`text-center py-6 ${className}`}>
      <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
      <h3 className="text-lg font-medium text-gray-900 mb-2">
        {error}
      </h3>
      <p className="text-gray-600 mb-4">
        请检查您的网络连接，然后重试。
      </p>
      <motion.button
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        onClick={onRetry}
        disabled={isRetrying}
        className="
          px-6 py-2 bg-purple-600 text-white rounded-lg
          hover:bg-purple-700 disabled:opacity-50
          transition-all duration-200
          focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2
        "
      >
        {isRetrying ? (
          <div className="flex items-center">
            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            <span>重试中...</span>
          </div>
        ) : (
          <div className="flex items-center">
            <RefreshCw className="w-4 h-4 mr-2" />
            <span>重试</span>
          </div>
        )}
      </motion.button>
    </div>
  );
};

export default {
  NetworkProvider,
  NetworkBadge,
  NetworkDependent,
  NetworkRetry
};