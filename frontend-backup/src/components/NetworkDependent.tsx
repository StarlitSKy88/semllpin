import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { WifiOff, Wifi, AlertTriangle } from 'lucide-react';
import { useNetworkStatus } from '../hooks/useNetworkStatus';

interface NetworkDependentProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  showOfflineMessage?: boolean;
  className?: string;
}

export const NetworkDependent: React.FC<NetworkDependentProps> = ({
  children,
  fallback,
  showOfflineMessage = true,
  className = '',
}) => {
  const { isOnline, effectiveType } = useNetworkStatus();

  const OfflineMessage = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="flex flex-col items-center justify-center p-8 text-center bg-gray-50 rounded-lg border-2 border-dashed border-gray-300"
    >
      <WifiOff className="w-12 h-12 text-gray-400 mb-4" />
      <h3 className="text-lg font-semibold text-gray-700 mb-2">
        网络连接已断开
      </h3>
      <p className="text-gray-500 mb-4">
        请检查您的网络连接，然后重试。
      </p>
      <motion.button
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => window.location.reload()}
        className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
      >
        重新加载
      </motion.button>
    </motion.div>
  );

  const SlowConnectionWarning = () => (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg flex items-center"
    >
      <AlertTriangle className="w-5 h-5 text-yellow-600 mr-2 flex-shrink-0" />
      <div className="text-sm text-yellow-800">
        <span className="font-medium">网络连接较慢</span>
        <span className="ml-1">({effectiveType}) - 某些功能可能加载缓慢</span>
      </div>
    </motion.div>
  );

  if (!isOnline) {
    return (
      <div className={className}>
        <AnimatePresence mode="wait">
          {showOfflineMessage ? (
            <OfflineMessage />
          ) : (
            fallback || <OfflineMessage />
          )}
        </AnimatePresence>
      </div>
    );
  }

  const isSlowConnection = effectiveType === 'slow-2g' || effectiveType === '2g';

  return (
    <div className={className}>
      <AnimatePresence>
        {isSlowConnection && <SlowConnectionWarning />}
      </AnimatePresence>
      
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3 }}
      >
        {children}
      </motion.div>
    </div>
  );
};

// 网络状态指示器组件
export const NetworkStatusIndicator: React.FC<{
  className?: string;
  showText?: boolean;
}> = ({ className = '', showText = false }) => {
  const { isOnline, effectiveType } = useNetworkStatus();

  const getConnectionQuality = () => {
    if (!isOnline) return 'offline';
    if (effectiveType === '4g') return 'excellent';
    if (effectiveType === '3g') return 'good';
    if (effectiveType === '2g') return 'poor';
    return 'unknown';
  };

  const quality = getConnectionQuality();

  const getIndicatorColor = () => {
    switch (quality) {
      case 'excellent':
        return 'text-green-500';
      case 'good':
        return 'text-blue-500';
      case 'poor':
        return 'text-yellow-500';
      case 'offline':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getStatusText = () => {
    switch (quality) {
      case 'excellent':
        return '网络优秀';
      case 'good':
        return '网络良好';
      case 'poor':
        return '网络较慢';
      case 'offline':
        return '离线';
      default:
        return '未知';
    }
  };

  return (
    <div className={`flex items-center ${className}`}>
      {isOnline ? (
        <Wifi className={`w-4 h-4 ${getIndicatorColor()}`} />
      ) : (
        <WifiOff className={`w-4 h-4 ${getIndicatorColor()}`} />
      )}
      
      {showText && (
        <span className={`ml-2 text-sm ${getIndicatorColor()}`}>
          {getStatusText()}
        </span>
      )}
    </div>
  );
};

export default NetworkDependent;