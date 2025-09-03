import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useUIStore } from '../../stores/uiStore';
import { Spin, Typography } from 'antd';
import './GlobalLoading.css';

const { Text } = Typography;

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
interface GlobalLoadingProps {
  // 可以添加额外的props
}

const GlobalLoading: React.FC<GlobalLoadingProps> = () => {
  const { globalLoading, loadingMessage } = useUIStore();

  return (
    <AnimatePresence>
      {globalLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm"
        >
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            className="bg-white rounded-2xl p-8 shadow-2xl flex flex-col items-center space-y-4"
          >
            <Spin size="large" />
            {loadingMessage && (
              <Text className="text-gray-600 text-center max-w-xs">
                {loadingMessage}
              </Text>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default GlobalLoading;