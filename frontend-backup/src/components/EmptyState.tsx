import React from 'react';
import { motion } from 'framer-motion';
import { 
  Search, 
  MapPin, 
  Users, 
  Heart, 
  MessageCircle, 
  FileText, 
  Wifi,
  AlertCircle
} from 'lucide-react';

interface EmptyStateProps {
  type?: 'search' | 'data' | 'error' | 'offline' | 'loading' | 'custom' | 'no-data';
  title: string;
  description?: string;
  icon?: React.ReactNode;
  action?: {
    label: string;
    onClick: () => void;
    variant?: 'primary' | 'secondary';
  };
  illustration?: React.ReactNode;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

const EmptyState: React.FC<EmptyStateProps> = ({
  type = 'data',
  title,
  description,
  icon,
  action,
  illustration,
  className = '',
  size = 'md'
}) => {
  const getDefaultIcon = () => {
    switch (type) {
      case 'search':
        return <Search className="w-12 h-12 text-gray-400" />;
      case 'error':
        return <AlertCircle className="w-12 h-12 text-red-400" />;
      case 'offline':
        return <Wifi className="w-12 h-12 text-gray-400" />;
      case 'loading':
        return <div className="w-12 h-12 border-4 border-gray-300 border-t-purple-500 rounded-full animate-spin" />;
      default:
        return <FileText className="w-12 h-12 text-gray-400" />;
    }
  };

  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'py-8 px-4';
      case 'md':
        return 'py-12 px-6';
      case 'lg':
        return 'py-16 px-8';
      default:
        return 'py-12 px-6';
    }
  };

  const getActionVariant = () => {
    switch (action?.variant) {
      case 'secondary':
        return 'bg-gray-100 hover:bg-gray-200 text-gray-700';
      default:
        return 'bg-purple-600 hover:bg-purple-700 text-white';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className={`
        flex flex-col items-center justify-center text-center
        ${getSizeClasses()}
        ${className}
      `}
      role="status"
      aria-live="polite"
    >
      {/* 插图或图标 */}
      <div className="mb-6">
        {illustration || icon || getDefaultIcon()}
      </div>

      {/* 标题 */}
      <h3 className="text-xl font-semibold text-gray-900 mb-2">
        {title}
      </h3>

      {/* 描述 */}
      {description && (
        <p className="text-gray-600 mb-6 max-w-md leading-relaxed">
          {description}
        </p>
      )}

      {/* 操作按钮 */}
      {action && (
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={action.onClick}
          className={`
            px-6 py-3 rounded-lg font-medium
            transition-all duration-200
            focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2
            ${getActionVariant()}
          `}
        >
          {action.label}
        </motion.button>
      )}
    </motion.div>
  );
};

// 预设的空状态组件
export const NoSearchResults: React.FC<{
  query?: string;
  onClear?: () => void;
}> = ({ query, onClear }) => (
  <EmptyState
    type="search"
    title="未找到相关结果"
    description={query ? `没有找到与"${query}"相关的内容，请尝试其他关键词。` : '请输入关键词进行搜索。'}
    action={onClear ? {
      label: '清除搜索',
      onClick: onClear,
      variant: 'secondary'
    } : undefined}
  />
);

export const NoMapPins: React.FC<{
  onCreatePin?: () => void;
}> = ({ onCreatePin }) => (
  <EmptyState
    icon={<MapPin className="w-12 h-12 text-purple-400" />}
    title="还没有标注"
    description="成为第一个在这里留下标注的人，分享你的有趣发现！"
    action={onCreatePin ? {
      label: '创建标注',
      onClick: onCreatePin
    } : undefined}
  />
);

export const NoComments: React.FC<{
  onAddComment?: () => void;
}> = ({ onAddComment }) => (
  <EmptyState
    icon={<MessageCircle className="w-12 h-12 text-blue-400" />}
    title="暂无评论"
    description="成为第一个评论的人，分享你的想法！"
    action={onAddComment ? {
      label: '添加评论',
      onClick: onAddComment
    } : undefined}
  />
);

export const NoFavorites: React.FC<{
  onExplore?: () => void;
}> = ({ onExplore }) => (
  <EmptyState
    icon={<Heart className="w-12 h-12 text-red-400" />}
    title="还没有收藏"
    description="探索地图，收藏你喜欢的标注和内容。"
    action={onExplore ? {
      label: '开始探索',
      onClick: onExplore
    } : undefined}
  />
);

export const NoFollowers: React.FC<{
  onShare?: () => void;
}> = ({ onShare }) => (
  <EmptyState
    icon={<Users className="w-12 h-12 text-green-400" />}
    title="还没有关注者"
    description="分享你的精彩内容，吸引更多用户关注你！"
    action={onShare ? {
      label: '分享内容',
      onClick: onShare
    } : undefined}
  />
);

export const NetworkError: React.FC<{
  onRetry?: () => void;
}> = ({ onRetry }) => (
  <EmptyState
    type="error"
    title="网络连接失败"
    description="请检查你的网络连接，然后重试。"
    action={onRetry ? {
      label: '重试',
      onClick: onRetry
    } : undefined}
  />
);

export const OfflineState: React.FC<{
  onRefresh?: () => void;
}> = ({ onRefresh }) => (
  <EmptyState
    type="offline"
    title="当前离线"
    description="你当前处于离线状态，部分功能可能无法使用。"
    action={onRefresh ? {
      label: '刷新页面',
      onClick: onRefresh,
      variant: 'secondary'
    } : undefined}
  />
);

// 加载状态组件
export const LoadingState: React.FC<{
  message?: string;
}> = ({ message = '正在加载...' }) => (
  <EmptyState
    type="loading"
    title={message}
    description="请稍候，我们正在为你准备内容。"
  />
);

// 自定义插图组件
export const CustomIllustration: React.FC<{
  children: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}> = ({ children, title, description, action }) => (
  <EmptyState
    type="custom"
    title={title}
    description={description}
    illustration={children}
    action={action}
  />
);

// 数据为空的通用组件
export const DataEmpty: React.FC<{
  entityName: string;
  onAction?: () => void;
  actionLabel?: string;
}> = ({ entityName, onAction, actionLabel }) => (
  <EmptyState
    title={`暂无${entityName}`}
    description={`还没有任何${entityName}，快来添加第一个吧！`}
    action={onAction && actionLabel ? {
      label: actionLabel,
      onClick: onAction
    } : undefined}
  />
);

export default EmptyState;