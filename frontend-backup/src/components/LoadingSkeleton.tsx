import React from 'react';
import { Skeleton } from 'antd';

interface LoadingSkeletonProps {
  type?: 'card' | 'list' | 'article' | 'profile' | 'custom';
  rows?: number;
  avatar?: boolean;
  title?: boolean;
  loading?: boolean;
  children?: React.ReactNode;
  className?: string;
}

export const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({
  type = 'card',
  rows = 3,
  avatar = false,
  title = true,
  loading = true,
  children,
  className = ''
}) => {
  if (!loading && children) {
    return <>{children}</>;
  }

  const renderSkeleton = () => {
    switch (type) {
      case 'card':
        return (
          <div className={`p-6 bg-white rounded-lg shadow-sm border ${className}`}>
            <Skeleton
              avatar={avatar}
              paragraph={{ rows }}
              title={title}
              active
            />
          </div>
        );

      case 'list':
        return (
          <div className={`space-y-4 ${className}`}>
            {Array.from({ length: rows }).map((_, index) => (
              <div key={`item-${index}`} className="flex items-center space-x-4 p-4 bg-white rounded-lg">
                <Skeleton.Avatar size="large" active />
                <div className="flex-1">
                  <Skeleton
                    paragraph={{ rows: 2 }}
                    title={{ width: '60%' }}
                    active
                  />
                </div>
              </div>
            ))}
          </div>
        );

      case 'article':
        return (
          <div className={`max-w-4xl mx-auto p-6 bg-white rounded-lg ${className}`}>
            <Skeleton.Input 
              style={{ width: '80%', height: 40 }} 
              active 
              className="mb-4"
            />
            <div className="flex items-center space-x-4 mb-6">
              <Skeleton.Avatar size="large" active />
              <div>
                <Skeleton.Input style={{ width: 120 }} active />
                <Skeleton.Input style={{ width: 80 }} active className="mt-2" />
              </div>
            </div>
            <Skeleton
              paragraph={{ rows: 8 }}
              title={false}
              active
            />
          </div>
        );

      case 'profile':
        return (
          <div className={`p-6 bg-white rounded-lg ${className}`}>
            <div className="flex items-center space-x-6 mb-6">
              <Skeleton.Avatar size={80} active />
              <div className="flex-1">
                <Skeleton.Input style={{ width: '60%' }} active className="mb-2" />
                <Skeleton.Input style={{ width: '40%' }} active className="mb-2" />
                <Skeleton.Input style={{ width: '80%' }} active />
              </div>
            </div>
            <Skeleton
              paragraph={{ rows: 4 }}
              title={false}
              active
            />
          </div>
        );

      case 'custom':
      default:
        return (
          <div className={className}>
            <Skeleton
              avatar={avatar}
              paragraph={{ rows }}
              title={title}
              active
            />
          </div>
        );
    }
  };

  return renderSkeleton();
};

// 特定用途的骨架屏组件
export const CardSkeleton: React.FC<{ count?: number; className?: string }> = ({ 
  count = 1, 
  className = '' 
}) => (
  <div className={`grid gap-6 ${className}`}>
    {Array.from({ length: count }).map((_, index) => (
      <LoadingSkeleton key={`item-${index}`} type="card" />
    ))}
  </div>
);

export const ListSkeleton: React.FC<{ count?: number; className?: string }> = ({ 
  count = 3, 
  className = '' 
}) => (
  <LoadingSkeleton type="list" rows={count} className={className} />
);

export const ArticleSkeleton: React.FC<{ className?: string }> = ({ className = '' }) => (
  <LoadingSkeleton type="article" className={className} />
);

export const ProfileSkeleton: React.FC<{ className?: string }> = ({ className = '' }) => (
  <LoadingSkeleton type="profile" className={className} />
);

// 页面级别的加载组件
export const PageLoading: React.FC<{ tip?: string }> = ({ tip = '加载中...' }) => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
      <p className="text-gray-600">{tip}</p>
    </div>
  </div>
);

export default LoadingSkeleton;