import React from 'react';
import { clsx } from 'clsx';
import { Loader2 } from 'lucide-react';

interface LoadingIndicatorProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  variant?: 'spinner' | 'dots' | 'pulse' | 'bars' | 'ring';
  color?: 'primary' | 'accent' | 'white' | 'gray';
  className?: string;
  text?: string;
  fullScreen?: boolean;
  overlay?: boolean;
}

const LoadingIndicator: React.FC<LoadingIndicatorProps> = ({
  size = 'md',
  variant = 'spinner',
  color = 'primary',
  className,
  text,
  fullScreen = false,
  overlay = false,
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
    xl: 'w-12 h-12',
  };

  const colorClasses = {
    primary: 'text-primary-500',
    accent: 'text-accent-500',
    white: 'text-white',
    gray: 'text-gray-500',
  };

  const textSizeClasses = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
    xl: 'text-xl',
  };

  const renderSpinner = () => {
    switch (variant) {
      case 'spinner':
        return (
          <Loader2 
            className={clsx(
              sizeClasses[size],
              colorClasses[color],
              'animate-spin'
            )}
            aria-hidden={true}
          />
        );
      
      case 'dots':
        return (
          <div className="flex space-x-1">
            {[0, 1, 2].map((i) => (
              <div
                key={`item-${i}`}
                className={clsx(
                  'rounded-full',
                  size === 'sm' ? 'w-1 h-1' : size === 'md' ? 'w-2 h-2' : size === 'lg' ? 'w-3 h-3' : 'w-4 h-4',
                  colorClasses[color].replace('text-', 'bg-'),
                  'animate-pulse'
                )}
                style={{
                  animationDelay: `${i * 0.2}s`,
                  animationDuration: '1.4s',
                }}
              />
            ))}
          </div>
        );
      
      case 'pulse':
        return (
          <div
            className={clsx(
              'rounded-full animate-pulse',
              sizeClasses[size],
              colorClasses[color].replace('text-', 'bg-')
            )}
          />
        );
      
      case 'bars':
        return (
          <div className="flex items-end space-x-1">
            {[0, 1, 2, 3].map((i) => (
              <div
                key={`item-${i}`}
                className={clsx(
                  'rounded-sm',
                  size === 'sm' ? 'w-1' : size === 'md' ? 'w-1.5' : size === 'lg' ? 'w-2' : 'w-3',
                  colorClasses[color].replace('text-', 'bg-'),
                  'animate-pulse'
                )}
                style={{
                  height: size === 'sm' ? '8px' : size === 'md' ? '12px' : size === 'lg' ? '16px' : '24px',
                  animationDelay: `${i * 0.1}s`,
                  animationDuration: '1.2s',
                }}
              />
            ))}
          </div>
        );
      
      case 'ring':
        return (
          <div
            className={clsx(
              'border-2 border-transparent rounded-full animate-spin',
              sizeClasses[size],
              `border-t-${color === 'primary' ? 'primary' : color === 'accent' ? 'accent' : color === 'white' ? 'white' : 'gray'}-500`
            )}
            style={{
              borderTopColor: color === 'primary' ? '#3b82f6' : 
                            color === 'accent' ? '#d946ef' : 
                            color === 'white' ? '#ffffff' : '#6b7280'
            }}
          />
        );
      
      default:
        return null;
    }
  };

  const content = (
    <div 
      className={clsx(
        'flex flex-col items-center justify-center space-y-2',
        fullScreen && 'min-h-screen',
        className
      )}
      role="status"
      aria-live="polite"
      aria-label={text || 'Loading'}
    >
      {renderSpinner()}
      {text && (
        <span 
          className={clsx(
            'font-medium',
            textSizeClasses[size],
            colorClasses[color]
          )}
        >
          {text}
        </span>
      )}
      <span className="sr-only">
        {text || 'Loading, please wait...'}
      </span>
    </div>
  );

  if (overlay) {
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-modal flex items-center justify-center">
        {content}
      </div>
    );
  }

  return content;
};

// 预设组件
const PageLoader: React.FC<{ text?: string }> = ({ text = 'Loading page...' }) => (
  <LoadingIndicator
    size="lg"
    variant="spinner"
    color="primary"
    text={text}
    fullScreen
  />
);

const ButtonLoader: React.FC<{ size?: 'sm' | 'md' }> = ({ size = 'sm' }) => (
  <LoadingIndicator
    size={size}
    variant="spinner"
    color="white"
  />
);

const CardLoader: React.FC<{ text?: string }> = ({ text }) => (
  <LoadingIndicator
    size="md"
    variant="dots"
    color="primary"
    text={text}
    className="py-8"
  />
);

const OverlayLoader: React.FC<{ text?: string }> = ({ text = 'Processing...' }) => (
  <LoadingIndicator
    size="lg"
    variant="spinner"
    color="white"
    text={text}
    overlay
  />
);

// 进度条组件
interface ProgressBarProps {
  progress: number; // 0-100
  size?: 'sm' | 'md' | 'lg';
  color?: 'primary' | 'accent' | 'success' | 'warning' | 'error';
  showPercentage?: boolean;
  className?: string;
  animated?: boolean;
}

const ProgressBar: React.FC<ProgressBarProps> = ({
  progress,
  size = 'md',
  color = 'primary',
  showPercentage = false,
  className,
  animated = true,
}) => {
  const heightClasses = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
  };

  const colorClasses = {
    primary: 'bg-primary-500',
    accent: 'bg-accent-500',
    success: 'bg-success-500',
    warning: 'bg-warning-500',
    error: 'bg-error-500',
  };

  const clampedProgress = Math.min(100, Math.max(0, progress));

  return (
    <div className={clsx('w-full', className)}>
      <div 
        className={clsx(
          'w-full bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden',
          heightClasses[size]
        )}
        role="progressbar"
        aria-valuenow={clampedProgress}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Progress: ${clampedProgress}%`}
      >
        <div
          className={clsx(
            'h-full rounded-full transition-all duration-300 ease-out',
            colorClasses[color],
            animated && 'transition-transform'
          )}
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
      {showPercentage && (
        <div className="mt-1 text-sm text-gray-600 dark:text-gray-400 text-center">
          {Math.round(clampedProgress)}%
        </div>
      )}
    </div>
  );
};

export { 
  LoadingIndicator, 
  PageLoader, 
  ButtonLoader, 
  CardLoader, 
  OverlayLoader,
  ProgressBar 
};
export default LoadingIndicator;