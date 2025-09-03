import React from 'react';
import { cn } from '@/lib/utils';

interface FlatRemixButtonProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
  fullWidth?: boolean;
}

const variantClasses = {
  primary: 'bg-blue-500 hover:bg-blue-600 text-white shadow-blue-500/25',
  secondary: 'bg-gray-500 hover:bg-gray-600 text-white shadow-gray-500/25',
  success: 'bg-green-500 hover:bg-green-600 text-white shadow-green-500/25',
  warning: 'bg-yellow-500 hover:bg-yellow-600 text-white shadow-yellow-500/25',
  danger: 'bg-red-500 hover:bg-red-600 text-white shadow-red-500/25',
  outline: 'bg-transparent border-2 border-current hover:bg-current/10 shadow-none'
};

const sizeClasses = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-base',
  lg: 'px-6 py-3 text-lg'
};

export const FlatRemixButton: React.FC<FlatRemixButtonProps> = ({
  children,
  className,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled = false,
  type = 'button',
  fullWidth = false
}) => {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'relative font-medium rounded-lg',
        'transition-all duration-200 ease-in-out',
        'shadow-lg hover:shadow-xl',
        'hover:-translate-y-0.5',
        'active:translate-y-0 active:shadow-md',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-lg',
        'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500',
        variantClasses[variant],
        sizeClasses[size],
        fullWidth && 'w-full',
        className
      )}
    >
      <div className="relative z-10 flex items-center justify-center gap-2">
        {children}
      </div>
    </button>
  );
};

export default FlatRemixButton;