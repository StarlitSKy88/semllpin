import React from 'react';
import { cn } from '@/lib/utils';

interface GlassmorphismButtonProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'accent' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
}

const variantClasses = {
  primary: 'bg-gradient-to-r from-blue-500/20 to-purple-600/20 hover:from-blue-500/30 hover:to-purple-600/30 border-blue-400/30',
  secondary: 'bg-white/10 hover:bg-white/20 border-white/20',
  accent: 'bg-gradient-to-r from-pink-500/20 to-rose-500/20 hover:from-pink-500/30 hover:to-rose-500/30 border-pink-400/30',
  outline: 'bg-transparent hover:bg-white/10 border-white/30 hover:border-white/50'
};

const sizeClasses = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-base',
  lg: 'px-6 py-3 text-lg'
};

export const GlassmorphismButton: React.FC<GlassmorphismButtonProps> = ({
  children,
  className,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled = false,
  type = 'button'
}) => {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'relative backdrop-blur-md border rounded-lg',
        'font-medium text-white',
        'transition-all duration-300 ease-in-out',
        'hover:shadow-lg hover:scale-105',
        'active:scale-95',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100',
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      style={{
        boxShadow: '0 4px 16px 0 rgba(31, 38, 135, 0.2)'
      }}
    >
      <div className="relative z-10">
        {children}
      </div>
    </button>
  );
};

export default GlassmorphismButton;