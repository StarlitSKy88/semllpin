import React from 'react';
import { cn } from '@/lib/utils';

interface FlatRemixCardProps {
  children: React.ReactNode;
  className?: string;
  variant?: 'default' | 'elevated' | 'outlined';
  padding?: 'none' | 'sm' | 'md' | 'lg';
  hover?: boolean;
}

const variantClasses = {
  default: 'bg-white shadow-lg',
  elevated: 'bg-white shadow-xl hover:shadow-2xl',
  outlined: 'bg-white border-2 border-gray-200 shadow-sm'
};

const paddingClasses = {
  none: '',
  sm: 'p-3',
  md: 'p-4',
  lg: 'p-6'
};

export const FlatRemixCard: React.FC<FlatRemixCardProps> = ({
  children,
  className,
  variant = 'default',
  padding = 'md',
  hover = false
}) => {
  return (
    <div
      className={cn(
        'relative rounded-xl',
        'transition-all duration-300 ease-in-out',
        hover && 'hover:-translate-y-1 hover:shadow-xl',
        variantClasses[variant],
        paddingClasses[padding],
        className
      )}
    >
      {children}
    </div>
  );
};

export default FlatRemixCard;