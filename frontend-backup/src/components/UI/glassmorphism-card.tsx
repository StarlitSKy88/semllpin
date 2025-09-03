import React from 'react';
import { cn } from '@/lib/utils';

interface GlassmorphismCardProps {
  children: React.ReactNode;
  className?: string;
  blur?: 'sm' | 'md' | 'lg' | 'xl';
  opacity?: number;
  border?: boolean;
}

const blurClasses = {
  sm: 'backdrop-blur-sm',
  md: 'backdrop-blur-md',
  lg: 'backdrop-blur-lg',
  xl: 'backdrop-blur-xl'
};

export const GlassmorphismCard: React.FC<GlassmorphismCardProps> = ({
  children,
  className,
  blur = 'md',
  opacity = 0.1,
  border = true
}) => {
  return (
    <div
      className={cn(
        'relative',
        blurClasses[blur],
        border && 'border border-white/20',
        'rounded-xl shadow-xl',
        className
      )}
      style={{
        background: `rgba(255, 255, 255, ${opacity})`,
        boxShadow: '0 8px 32px 0 rgba(31, 38, 135, 0.37)'
      }}
    >
      {children}
    </div>
  );
};

export default GlassmorphismCard;