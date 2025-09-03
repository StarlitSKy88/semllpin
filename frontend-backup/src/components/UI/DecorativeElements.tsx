import React from 'react';
import { motion } from 'framer-motion';
import { 
  PomegranateIcon, 
  FlowerIcon, 
  LeafIcon, 
  PetalIcon, 
  OrientalPattern, 
  DecorativeBorder 
} from '../../assets/icons';

interface DecorativeElementsProps {
  variant?: 'floating' | 'border' | 'background' | 'accent';
  position?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center';
  className?: string;
  animate?: boolean;
}

export const DecorativeElements: React.FC<DecorativeElementsProps> = ({
  variant = 'floating',
  position = 'top-right',
  className = '',
  animate = true
}) => {
  const getPositionClasses = () => {
    const baseClasses = 'absolute pointer-events-none';
    switch (position) {
      case 'top-left':
        return `${baseClasses} top-4 left-4`;
      case 'top-right':
        return `${baseClasses} top-4 right-4`;
      case 'bottom-left':
        return `${baseClasses} bottom-4 left-4`;
      case 'bottom-right':
        return `${baseClasses} bottom-4 right-4`;
      case 'center':
        return `${baseClasses} top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2`;
      default:
        return `${baseClasses} top-4 right-4`;
    }
  };

  const floatingAnimation = {
    y: [0, -10, 0],
    rotate: [0, 5, -5, 0],
    transition: {
      duration: 4,
      repeat: Infinity,
      ease: "easeInOut"
    }
  };

  const pulseAnimation = {
    scale: [1, 1.1, 1],
    opacity: [0.6, 0.8, 0.6],
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: "easeInOut"
    }
  };

  const renderFloatingElements = () => (
    <div className={`${getPositionClasses()} ${className}`}>
      <motion.div
        animate={animate ? floatingAnimation : {}}
        className="relative"
      >
        <PomegranateIcon 
          size={32} 
          className="text-pomegranate-600 opacity-60" 
        />
      </motion.div>
      
      <motion.div
        animate={animate ? { ...floatingAnimation, transition: { ...floatingAnimation.transition, delay: 1 } } : {}}
        className="absolute -top-2 -right-2"
      >
        <FlowerIcon 
          size={20} 
          className="text-pomegranate-400 opacity-50" 
        />
      </motion.div>
      
      <motion.div
        animate={animate ? { ...floatingAnimation, transition: { ...floatingAnimation.transition, delay: 2 } } : {}}
        className="absolute -bottom-1 -left-1"
      >
        <LeafIcon 
          size={16} 
          className="text-pomegranate-500 opacity-40" 
        />
      </motion.div>
    </div>
  );

  const renderBorderElements = () => (
    <div className={`${className}`}>
      <DecorativeBorder 
        width={300}
        height={20}
        className="text-pomegranate-500 opacity-30"
        position="top"
      />
    </div>
  );

  const renderBackgroundElements = () => (
    <div className={`fixed inset-0 pointer-events-none overflow-hidden ${className}`}>
      {/* Top left pattern */}
      <motion.div
        animate={animate ? pulseAnimation : {}}
        className="absolute top-10 left-10"
      >
        <OrientalPattern 
          size={80} 
          className="text-pomegranate-200 opacity-20" 
        />
      </motion.div>
      
      {/* Top right pattern */}
      <motion.div
        animate={animate ? { ...pulseAnimation, transition: { ...pulseAnimation.transition, delay: 1.5 } } : {}}
        className="absolute top-20 right-20"
      >
        <PomegranateIcon 
          size={60} 
          className="text-pomegranate-300 opacity-15" 
        />
      </motion.div>
      
      {/* Bottom left pattern */}
      <motion.div
        animate={animate ? { ...pulseAnimation, transition: { ...pulseAnimation.transition, delay: 3 } } : {}}
        className="absolute bottom-20 left-20"
      >
        <FlowerIcon 
          size={70} 
          className="text-pomegranate-200 opacity-10" 
        />
      </motion.div>
      
      {/* Bottom right pattern */}
      <motion.div
        animate={animate ? { ...pulseAnimation, transition: { ...pulseAnimation.transition, delay: 4.5 } } : {}}
        className="absolute bottom-10 right-10"
      >
        <OrientalPattern 
          size={90} 
          className="text-pomegranate-100 opacity-25" 
        />
      </motion.div>
      
      {/* Scattered petals */}
      <motion.div
        animate={animate ? {
          x: [0, 20, -10, 0],
          y: [0, -15, 10, 0],
          rotate: [0, 180, 360],
          transition: { duration: 8, repeat: Infinity, ease: "linear" }
        } : {}}
        className="absolute top-1/3 left-1/4"
      >
        <PetalIcon 
          size={24} 
          className="text-pomegranate-300 opacity-20" 
        />
      </motion.div>
      
      <motion.div
        animate={animate ? {
          x: [0, -25, 15, 0],
          y: [0, 20, -5, 0],
          rotate: [0, -180, -360],
          transition: { duration: 10, repeat: Infinity, ease: "linear" }
        } : {}}
        className="absolute top-2/3 right-1/3"
      >
        <LeafIcon 
          size={28} 
          className="text-pomegranate-400 opacity-15" 
        />
      </motion.div>
    </div>
  );

  const renderAccentElements = () => (
    <div className={`${getPositionClasses()} ${className}`}>
      <motion.div
        animate={animate ? {
          rotate: [0, 360],
          transition: { duration: 20, repeat: Infinity, ease: "linear" }
        } : {}}
        className="relative"
      >
        <OrientalPattern 
          size={48} 
          className="text-pomegranate-500 opacity-40" 
        />
      </motion.div>
    </div>
  );

  switch (variant) {
    case 'floating':
      return renderFloatingElements();
    case 'border':
      return renderBorderElements();
    case 'background':
      return renderBackgroundElements();
    case 'accent':
      return renderAccentElements();
    default:
      return renderFloatingElements();
  }
};

export default DecorativeElements;