import React, { useMemo } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import type { HTMLMotionProps } from 'framer-motion';
import { optimizedVariants, listVariants } from '../constants/motionVariants';

// 性能优化的Motion组件
interface OptimizedMotionProps extends HTMLMotionProps<'div'> {
  variant?: keyof typeof optimizedVariants;
  children: React.ReactNode;
  className?: string;
  reduceMotion?: boolean;
}

export const OptimizedMotion: React.FC<OptimizedMotionProps> = ({
  variant = 'fadeIn',
  children,
  className,
  reduceMotion,
  ...motionProps
}) => {
  const shouldReduceMotion = useReducedMotion();
  const finalReduceMotion = reduceMotion ?? shouldReduceMotion;
  
  const animationProps = useMemo(() => {
    if (finalReduceMotion) {
      // 如果用户偏好减少动画，只保留基本的透明度变化
      return {
        initial: { opacity: 0 },
        animate: { opacity: 1 },
        exit: { opacity: 0 }
      };
    }
    
    const variantConfig = optimizedVariants[variant];
    const { transition: _transition, ...rest } = variantConfig as {
      transition?: Record<string, unknown>;
      [key: string]: unknown;
    };
    return rest;
  }, [variant, finalReduceMotion]);
  
  const transitionProps = useMemo(() => {
    if (finalReduceMotion) {
      return { duration: 0.1 };
    }
    
    const variantConfig = optimizedVariants[variant] as {
      transition?: Record<string, unknown>;
    };
    return variantConfig.transition || { duration: 0.3, ease: 'easeOut' };
  }, [variant, finalReduceMotion]);
  
  return (
    <motion.div
      className={className}
      {...animationProps}
      transition={transitionProps}
      {...motionProps}
      // 强制使用GPU加速
      style={{
        willChange: 'transform, opacity',
        ...motionProps.style
      }}
    >
      {children}
    </motion.div>
  );
};

// 预定义的优化动画组件
export const FadeIn: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="fadeIn" {...props} />
);

export const SlideUp: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="slideUp" {...props} />
);

export const SlideDown: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="slideDown" {...props} />
);

export const SlideLeft: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="slideLeft" {...props} />
);

export const SlideRight: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="slideRight" {...props} />
);

export const ScaleIn: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="scaleIn" {...props} />
);

export const Bounce: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="bounce" {...props} />
);

export const RotateIn: React.FC<Omit<OptimizedMotionProps, 'variant'>> = (props) => (
  <OptimizedMotion variant="rotateIn" {...props} />
);

// 列表动画组件
interface AnimatedListProps {
  children: React.ReactNode;
  className?: string;
  itemClassName?: string;
}

export const AnimatedList: React.FC<AnimatedListProps> = ({
  children,
  className,
  itemClassName
}) => {
  const shouldReduceMotion = useReducedMotion();
  
  if (shouldReduceMotion) {
    return <div className={className}>{children}</div>;
  }
  
  return (
    <motion.div
      className={className}
      variants={listVariants.container}
      initial="initial"
      animate="animate"
      exit="exit"
    >
      {React.Children.map(children, (child, index) => (
        <motion.div
          key={`item-${index}`}
          className={itemClassName}
          variants={listVariants.item}
          style={{ willChange: 'transform, opacity' }}
        >
          {child}
        </motion.div>
      ))}
    </motion.div>
  );
};

export default OptimizedMotion;