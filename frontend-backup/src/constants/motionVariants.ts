// 性能优化的动画变体
export const optimizedVariants = {
  // 淡入淡出动画（仅使用opacity）
  fadeIn: {
    initial: { opacity: 0 },
    animate: { opacity: 1 },
    exit: { opacity: 0 },
    transition: { duration: 0.3, ease: 'easeOut' }
  },
  
  // 滑入动画（使用transform）
  slideUp: {
    initial: { opacity: 0, transform: 'translateY(20px)' },
    animate: { opacity: 1, transform: 'translateY(0px)' },
    exit: { opacity: 0, transform: 'translateY(-20px)' },
    transition: { duration: 0.4, ease: 'easeOut' }
  },
  
  slideDown: {
    initial: { opacity: 0, transform: 'translateY(-20px)' },
    animate: { opacity: 1, transform: 'translateY(0px)' },
    exit: { opacity: 0, transform: 'translateY(20px)' },
    transition: { duration: 0.4, ease: 'easeOut' }
  },
  
  slideLeft: {
    initial: { opacity: 0, transform: 'translateX(20px)' },
    animate: { opacity: 1, transform: 'translateX(0px)' },
    exit: { opacity: 0, transform: 'translateX(-20px)' },
    transition: { duration: 0.4, ease: 'easeOut' }
  },
  
  slideRight: {
    initial: { opacity: 0, transform: 'translateX(-20px)' },
    animate: { opacity: 1, transform: 'translateX(0px)' },
    exit: { opacity: 0, transform: 'translateX(20px)' },
    transition: { duration: 0.4, ease: 'easeOut' }
  },
  
  // 缩放动画（使用transform scale）
  scaleIn: {
    initial: { opacity: 0, transform: 'scale(0.9)' },
    animate: { opacity: 1, transform: 'scale(1)' },
    exit: { opacity: 0, transform: 'scale(0.9)' },
    transition: { duration: 0.3, ease: 'easeOut' }
  },
  
  // 弹性动画
  bounce: {
    initial: { opacity: 0, transform: 'scale(0.3)' },
    animate: { 
      opacity: 1, 
      transform: 'scale(1)',
      transition: {
        type: 'spring',
        stiffness: 260,
        damping: 20
      }
    },
    exit: { opacity: 0, transform: 'scale(0.3)' }
  },
  
  // 旋转淡入
  rotateIn: {
    initial: { opacity: 0, transform: 'rotate(-10deg) scale(0.9)' },
    animate: { opacity: 1, transform: 'rotate(0deg) scale(1)' },
    exit: { opacity: 0, transform: 'rotate(10deg) scale(0.9)' },
    transition: { duration: 0.5, ease: 'easeOut' }
  }
};

// 列表动画变体
export const listVariants = {
  container: {
    initial: {},
    animate: {
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.1
      }
    },
    exit: {
      transition: {
        staggerChildren: 0.05,
        staggerDirection: -1
      }
    }
  },
  item: {
    initial: { opacity: 0, transform: 'translateY(20px)' },
    animate: { opacity: 1, transform: 'translateY(0px)' },
    exit: { opacity: 0, transform: 'translateY(-20px)' },
    transition: { duration: 0.3, ease: 'easeOut' }
  }
};