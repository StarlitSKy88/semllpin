import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';
import { useMobile, useMobileState, useVirtualKeyboard, MobileContext } from '../hooks/useMobile';

// 自定义 PanInfo 接口
interface PanInfo {
  offset: {
    x: number;
    y: number;
  };
  velocity: {
    x: number;
    y: number;
  };
}

// 移动端相关Hook和Context已移动到 ../hooks/useMobile.ts

// 移动端提供者组件
interface MobileProviderProps {
  children: React.ReactNode;
}

export const MobileProvider: React.FC<MobileProviderProps> = ({ children }) => {
  const mobileState = useMobileState();

  return (
    <MobileContext.Provider value={mobileState}>
      {children}
    </MobileContext.Provider>
  );
};

// 移动端导航抽屉
interface MobileDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
  title?: string;
  position?: 'left' | 'right' | 'bottom';
}

export const MobileDrawer: React.FC<MobileDrawerProps> = ({
  isOpen,
  onClose,
  children,
  title,
  position = 'left'
}) => {
  const { safeAreaInsets } = useMobile();
  const [dragOffset, setDragOffset] = useState(0);

  const getDrawerVariants = () => {
    switch (position) {
      case 'right':
        return {
          closed: { x: '100%' },
          open: { x: 0 }
        };
      case 'bottom':
        return {
          closed: { y: '100%' },
          open: { y: 0 }
        };
      default:
        return {
          closed: { x: '-100%' },
          open: { x: 0 }
        };
    }
  };

  const handleDrag = (_event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    if (position === 'bottom') {
      if (info.offset.y > 0) {
        setDragOffset(info.offset.y);
      }
    } else {
      const offset = position === 'left' ? info.offset.x : -info.offset.x;
      if (offset < 0) {
        setDragOffset(Math.abs(offset));
      }
    }
  };

  const handleDragEnd = (_event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    const threshold = 100;
    const velocity = position === 'bottom' ? info.velocity.y : 
                    position === 'left' ? info.velocity.x : -info.velocity.x;
    
    if (dragOffset > threshold || velocity > 500) {
      onClose();
    }
    setDragOffset(0);
  };

  // 动态样式对象
  const dynamicStyles = {
    transform: position === 'bottom' ? `translateY(${dragOffset}px)` :
              position === 'left' ? `translateX(-${dragOffset}px)` :
              `translateX(${dragOffset}px)`,
    paddingTop: position !== 'bottom' ? safeAreaInsets.top : 0,
    paddingBottom: safeAreaInsets.bottom,
    paddingLeft: position === 'left' ? safeAreaInsets.left : 0,
    paddingRight: position === 'right' ? safeAreaInsets.right : 0
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* 背景遮罩 */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black bg-opacity-50 z-40"
          />
          
          {/* 抽屉内容 */}
          <motion.div
            initial="closed"
            animate="open"
            exit="closed"
            variants={getDrawerVariants()}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            drag={position === 'bottom' ? 'y' : 'x'}
            dragConstraints={position === 'bottom' ? { top: 0 } : 
                           position === 'left' ? { right: 0 } : { left: 0 }}
            dragElastic={0.2}
            onDrag={handleDrag}
            onDragEnd={handleDragEnd}
            className={`
              fixed z-50 bg-white shadow-xl flex flex-col
              ${position === 'bottom' 
                ? 'bottom-0 left-0 right-0 rounded-t-2xl max-h-[80vh]' 
                : position === 'right'
                ? 'top-0 right-0 bottom-0 w-80 max-w-[85vw]'
                : 'top-0 left-0 bottom-0 w-80 max-w-[85vw]'
              }
            `}
            style={dynamicStyles}
          >
            {/* 拖拽指示器 */}
            {position === 'bottom' && (
              <div className="flex justify-center py-2">
                <div className="w-12 h-1 bg-gray-300 rounded-full" />
              </div>
            )}
            
            {/* 标题栏 */}
            {title && (
              <div className="flex items-center justify-between p-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
                <button
                  onClick={onClose}
                  className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
                  aria-label="关闭"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            )}
            
            {/* 内容区域 */}
            <div className="flex-1 overflow-y-auto">
              {children}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

// 移动端底部操作栏
interface MobileActionBarProps {
  actions: Array<{
    icon: React.ReactNode;
    label: string;
    onClick: () => void;
    primary?: boolean;
    disabled?: boolean;
  }>;
  className?: string;
}

export const MobileActionBar: React.FC<MobileActionBarProps> = ({
  actions,
  className = ''
}) => {
  const { safeAreaInsets } = useMobile();

  return (
    <div 
      className={`
        fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 z-30
        ${className}
      `}
      style={{ paddingBottom: safeAreaInsets.bottom }}
    >
      <div className="flex items-center justify-around py-3 px-4">
        {actions.map((action, index) => (
          <motion.button
            key={`item-${index}`}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={action.onClick}
            disabled={action.disabled}
            className={`
              flex flex-col items-center space-y-1 px-3 py-2 rounded-lg
              transition-all duration-200
              disabled:opacity-50 disabled:cursor-not-allowed
              ${
                action.primary
                  ? 'bg-purple-600 text-white'
                  : 'text-gray-600 hover:text-purple-600 hover:bg-purple-50'
              }
            `}
          >
            <div className="w-6 h-6">{action.icon}</div>
            <span className="text-xs font-medium">{action.label}</span>
          </motion.button>
        ))}
      </div>
    </div>
  );
};

// 移动端滑动操作
interface SwipeActionProps {
  children: React.ReactNode;
  leftActions?: Array<{
    icon: React.ReactNode;
    label: string;
    onClick: () => void;
    color?: 'red' | 'green' | 'blue' | 'yellow';
  }>;
  rightActions?: Array<{
    icon: React.ReactNode;
    label: string;
    onClick: () => void;
    color?: 'red' | 'green' | 'blue' | 'yellow';
  }>;
  threshold?: number;
}

export const SwipeAction: React.FC<SwipeActionProps> = ({
  children,
  leftActions = [],
  rightActions = [],
  threshold = 80
}) => {
  const [dragOffset, setDragOffset] = useState(0);
  const [isRevealed, setIsRevealed] = useState<'left' | 'right' | null>(null);

  const getActionColor = (color: string = 'blue') => {
    const colors = {
      red: 'bg-red-500 text-white',
      green: 'bg-green-500 text-white',
      blue: 'bg-blue-500 text-white',
      yellow: 'bg-yellow-500 text-white'
    };
    return colors[color as keyof typeof colors] || colors.blue;
  };

  const handleDrag = (_event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    setDragOffset(info.offset.x);
  };

  const handleDragEnd = (_event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    const offset = info.offset.x;
    const velocity = info.velocity.x;

    if (Math.abs(offset) > threshold || Math.abs(velocity) > 500) {
      if (offset > 0 && leftActions.length > 0) {
        setIsRevealed('left');
        setDragOffset(leftActions.length * 80);
      } else if (offset < 0 && rightActions.length > 0) {
        setIsRevealed('right');
        setDragOffset(-rightActions.length * 80);
      } else {
        setIsRevealed(null);
        setDragOffset(0);
      }
    } else {
      setIsRevealed(null);
      setDragOffset(0);
    }
  };

  const executeAction = (action: { onClick: () => void }) => {
    action.onClick();
    setIsRevealed(null);
    setDragOffset(0);
  };

  return (
    <div className="relative overflow-hidden">
      {/* 左侧操作 */}
      {leftActions.length > 0 && (
        <div className="absolute left-0 top-0 bottom-0 flex">
          {leftActions.map((action, index) => (
            <motion.button
              key={`item-${index}`}
              onClick={() => executeAction(action)}
              className={`
                w-20 flex flex-col items-center justify-center
                ${getActionColor(action.color)}
              `}
              initial={{ x: -80 }}
              animate={{ x: isRevealed === 'left' ? 0 : -80 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            >
              <div className="w-6 h-6 mb-1">{action.icon}</div>
              <span className="text-xs">{action.label}</span>
            </motion.button>
          ))}
        </div>
      )}

      {/* 右侧操作 */}
      {rightActions.length > 0 && (
        <div className="absolute right-0 top-0 bottom-0 flex">
          {rightActions.map((action, index) => (
            <motion.button
              key={`item-${index}`}
              onClick={() => executeAction(action)}
              className={`
                w-20 flex flex-col items-center justify-center
                ${getActionColor(action.color)}
              `}
              initial={{ x: 80 }}
              animate={{ x: isRevealed === 'right' ? 0 : 80 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            >
              <div className="w-6 h-6 mb-1">{action.icon}</div>
              <span className="text-xs">{action.label}</span>
            </motion.button>
          ))}
        </div>
      )}

      {/* 主内容 */}
      <motion.div
        drag="x"
        dragConstraints={{ left: -rightActions.length * 80, right: leftActions.length * 80 }}
        dragElastic={0.2}
        onDrag={handleDrag}
        onDragEnd={handleDragEnd}
        animate={{ x: dragOffset }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        className="bg-white"
      >
        {children}
      </motion.div>
    </div>
  );
};

// 移动端触摸反馈
interface TouchFeedbackProps {
  children: React.ReactNode;
  onTap?: () => void;
  onLongPress?: () => void;
  haptic?: boolean;
  className?: string;
}

export const TouchFeedback: React.FC<TouchFeedbackProps> = ({
  children,
  onTap,
  onLongPress,
  haptic = false,
  className = ''
}) => {
  const [isPressed, setIsPressed] = useState(false);
  const longPressTimer = useRef<NodeJS.Timeout | null>(null);

  const triggerHaptic = () => {
    if (haptic && 'vibrate' in navigator) {
      navigator.vibrate(10);
    }
  };

  const handleTouchStart = () => {
    setIsPressed(true);
    triggerHaptic();
    
    if (onLongPress) {
      longPressTimer.current = setTimeout(() => {
        onLongPress();
        triggerHaptic();
      }, 500);
    }
  };

  const handleTouchEnd = () => {
    setIsPressed(false);
    
    if (longPressTimer.current) {
      clearTimeout(longPressTimer.current);
      longPressTimer.current = null;
    }
    
    if (onTap) {
      onTap();
    }
  };

  const handleTouchCancel = () => {
    setIsPressed(false);
    
    if (longPressTimer.current) {
      clearTimeout(longPressTimer.current);
      longPressTimer.current = null;
    }
  };

  return (
    <motion.div
      className={`
        select-none cursor-pointer
        ${isPressed ? 'opacity-70' : 'opacity-100'}
        ${className}
      `}
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
      onTouchCancel={handleTouchCancel}
      onMouseDown={handleTouchStart}
      onMouseUp={handleTouchEnd}
      onMouseLeave={handleTouchCancel}
      whileTap={{ scale: 0.98 }}
      transition={{ duration: 0.1 }}
    >
      {children}
    </motion.div>
  );
};

// 移动端虚拟键盘适配Hook已移动到 ../hooks/useMobile.ts

export default {
  MobileProvider,
  useMobile,
  MobileDrawer,
  MobileActionBar,
  SwipeAction,
  TouchFeedback,
  useVirtualKeyboard
};