/**
 * 现代化模态框组件
 * 基于设计令牌系统的统一模态框实现
 */

import React, { useEffect, useRef, forwardRef, useId, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useModalAccessibility } from '../../hooks/useAccessibility';
import { useKeyboardNavigation } from '../../hooks/useAccessibility';
import Button from './Button';

export interface ModalProps extends AccessibilityProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full';
  centered?: boolean;
  closable?: boolean;
  maskClosable?: boolean;
  keyboard?: boolean;
  destroyOnClose?: boolean;
  className?: string;
  overlayClassName?: string;
  bodyClassName?: string;
  headerClassName?: string;
  footerClassName?: string;
  zIndex?: number;
  loading?: boolean;
  onAfterOpen?: () => void;
  onAfterClose?: () => void;
}

const Modal = forwardRef<HTMLDivElement, ModalProps>((
  {
    open,
    onClose,
    title,
    children,
    footer,
    size = 'md',
    centered = true,
    closable = true,
    maskClosable = true,
    keyboard = true,
    destroyOnClose = false,
    className,
    overlayClassName,
    bodyClassName,
    headerClassName,
    footerClassName,
    zIndex = 1000,
    loading = false,
    onAfterOpen,
    onAfterClose,
    // ..._accessibilityProps
  }
) => {
  useTheme();
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);
  const modalId = useId();
  
  // 初始化无障碍功能钩子
  const { handleKeyDown } = useKeyboardNavigation([]);
  
  // 使用无障碍功能钩子
  const {
    announce
  } = useModalAccessibility(open);

  // 模拟props对象
  const overlayProps = {};
  const modalProps = {};
  const titleProps = {};
  const closeButtonProps = {};
  const contentProps = {};

  // 尺寸样式
  const sizeStyles = {
    xs: 'max-w-xs',
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
    '2xl': 'max-w-2xl',
    full: 'max-w-full mx-4',
  };

  // 处理键盘事件
  useEffect(() => {
    if (!open || !keyboard) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, keyboard, onClose]);

  // 处理焦点管理
  useEffect(() => {
    if (open) {
      previousActiveElement.current = document.activeElement as HTMLElement;
      
      // 延迟聚焦以确保模态框已渲染
      const timer = setTimeout(() => {
        if (modalRef.current) {
          const focusableElement = modalRef.current.querySelector(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          ) as HTMLElement;
          
          if (focusableElement) {
            focusableElement.focus();
          } else {
            modalRef.current.focus();
          }
        }
        
        // 语音播报模态框已打开
        const modalTitle = title ? (typeof title === 'string' ? title : '模态框') : '模态框';
        announce(`${modalTitle}已打开`);
        
        onAfterOpen?.();
      }, 100);

      return () => clearTimeout(timer);
    } else {
      // 恢复之前的焦点
      if (previousActiveElement.current) {
        previousActiveElement.current.focus();
      }
      onAfterClose?.();
    }
  }, [open, onAfterOpen, onAfterClose, title, announce]);

  // 处理遮罩点击
  const handleMaskClick = useCallback((event: React.MouseEvent) => {
    if (maskClosable && event.target === event.currentTarget) {
      announce('模态框已关闭');
      onClose();
    }
  }, [maskClosable, onClose, announce]);

  // 阻止模态框内容区域的点击事件冒泡
  const handleContentClick = useCallback((event: React.MouseEvent) => {
    event.stopPropagation();
  }, []);

  // 处理键盘事件
  const handleKeyDownEvent = useCallback((event: React.KeyboardEvent) => {
    handleKeyDown(event.nativeEvent);
    
    if (event.key === 'Escape' && keyboard) {
      announce('模态框已关闭');
      onClose();
    }
  }, [handleKeyDown, keyboard, onClose, announce]);

  // 处理关闭按钮点击
  const handleCloseClick = useCallback(() => {
    announce('模态框已关闭');
    onClose();
  }, [onClose, announce]);

  // 如果未打开且设置了销毁，则不渲染
  if (!open && destroyOnClose) {
    return null;
  }

  const modalContent = (
    <div
      className={cn(
        'fixed inset-0 z-50 flex items-center justify-center p-4',
        centered ? 'items-center' : 'items-start pt-16',
        overlayClassName
      )}
      style={{ zIndex }}
      onClick={handleMaskClick}
      aria-hidden={!open}
      {...overlayProps}
    >
      {/* 遮罩层 */}
      <div
        className={cn(
          'absolute inset-0 bg-gradient-to-br from-black/60 via-pomegranate-900/40 to-black/60 backdrop-blur-sm transition-opacity duration-300',
          'before:absolute before:inset-0 before:bg-pattern-pomegranate before:opacity-10',
          open ? 'opacity-100 animate-fade-in' : 'opacity-0 animate-fade-out'
        )}
        aria-hidden="true"
      />

      {/* 模态框内容 */}
      <div
        ref={modalRef}
        id={modalId}
        className={cn(
          'relative w-full bg-gradient-to-br from-white via-floral-50 to-white dark:from-gray-800 dark:via-pomegranate-900/20 dark:to-gray-800',
          'rounded-lg shadow-pomegranate border border-pomegranate-200/30 dark:border-pomegranate-700/50',
          'transform transition-all duration-500 ease-out',
          'max-h-[90vh] flex flex-col backdrop-blur-sm',
          'before:absolute before:inset-0 before:bg-pattern-floral before:opacity-5 before:rounded-lg',
          open ? 'opacity-100 scale-100 translate-y-0 animate-pomegranate-bloom' : 'opacity-0 scale-95 translate-y-4',
          sizeStyles[size],
          className
        )}
        onClick={handleContentClick}
        onKeyDown={handleKeyDownEvent}
        {...modalProps}
      >
        {/* 加载覆盖层 */}
        {loading && (
          <div className="absolute inset-0 bg-white/80 dark:bg-gray-800/80 flex items-center justify-center z-10 rounded-lg backdrop-blur-sm">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-pomegranate-300 border-t-pomegranate-600 shadow-glow" />
          </div>
        )}

        {/* 头部 */}
        {(title || closable) && (
          <div
            className={cn(
              'flex items-center justify-between p-6 border-b border-pomegranate-200/40 dark:border-pomegranate-700/60',
              'bg-gradient-to-r from-floral-50/50 to-transparent dark:from-pomegranate-900/20 dark:to-transparent',
              'backdrop-blur-sm',
              headerClassName
            )}
          >
            {title && (
              <h2
                {...titleProps}
                className="text-xl font-semibold text-pomegranate-800 dark:text-pomegranate-100 drop-shadow-sm"
              >
                {title}
              </h2>
            )}
            
            {closable && (
              <Button
                variant="ghost"
                size="sm"
                icon={<X aria-hidden="true" />}
                onClick={handleCloseClick}
                className="ml-4 text-pomegranate-400 hover:text-pomegranate-600 dark:hover:text-pomegranate-300 transition-colors duration-200"
                {...closeButtonProps}
              />
            )}
          </div>
        )}

        {/* 内容区域 */}
        <div
          {...contentProps}
          className={cn(
            'flex-1 overflow-y-auto p-6',
            'text-gray-700 dark:text-gray-300',
            'scrollbar-thin scrollbar-track-floral-100 scrollbar-thumb-pomegranate-300 dark:scrollbar-track-pomegranate-900 dark:scrollbar-thumb-pomegranate-600',
            bodyClassName
          )}
        >
          {children}
        </div>

        {/* 底部 */}
        {footer && (
          <div
            className={cn(
              'flex items-center justify-end gap-3 p-6 border-t border-pomegranate-200/40 dark:border-pomegranate-700/60',
              'bg-gradient-to-r from-transparent to-floral-50/50 dark:from-transparent dark:to-pomegranate-900/20',
              'backdrop-blur-sm',
              footerClassName
            )}
          >
            {footer}
          </div>
        )}
      </div>
    </div>
  );

  // 使用 Portal 渲染到 body
  return createPortal(modalContent, document.body);
});

Modal.displayName = 'Modal';

// 确认对话框组件
export interface ConfirmModalProps {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  title?: React.ReactNode;
  content?: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  confirmButtonProps?: any;
  cancelButtonProps?: any;
  type?: 'info' | 'warning' | 'error' | 'success';
  loading?: boolean;
}

export const ConfirmModal: React.FC<ConfirmModalProps> = ({
  open,
  onConfirm,
  onCancel,
  title = '确认操作',
  content = '您确定要执行此操作吗？',
  confirmText = '确认',
  cancelText = '取消',
  confirmButtonProps = {},
  cancelButtonProps = {},
  type = 'info',
  loading = false,
}) => {
  const typeStyles = {
    info: {
      confirmVariant: 'primary' as const,
      icon: '🌸',
    },
    warning: {
      confirmVariant: 'primary' as const,
      icon: '🍃',
    },
    error: {
      confirmVariant: 'danger' as const,
      icon: '🥀',
    },
    success: {
      confirmVariant: 'success' as const,
      icon: '🌺',
    },
  };

  const currentType = typeStyles[type];

  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={
        <div className="flex items-center gap-3">
          <span className="text-2xl">{currentType.icon}</span>
          {title}
        </div>
      }
      size="sm"
      loading={loading}
      footer={
        <>
          <Button
            variant="ghost"
            onClick={onCancel}
            disabled={loading}
            {...cancelButtonProps}
          >
            {cancelText}
          </Button>
          <Button
            variant={currentType.confirmVariant}
            onClick={onConfirm}
            loading={loading}
            {...confirmButtonProps}
          >
            {confirmText}
          </Button>
        </>
      }
    >
      <div className="text-pomegranate-700 dark:text-pomegranate-300">
        {content}
      </div>
    </Modal>
  );
};

// 信息对话框组件
export interface InfoModalProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  content?: React.ReactNode;
  okText?: string;
  type?: 'info' | 'warning' | 'error' | 'success';
}

export const InfoModal: React.FC<InfoModalProps> = ({
  open,
  onClose,
  title = '信息',
  content,
  okText = '确定',
  type = 'info',
}) => {
  const typeStyles = {
    info: {
      variant: 'primary' as const,
      icon: '🌸',
    },
    warning: {
      variant: 'primary' as const,
      icon: '🍃',
    },
    error: {
      variant: 'danger' as const,
      icon: '🥀',
    },
    success: {
        variant: 'success' as const,
        icon: '🌺',
      },
    };

  const currentType = typeStyles[type];

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={
        <div className="flex items-center gap-3">
          <span className="text-2xl">{currentType.icon}</span>
          {title}
        </div>
      }
      size="sm"
      footer={
        <Button
          variant={currentType.variant}
          onClick={onClose}
        >
          {okText}
        </Button>
      }
    >
      <div className="text-pomegranate-700 dark:text-pomegranate-300">
        {content}
      </div>
    </Modal>
  );
};

export default Modal;