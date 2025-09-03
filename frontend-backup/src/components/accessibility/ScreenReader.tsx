import React, { useEffect, useRef, useState, useCallback } from 'react';
import { ScreenReaderContext } from '../../contexts/ScreenReaderContext';

interface ScreenReaderAnnouncementProps {
  message: string;
  priority?: 'polite' | 'assertive';
  delay?: number;
}

/**
 * 屏幕阅读器公告组件
 * 用于向屏幕阅读器用户提供实时信息
 */
export const ScreenReaderAnnouncement: React.FC<ScreenReaderAnnouncementProps> = ({
  message,
  priority = 'polite',
  delay = 0
}) => {
  const [announcement, setAnnouncement] = useState('');
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (message) {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      
      timeoutRef.current = setTimeout(() => {
        setAnnouncement(message);
      }, delay);
    } else {
      setAnnouncement('');
    }

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [message, delay]);

  return (
    <div
      aria-live={priority}
      aria-atomic={true}
      className="sr-only"
      role="status"
    >
      {announcement}
    </div>
  );
};

/**
 * 屏幕阅读器专用内容组件
 * 提供仅对屏幕阅读器可见的内容
 */
export const ScreenReaderOnly: React.FC<{
  children: React.ReactNode;
  as?: React.ElementType;
}> = ({ children, as: Component = 'span' }) => {
  return (
    <Component className="sr-only">
      {children}
    </Component>
  );
};

/**
 * 页面标题管理组件
 * 自动更新页面标题并通知屏幕阅读器
 */
export const PageTitle: React.FC<{
  title: string;
  announce?: boolean;
}> = ({ title, announce = true }) => {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = title;

    return () => {
      document.title = previousTitle;
    };
  }, [title]);

  if (!announce) return null;

  return (
    <ScreenReaderAnnouncement 
      message={`页面已切换到: ${title}`}
      priority="polite"
    />
  );
};

/**
 * 加载状态公告组件
 */
export const LoadingAnnouncement: React.FC<{
  isLoading: boolean;
  loadingMessage?: string;
  completeMessage?: string;
}> = ({ 
  isLoading, 
  loadingMessage = '正在加载内容',
  completeMessage = '内容加载完成'
}) => {
  const [message, setMessage] = useState('');
  const previousLoadingState = useRef(isLoading);

  useEffect(() => {
    if (isLoading && !previousLoadingState.current) {
      setMessage(loadingMessage);
    } else if (!isLoading && previousLoadingState.current) {
      setMessage(completeMessage);
    }
    
    previousLoadingState.current = isLoading;
  }, [isLoading, loadingMessage, completeMessage]);

  return (
    <ScreenReaderAnnouncement 
      message={message}
      priority="polite"
    />
  );
};

/**
 * 表单验证公告组件
 */
export const FormValidationAnnouncement: React.FC<{
  errors: string[];
  fieldName?: string;
}> = ({ errors, fieldName }) => {
  const [announcement, setAnnouncement] = useState('');

  useEffect(() => {
    if (errors.length > 0) {
      const errorMessage = fieldName 
        ? `${fieldName}字段有错误: ${errors.join(', ')}`
        : `表单验证错误: ${errors.join(', ')}`;
      setAnnouncement(errorMessage);
    } else {
      setAnnouncement('');
    }
  }, [errors, fieldName]);

  return (
    <ScreenReaderAnnouncement 
      message={announcement}
      priority="assertive"
    />
  );
};

/**
 * 导航状态公告组件
 */
export const NavigationAnnouncement: React.FC<{
  currentPage: string;
  totalPages?: number;
  currentPosition?: number;
}> = ({ currentPage, totalPages, currentPosition }) => {
  const [announcement, setAnnouncement] = useState('');
  const previousPage = useRef(currentPage);

  useEffect(() => {
    if (currentPage !== previousPage.current) {
      let message = `导航到 ${currentPage}`;
      
      if (totalPages && currentPosition) {
        message += `, 第 ${currentPosition} 页，共 ${totalPages} 页`;
      }
      
      setAnnouncement(message);
      previousPage.current = currentPage;
    }
  }, [currentPage, totalPages, currentPosition]);

  return (
    <ScreenReaderAnnouncement 
      message={announcement}
      priority="polite"
    />
  );
};

/**
 * 数据更新公告组件
 */
export const DataUpdateAnnouncement: React.FC<{
  count: number;
  itemType: string;
  action?: 'added' | 'updated' | 'deleted' | 'loaded';
}> = ({ count, itemType, action = 'loaded' }) => {
  const [announcement, setAnnouncement] = useState('');
  const previousCount = useRef(count);

  useEffect(() => {
    if (count !== previousCount.current) {
      const actionText = {
        added: '已添加',
        updated: '已更新', 
        deleted: '已删除',
        loaded: '已加载'
      }[action];
      
      const message = `${actionText} ${count} 个${itemType}`;
      setAnnouncement(message);
      previousCount.current = count;
    }
  }, [count, itemType, action]);

  return (
    <ScreenReaderAnnouncement 
      message={announcement}
      priority="polite"
    />
  );
};

/**
 * 屏幕阅读器上下文提供者
 */

export const ScreenReaderProvider: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  const [announcements, setAnnouncements] = useState<{
    id: string;
    message: string;
    priority: 'polite' | 'assertive';
  }[]>([]);

  const announce = useCallback((message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    setAnnouncements(prev => [...prev, { id, message, priority }]);
    
    // 清除公告
    const timeoutId = setTimeout(() => {
      setAnnouncements(prev => prev.filter(a => a.id !== id));
    }, 1000);
    
    return () => clearTimeout(timeoutId);
  }, []);

  const announceNavigation = (page: string) => {
    announce(`导航到 ${page}`);
  };

  const announceLoading = (isLoading: boolean) => {
    announce(isLoading ? '正在加载' : '加载完成');
  };

  const announceError = (error: string) => {
    announce(`错误: ${error}`, 'assertive');
  };

  const announceSuccess = (message: string) => {
    announce(`成功: ${message}`);
  };

  const contextValue = {
    announce,
    announceNavigation,
    announceLoading,
    announceError,
    announceSuccess
  };

  return (
    <ScreenReaderContext.Provider value={contextValue}>
      {children}
      
      {/* 渲染所有公告 */}
      {announcements.map(announcement => (
        <ScreenReaderAnnouncement
          key={announcement.id}
          message={announcement.message}
          priority={announcement.priority}
        />
      ))}
      
      {/* 全局屏幕阅读器样式 */}
      <style>{`
        .sr-only {
          position: absolute !important;
          width: 1px !important;
          height: 1px !important;
          padding: 0 !important;
          margin: -1px !important;
          overflow: hidden !important;
          clip: rect(0, 0, 0, 0) !important;
          white-space: nowrap !important;
          border: 0 !important;
        }
        
        .sr-only-focusable:focus {
          position: static !important;
          width: auto !important;
          height: auto !important;
          padding: inherit !important;
          margin: inherit !important;
          overflow: visible !important;
          clip: auto !important;
          white-space: normal !important;
        }
      `}</style>
    </ScreenReaderContext.Provider>
  );
};

/**
 * 使用屏幕阅读器上下文的 Hook
 */