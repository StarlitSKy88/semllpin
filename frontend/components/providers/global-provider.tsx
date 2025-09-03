'use client';

import React, { useEffect, ReactNode } from 'react';
import { useGlobalStore } from '@/lib/stores/global-store';
import { Toaster } from '@/components/ui/toaster';
import { useToast } from '@/hooks/use-toast';

interface GlobalProviderProps {
  children: ReactNode;
}

export function GlobalProvider({ children }: GlobalProviderProps) {
  const {
    notifications,
    isOnline,
    setOnlineStatus,
    setAppInitialized,
    removeNotification,
  } = useGlobalStore();
  
  const { toast } = useToast();

  // 监听网络状态
  useEffect(() => {
    const handleOnline = () => setOnlineStatus(true);
    const handleOffline = () => setOnlineStatus(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // 初始化网络状态
    setOnlineStatus(navigator.onLine);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [setOnlineStatus]);

  // 处理通知显示
  useEffect(() => {
    notifications.forEach((notification) => {
      if (!notification.read) {
        toast({
          title: notification.title,
          description: notification.message,
          variant: notification.type === 'error' ? 'destructive' : 'default',
          duration: notification.duration || 4000,
        });
        
        // 标记为已读
        setTimeout(() => {
          removeNotification(notification.id);
        }, notification.duration || 4000);
      }
    });
  }, [notifications, toast, removeNotification]);

  // 应用初始化
  useEffect(() => {
    // 执行应用初始化逻辑
    const initializeApp = async () => {
      try {
        // 这里可以添加应用启动时需要执行的逻辑
        // 比如检查认证状态、加载用户配置等
        
        setAppInitialized(true);
      } catch (error) {
        console.error('App initialization failed:', error);
      }
    };

    initializeApp();
  }, [setAppInitialized]);

  // 网络状态提示
  useEffect(() => {
    if (!isOnline) {
      toast({
        title: '网络连接断开',
        description: '请检查您的网络连接',
        variant: 'destructive',
        duration: 0, // 不自动消失
      });
    }
  }, [isOnline, toast]);

  return (
    <>
      {children}
      <Toaster />
      
      {/* 全局加载遮罩 */}
      <GlobalLoadingOverlay />
      
      {/* 全局模态框容器 */}
      <GlobalModalContainer />
      
      {/* 网络状态指示器 */}
      {!isOnline && (
        <div className="fixed top-0 left-0 right-0 bg-red-500 text-white text-center py-2 z-50">
          <span className="text-sm">网络连接已断开，请检查网络设置</span>
        </div>
      )}
    </>
  );
}

// 全局加载遮罩组件
function GlobalLoadingOverlay() {
  const { loading } = useGlobalStore();

  if (!loading.global) {
    return null;
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 flex flex-col items-center space-y-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        {loading.message && (
          <p className="text-gray-600 text-sm">{loading.message}</p>
        )}
      </div>
    </div>
  );
}

// 全局模态框容器组件
function GlobalModalContainer() {
  const { modals, closeModal } = useGlobalStore();

  if (modals.length === 0) {
    return null;
  }

  return (
    <>
      {modals.map((modal) => (
        <div
          key={modal.id}
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-40"
          onClick={(e) => {
            if (e.target === e.currentTarget && modal.maskClosable !== false) {
              closeModal(modal.id);
            }
          }}
        >
          <div className="bg-white rounded-lg max-w-md w-full mx-4 max-h-[90vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b">
              <h3 className="text-lg font-semibold">{modal.title}</h3>
              {modal.closable !== false && (
                <button
                  onClick={() => closeModal(modal.id)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              )}
            </div>
            <div className="p-4">
              {typeof modal.content === 'string' ? (
                <p>{modal.content}</p>
              ) : (
                modal.content
              )}
            </div>
          </div>
        </div>
      ))}
    </>
  );
}

// 导出 Hook 用于组件中使用全局状态
export function useGlobalLoading() {
  const { loading, setGlobalLoading, setComponentLoading } = useGlobalStore();
  
  return {
    isGlobalLoading: loading.global,
    loadingMessage: loading.message,
    componentLoading: loading.components,
    setGlobalLoading,
    setComponentLoading,
    isComponentLoading: (component: string) => loading.components[component] || false,
  };
}

export function useGlobalNotifications() {
  const {
    notifications,
    unreadCount,
    addNotification,
    removeNotification,
    markNotificationAsRead,
    markAllNotificationsAsRead,
    clearNotifications,
  } = useGlobalStore();
  
  return {
    notifications,
    unreadCount,
    addNotification,
    removeNotification,
    markNotificationAsRead,
    markAllNotificationsAsRead,
    clearNotifications,
  };
}

export function useGlobalModals() {
  const { modals, openModal, closeModal, closeAllModals } = useGlobalStore();
  
  return {
    modals,
    openModal,
    closeModal,
    closeAllModals,
  };
}

export function useGlobalTheme() {
  const {
    theme,
    setThemeMode,
    setPrimaryColor,
    setFontSize,
    toggleCompactMode,
  } = useGlobalStore();
  
  return {
    theme,
    setThemeMode,
    setPrimaryColor,
    setFontSize,
    toggleCompactMode,
  };
}

export function useGlobalLayout() {
  const {
    layout,
    toggleSidebar,
    setSidebarCollapsed,
    setHeaderVisible,
    setFooterVisible,
    setBreadcrumbVisible,
  } = useGlobalStore();
  
  return {
    layout,
    toggleSidebar,
    setSidebarCollapsed,
    setHeaderVisible,
    setFooterVisible,
    setBreadcrumbVisible,
  };
}