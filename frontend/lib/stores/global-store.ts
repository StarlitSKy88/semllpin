import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

// 通知接口
interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  duration?: number; // 自动消失时间（毫秒），0表示不自动消失
  timestamp: number;
  read: boolean;
  persistent?: boolean; // 是否持久化
}

// 模态框接口
interface Modal {
  id: string;
  type: string;
  title: string;
  content?: any;
  props?: Record<string, any>;
  closable?: boolean;
  maskClosable?: boolean;
}

// 加载状态接口
interface LoadingState {
  global: boolean;
  components: Record<string, boolean>;
  message?: string;
}

// 主题配置
interface ThemeConfig {
  mode: 'light' | 'dark' | 'auto';
  primaryColor: string;
  fontSize: 'small' | 'medium' | 'large';
  compactMode: boolean;
}

// 布局配置
interface LayoutConfig {
  sidebarCollapsed: boolean;
  headerVisible: boolean;
  footerVisible: boolean;
  breadcrumbVisible: boolean;
}

// 全局状态接口
interface GlobalState {
  // 通知系统
  notifications: Notification[];
  unreadCount: number;
  
  // 模态框系统
  modals: Modal[];
  
  // 加载状态
  loading: LoadingState;
  
  // 主题配置
  theme: ThemeConfig;
  
  // 布局配置
  layout: LayoutConfig;
  
  // 网络状态
  isOnline: boolean;
  
  // 错误状态
  globalError: string | null;
  
  // 应用状态
  appInitialized: boolean;
  
  // Actions - 通知管理
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
  removeNotification: (id: string) => void;
  markNotificationAsRead: (id: string) => void;
  markAllNotificationsAsRead: () => void;
  clearNotifications: () => void;
  
  // Actions - 模态框管理
  openModal: (modal: Omit<Modal, 'id'>) => string;
  closeModal: (id: string) => void;
  closeAllModals: () => void;
  
  // Actions - 加载状态管理
  setGlobalLoading: (loading: boolean, message?: string) => void;
  setComponentLoading: (component: string, loading: boolean) => void;
  clearAllLoading: () => void;
  
  // Actions - 主题管理
  setThemeMode: (mode: 'light' | 'dark' | 'auto') => void;
  setPrimaryColor: (color: string) => void;
  setFontSize: (size: 'small' | 'medium' | 'large') => void;
  toggleCompactMode: () => void;
  
  // Actions - 布局管理
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setHeaderVisible: (visible: boolean) => void;
  setFooterVisible: (visible: boolean) => void;
  setBreadcrumbVisible: (visible: boolean) => void;
  
  // Actions - 应用状态管理
  setOnlineStatus: (online: boolean) => void;
  setGlobalError: (error: string | null) => void;
  setAppInitialized: (initialized: boolean) => void;
  
  // Actions - 工具方法
  reset: () => void;
}

const initialState = {
  notifications: [],
  unreadCount: 0,
  modals: [],
  loading: {
    global: false,
    components: {},
    message: undefined,
  },
  theme: {
    mode: 'light' as const,
    primaryColor: '#3b82f6',
    fontSize: 'medium' as const,
    compactMode: false,
  },
  layout: {
    sidebarCollapsed: false,
    headerVisible: true,
    footerVisible: true,
    breadcrumbVisible: true,
  },
  isOnline: true,
  globalError: null,
  appInitialized: false,
};

export const useGlobalStore = create<GlobalState>()(devtools(
  persist(
    (set, get) => ({
      ...initialState,

      // 通知管理
      addNotification: (notification) => {
        const id = `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const newNotification: Notification = {
          ...notification,
          id,
          timestamp: Date.now(),
          read: false,
        };
        
        set((state) => ({
          notifications: [newNotification, ...state.notifications],
          unreadCount: state.unreadCount + 1,
        }));
        
        // 自动移除通知
        if (notification.duration && notification.duration > 0) {
          setTimeout(() => {
            get().removeNotification(id);
          }, notification.duration);
        }
      },

      removeNotification: (id) => {
        set((state) => {
          const notification = state.notifications.find(n => n.id === id);
          const wasUnread = notification && !notification.read;
          
          return {
            notifications: state.notifications.filter(n => n.id !== id),
            unreadCount: wasUnread ? Math.max(0, state.unreadCount - 1) : state.unreadCount,
          };
        });
      },

      markNotificationAsRead: (id) => {
        set((state) => {
          const notifications = state.notifications.map(n => 
            n.id === id ? { ...n, read: true } : n
          );
          const unreadCount = notifications.filter(n => !n.read).length;
          
          return { notifications, unreadCount };
        });
      },

      markAllNotificationsAsRead: () => {
        set((state) => ({
          notifications: state.notifications.map(n => ({ ...n, read: true })),
          unreadCount: 0,
        }));
      },

      clearNotifications: () => {
        set({ notifications: [], unreadCount: 0 });
      },

      // 模态框管理
      openModal: (modal) => {
        const id = `modal_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const newModal: Modal = { ...modal, id };
        
        set((state) => ({
          modals: [...state.modals, newModal],
        }));
        
        return id;
      },

      closeModal: (id) => {
        set((state) => ({
          modals: state.modals.filter(m => m.id !== id),
        }));
      },

      closeAllModals: () => {
        set({ modals: [] });
      },

      // 加载状态管理
      setGlobalLoading: (loading, message) => {
        set((state) => ({
          loading: {
            ...state.loading,
            global: loading,
            message: loading ? message : undefined,
          },
        }));
      },

      setComponentLoading: (component, loading) => {
        set((state) => ({
          loading: {
            ...state.loading,
            components: {
              ...state.loading.components,
              [component]: loading,
            },
          },
        }));
      },

      clearAllLoading: () => {
        set((state) => ({
          loading: {
            global: false,
            components: {},
            message: undefined,
          },
        }));
      },

      // 主题管理
      setThemeMode: (mode) => {
        set((state) => ({
          theme: { ...state.theme, mode },
        }));
      },

      setPrimaryColor: (primaryColor) => {
        set((state) => ({
          theme: { ...state.theme, primaryColor },
        }));
      },

      setFontSize: (fontSize) => {
        set((state) => ({
          theme: { ...state.theme, fontSize },
        }));
      },

      toggleCompactMode: () => {
        set((state) => ({
          theme: { ...state.theme, compactMode: !state.theme.compactMode },
        }));
      },

      // 布局管理
      toggleSidebar: () => {
        set((state) => ({
          layout: { ...state.layout, sidebarCollapsed: !state.layout.sidebarCollapsed },
        }));
      },

      setSidebarCollapsed: (collapsed) => {
        set((state) => ({
          layout: { ...state.layout, sidebarCollapsed: collapsed },
        }));
      },

      setHeaderVisible: (visible) => {
        set((state) => ({
          layout: { ...state.layout, headerVisible: visible },
        }));
      },

      setFooterVisible: (visible) => {
        set((state) => ({
          layout: { ...state.layout, footerVisible: visible },
        }));
      },

      setBreadcrumbVisible: (visible) => {
        set((state) => ({
          layout: { ...state.layout, breadcrumbVisible: visible },
        }));
      },

      // 应用状态管理
      setOnlineStatus: (online) => {
        set({ isOnline: online });
      },

      setGlobalError: (error) => {
        set({ globalError: error });
      },

      setAppInitialized: (initialized) => {
        set({ appInitialized: initialized });
      },

      // 重置状态
      reset: () => {
        set(initialState);
      },
    }),
    {
      name: 'smellpin-global-store',
      partialize: (state) => ({
        theme: state.theme,
        layout: state.layout,
        notifications: state.notifications.filter(n => n.persistent),
      }),
    }
  ),
  {
    name: 'global-store',
  }
));

// 导出类型
export type { Notification, Modal, LoadingState, ThemeConfig, LayoutConfig };

// 工具函数
export const createNotification = {
  success: (title: string, message: string, duration = 4000) => ({
    type: 'success' as const,
    title,
    message,
    duration,
  }),
  
  error: (title: string, message: string, duration = 6000) => ({
    type: 'error' as const,
    title,
    message,
    duration,
  }),
  
  warning: (title: string, message: string, duration = 5000) => ({
    type: 'warning' as const,
    title,
    message,
    duration,
  }),
  
  info: (title: string, message: string, duration = 4000) => ({
    type: 'info' as const,
    title,
    message,
    duration,
  }),
};