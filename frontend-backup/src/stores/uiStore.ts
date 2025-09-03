import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface Modal {
  id: string;
  type: string;
  props?: Record<string, unknown>;
}

interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
}

interface UIState {
  sidebarOpen: boolean;
  globalLoading: boolean;
  loadingMessage: string;
  modals: Modal[];
  notifications: Notification[];
}

interface UIActions {
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  setGlobalLoading: (loading: boolean, message?: string) => void;
  openModal: (modal: Omit<Modal, 'id'>) => void;
  closeModal: (id: string) => void;
  closeAllModals: () => void;
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
}

type UIStore = UIState & UIActions;

export const useUIStore = create<UIStore>()(persist(
  (set, get) => ({
    // 初始状态
    sidebarOpen: true,
    globalLoading: false,
    loadingMessage: '',
    modals: [],
    notifications: [],

    // 侧边栏操作
    toggleSidebar: () => {
      set((state) => ({ sidebarOpen: !state.sidebarOpen }));
    },

    setSidebarOpen: (open: boolean) => {
      set({ sidebarOpen: open });
    },

    // 全局加载状态
    setGlobalLoading: (loading: boolean, message = '') => {
      set({ globalLoading: loading, loadingMessage: message });
    },

    // 模态框管理
    openModal: (modal: Omit<Modal, 'id'>) => {
      const id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
      const newModal = { ...modal, id };
      set((state) => ({ modals: [...state.modals, newModal] }));
    },

    closeModal: (id: string) => {
      set((state) => ({ modals: state.modals.filter(modal => modal.id !== id) }));
    },

    closeAllModals: () => {
      set({ modals: [] });
    },

    // 通知管理
    addNotification: (notification: Omit<Notification, 'id'>) => {
      const id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
      const newNotification = { ...notification, id };
      set((state) => ({ notifications: [...state.notifications, newNotification] }));
      
      // 自动移除通知
      if (notification.duration !== 0) {
        setTimeout(() => {
          get().removeNotification(id);
        }, notification.duration || 5000);
      }
    },

    removeNotification: (id: string) => {
      set((state) => ({ notifications: state.notifications.filter(notif => notif.id !== id) }));
    },

    clearNotifications: () => {
      set({ notifications: [] });
    },
  }),
  {
    name: 'ui-store',
    partialize: (state) => ({ sidebarOpen: state.sidebarOpen }),
  }
));

export default useUIStore;