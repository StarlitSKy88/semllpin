// Toast 工具函数

interface ToastData {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  duration?: number;
}

let toastId = 0;
const toastListeners: Array<(toasts: ToastData[]) => void> = [];
let toasts: ToastData[] = [];

export const showToast = (toast: Omit<ToastData, 'id'>) => {
  const newToast = { ...toast, id: `toast-${++toastId}` };
  toasts = [...toasts, newToast];
  toastListeners.forEach(listener => listener(toasts));
};

export const removeToast = (id: string) => {
  toasts = toasts.filter(toast => toast.id !== id);
  toastListeners.forEach(listener => listener(toasts));
};

export const getToasts = () => toasts;

export const addToastListener = (listener: (toasts: ToastData[]) => void) => {
  toastListeners.push(listener);
  return () => {
    const index = toastListeners.indexOf(listener);
    if (index > -1) {
      toastListeners.splice(index, 1);
    }
  };
};

export type { ToastData };