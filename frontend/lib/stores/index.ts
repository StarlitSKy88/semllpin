// 统一导出所有状态管理 store

// 全局状态
export { useGlobalStore } from './global-store';
export type {
  GlobalState,
  Notification,
  Modal,
  LoadingState,
  ThemeConfig,
  LayoutConfig,
} from './global-store';

// 认证状态
export { useAuthStore } from './auth-store';
export type { AuthState, User } from './auth-store';

// 地图状态
export { useMapStore } from './map-store';
export type { MapState, Annotation } from './map-store';

// LBS状态
export { useLBSStore } from './lbs-store';
export type { LBSState, LocationData, NearbyAnnotation } from './lbs-store';

// 新闻状态
export { useNewsStore } from './news-store';
export type { NewsState, NewsItem } from './news-store';

// 评论状态
export { useCommentStore } from './comment-store';
export type {
  CommentState,
} from './comment-store';

// 支付状态
export { usePaymentStore } from './payment-store';
export type { PaymentState, PaymentMethod, Transaction } from './payment-store';

// 钱包状态
export { useWalletStore } from './wallet-store';
export type { WalletState, WalletTransaction } from './wallet-store';

// Provider hooks (从 global-provider 导出)
export {
  useGlobalLoading,
  useGlobalNotifications,
  useGlobalModals,
  useGlobalTheme,
  useGlobalLayout,
} from '../../components/providers/global-provider';

// 状态管理工具函数
export const storeUtils = {
  // 重置所有状态
  resetAllStores: () => {
    useAuthStore.getState().reset();
    useMapStore.getState().reset();
    useLBSStore.getState().reset();
    useNewsStore.getState().reset();
    useCommentStore.getState().reset();
    usePaymentStore.getState().reset();
    useWalletStore.getState().reset();
    useGlobalStore.getState().reset();
  },
  
  // 获取所有状态的快照
  getStateSnapshot: () => {
    return {
      auth: useAuthStore.getState(),
      map: useMapStore.getState(),
      lbs: useLBSStore.getState(),
      news: useNewsStore.getState(),
      comment: useCommentStore.getState(),
      payment: usePaymentStore.getState(),
      wallet: useWalletStore.getState(),
      global: useGlobalStore.getState(),
    };
  },
  
  // 检查是否有加载状态
  hasAnyLoading: () => {
    const globalLoading = useGlobalStore.getState().loading.global;
    const authLoading = useAuthStore.getState().loading;
    const mapLoading = useMapStore.getState().loading;
    const lbsLoading = useLBSStore.getState().loading;
    const newsLoading = useNewsStore.getState().loading;
    const commentLoading = useCommentStore.getState().loading;
    const paymentLoading = usePaymentStore.getState().loading;
    const walletLoading = useWalletStore.getState().loading;
    
    return globalLoading || authLoading || mapLoading || lbsLoading || 
           newsLoading || commentLoading || paymentLoading || walletLoading;
  },
  
  // 检查是否有错误状态
  hasAnyError: () => {
    const globalError = useGlobalStore.getState().error;
    const authError = useAuthStore.getState().error;
    const mapError = useMapStore.getState().error;
    const lbsError = useLBSStore.getState().error;
    const newsError = useNewsStore.getState().error;
    const commentError = useCommentStore.getState().error;
    const paymentError = usePaymentStore.getState().error;
    const walletError = useWalletStore.getState().error;
    
    return !!(globalError || authError || mapError || lbsError || 
             newsError || commentError || paymentError || walletError);
  },
};

// 状态持久化配置
export const persistConfig = {
  // 需要持久化的状态
  persistedStores: [
    'auth-store',
    'global-store',
    'wallet-store',
  ],
  
  // 不需要持久化的状态
  temporaryStores: [
    'map-store',
    'lbs-store',
    'news-store',
    'comment-store',
    'payment-store',
  ],
};

// 开发工具
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  // 在开发环境下将状态管理工具挂载到 window 对象上
  (window as any).__SMELLPIN_STORES__ = {
    auth: useAuthStore,
    map: useMapStore,
    lbs: useLBSStore,
    news: useNewsStore,
    comment: useCommentStore,
    payment: usePaymentStore,
    wallet: useWalletStore,
    global: useGlobalStore,
    utils: storeUtils,
  };
  
  console.log('🏪 SmellPin Stores initialized. Access via window.__SMELLPIN_STORES__');
}