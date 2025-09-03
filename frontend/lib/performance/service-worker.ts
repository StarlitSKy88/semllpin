/**
 * Service Worker Manager
 * Advanced service worker for offline functionality, caching, and performance
 */

// ==================== TYPES ====================

export interface ServiceWorkerConfig {
  cacheName: string;
  version: string;
  enableOffline: boolean;
  enablePushNotifications: boolean;
  enableBackgroundSync: boolean;
  cacheStrategy: 'cache-first' | 'network-first' | 'stale-while-revalidate';
  maxCacheAge: number; // in milliseconds
  maxCacheSize: number; // in bytes
  excludePatterns: RegExp[];
}

interface CacheItem {
  url: string;
  response: Response;
  timestamp: number;
  size: number;
}

// ==================== DEFAULT CONFIG ====================

const defaultConfig: ServiceWorkerConfig = {
  cacheName: 'smellpin-cache-v1',
  version: '1.0.0',
  enableOffline: true,
  enablePushNotifications: true,
  enableBackgroundSync: true,
  cacheStrategy: 'stale-while-revalidate',
  maxCacheAge: 24 * 60 * 60 * 1000, // 24 hours
  maxCacheSize: 50 * 1024 * 1024, // 50MB
  excludePatterns: [
    /\/api\/auth\//,
    /\/api\/payments\//,
    /\?.*no-cache/,
  ],
};

// ==================== SERVICE WORKER REGISTRATION ====================

export class ServiceWorkerManager {
  private config: ServiceWorkerConfig;
  private registration: ServiceWorkerRegistration | null = null;
  private isSupported: boolean = false;

  constructor(config: Partial<ServiceWorkerConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    this.isSupported = this.checkSupport();
  }

  /**
   * Check if service worker is supported
   */
  private checkSupport(): boolean {
    return (
      typeof window !== 'undefined' &&
      'serviceWorker' in navigator &&
      'caches' in window &&
      'fetch' in window
    );
  }

  /**
   * Register service worker
   */
  async register(swPath: string = '/sw.js'): Promise<ServiceWorkerRegistration | null> {
    if (!this.isSupported) {
      console.warn('Service Worker not supported');
      return null;
    }

    try {
      this.registration = await navigator.serviceWorker.register(swPath, {
        scope: '/',
        updateViaCache: 'none',
      });

      console.log('Service Worker registered successfully');

      // Handle updates
      this.registration.addEventListener('updatefound', this.handleUpdate.bind(this));

      // Check for existing controller
      if (navigator.serviceWorker.controller) {
        this.setupMessageChannel();
      }

      // Listen for controller change
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        this.setupMessageChannel();
        window.location.reload();
      });

      return this.registration;
    } catch (error) {
      console.error('Service Worker registration failed:', error);
      return null;
    }
  }

  /**
   * Handle service worker updates
   */
  private handleUpdate(): void {
    if (!this.registration?.installing) return;

    const installingWorker = this.registration.installing;

    installingWorker.addEventListener('statechange', () => {
      if (installingWorker.state === 'installed') {
        if (navigator.serviceWorker.controller) {
          // New version available
          this.notifyUpdate();
        }
      }
    });
  }

  /**
   * Notify user of available update
   */
  private notifyUpdate(): void {
    // Dispatch custom event
    window.dispatchEvent(new CustomEvent('sw-update-available', {
      detail: {
        registration: this.registration,
        skipWaiting: this.skipWaiting.bind(this),
      }
    }));
  }

  /**
   * Skip waiting and activate new service worker
   */
  async skipWaiting(): Promise<void> {
    if (!this.registration?.waiting) return;

    this.registration.waiting.postMessage({ type: 'SKIP_WAITING' });
  }

  /**
   * Setup message channel with service worker
   */
  private setupMessageChannel(): void {
    const channel = new MessageChannel();
    
    channel.port1.onmessage = (event) => {
      this.handleMessage(event.data);
    };

    navigator.serviceWorker.controller?.postMessage(
      { type: 'INIT', config: this.config },
      [channel.port2]
    );
  }

  /**
   * Handle messages from service worker
   */
  private handleMessage(data: any): void {
    switch (data.type) {
      case 'CACHE_UPDATED':
        console.log('Cache updated:', data.url);
        break;
      case 'OFFLINE':
        this.handleOffline();
        break;
      case 'ONLINE':
        this.handleOnline();
        break;
      case 'SYNC_COMPLETE':
        console.log('Background sync completed:', data.tag);
        break;
      default:
        console.log('Unknown message from SW:', data);
    }
  }

  /**
   * Handle offline state
   */
  private handleOffline(): void {
    document.body.classList.add('offline');
    
    // Dispatch offline event
    window.dispatchEvent(new CustomEvent('app-offline'));
  }

  /**
   * Handle online state
   */
  private handleOnline(): void {
    document.body.classList.remove('offline');
    
    // Dispatch online event
    window.dispatchEvent(new CustomEvent('app-online'));
  }

  /**
   * Get cache statistics
   */
  async getCacheStats(): Promise<{
    size: number;
    itemCount: number;
    oldestItem: Date | null;
    newestItem: Date | null;
  }> {
    if (!this.isSupported) {
      return { size: 0, itemCount: 0, oldestItem: null, newestItem: null };
    }

    try {
      const cache = await caches.open(this.config.cacheName);
      const keys = await cache.keys();
      
      let totalSize = 0;
      let oldestTimestamp = Infinity;
      let newestTimestamp = 0;

      for (const request of keys) {
        const response = await cache.match(request);
        if (response) {
          const blob = await response.blob();
          totalSize += blob.size;

          const timestamp = parseInt(response.headers.get('sw-timestamp') || '0');
          if (timestamp) {
            oldestTimestamp = Math.min(oldestTimestamp, timestamp);
            newestTimestamp = Math.max(newestTimestamp, timestamp);
          }
        }
      }

      return {
        size: totalSize,
        itemCount: keys.length,
        oldestItem: oldestTimestamp !== Infinity ? new Date(oldestTimestamp) : null,
        newestItem: newestTimestamp ? new Date(newestTimestamp) : null,
      };
    } catch (error) {
      console.error('Failed to get cache stats:', error);
      return { size: 0, itemCount: 0, oldestItem: null, newestItem: null };
    }
  }

  /**
   * Clear cache
   */
  async clearCache(): Promise<boolean> {
    if (!this.isSupported) return false;

    try {
      const deleted = await caches.delete(this.config.cacheName);
      console.log('Cache cleared:', deleted);
      return deleted;
    } catch (error) {
      console.error('Failed to clear cache:', error);
      return false;
    }
  }

  /**
   * Precache critical resources
   */
  async precacheResources(urls: string[]): Promise<void> {
    if (!this.isSupported || !navigator.serviceWorker.controller) return;

    navigator.serviceWorker.controller.postMessage({
      type: 'PRECACHE',
      urls,
    });
  }

  /**
   * Check if app is running in standalone mode (PWA)
   */
  isStandalone(): boolean {
    return (
      window.matchMedia('(display-mode: standalone)').matches ||
      ('standalone' in navigator && (navigator as any).standalone === true)
    );
  }

  /**
   * Request persistent storage
   */
  async requestPersistentStorage(): Promise<boolean> {
    if (!('storage' in navigator) || !('persist' in navigator.storage)) {
      return false;
    }

    try {
      const persistent = await navigator.storage.persist();
      console.log('Persistent storage:', persistent);
      return persistent;
    } catch (error) {
      console.error('Failed to request persistent storage:', error);
      return false;
    }
  }

  /**
   * Get storage estimate
   */
  async getStorageEstimate(): Promise<StorageEstimate | null> {
    if (!('storage' in navigator) || !('estimate' in navigator.storage)) {
      return null;
    }

    try {
      return await navigator.storage.estimate();
    } catch (error) {
      console.error('Failed to get storage estimate:', error);
      return null;
    }
  }

  /**
   * Unregister service worker
   */
  async unregister(): Promise<boolean> {
    if (!this.registration) return false;

    try {
      const unregistered = await this.registration.unregister();
      console.log('Service Worker unregistered:', unregistered);
      return unregistered;
    } catch (error) {
      console.error('Failed to unregister service worker:', error);
      return false;
    }
  }
}

// ==================== PUSH NOTIFICATIONS ====================

export class PushNotificationManager {
  private registration: ServiceWorkerRegistration | null = null;

  constructor(registration: ServiceWorkerRegistration | null) {
    this.registration = registration;
  }

  /**
   * Check if push notifications are supported
   */
  isSupported(): boolean {
    return (
      'PushManager' in window &&
      'Notification' in window &&
      this.registration !== null
    );
  }

  /**
   * Request notification permission
   */
  async requestPermission(): Promise<NotificationPermission> {
    if (!('Notification' in window)) {
      return 'denied';
    }

    if (Notification.permission === 'granted') {
      return 'granted';
    }

    if (Notification.permission === 'denied') {
      return 'denied';
    }

    const permission = await Notification.requestPermission();
    return permission;
  }

  /**
   * Subscribe to push notifications
   */
  async subscribe(vapidPublicKey: string): Promise<PushSubscription | null> {
    if (!this.isSupported() || !this.registration) {
      return null;
    }

    const permission = await this.requestPermission();
    if (permission !== 'granted') {
      return null;
    }

    try {
      const subscription = await this.registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: this.urlBase64ToUint8Array(vapidPublicKey),
      });

      console.log('Push subscription created:', subscription);
      return subscription;
    } catch (error) {
      console.error('Failed to subscribe to push notifications:', error);
      return null;
    }
  }

  /**
   * Unsubscribe from push notifications
   */
  async unsubscribe(): Promise<boolean> {
    if (!this.registration) return false;

    try {
      const subscription = await this.registration.pushManager.getSubscription();
      if (!subscription) return true;

      const unsubscribed = await subscription.unsubscribe();
      console.log('Push unsubscribed:', unsubscribed);
      return unsubscribed;
    } catch (error) {
      console.error('Failed to unsubscribe from push notifications:', error);
      return false;
    }
  }

  /**
   * Get current push subscription
   */
  async getSubscription(): Promise<PushSubscription | null> {
    if (!this.registration) return null;

    try {
      return await this.registration.pushManager.getSubscription();
    } catch (error) {
      console.error('Failed to get push subscription:', error);
      return null;
    }
  }

  /**
   * Show local notification
   */
  async showNotification(
    title: string,
    options: NotificationOptions = {}
  ): Promise<void> {
    if (!this.registration) return;

    const permission = await this.requestPermission();
    if (permission !== 'granted') return;

    await this.registration.showNotification(title, {
      icon: '/icons/icon-192x192.png',
      badge: '/icons/badge-72x72.png',
      vibrate: [200, 100, 200],
      ...options,
    });
  }

  /**
   * Convert VAPID key from base64 to Uint8Array
   */
  private urlBase64ToUint8Array(base64String: string): Uint8Array {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }

    return outputArray;
  }
}

// ==================== BACKGROUND SYNC ====================

export class BackgroundSyncManager {
  private registration: ServiceWorkerRegistration | null = null;

  constructor(registration: ServiceWorkerRegistration | null) {
    this.registration = registration;
  }

  /**
   * Check if background sync is supported
   */
  isSupported(): boolean {
    return (
      'serviceWorker' in navigator &&
      'sync' in window.ServiceWorkerRegistration.prototype &&
      this.registration !== null
    );
  }

  /**
   * Register background sync
   */
  async registerSync(tag: string): Promise<void> {
    if (!this.isSupported() || !this.registration) return;

    try {
      await (this.registration as any).sync.register(tag);
      console.log('Background sync registered:', tag);
    } catch (error) {
      console.error('Failed to register background sync:', error);
    }
  }

  /**
   * Get sync tags
   */
  async getTags(): Promise<string[]> {
    if (!this.isSupported() || !this.registration) return [];

    try {
      return await (this.registration as any).sync.getTags();
    } catch (error) {
      console.error('Failed to get sync tags:', error);
      return [];
    }
  }
}

// ==================== HOOKS ====================

/**
 * React hook for service worker
 */
export function useServiceWorker(config?: Partial<ServiceWorkerConfig>) {
  const [swManager] = React.useState(() => new ServiceWorkerManager(config));
  const [registration, setRegistration] = React.useState<ServiceWorkerRegistration | null>(null);
  const [updateAvailable, setUpdateAvailable] = React.useState(false);
  const [isOnline, setIsOnline] = React.useState(navigator.onLine);

  React.useEffect(() => {
    // Register service worker
    swManager.register().then(setRegistration);

    // Listen for update events
    const handleUpdateAvailable = () => setUpdateAvailable(true);
    window.addEventListener('sw-update-available', handleUpdateAvailable);

    // Listen for online/offline events
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    window.addEventListener('app-online', handleOnline);
    window.addEventListener('app-offline', handleOffline);

    return () => {
      window.removeEventListener('sw-update-available', handleUpdateAvailable);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      window.removeEventListener('app-online', handleOnline);
      window.removeEventListener('app-offline', handleOffline);
    };
  }, [swManager]);

  const applyUpdate = React.useCallback(() => {
    swManager.skipWaiting();
    setUpdateAvailable(false);
  }, [swManager]);

  return {
    registration,
    updateAvailable,
    isOnline,
    applyUpdate,
    swManager,
  };
}

// ==================== EXPORTS ====================

export default ServiceWorkerManager;