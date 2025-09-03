// PWA推送通知服务
import api from '../utils/api';

interface PushSubscriptionData {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

class PushNotificationService {
  private vapidPublicKey = import.meta.env.VITE_VAPID_PUBLIC_KEY || '';
  private serviceWorkerRegistration: ServiceWorkerRegistration | null = null;

  constructor() {
    this.initializeServiceWorker();
  }

  // 初始化Service Worker
  private async initializeServiceWorker() {
    if ('serviceWorker' in navigator) {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js', {
          scope: '/'
        });
        
        this.serviceWorkerRegistration = registration;
        console.log('Service Worker 注册成功:', registration);
        
        // 监听Service Worker更新
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // 新的Service Worker已安装，提示用户刷新
                this.notifyUpdate();
              }
            });
          }
        });
        
      } catch (error) {
        console.error('Service Worker 注册失败:', error);
      }
    } else {
      console.warn('浏览器不支持Service Worker');
    }
  }

  // 检查推送通知支持
  public isPushSupported(): boolean {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  }

  // 请求通知权限
  public async requestNotificationPermission(): Promise<NotificationPermission> {
    if (!('Notification' in window)) {
      throw new Error('浏览器不支持通知');
    }

    let permission = Notification.permission;
    
    if (permission === 'default') {
      permission = await Notification.requestPermission();
    }
    
    return permission;
  }

  // 订阅推送通知
  public async subscribeToPush(): Promise<PushSubscriptionData | null> {
    if (!this.isPushSupported()) {
      throw new Error('浏览器不支持推送通知');
    }

    if (!this.serviceWorkerRegistration) {
      throw new Error('Service Worker 未注册');
    }

    // 请求通知权限
    const permission = await this.requestNotificationPermission();
    if (permission !== 'granted') {
      throw new Error('用户拒绝了通知权限');
    }

    try {
      // 检查是否已有订阅
      let subscription = await this.serviceWorkerRegistration.pushManager.getSubscription();
      
      if (!subscription) {
        // 创建新订阅
        subscription = await this.serviceWorkerRegistration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: this.urlBase64ToUint8Array(this.vapidPublicKey)
        });
      }

      // 转换订阅数据格式
      const subscriptionData: PushSubscriptionData = {
        endpoint: subscription.endpoint,
        keys: {
          p256dh: this.arrayBufferToBase64(subscription.getKey('p256dh')!),
          auth: this.arrayBufferToBase64(subscription.getKey('auth')!)
        }
      };

      console.log('推送订阅成功:', subscriptionData);
      return subscriptionData;
      
    } catch (error) {
      console.error('订阅推送通知失败:', error);
      throw error;
    }
  }

  // 取消订阅推送通知
  public async unsubscribeFromPush(): Promise<boolean> {
    if (!this.serviceWorkerRegistration) {
      return false;
    }

    try {
      const subscription = await this.serviceWorkerRegistration.pushManager.getSubscription();
      
      if (subscription) {
        const result = await subscription.unsubscribe();
        console.log('取消推送订阅:', result);
        return result;
      }
      
      return true;
    } catch (error) {
      console.error('取消推送订阅失败:', error);
      return false;
    }
  }

  // 获取当前订阅状态
  public async getSubscriptionStatus(): Promise<{
    isSubscribed: boolean;
    subscription: PushSubscriptionData | null;
  }> {
    if (!this.serviceWorkerRegistration) {
      return { isSubscribed: false, subscription: null };
    }

    try {
      const subscription = await this.serviceWorkerRegistration.pushManager.getSubscription();
      
      if (subscription) {
        return {
          isSubscribed: true,
          subscription: {
            endpoint: subscription.endpoint,
            keys: {
              p256dh: this.arrayBufferToBase64(subscription.getKey('p256dh')!),
              auth: this.arrayBufferToBase64(subscription.getKey('auth')!)
            }
          }
        };
      }
      
      return { isSubscribed: false, subscription: null };
    } catch (error) {
      console.error('获取订阅状态失败:', error);
      return { isSubscribed: false, subscription: null };
    }
  }

  // 发送订阅信息到服务器
  public async sendSubscriptionToServer(subscriptionData: PushSubscriptionData): Promise<boolean> {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('用户未登录');
      }

      const baseURL = api.defaults.baseURL;

      const response = await fetch(`${baseURL}/notifications/push/subscribe`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(subscriptionData)
      });

      if (!response.ok) {
        throw new Error(`服务器错误: ${response.status}`);
      }

      const result = await response.json();
      console.log('订阅信息已发送到服务器:', result);
      return true;
      
    } catch (error) {
      console.error('发送订阅信息到服务器失败:', error);
      return false;
    }
  }

  // 从服务器移除订阅信息
  public async removeSubscriptionFromServer(): Promise<boolean> {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        return true; // 用户未登录，认为移除成功
      }

      const baseURL = api.defaults.baseURL;

      const response = await fetch(`${baseURL}/notifications/push/unsubscribe`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error(`服务器错误: ${response.status}`);
      }

      console.log('订阅信息已从服务器移除');
      return true;
      
    } catch (error) {
      console.error('从服务器移除订阅信息失败:', error);
      return false;
    }
  }

  // 测试推送通知
  public async testPushNotification(): Promise<boolean> {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('用户未登录');
      }

      const baseURL = api.defaults.baseURL;

      const response = await fetch(`${baseURL}/notifications/push/test`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error(`服务器错误: ${response.status}`);
      }

      console.log('测试推送通知已发送');
      return true;
      
    } catch (error) {
      console.error('发送测试推送通知失败:', error);
      return false;
    }
  }

  // 显示本地通知（用于测试）
  public async showLocalNotification(title: string, options: NotificationOptions = {}) {
    const permission = await this.requestNotificationPermission();
    
    if (permission === 'granted') {
      const notification = new Notification(title, {
        icon: '/favicon.ico',
        badge: '/favicon.ico',
        ...options
      });
      
      // 3秒后自动关闭
      setTimeout(() => {
        notification.close();
      }, 3000);
      
      return notification;
    }
    
    throw new Error('通知权限被拒绝');
  }

  // 通知Service Worker更新
  private notifyUpdate() {
    if (confirm('应用有新版本可用，是否立即更新？')) {
      if (this.serviceWorkerRegistration?.waiting) {
        this.serviceWorkerRegistration.waiting.postMessage({ type: 'SKIP_WAITING' });
        window.location.reload();
      }
    }
  }

  // 工具函数：将URL安全的Base64转换为Uint8Array
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

  // 工具函数：将ArrayBuffer转换为Base64
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
}

// 创建全局实例
export const pushNotificationService = new PushNotificationService();
export default pushNotificationService;