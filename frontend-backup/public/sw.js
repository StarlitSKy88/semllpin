// Service Worker for PWA Push Notifications

const CACHE_NAME = 'smellpin-v2-' + Date.now();
const urlsToCache = [
  '/',
  '/static/js/bundle.js',
  '/static/css/main.css',
  '/manifest.json'
];

// 安装事件
self.addEventListener('install', (event) => {
  console.log('Service Worker 安装中...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('缓存已打开');
        return cache.addAll(urlsToCache);
      })
  );
});

// 激活事件
self.addEventListener('activate', (event) => {
  console.log('Service Worker 激活中...');
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('删除旧缓存:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// 拦截网络请求 - 网络优先策略
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // 如果网络请求成功，更新缓存并返回响应
        if (response && response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME)
            .then((cache) => {
              cache.put(event.request, responseClone);
            });
        }
        return response;
      })
      .catch(() => {
        // 网络失败时，从缓存中获取
        return caches.match(event.request);
      })
  );
});

// 推送通知事件
self.addEventListener('push', (event) => {
  console.log('收到推送消息:', event);
  
  let notificationData = {
    title: 'SmellPin 通知',
    body: '您有新的通知',
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    tag: 'smellpin-notification',
    requireInteraction: true,
    actions: [
      {
        action: 'view',
        title: '查看',
        icon: '/favicon.ico'
      },
      {
        action: 'dismiss',
        title: '忽略'
      }
    ],
    data: {
      url: '/notifications'
    }
  };

  // 如果推送包含数据，解析数据
  if (event.data) {
    try {
      const pushData = event.data.json();
      notificationData = {
        ...notificationData,
        title: pushData.title || notificationData.title,
        body: pushData.body || pushData.content || notificationData.body,
        icon: pushData.icon || notificationData.icon,
        tag: pushData.tag || `notification-${pushData.id || Date.now()}`,
        data: {
          url: pushData.actionUrl || '/notifications',
          notificationId: pushData.id,
          type: pushData.type
        }
      };
    } catch (error) {
      console.error('解析推送数据失败:', error);
    }
  }

  event.waitUntil(
    self.registration.showNotification(notificationData.title, notificationData)
  );
});

// 通知点击事件
self.addEventListener('notificationclick', (event) => {
  console.log('通知被点击:', event);
  
  event.notification.close();
  
  const action = event.action;
  const notificationData = event.notification.data;
  
  if (action === 'dismiss') {
    // 用户选择忽略，不做任何操作
    return;
  }
  
  // 打开或聚焦到应用
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        const url = notificationData?.url || '/notifications';
        
        // 检查是否已有打开的窗口
        for (let i = 0; i < clientList.length; i++) {
          const client = clientList[i];
          if (client.url.includes(self.location.origin)) {
            // 聚焦到现有窗口并导航到通知页面
            return client.focus().then(() => {
              return client.navigate(url);
            });
          }
        }
        
        // 如果没有打开的窗口，打开新窗口
        return clients.openWindow(url);
      })
  );
});

// 通知关闭事件
self.addEventListener('notificationclose', (event) => {
  console.log('通知被关闭:', event);
  
  // 可以在这里发送分析数据
  const notificationData = event.notification.data;
  if (notificationData?.notificationId) {
    // 发送通知关闭事件到服务器
    fetch('/api/v1/notifications/analytics', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        notificationId: notificationData.notificationId,
        action: 'closed',
        timestamp: new Date().toISOString()
      })
    }).catch(error => {
      console.error('发送通知分析数据失败:', error);
    });
  }
});

// 后台同步事件
self.addEventListener('sync', (event) => {
  console.log('后台同步事件:', event);
  
  if (event.tag === 'background-sync') {
    event.waitUntil(
      // 执行后台同步任务
      syncNotifications()
    );
  }
});

// 同步通知的函数
async function syncNotifications() {
  try {
    // 获取未读通知数量
    const response = await fetch('/api/v1/social/notifications/stats');
    if (response.ok) {
      const data = await response.json();
      
      // 如果有未读通知，可以显示一个汇总通知
      if (data.data && data.data.unread > 0) {
        await self.registration.showNotification('SmellPin', {
          body: `您有 ${data.data.unread} 条未读通知`,
          icon: '/favicon.ico',
          tag: 'unread-summary',
          data: {
            url: '/notifications'
          }
        });
      }
    }
  } catch (error) {
    console.error('同步通知失败:', error);
  }
}

// 消息事件（用于与主线程通信）
self.addEventListener('message', (event) => {
  console.log('Service Worker 收到消息:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'GET_VERSION') {
    event.ports[0].postMessage({ version: CACHE_NAME });
  }
});