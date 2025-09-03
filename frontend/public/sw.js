/**
 * SmellPin Service Worker
 * Provides offline support, caching, and performance optimization
 */

const CACHE_NAME = 'smellpin-v1.0.0';
const STATIC_CACHE = 'smellpin-static-v1.0.0';
const DYNAMIC_CACHE = 'smellpin-dynamic-v1.0.0';
const API_CACHE = 'smellpin-api-v1.0.0';

// Files to cache immediately
const STATIC_ASSETS = [
  '/',
  '/offline.html',
  '/manifest.json',
  '/favicon.ico',
  '/apple-touch-icon.png',
  // Add other critical static assets
];

// API endpoints to cache
const API_ENDPOINTS = [
  '/api/v1/health',
  '/api/v1/annotations/list',
  '/api/v1/lbs/locations'
];

// Cache strategies
const CACHE_STRATEGIES = {
  // Network first for API calls
  networkFirst: (request) => {
    return fetch(request)
      .then(response => {
        if (response.ok) {
          const responseClone = response.clone();
          caches.open(API_CACHE).then(cache => {
            cache.put(request, responseClone);
          });
        }
        return response;
      })
      .catch(() => {
        return caches.match(request);
      });
  },

  // Cache first for static assets
  cacheFirst: (request) => {
    return caches.match(request).then(response => {
      return response || fetch(request).then(fetchResponse => {
        if (fetchResponse.ok) {
          const responseClone = fetchResponse.clone();
          caches.open(STATIC_CACHE).then(cache => {
            cache.put(request, responseClone);
          });
        }
        return fetchResponse;
      });
    });
  },

  // Stale while revalidate for dynamic content
  staleWhileRevalidate: (request) => {
    return caches.open(DYNAMIC_CACHE).then(cache => {
      return cache.match(request).then(response => {
        const fetchPromise = fetch(request).then(fetchResponse => {
          if (fetchResponse.ok) {
            cache.put(request, fetchResponse.clone());
          }
          return fetchResponse;
        });
        return response || fetchPromise;
      });
    });
  }
};

// Install event
self.addEventListener('install', (event) => {
  console.log('Service Worker: Installing...');
  
  event.waitUntil(
    Promise.all([
      caches.open(STATIC_CACHE).then(cache => {
        console.log('Service Worker: Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      }),
      self.skipWaiting()
    ])
  );
});

// Activate event
self.addEventListener('activate', (event) => {
  console.log('Service Worker: Activating...');
  
  event.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (![CACHE_NAME, STATIC_CACHE, DYNAMIC_CACHE, API_CACHE].includes(cacheName)) {
              console.log('Service Worker: Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      }),
      self.clients.claim()
    ])
  );
});

// Fetch event
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip cross-origin requests
  if (url.origin !== self.location.origin) {
    return;
  }

  // Handle different request types
  if (url.pathname.startsWith('/api/')) {
    // API requests - Network first
    event.respondWith(
      CACHE_STRATEGIES.networkFirst(request).catch(() => {
        // Fallback for offline API requests
        if (url.pathname.includes('/annotations') || url.pathname.includes('/lbs')) {
          return new Response(JSON.stringify({
            success: false,
            message: 'Offline mode - cached data may be available',
            data: null,
            offline: true
          }), {
            headers: { 'Content-Type': 'application/json' },
            status: 503
          });
        }
        return caches.match('/offline.html');
      })
    );
  } else if (
    url.pathname.includes('_next/static/') ||
    url.pathname.includes('/static/') ||
    url.pathname.match(/\.(css|js|woff|woff2|ttf|eot|ico|png|jpg|jpeg|gif|svg|webp|avif)$/)
  ) {
    // Static assets - Cache first
    event.respondWith(CACHE_STRATEGIES.cacheFirst(request));
  } else {
    // HTML pages - Stale while revalidate
    event.respondWith(
      CACHE_STRATEGIES.staleWhileRevalidate(request).catch(() => {
        return caches.match('/offline.html');
      })
    );
  }
});

// Push notifications
self.addEventListener('push', (event) => {
  console.log('Service Worker: Push notification received');
  
  if (event.data) {
    const data = event.data.json();
    const options = {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/badge-72.png',
      tag: data.tag || 'smellpin-notification',
      requireInteraction: data.requireInteraction || false,
      actions: data.actions || [],
      data: data.data || {}
    };

    event.waitUntil(
      self.registration.showNotification(data.title, options)
    );
  }
});

// Notification click
self.addEventListener('notificationclick', (event) => {
  console.log('Service Worker: Notification clicked');
  
  event.notification.close();
  
  // Handle notification actions
  if (event.action) {
    switch (event.action) {
      case 'view':
        event.waitUntil(
          clients.openWindow(event.notification.data.url || '/')
        );
        break;
      case 'dismiss':
        // Just close the notification
        break;
    }
  } else {
    // Default action - open app
    event.waitUntil(
      clients.matchAll().then(windowClients => {
        if (windowClients.length > 0) {
          return windowClients[0].focus();
        } else {
          return clients.openWindow('/');
        }
      })
    );
  }
});

// Background sync
self.addEventListener('sync', (event) => {
  console.log('Service Worker: Background sync triggered');
  
  if (event.tag === 'background-sync-annotations') {
    event.waitUntil(syncAnnotations());
  } else if (event.tag === 'background-sync-location') {
    event.waitUntil(syncLocationData());
  }
});

// Sync functions
async function syncAnnotations() {
  try {
    // Get pending annotations from IndexedDB
    const pendingAnnotations = await getPendingAnnotations();
    
    for (const annotation of pendingAnnotations) {
      try {
        const response = await fetch('/api/v1/annotations', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(annotation.data)
        });
        
        if (response.ok) {
          await removePendingAnnotation(annotation.id);
          console.log('Service Worker: Annotation synced successfully');
        }
      } catch (error) {
        console.error('Service Worker: Failed to sync annotation:', error);
      }
    }
  } catch (error) {
    console.error('Service Worker: Background sync failed:', error);
  }
}

async function syncLocationData() {
  try {
    const pendingLocations = await getPendingLocations();
    
    for (const location of pendingLocations) {
      try {
        const response = await fetch('/api/v1/lbs/report-location', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(location.data)
        });
        
        if (response.ok) {
          await removePendingLocation(location.id);
          console.log('Service Worker: Location data synced successfully');
        }
      } catch (error) {
        console.error('Service Worker: Failed to sync location:', error);
      }
    }
  } catch (error) {
    console.error('Service Worker: Location sync failed:', error);
  }
}

// IndexedDB helpers (simplified)
async function getPendingAnnotations() {
  // Implementation would use IndexedDB to store/retrieve pending annotations
  return [];
}

async function removePendingAnnotation(id) {
  // Implementation would remove from IndexedDB
  return true;
}

async function getPendingLocations() {
  // Implementation would use IndexedDB to store/retrieve pending locations
  return [];
}

async function removePendingLocation(id) {
  // Implementation would remove from IndexedDB
  return true;
}

// Error handling
self.addEventListener('error', (event) => {
  console.error('Service Worker error:', event.error);
});

self.addEventListener('unhandledrejection', (event) => {
  console.error('Service Worker unhandled promise rejection:', event.reason);
  event.preventDefault();
});

// Performance monitoring
self.addEventListener('fetch', (event) => {
  // Log performance metrics for monitoring
  const start = performance.now();
  
  event.respondWith(
    fetch(event.request).then(response => {
      const duration = performance.now() - start;
      
      // Log slow requests
      if (duration > 1000) {
        console.warn(`Service Worker: Slow request detected: ${event.request.url} (${duration}ms)`);
      }
      
      return response;
    })
  );
});