'use client';

/**
 * Resource preloading utilities for SmellPin
 * Optimizes critical resource loading and reduces Time to Interactive (TTI)
 */

interface PreloadOptions {
  as: 'script' | 'style' | 'font' | 'image' | 'fetch';
  type?: string;
  crossorigin?: 'anonymous' | 'use-credentials';
  media?: string;
  priority?: 'high' | 'low';
}

class ResourcePreloader {
  private preloadedResources = new Set<string>();
  private observer: IntersectionObserver | null = null;
  
  constructor() {
    if (typeof window !== 'undefined') {
      this.setupIntersectionObserver();
    }
  }
  
  private setupIntersectionObserver() {
    this.observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const element = entry.target as HTMLElement;
          const preloadUrls = element.dataset.preload?.split(',') || [];
          preloadUrls.forEach(url => this.preloadResource(url.trim()));
          this.observer?.unobserve(element);
        }
      });
    }, {
      rootMargin: '50px',
      threshold: 0.1
    });
  }
  
  preloadResource(url: string, options: PreloadOptions = { as: 'script' }) {
    if (typeof document === 'undefined' || this.preloadedResources.has(url)) {
      return;
    }
    
    const link = document.createElement('link');
    link.rel = 'preload';
    link.href = url;
    link.as = options.as;
    
    if (options.type) link.type = options.type;
    if (options.crossorigin) link.crossOrigin = options.crossorigin;
    if (options.media) link.media = options.media;
    
    // Add to head
    document.head.appendChild(link);
    this.preloadedResources.add(url);
    
    // Remove after load to cleanup
    link.addEventListener('load', () => {
      setTimeout(() => {
        if (link.parentNode) {
          link.parentNode.removeChild(link);
        }
      }, 1000);
    });
  }
  
  preloadCriticalResources() {
    // Critical CSS and JS chunks
    const criticalResources = [
      { url: '/_next/static/chunks/framework.js', as: 'script' as const },
      { url: '/_next/static/chunks/main.js', as: 'script' as const },
      { url: '/_next/static/chunks/webpack.js', as: 'script' as const },
      { url: '/_next/static/css/app/globals.css', as: 'style' as const },
    ];
    
    criticalResources.forEach(({ url, as }) => {
      this.preloadResource(url, { as });
    });
  }
  
  preloadRouteResources(routes: string[]) {
    routes.forEach(route => {
      // Preload page chunks
      this.preloadResource(`/_next/static/chunks/pages${route}.js`, { as: 'script' });
      // Preload potential CSS for route
      this.preloadResource(`/_next/static/css${route}.css`, { as: 'style' });
    });
  }
  
  preloadComponentChunks(components: string[]) {
    components.forEach(component => {
      // These would be generated chunk names from webpack
      const chunkName = component.toLowerCase().replace(/([A-Z])/g, '-$1');
      this.preloadResource(`/_next/static/chunks/components/${chunkName}.js`, { as: 'script' });
    });
  }
  
  preloadOnHover(element: Element, resources: string[]) {
    let hasPreloaded = false;
    
    const preloadHandler = () => {
      if (!hasPreloaded) {
        hasPreloaded = true;
        resources.forEach(url => {
          this.preloadResource(url, { as: 'script' });
        });
      }
    };
    
    element.addEventListener('mouseenter', preloadHandler, { once: true });
    element.addEventListener('touchstart', preloadHandler, { once: true });
  }
  
  preloadOnVisible(element: Element, resources: string[]) {
    if (this.observer) {
      element.setAttribute('data-preload', resources.join(','));
      this.observer.observe(element);
    }
  }
  
  preloadFonts() {
    const fonts = [
      {
        family: 'Inter',
        weight: '400',
        display: 'swap'
      },
      {
        family: 'Inter',
        weight: '500', 
        display: 'swap'
      },
      {
        family: 'Inter',
        weight: '600',
        display: 'swap'
      }
    ];
    
    fonts.forEach(font => {
      const fontUrl = `https://fonts.googleapis.com/css2?family=${font.family}:wght@${font.weight}&display=${font.display}`;
      this.preloadResource(fontUrl, { 
        as: 'style',
        crossorigin: 'anonymous'
      });
    });
  }
  
  preloadImages(urls: string[]) {
    urls.forEach(url => {
      this.preloadResource(url, { as: 'image' });
    });
  }
  
  preloadAPIData(endpoints: string[]) {
    endpoints.forEach(endpoint => {
      this.preloadResource(endpoint, { 
        as: 'fetch',
        crossorigin: 'anonymous'
      });
    });
  }
  
  // Smart preloading based on user behavior
  smartPreload() {
    // Preload next likely routes based on current route
    const currentPath = window.location.pathname;
    let likelyNextRoutes: string[] = [];
    
    switch (currentPath) {
      case '/':
        likelyNextRoutes = ['/map', '/auth/login', '/profile'];
        break;
      case '/auth/login':
        likelyNextRoutes = ['/profile', '/map'];
        break;
      case '/map':
        likelyNextRoutes = ['/profile/annotations', '/profile/wallet'];
        break;
      case '/profile':
        likelyNextRoutes = ['/profile/settings', '/profile/wallet', '/profile/annotations'];
        break;
      default:
        likelyNextRoutes = ['/', '/map'];
    }
    
    // Delay preloading to not interfere with critical resources
    setTimeout(() => {
      this.preloadRouteResources(likelyNextRoutes);
    }, 2000);
  }
  
  // Adaptive preloading based on connection quality
  adaptivePreload() {
    if ('connection' in navigator) {
      const connection = (navigator as any).connection;
      const effectiveType = connection?.effectiveType;
      
      switch (effectiveType) {
        case '4g':
          // Aggressive preloading for fast connections
          this.preloadRouteResources(['/map', '/profile', '/admin']);
          this.preloadComponentChunks(['InteractiveMap', 'PaymentModal', 'AdminPanel']);
          break;
        case '3g':
          // Moderate preloading
          this.preloadRouteResources(['/map', '/profile']);
          break;
        case '2g':
        case 'slow-2g':
          // Minimal preloading for slow connections
          this.preloadCriticalResources();
          break;
        default:
          // Default moderate approach
          this.preloadCriticalResources();
          this.smartPreload();
      }
    } else {
      // Fallback for browsers without connection API
      this.preloadCriticalResources();
      this.smartPreload();
    }
  }
  
  destroy() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }
}

// Singleton instance
let preloader: ResourcePreloader | null = null;

export const getResourcePreloader = () => {
  if (!preloader && typeof window !== 'undefined') {
    preloader = new ResourcePreloader();
  }
  return preloader;
};

// React hook for component-level preloading
export const useResourcePreloader = () => {
  const preloader = getResourcePreloader();
  
  return {
    preloadResource: preloader?.preloadResource.bind(preloader),
    preloadOnHover: preloader?.preloadOnHover.bind(preloader),
    preloadOnVisible: preloader?.preloadOnVisible.bind(preloader),
    preloadRoutes: preloader?.preloadRouteResources.bind(preloader),
    smartPreload: preloader?.smartPreload.bind(preloader),
    adaptivePreload: preloader?.adaptivePreload.bind(preloader)
  };
};

// Initialize preloader on page load
export const initializePreloader = () => {
  if (typeof window !== 'undefined') {
    const preloader = getResourcePreloader();
    
    // Wait for page to be interactive before starting preloading
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => preloader?.adaptivePreload(), 500);
      });
    } else {
      setTimeout(() => preloader?.adaptivePreload(), 500);
    }
  }
};

// Export for cleanup
export const cleanupPreloader = () => {
  if (preloader) {
    preloader.destroy();
    preloader = null;
  }
};