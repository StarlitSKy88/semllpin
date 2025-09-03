/**
 * Bundle optimization utilities for SmellPin
 * Provides tree-shaking optimization and selective imports
 */

// Selective import utilities for better tree-shaking
export const importUtils = {
  // Lodash selective imports
  debounce: () => import('lodash-es/debounce'),
  throttle: () => import('lodash-es/throttle'),
  cloneDeep: () => import('lodash-es/cloneDeep'),
  merge: () => import('lodash-es/merge'),
  
  // Date-fns selective imports
  formatDate: () => import('date-fns/format'),
  parseDate: () => import('date-fns/parse'),
  isValid: () => import('date-fns/isValid'),
  differenceInDays: () => import('date-fns/differenceInDays'),
  
  // Lucide icons selective imports
  mapPin: () => import('lucide-react/dist/esm/icons/map-pin'),
  settings: () => import('lucide-react/dist/esm/icons/settings'),
  user: () => import('lucide-react/dist/esm/icons/user'),
  wallet: () => import('lucide-react/dist/esm/icons/wallet'),
  bell: () => import('lucide-react/dist/esm/icons/bell'),
  search: () => import('lucide-react/dist/esm/icons/search'),
  filter: () => import('lucide-react/dist/esm/icons/filter'),
  menu: () => import('lucide-react/dist/esm/icons/menu'),
  x: () => import('lucide-react/dist/esm/icons/x'),
  plus: () => import('lucide-react/dist/esm/icons/plus'),
  minus: () => import('lucide-react/dist/esm/icons/minus'),
  
  // Chart.js selective imports
  chartCore: () => import('chart.js/auto'),
  chartLine: () => import('chart.js/dist/chart.esm.js').then(mod => mod.LineController),
  chartBar: () => import('chart.js/dist/chart.esm.js').then(mod => mod.BarController),
  chartPie: () => import('chart.js/dist/chart.esm.js').then(mod => mod.PieController),
};

// Code splitting utilities
export const splitImports = {
  // Map-related imports
  async loadMapComponents() {
    const [
      { default: InteractiveMap },
      { default: EnhancedInteractiveMap }
    ] = await Promise.all([
      import('@/components/map/interactive-map'),
      import('@/components/map/enhanced-interactive-map')
    ]);
    return { InteractiveMap, EnhancedInteractiveMap };
  },
  
  // Admin components
  async loadAdminComponents() {
    const [
      { default: AnalyticsCharts },
      { default: UserManagement },
      { default: AnnotationReview },
      { default: ReportManagement },
      { default: SystemSettings }
    ] = await Promise.all([
      import('@/components/admin/analytics-charts'),
      import('@/components/admin/user-management'),
      import('@/components/admin/annotation-review'),
      import('@/components/admin/report-management'),
      import('@/components/admin/system-settings')
    ]);
    return { 
      AnalyticsCharts, 
      UserManagement, 
      AnnotationReview, 
      ReportManagement, 
      SystemSettings 
    };
  },
  
  // Payment components
  async loadPaymentComponents() {
    const [
      { default: PaymentModal },
      { default: PaymentButton },
      { default: WalletModal },
      { default: WalletPage }
    ] = await Promise.all([
      import('@/components/payment/payment-modal'),
      import('@/components/payment/payment-button'),
      import('@/components/wallet/wallet-modal'),
      import('@/components/wallet/wallet-page')
    ]);
    return { PaymentModal, PaymentButton, WalletModal, WalletPage };
  },
  
  // LBS components
  async loadLBSComponents() {
    const [
      { default: LocationTracker },
      { default: NearbyAnnotations },
      { default: RewardDiscoveryAnimation },
      { default: EnhancedLocationTracker }
    ] = await Promise.all([
      import('@/components/lbs/location-tracker'),
      import('@/components/lbs/nearby-annotations'),
      import('@/components/lbs/reward-discovery-animation'),
      import('@/components/lbs/enhanced-location-tracker')
    ]);
    return { 
      LocationTracker, 
      NearbyAnnotations, 
      RewardDiscoveryAnimation, 
      EnhancedLocationTracker 
    };
  },
  
  // Three.js and animation components
  async loadAnimationComponents() {
    const [
      { default: Scene },
      { default: GlowScene },
      { default: CyberspaceScene },
      { default: EtherealScene },
      { default: QuantumScene }
    ] = await Promise.all([
      import('@/components/scene'),
      import('@/components/glow-scene'),
      import('@/components/project/cyberscape-scene'),
      import('@/components/project/ethereal-scene'),
      import('@/components/project/quantum-scene')
    ]);
    return { 
      Scene, 
      GlowScene, 
      CyberspaceScene, 
      EtherealScene, 
      QuantumScene 
    };
  },
  
  // Auth components
  async loadAuthComponents() {
    const [
      { default: AuthModal },
      { default: AccessibleAuthModal }
    ] = await Promise.all([
      import('@/components/auth/auth-modal'),
      import('@/components/auth/accessible-auth-modal')
    ]);
    return { AuthModal, AccessibleAuthModal };
  }
};

// Performance monitoring for bundle size
export const bundleMetrics = {
  measureComponentLoad: async (componentName: string, loadFn: () => Promise<any>) => {
    const startTime = performance.now();
    const startMemory = (performance as any).memory?.usedJSHeapSize || 0;
    
    try {
      const component = await loadFn();
      const endTime = performance.now();
      const endMemory = (performance as any).memory?.usedJSHeapSize || 0;
      
      const metrics = {
        componentName,
        loadTime: endTime - startTime,
        memoryDelta: endMemory - startMemory,
        success: true
      };
      
      // Send metrics to performance monitoring (if enabled)
      if (process.env.NODE_ENV === 'development') {
        console.log(`🚀 Component Load Metrics:`, metrics);
      }
      
      return { component, metrics };
    } catch (error) {
      console.error(`❌ Failed to load component ${componentName}:`, error);
      return { 
        component: null, 
        metrics: { 
          componentName, 
          loadTime: performance.now() - startTime, 
          success: false, 
          error 
        } 
      };
    }
  },
  
  trackBundleSize: () => {
    if (typeof window !== 'undefined' && 'performance' in window) {
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
      
      const bundleStats = {
        mainBundle: resources.find(r => r.name.includes('/_next/static/chunks/pages/'))?.transferSize || 0,
        vendorBundle: resources.find(r => r.name.includes('/_next/static/chunks/framework-'))?.transferSize || 0,
        totalJS: resources
          .filter(r => r.name.includes('.js'))
          .reduce((total, r) => total + (r.transferSize || 0), 0),
        totalCSS: resources
          .filter(r => r.name.includes('.css'))
          .reduce((total, r) => total + (r.transferSize || 0), 0),
        loadTime: navigation.loadEventEnd - navigation.loadEventStart,
        domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart
      };
      
      if (process.env.NODE_ENV === 'development') {
        console.table(bundleStats);
      }
      
      return bundleStats;
    }
    
    return null;
  }
};

// Tree-shaking helper for conditional imports
export const conditionalImport = {
  async loadIfNeeded<T>(
    condition: boolean, 
    importFn: () => Promise<T>
  ): Promise<T | null> {
    if (condition) {
      return await importFn();
    }
    return null;
  },
  
  async loadIfUserAgent(
    userAgentCheck: (ua: string) => boolean,
    importFn: () => Promise<any>
  ) {
    if (typeof window !== 'undefined' && userAgentCheck(navigator.userAgent)) {
      return await importFn();
    }
    return null;
  },
  
  async loadIfFeatureSupported(
    featureCheck: () => boolean,
    importFn: () => Promise<any>
  ) {
    if (featureCheck()) {
      return await importFn();
    }
    return null;
  }
};

// Module federation helpers for micro-frontends (if needed in future)
export const modulePreload = {
  preloadCritical: async () => {
    // Preload critical modules that are likely to be needed
    const criticalModules = [
      () => import('@/components/header'),
      () => import('@/components/footer'),
      () => import('@/components/ui/button'),
      () => import('@/components/ui/dialog'),
      () => import('@/components/providers/auth-provider')
    ];
    
    return Promise.all(criticalModules.map(mod => mod()));
  },
  
  preloadOnIdle: (importFn: () => Promise<any>) => {
    if ('requestIdleCallback' in window) {
      requestIdleCallback(() => importFn());
    } else {
      setTimeout(() => importFn(), 1000);
    }
  },
  
  preloadOnHover: (element: HTMLElement, importFn: () => Promise<any>) => {
    let hasPreloaded = false;
    
    const preload = () => {
      if (!hasPreloaded) {
        hasPreloaded = true;
        importFn();
      }
    };
    
    element.addEventListener('mouseenter', preload, { once: true });
    element.addEventListener('touchstart', preload, { once: true });
    
    return () => {
      element.removeEventListener('mouseenter', preload);
      element.removeEventListener('touchstart', preload);
    };
  }
};