'use client';

import { useEffect, useState, useCallback } from 'react';

/**
 * Mobile-specific performance optimizations for SmellPin
 * Handles device detection, touch interactions, and mobile-specific features
 */

export interface MobileDeviceInfo {
  isMobile: boolean;
  isTablet: boolean;
  isIOS: boolean;
  isAndroid: boolean;
  screenSize: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  orientation: 'portrait' | 'landscape';
  hasTouch: boolean;
  connectionType: string;
  pixelRatio: number;
  viewportHeight: number;
  viewportWidth: number;
  safeAreaInsets: {
    top: number;
    bottom: number;
    left: number;
    right: number;
  };
}

const getScreenSize = (width: number): MobileDeviceInfo['screenSize'] => {
  if (width < 640) return 'xs';
  if (width < 768) return 'sm';
  if (width < 1024) return 'md';
  if (width < 1280) return 'lg';
  return 'xl';
};

const getSafeAreaInsets = () => {
  if (typeof window === 'undefined') return { top: 0, bottom: 0, left: 0, right: 0 };
  
  const computedStyle = getComputedStyle(document.documentElement);
  return {
    top: parseInt(computedStyle.getPropertyValue('--safe-area-inset-top') || '0', 10),
    bottom: parseInt(computedStyle.getPropertyValue('--safe-area-inset-bottom') || '0', 10),
    left: parseInt(computedStyle.getPropertyValue('--safe-area-inset-left') || '0', 10),
    right: parseInt(computedStyle.getPropertyValue('--safe-area-inset-right') || '0', 10),
  };
};

export const useMobileDetection = (): MobileDeviceInfo => {
  const [deviceInfo, setDeviceInfo] = useState<MobileDeviceInfo>(() => ({
    isMobile: false,
    isTablet: false,
    isIOS: false,
    isAndroid: false,
    screenSize: 'md',
    orientation: 'portrait',
    hasTouch: false,
    connectionType: '4g',
    pixelRatio: 1,
    viewportHeight: 0,
    viewportWidth: 0,
    safeAreaInsets: { top: 0, bottom: 0, left: 0, right: 0 },
  }));

  const updateDeviceInfo = useCallback(() => {
    if (typeof window === 'undefined') return;

    const userAgent = navigator.userAgent;
    const width = window.innerWidth;
    const height = window.innerHeight;
    
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
    const isTablet = /iPad|Android(?=.*Mobile)|Tablet/i.test(userAgent) && width >= 768;
    const isIOS = /iPad|iPhone|iPod/.test(userAgent);
    const isAndroid = /Android/.test(userAgent);
    const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    
    const connection = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection;
    const connectionType = connection?.effectiveType || '4g';
    
    const orientation = height > width ? 'portrait' : 'landscape';
    const pixelRatio = window.devicePixelRatio || 1;
    const safeAreaInsets = getSafeAreaInsets();

    setDeviceInfo({
      isMobile,
      isTablet,
      isIOS,
      isAndroid,
      screenSize: getScreenSize(width),
      orientation,
      hasTouch,
      connectionType,
      pixelRatio,
      viewportHeight: height,
      viewportWidth: width,
      safeAreaInsets,
    });
  }, []);

  useEffect(() => {
    updateDeviceInfo();
    
    window.addEventListener('resize', updateDeviceInfo);
    window.addEventListener('orientationchange', updateDeviceInfo);
    
    return () => {
      window.removeEventListener('resize', updateDeviceInfo);
      window.removeEventListener('orientationchange', updateDeviceInfo);
    };
  }, [updateDeviceInfo]);

  return deviceInfo;
};

// Touch gesture optimization hook
export const useTouchOptimization = () => {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Prevent zoom on double-tap for better UX
    let lastTouchEnd = 0;
    const preventZoom = (e: TouchEvent) => {
      const now = new Date().getTime();
      if (now - lastTouchEnd <= 300) {
        e.preventDefault();
      }
      lastTouchEnd = now;
    };

    // Optimize touch scrolling
    const optimizeScrolling = () => {
      document.body.style.touchAction = 'pan-y';
      document.body.style.webkitOverflowScrolling = 'touch';
    };

    // Add passive event listeners for better performance
    const addPassiveListeners = () => {
      const passiveOptions = { passive: true };
      document.addEventListener('touchstart', () => {}, passiveOptions);
      document.addEventListener('touchmove', () => {}, passiveOptions);
      document.addEventListener('touchend', () => {}, passiveOptions);
    };

    document.addEventListener('touchend', preventZoom, false);
    optimizeScrolling();
    addPassiveListeners();

    return () => {
      document.removeEventListener('touchend', preventZoom);
    };
  }, []);
};

// Viewport optimization for mobile
export const useViewportOptimization = (deviceInfo: MobileDeviceInfo) => {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const viewport = document.querySelector('meta[name="viewport"]');
    
    if (deviceInfo.isMobile) {
      // Optimize viewport for mobile devices
      const content = [
        'width=device-width',
        'initial-scale=1.0',
        'maximum-scale=1.0',
        'user-scalable=no',
        'viewport-fit=cover'
      ].join(', ');
      
      if (viewport) {
        viewport.setAttribute('content', content);
      } else {
        const newViewport = document.createElement('meta');
        newViewport.name = 'viewport';
        newViewport.content = content;
        document.head.appendChild(newViewport);
      }

      // Handle safe area insets
      document.documentElement.style.setProperty('--safe-area-inset-top', `${deviceInfo.safeAreaInsets.top}px`);
      document.documentElement.style.setProperty('--safe-area-inset-bottom', `${deviceInfo.safeAreaInsets.bottom}px`);
      document.documentElement.style.setProperty('--safe-area-inset-left', `${deviceInfo.safeAreaInsets.left}px`);
      document.documentElement.style.setProperty('--safe-area-inset-right', `${deviceInfo.safeAreaInsets.right}px`);

      // Set CSS custom properties for mobile optimization
      document.documentElement.style.setProperty('--vh', `${deviceInfo.viewportHeight * 0.01}px`);
      document.documentElement.style.setProperty('--vw', `${deviceInfo.viewportWidth * 0.01}px`);
    }
  }, [deviceInfo]);
};

// Performance optimization for mobile scrolling
export const useScrollOptimization = () => {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Throttle scroll events
    let ticking = false;
    const handleScroll = () => {
      if (!ticking) {
        requestAnimationFrame(() => {
          // Optimize scroll performance
          ticking = false;
        });
        ticking = true;
      }
    };

    // Add optimized scroll listener
    window.addEventListener('scroll', handleScroll, { passive: true });

    // Optimize CSS for better scroll performance
    const optimizeScrollCSS = () => {
      const style = document.createElement('style');
      style.textContent = `
        * {
          -webkit-transform: translate3d(0, 0, 0);
          transform: translate3d(0, 0, 0);
        }
        
        .scroll-smooth {
          scroll-behavior: smooth;
          -webkit-overflow-scrolling: touch;
        }
        
        .will-change-scroll {
          will-change: scroll-position;
        }
        
        @media (max-width: 768px) {
          .mobile-scroll-optimize {
            overscroll-behavior: contain;
            -webkit-overflow-scrolling: touch;
            transform: translateZ(0);
          }
        }
      `;
      document.head.appendChild(style);
    };

    optimizeScrollCSS();

    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);
};

// Image optimization for mobile
export const useMobileImageOptimization = (deviceInfo: MobileDeviceInfo) => {
  const getOptimizedImageSrc = useCallback((originalSrc: string, width?: number, height?: number) => {
    if (typeof window === 'undefined') return originalSrc;

    // Adjust image quality based on connection speed
    let quality = 80; // default quality
    switch (deviceInfo.connectionType) {
      case 'slow-2g':
      case '2g':
        quality = 40;
        break;
      case '3g':
        quality = 60;
        break;
      case '4g':
      default:
        quality = 80;
        break;
    }

    // Adjust size based on device pixel ratio
    const adjustedWidth = width ? Math.round(width * deviceInfo.pixelRatio) : undefined;
    const adjustedHeight = height ? Math.round(height * deviceInfo.pixelRatio) : undefined;

    // Return optimized image URL (would integrate with your image optimization service)
    const params = new URLSearchParams();
    if (adjustedWidth) params.set('w', adjustedWidth.toString());
    if (adjustedHeight) params.set('h', adjustedHeight.toString());
    params.set('q', quality.toString());
    params.set('f', 'webp'); // Modern format for mobile

    return `${originalSrc}?${params.toString()}`;
  }, [deviceInfo.connectionType, deviceInfo.pixelRatio]);

  return { getOptimizedImageSrc };
};

// Font optimization for mobile
export const useMobileFontOptimization = () => {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const optimizeFonts = () => {
      const style = document.createElement('style');
      style.textContent = `
        @media (max-width: 768px) {
          /* Optimize font loading for mobile */
          body {
            font-display: swap;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            text-rendering: optimizeSpeed;
          }
          
          /* Reduce font sizes slightly for mobile */
          .text-sm { font-size: 0.8rem; }
          .text-base { font-size: 0.9rem; }
          .text-lg { font-size: 1rem; }
          
          /* Optimize line heights for mobile reading */
          p, div {
            line-height: 1.6;
          }
          
          /* Improve tap targets */
          button, a, [role="button"] {
            min-height: 44px;
            min-width: 44px;
            padding: 12px 16px;
          }
        }
      `;
      document.head.appendChild(style);
    };

    optimizeFonts();
  }, []);
};

// Battery optimization
export const useBatteryOptimization = () => {
  const [batteryLevel, setBatteryLevel] = useState<number>(1);
  const [isCharging, setIsCharging] = useState<boolean>(true);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const updateBatteryInfo = (battery: any) => {
      setBatteryLevel(battery.level);
      setIsCharging(battery.charging);
    };

    // Get battery information if available
    if ('getBattery' in navigator) {
      (navigator as any).getBattery().then((battery: any) => {
        updateBatteryInfo(battery);
        
        battery.addEventListener('chargingchange', () => updateBatteryInfo(battery));
        battery.addEventListener('levelchange', () => updateBatteryInfo(battery));
      });
    }
  }, []);

  // Return optimization recommendations based on battery
  const shouldReduceAnimations = batteryLevel < 0.2 && !isCharging;
  const shouldReduceQuality = batteryLevel < 0.3 && !isCharging;

  return {
    batteryLevel,
    isCharging,
    shouldReduceAnimations,
    shouldReduceQuality,
  };
};

// Network-aware loading
export const useNetworkAwareLoading = (deviceInfo: MobileDeviceInfo) => {
  const shouldPreload = deviceInfo.connectionType === '4g' || deviceInfo.connectionType === '3g';
  const shouldLazyLoad = deviceInfo.connectionType === '2g' || deviceInfo.connectionType === 'slow-2g';
  
  return {
    shouldPreload,
    shouldLazyLoad,
    connectionType: deviceInfo.connectionType,
  };
};