'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { useAnimation, MotionValue, useMotionValue, useSpring } from 'framer-motion';

// Performance monitoring hook
export const usePerformanceMonitor = () => {
  const [fps, setFps] = useState(60);
  const [isLowPerformance, setIsLowPerformance] = useState(false);
  const frameCount = useRef(0);
  const lastTime = useRef(performance.now());
  const animationId = useRef<number>();

  const measureFPS = useCallback(() => {
    const now = performance.now();
    frameCount.current++;
    
    if (now - lastTime.current >= 1000) {
      const currentFPS = Math.round((frameCount.current * 1000) / (now - lastTime.current));
      setFps(currentFPS);
      setIsLowPerformance(currentFPS < 45); // Consider < 45fps as low performance
      
      frameCount.current = 0;
      lastTime.current = now;
    }
    
    animationId.current = requestAnimationFrame(measureFPS);
  }, []);

  useEffect(() => {
    animationId.current = requestAnimationFrame(measureFPS);
    
    return () => {
      if (animationId.current) {
        cancelAnimationFrame(animationId.current);
      }
    };
  }, [measureFPS]);

  return { fps, isLowPerformance };
};

// Optimized animation settings based on performance
export const useOptimizedAnimations = () => {
  const { isLowPerformance } = usePerformanceMonitor();

  const getAnimationConfig = useCallback((type: 'fast' | 'normal' | 'slow' = 'normal') => {
    const baseConfigs = {
      fast: { duration: 0.2, ease: 'easeOut' },
      normal: { duration: 0.4, ease: 'easeInOut' },
      slow: { duration: 0.8, ease: 'easeInOut' }
    };

    const lowPerformanceConfigs = {
      fast: { duration: 0.1, ease: 'linear' },
      normal: { duration: 0.2, ease: 'linear' },
      slow: { duration: 0.4, ease: 'linear' }
    };

    return isLowPerformance ? lowPerformanceConfigs[type] : baseConfigs[type];
  }, [isLowPerformance]);

  const getSpringConfig = useCallback((type: 'gentle' | 'bouncy' | 'stiff' = 'gentle') => {
    const baseConfigs = {
      gentle: { tension: 120, friction: 14 },
      bouncy: { tension: 170, friction: 8 },
      stiff: { tension: 300, friction: 30 }
    };

    const lowPerformanceConfigs = {
      gentle: { tension: 80, friction: 20 },
      bouncy: { tension: 100, friction: 15 },
      stiff: { tension: 150, friction: 25 }
    };

    return isLowPerformance ? lowPerformanceConfigs[type] : baseConfigs[type];
  }, [isLowPerformance]);

  return { getAnimationConfig, getSpringConfig, isLowPerformance };
};

// Intersection observer for performance optimization
export const useIntersectionObserver = (
  options: IntersectionObserverInit = { threshold: 0.1 }
) => {
  const [isIntersecting, setIsIntersecting] = useState(false);
  const [hasIntersected, setHasIntersected] = useState(false);
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        setIsIntersecting(entry.isIntersecting);
        if (entry.isIntersecting && !hasIntersected) {
          setHasIntersected(true);
        }
      },
      options
    );

    observer.observe(element);

    return () => {
      if (element) observer.unobserve(element);
    };
  }, [options, hasIntersected]);

  return { ref, isIntersecting, hasIntersected };
};

// Debounced resize observer
export const useResizeObserver = (callback: (entry: ResizeObserverEntry) => void) => {
  const ref = useRef<HTMLElement>(null);
  const callbackRef = useRef(callback);
  const timeoutRef = useRef<NodeJS.Timeout>();

  // Update callback ref
  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const resizeObserver = new ResizeObserver((entries) => {
      // Debounce the callback to avoid excessive calls
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      
      timeoutRef.current = setTimeout(() => {
        callbackRef.current(entries[0]);
      }, 16); // ~60fps
    });

    resizeObserver.observe(element);

    return () => {
      resizeObserver.unobserve(element);
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  return ref;
};

// Smooth scrolling with performance optimization
export const useSmoothScroll = () => {
  const { isLowPerformance } = usePerformanceMonitor();

  const smoothScrollTo = useCallback((
    element: HTMLElement | null, 
    target: number, 
    duration: number = 300
  ) => {
    if (!element) return;

    const start = element.scrollTop;
    const distance = target - start;
    const startTime = performance.now();

    const animateScroll = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Use linear easing for low performance
      const easing = isLowPerformance 
        ? progress 
        : progress * (2 - progress); // easeOutQuad
      
      element.scrollTop = start + (distance * easing);

      if (progress < 1) {
        requestAnimationFrame(animateScroll);
      }
    };

    requestAnimationFrame(animateScroll);
  }, [isLowPerformance]);

  return { smoothScrollTo };
};

// Memory-efficient list virtualization
export const useVirtualization = <T,>(
  items: T[],
  itemHeight: number,
  containerHeight: number,
  overscan: number = 5
) => {
  const [scrollTop, setScrollTop] = useState(0);

  const visibleStart = Math.floor(scrollTop / itemHeight);
  const visibleEnd = Math.min(
    visibleStart + Math.ceil(containerHeight / itemHeight),
    items.length - 1
  );

  const startIndex = Math.max(0, visibleStart - overscan);
  const endIndex = Math.min(items.length - 1, visibleEnd + overscan);

  const visibleItems = items.slice(startIndex, endIndex + 1);
  const offsetY = startIndex * itemHeight;
  const totalHeight = items.length * itemHeight;

  return {
    visibleItems,
    startIndex,
    endIndex,
    offsetY,
    totalHeight,
    setScrollTop
  };
};

// Gesture handling with performance optimization
export const useOptimizedGestures = () => {
  const { isLowPerformance } = usePerformanceMonitor();
  
  const createPanHandler = useCallback((
    onPan: (info: { offset: { x: number; y: number }; velocity: { x: number; y: number } }) => void,
    threshold: number = 10
  ) => {
    return {
      onPan: (event: any, info: any) => {
        // Reduce sensitivity on low-performance devices
        const adjustedThreshold = isLowPerformance ? threshold * 2 : threshold;
        
        if (Math.abs(info.offset.x) > adjustedThreshold || Math.abs(info.offset.y) > adjustedThreshold) {
          onPan(info);
        }
      },
      // Reduce drag constraint updates on low-performance devices
      dragConstraints: isLowPerformance ? { left: 0, right: 0, top: 0, bottom: 0 } : undefined,
      dragElastic: isLowPerformance ? 0 : 0.2
    };
  }, [isLowPerformance]);

  return { createPanHandler };
};

// Optimized motion values with springs
export const useOptimizedMotionValues = () => {
  const { getSpringConfig } = useOptimizedAnimations();
  
  const createSmoothValue = useCallback((initialValue: number = 0, springType: 'gentle' | 'bouncy' | 'stiff' = 'gentle') => {
    const motionValue = useMotionValue(initialValue);
    const springValue = useSpring(motionValue, getSpringConfig(springType));
    
    return { motionValue, springValue };
  }, [getSpringConfig]);

  return { createSmoothValue };
};

// Battery and connection status for adaptive performance
export const useDeviceCapabilities = () => {
  const [batteryLevel, setBatteryLevel] = useState(1);
  const [isCharging, setIsCharging] = useState(true);
  const [connectionType, setConnectionType] = useState<'4g' | '3g' | '2g' | 'wifi' | 'unknown'>('unknown');
  
  useEffect(() => {
    // Battery API
    if ('getBattery' in navigator) {
      (navigator as any).getBattery().then((battery: any) => {
        setBatteryLevel(battery.level);
        setIsCharging(battery.charging);
        
        battery.addEventListener('levelchange', () => setBatteryLevel(battery.level));
        battery.addEventListener('chargingchange', () => setIsCharging(battery.charging));
      });
    }

    // Connection API
    if ('connection' in navigator) {
      const connection = (navigator as any).connection;
      setConnectionType(connection.effectiveType || 'unknown');
      
      connection.addEventListener('change', () => {
        setConnectionType(connection.effectiveType || 'unknown');
      });
    }
  }, []);

  const shouldReduceAnimations = batteryLevel < 0.2 && !isCharging;
  const shouldReduceNetworkRequests = ['2g', '3g'].includes(connectionType);

  return {
    batteryLevel,
    isCharging,
    connectionType,
    shouldReduceAnimations,
    shouldReduceNetworkRequests
  };
};

// Main performance optimization hook that combines all optimizations
export const usePerformanceOptimization = () => {
  const { fps, isLowPerformance } = usePerformanceMonitor();
  const { getAnimationConfig, getSpringConfig } = useOptimizedAnimations();
  const { shouldReduceAnimations } = useDeviceCapabilities();
  
  const optimizationLevel = useMemo(() => {
    if (shouldReduceAnimations || isLowPerformance || fps < 30) return 'high';
    if (fps < 45) return 'medium';
    return 'low';
  }, [shouldReduceAnimations, isLowPerformance, fps]);

  const getOptimizedProps = useCallback((type: 'animation' | 'spring' | 'transition' = 'animation') => {
    switch (optimizationLevel) {
      case 'high':
        return type === 'spring' 
          ? { tension: 80, friction: 20, bounce: 0 }
          : { duration: 0.1, ease: 'linear' };
      case 'medium':
        return type === 'spring'
          ? { tension: 120, friction: 15, bounce: 0.1 }
          : { duration: 0.2, ease: 'easeOut' };
      default:
        return type === 'spring'
          ? { tension: 170, friction: 12, bounce: 0.2 }
          : { duration: 0.3, ease: 'easeInOut' };
    }
  }, [optimizationLevel]);

  return {
    fps,
    isLowPerformance,
    optimizationLevel,
    getAnimationConfig,
    getSpringConfig,
    getOptimizedProps
  };
};

// Memoized hook for expensive calculations
export const useMemoizedCalculation = <T,>(
  calculation: () => T,
  dependencies: any[],
  shouldSkip: boolean = false
): T | null => {
  const [result, setResult] = useState<T | null>(null);
  const dependenciesRef = useRef(dependencies);
  
  useEffect(() => {
    if (shouldSkip) return;
    
    // Check if dependencies have changed
    const hasChanged = dependencies.some((dep, index) => dep !== dependenciesRef.current[index]);
    
    if (hasChanged) {
      // Defer expensive calculations to avoid blocking the main thread
      const timeoutId = setTimeout(() => {
        setResult(calculation());
        dependenciesRef.current = dependencies;
      }, 0);
      
      return () => clearTimeout(timeoutId);
    }
  }, [...dependencies, shouldSkip]);

  return result;
};