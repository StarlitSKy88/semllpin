import { useState, useEffect, createContext, useContext } from 'react';

// 移动端上下文
interface MobileContextType {
  isMobile: boolean;
  isTablet: boolean;
  orientation: 'portrait' | 'landscape';
  viewportHeight: number;
  safeAreaInsets: {
    top: number;
    bottom: number;
    left: number;
    right: number;
  };
}

const MobileContext = createContext<MobileContextType | undefined>(undefined);

// 移动端Hook
export const useMobile = () => {
  const context = useContext(MobileContext);
  if (!context) {
    throw new Error('useMobile must be used within MobileProvider');
  }
  return context;
};

// 移动端状态管理Hook
export const useMobileState = () => {
  const [mobileState, setMobileState] = useState<MobileContextType>({
    isMobile: false,
    isTablet: false,
    orientation: 'portrait',
    viewportHeight: window.innerHeight,
    safeAreaInsets: { top: 0, bottom: 0, left: 0, right: 0 }
  });

  useEffect(() => {
    const updateMobileState = () => {
      const width = window.innerWidth;
      const height = window.innerHeight;
      
      // 检测设备类型
      const isMobile = width < 768;
      const isTablet = width >= 768 && width < 1024;
      const orientation = width > height ? 'landscape' : 'portrait';
      
      // 获取安全区域（iOS）
      const safeAreaInsets = {
        top: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sat') || '0'),
        bottom: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sab') || '0'),
        left: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sal') || '0'),
        right: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sar') || '0')
      };

      setMobileState({
        isMobile,
        isTablet,
        orientation,
        viewportHeight: height,
        safeAreaInsets
      });
    };

    // 初始化
    updateMobileState();

    // 监听窗口变化
    window.addEventListener('resize', updateMobileState);
    window.addEventListener('orientationchange', updateMobileState);

    return () => {
      window.removeEventListener('resize', updateMobileState);
      window.removeEventListener('orientationchange', updateMobileState);
    };
  }, []);

  return mobileState;
};

// 移动端虚拟键盘适配Hook
export const useVirtualKeyboard = () => {
  const [keyboardHeight, setKeyboardHeight] = useState(0);
  const [isKeyboardOpen, setIsKeyboardOpen] = useState(false);

  useEffect(() => {
    const handleResize = () => {
      const viewportHeight = window.visualViewport?.height || window.innerHeight;
      const windowHeight = window.innerHeight;
      const heightDiff = windowHeight - viewportHeight;
      
      if (heightDiff > 150) {
        setKeyboardHeight(heightDiff);
        setIsKeyboardOpen(true);
      } else {
        setKeyboardHeight(0);
        setIsKeyboardOpen(false);
      }
    };

    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', handleResize);
    } else {
      window.addEventListener('resize', handleResize);
    }

    return () => {
      if (window.visualViewport) {
        window.visualViewport.removeEventListener('resize', handleResize);
      } else {
        window.removeEventListener('resize', handleResize);
      }
    };
  }, []);

  return { keyboardHeight, isKeyboardOpen };
};

export { MobileContext };
export type { MobileContextType };