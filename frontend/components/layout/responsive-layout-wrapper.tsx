'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useMediaQuery } from '@/hooks/use-media-query';
import { 
  Menu, X, ChevronUp, ChevronDown, Settings, 
  User, Map, Trophy, Wallet, Bell, Search
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface ResponsiveLayoutWrapperProps {
  children: React.ReactNode;
  navigation?: React.ReactNode;
  sidebar?: React.ReactNode;
  className?: string;
}

interface NavigationItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  href?: string;
  onClick?: () => void;
}

const ResponsiveLayoutWrapper: React.FC<ResponsiveLayoutWrapperProps> = ({
  children,
  navigation,
  sidebar,
  className = ""
}) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isBottomSheetOpen, setIsBottomSheetOpen] = useState(false);
  const [sidebarContent, setSidebarContent] = useState<'tracker' | 'achievements' | 'wallet' | null>(null);
  
  // Responsive breakpoints
  const isMobile = useMediaQuery('(max-width: 768px)');
  const isTablet = useMediaQuery('(min-width: 769px) and (max-width: 1024px)');
  const isDesktop = useMediaQuery('(min-width: 1025px)');

  // Handle escape key
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsMobileMenuOpen(false);
        setIsBottomSheetOpen(false);
        setSidebarContent(null);
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, []);

  // Handle mobile menu toggle
  const toggleMobileMenu = useCallback(() => {
    setIsMobileMenuOpen(prev => !prev);
  }, []);

  // Handle bottom sheet toggle
  const toggleBottomSheet = useCallback(() => {
    setIsBottomSheetOpen(prev => !prev);
  }, []);

  // Navigation items
  const navigationItems: NavigationItem[] = [
    {
      id: 'map',
      label: '地图',
      icon: Map,
      onClick: () => setSidebarContent(null)
    },
    {
      id: 'tracker',
      label: '追踪',
      icon: Settings,
      badge: '新',
      onClick: () => setSidebarContent('tracker')
    },
    {
      id: 'achievements',
      label: '成就',
      icon: Trophy,
      badge: '3',
      onClick: () => setSidebarContent('achievements')
    },
    {
      id: 'wallet',
      label: '钱包',
      icon: Wallet,
      onClick: () => setSidebarContent('wallet')
    },
    {
      id: 'profile',
      label: '个人',
      icon: User,
      onClick: () => {}
    }
  ];

  // Mobile Navigation Component
  const MobileNavigation = () => (
    <AnimatePresence>
      {isMobileMenuOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
            onClick={() => setIsMobileMenuOpen(false)}
          />
          
          {/* Menu */}
          <motion.div
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
            className="fixed left-0 top-0 bottom-0 w-80 bg-white/10 backdrop-blur-xl border-r border-white/20 z-50 p-6"
          >
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-xl font-bold text-white">SmellPin</h2>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setIsMobileMenuOpen(false)}
                className="text-white hover:bg-white/10"
              >
                <X className="w-5 h-5" />
              </Button>
            </div>

            <nav className="space-y-2">
              {navigationItems.map((item) => {
                const IconComponent = item.icon;
                return (
                  <motion.button
                    key={item.id}
                    whileHover={{ x: 4 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => {
                      item.onClick?.();
                      setIsMobileMenuOpen(false);
                    }}
                    className="w-full flex items-center gap-3 p-3 rounded-xl text-left text-white hover:bg-white/10 transition-colors"
                  >
                    <IconComponent className="w-5 h-5" />
                    <span className="font-medium">{item.label}</span>
                    {item.badge && (
                      <Badge className="ml-auto bg-red-500 text-white text-xs">
                        {item.badge}
                      </Badge>
                    )}
                  </motion.button>
                );
              })}
            </nav>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );

  // Bottom Navigation Component (Mobile)
  const BottomNavigation = () => (
    <motion.div
      initial={{ y: 100 }}
      animate={{ y: 0 }}
      className="fixed bottom-0 left-0 right-0 bg-white/10 backdrop-blur-xl border-t border-white/20 z-30 safe-area-padding-bottom"
    >
      <div className="flex items-center justify-around p-3">
        {navigationItems.map((item) => {
          const IconComponent = item.icon;
          const isActive = sidebarContent === item.id || (item.id === 'map' && !sidebarContent);
          
          return (
            <motion.button
              key={item.id}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={item.onClick}
              className={`relative flex flex-col items-center gap-1 p-2 rounded-lg transition-colors ${
                isActive ? 'text-blue-400 bg-blue-400/20' : 'text-white/60 hover:text-white hover:bg-white/10'
              }`}
            >
              <IconComponent className="w-5 h-5" />
              <span className="text-xs font-medium">{item.label}</span>
              {item.badge && (
                <Badge className="absolute -top-1 -right-1 bg-red-500 text-white text-xs w-4 h-4 p-0 flex items-center justify-center">
                  {item.badge}
                </Badge>
              )}
            </motion.button>
          );
        })}
      </div>
    </motion.div>
  );

  // Desktop Sidebar Component
  const DesktopSidebar = () => (
    <AnimatePresence>
      {sidebarContent && (
        <motion.div
          initial={{ width: 0, opacity: 0 }}
          animate={{ width: 400, opacity: 1 }}
          exit={{ width: 0, opacity: 0 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
          className="fixed right-0 top-0 bottom-0 bg-white/10 backdrop-blur-xl border-l border-white/20 z-40 overflow-hidden"
        >
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between p-6 border-b border-white/10">
              <h3 className="text-lg font-semibold text-white capitalize">
                {sidebarContent === 'tracker' && '位置追踪'}
                {sidebarContent === 'achievements' && '成就系统'}
                {sidebarContent === 'wallet' && '我的钱包'}
              </h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSidebarContent(null)}
                className="text-white hover:bg-white/10"
              >
                <X className="w-5 h-5" />
              </Button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-6">
              {sidebar}
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  // Mobile Bottom Sheet Component
  const MobileBottomSheet = () => (
    <AnimatePresence>
      {isBottomSheetOpen && sidebarContent && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
            onClick={() => setIsBottomSheetOpen(false)}
          />
          
          {/* Bottom Sheet */}
          <motion.div
            initial={{ y: '100%' }}
            animate={{ y: 0 }}
            exit={{ y: '100%' }}
            drag="y"
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0, bottom: 0.2 }}
            onDragEnd={(_, info) => {
              if (info.offset.y > 100) {
                setIsBottomSheetOpen(false);
              }
            }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
            className="fixed bottom-0 left-0 right-0 bg-white/10 backdrop-blur-xl border-t border-white/20 z-50 max-h-[80vh] rounded-t-3xl"
          >
            {/* Handle */}
            <div className="flex justify-center py-3">
              <div className="w-12 h-1 bg-white/30 rounded-full" />
            </div>
            
            <div className="px-6 pb-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">
                  {sidebarContent === 'tracker' && '位置追踪'}
                  {sidebarContent === 'achievements' && '成就系统'}
                  {sidebarContent === 'wallet' && '我的钱包'}
                </h3>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsBottomSheetOpen(false)}
                  className="text-white hover:bg-white/10"
                >
                  <ChevronDown className="w-5 h-5" />
                </Button>
              </div>
              
              <div className="max-h-[60vh] overflow-y-auto">
                {sidebar}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );

  // Show sidebar content in bottom sheet on mobile
  useEffect(() => {
    if (sidebarContent && isMobile) {
      setIsBottomSheetOpen(true);
    }
  }, [sidebarContent, isMobile]);

  return (
    <div className={`min-h-screen bg-gradient-to-br from-purple-900 via-blue-900 to-black relative overflow-hidden ${className}`}>
      {/* Background effects */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http://www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fill-rule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%23ffffff%22%20fill-opacity%3D%220.03%22%3E%3Cpath%20d%3D%22M36%2034v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6%2034v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6%204V0H4v4H0v2h4v4h2V6h4V4H6z%22/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] opacity-20" />

      {/* Mobile Header */}
      {isMobile && (
        <motion.header
          initial={{ y: -100 }}
          animate={{ y: 0 }}
          className="fixed top-0 left-0 right-0 bg-white/10 backdrop-blur-xl border-b border-white/20 z-30 safe-area-padding-top"
        >
          <div className="flex items-center justify-between p-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={toggleMobileMenu}
              className="text-white hover:bg-white/10"
            >
              <Menu className="w-5 h-5" />
            </Button>
            
            <h1 className="text-lg font-bold text-white">SmellPin</h1>
            
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                className="text-white hover:bg-white/10 relative"
              >
                <Bell className="w-5 h-5" />
                <Badge className="absolute -top-1 -right-1 bg-red-500 text-white text-xs w-4 h-4 p-0 flex items-center justify-center">
                  3
                </Badge>
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="text-white hover:bg-white/10"
              >
                <Search className="w-5 h-5" />
              </Button>
            </div>
          </div>
        </motion.header>
      )}

      {/* Desktop Navigation */}
      {isDesktop && (
        <motion.nav
          initial={{ x: -100 }}
          animate={{ x: 0 }}
          className="fixed left-0 top-0 bottom-0 w-20 bg-white/10 backdrop-blur-xl border-r border-white/20 z-30 flex flex-col items-center py-6"
        >
          <div className="mb-8">
            <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-500 rounded-xl flex items-center justify-center">
              <span className="text-white font-bold text-lg">S</span>
            </div>
          </div>

          <div className="flex-1 flex flex-col gap-4">
            {navigationItems.map((item) => {
              const IconComponent = item.icon;
              const isActive = sidebarContent === item.id || (item.id === 'map' && !sidebarContent);
              
              return (
                <motion.button
                  key={item.id}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={item.onClick}
                  className={`relative p-3 rounded-xl transition-colors ${
                    isActive ? 'bg-blue-500 text-white' : 'text-white/60 hover:text-white hover:bg-white/10'
                  }`}
                  title={item.label}
                >
                  <IconComponent className="w-5 h-5" />
                  {item.badge && (
                    <Badge className="absolute -top-1 -right-1 bg-red-500 text-white text-xs w-4 h-4 p-0 flex items-center justify-center">
                      {item.badge}
                    </Badge>
                  )}
                </motion.button>
              );
            })}
          </div>
        </motion.nav>
      )}

      {/* Main Content */}
      <main className={`
        relative z-10
        ${isMobile ? 'pt-20 pb-20' : ''}
        ${isTablet ? 'pb-20' : ''}
        ${isDesktop ? 'ml-20' : ''}
        ${sidebarContent && isDesktop ? 'mr-[400px]' : ''}
        transition-all duration-300
      `}>
        {children}
      </main>

      {/* Navigation Components */}
      <MobileNavigation />
      {(isMobile || isTablet) && <BottomNavigation />}
      {isDesktop && <DesktopSidebar />}
      {isMobile && <MobileBottomSheet />}

      {/* Accessibility */}
      <div className="sr-only" role="region" aria-label="Navigation landmarks">
        <p>Use tab to navigate between map controls and menu items</p>
        <p>Press escape to close modal dialogs and side panels</p>
        <p>Mobile users can swipe down to dismiss bottom sheets</p>
      </div>
    </div>
  );
};

// Custom hook for media queries
const useMediaQuery = (query: string): boolean => {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    if (media.matches !== matches) {
      setMatches(media.matches);
    }
    
    const listener = () => setMatches(media.matches);
    media.addEventListener('change', listener);
    
    return () => media.removeEventListener('change', listener);
  }, [matches, query]);

  return matches;
};

export default ResponsiveLayoutWrapper;