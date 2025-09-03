// 路由预加载工具函数

// 懒加载组件的预加载功能
export const preloadRoute = (importFunc: () => Promise<{ default: React.ComponentType<Record<string, unknown>> }>) => {
  // 在空闲时间预加载组件
  if ('requestIdleCallback' in window) {
    requestIdleCallback(() => {
      importFunc();
    });
  } else {
    // 降级方案
    setTimeout(() => {
      importFunc();
    }, 100);
  }
};

// 路由预加载钩子
export const useRoutePreload = () => {
  const preloadHomePage = () => preloadRoute(() => import('../pages/HomePage'));
  // const preloadAboutPage = () => preloadRoute(() => import('../pages/AboutPage'));
  // const preloadContactPage = () => preloadRoute(() => import('../pages/ContactPage'));
  const preloadProfilePage = () => preloadRoute(() => import('../pages/ProfilePage'));
  const preloadSettingsPage = () => preloadRoute(() => import('../pages/Settings'));
  
  return {
    preloadHomePage,
    // preloadAboutPage,
    // preloadContactPage,
    preloadProfilePage,
    preloadSettingsPage
  };
};