import { useEffect, useCallback, useMemo, useRef, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';
import { useAuthStore } from './stores/authStore';
import useNotificationStore from './stores/notificationStore';
import { AccessibilityProvider } from './components/AccessibilityTools';
import { ThemeProvider } from './contexts/ThemeContext';
import Navbar from './components/Layout/Layout';

import ErrorBoundary from './components/common/ErrorBoundary';
import HomePage from './pages/HomePage';
import MapPage from './pages/MapPage';
import AboutPage from './pages/AboutPage';
import Login from './pages/LoginPage';
import Register from './pages/RegisterPage';
import Dashboard from './pages/AdminDashboardPage';
import AdminUserManagement from './pages/AdminUserManagementPage';
import AdminContentReview from './pages/AdminContentReviewPage';
import AdminFinancialManagement from './pages/AdminFinancialManagementPage';
import AdminDataAnalytics from './pages/AdminDataAnalyticsPage';
import AdminSystemConfig from './pages/AdminSystemConfigPage';
import Profile from './pages/ProfilePage';
import Settings from './pages/Settings';
import LBSDemo from './pages/LBSDemo';
import './App.css';

function App() {
  const { isAuthenticated, checkAuth, token, isLoading } = useAuthStore();
  const { connectWebSocket, disconnectWebSocket, isConnected } = useNotificationStore();
  
  // 防止重复初始化的标记
  const initRef = useRef(false);
  const wsConnectedRef = useRef(false);
  const mountedRef = useRef(true);
  
  // 添加内部状态来控制渲染
  const [appReady, setAppReady] = useState(false);
  const [renderKey, setRenderKey] = useState(0);
  
  // 使用useCallback防止函数重新创建，添加更严格的检查
  const handleCheckAuth = useCallback(() => {
    if (!initRef.current && mountedRef.current && !isLoading) {
      initRef.current = true;
      checkAuth();
    }
  }, [checkAuth, isLoading]);
  
  const handleWebSocketConnection = useCallback(() => {
    if (!mountedRef.current) return;
    
    const shouldConnect = isAuthenticated && token && !isConnected && !wsConnectedRef.current;
    const shouldDisconnect = (!isAuthenticated || !token) && (isConnected || wsConnectedRef.current);
    
    if (shouldConnect) {
      wsConnectedRef.current = true;
      connectWebSocket();
    } else if (shouldDisconnect) {
      wsConnectedRef.current = false;
      disconnectWebSocket();
    }
  }, [isAuthenticated, token, isConnected, connectWebSocket, disconnectWebSocket]);

  // 组件挂载时的初始化
  useEffect(() => {
    mountedRef.current = true;
    
    // 延迟初始化，避免立即触发状态更新
    const initTimer = setTimeout(() => {
      if (mountedRef.current) {
        handleCheckAuth();
        setAppReady(true);
      }
    }, 100);
    
    return () => {
      clearTimeout(initTimer);
      mountedRef.current = false;
    };
  }, [handleCheckAuth]); // 添加handleCheckAuth依赖
  
  // 初始化通知权限和WebSocket连接
  useEffect(() => {
    if (!appReady || !mountedRef.current) return;
    
    // 请求通知权限
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission().catch(() => {
        // 忽略权限请求失败
      });
    }
    
    // 延迟WebSocket连接，避免与认证检查冲突
    const wsTimer = setTimeout(() => {
      if (mountedRef.current) {
        handleWebSocketConnection();
      }
    }, 200);
    
    return () => {
      clearTimeout(wsTimer);
    };
  }, [appReady, handleWebSocketConnection]); // 添加handleWebSocketConnection依赖

  // 使用useMemo缓存路由配置，避免不必要的重新渲染
  const routes = useMemo(() => {
    // 添加更严格的状态检查
    const authChecked = typeof isAuthenticated === 'boolean' && !isLoading;
    
    if (!appReady || !authChecked) {
      // 认证状态未确定时显示加载状态
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-2"></div>
            <p className="text-gray-600">正在加载...</p>
          </div>
        </div>
      );
    }
    
    return (
      <Routes>
        {/* HomePage不使用Navbar布局，实现全屏效果 */}
        <Route path="/" element={<HomePage />} />
        
        {/* 地图页面和关于页面使用Navbar布局 */}
        <Route 
          path="/map" 
          element={
            <Navbar>
              <main className="container mx-auto px-4 py-8">
                <MapPage />
              </main>
            </Navbar>
          } 
        />
        <Route 
          path="/about" 
          element={
            <Navbar>
              <main className="container mx-auto px-4 py-8">
                <AboutPage />
              </main>
            </Navbar>
          } 
        />
        
        {/* 其他页面使用Navbar布局 */}
        <Route 
          path="/login" 
          element={
            isAuthenticated ? (
              <Navigate to="/dashboard" />
            ) : (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <Login />
                </main>
              </Navbar>
            )
          } 
        />
        <Route 
          path="/register" 
          element={
            isAuthenticated ? (
              <Navigate to="/dashboard" />
            ) : (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <Register />
                </main>
              </Navbar>
            )
          } 
        />
        <Route 
          path="/dashboard" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <Dashboard />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/admin/users" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <AdminUserManagement />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/admin/content" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <AdminContentReview />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/admin/financial" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <AdminFinancialManagement />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/admin/analytics" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <AdminDataAnalytics />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/admin/system" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <AdminSystemConfig />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/profile" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <Profile />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/settings" 
          element={
            isAuthenticated ? (
              <Navbar>
                <main className="container mx-auto px-4 py-8">
                  <Settings />
                </main>
              </Navbar>
            ) : (
              <Navigate to="/login" />
            )
          } 
        />
        <Route 
          path="/lbs" 
          element={
            <Navbar>
              <main className="container mx-auto px-4 py-8">
                <LBSDemo />
              </main>
            </Navbar>
          } 
        />
      </Routes>
    );
  }, [isAuthenticated, isLoading, appReady]);

  // 组件卸载时的清理
  useEffect(() => {
    return () => {
      mountedRef.current = false;
      if (wsConnectedRef.current) {
        wsConnectedRef.current = false;
        disconnectWebSocket();
      }
    };
  }, [disconnectWebSocket]);
  
  // 错误恢复机制
  const handleError = useCallback((error: Error) => {
    console.error('App组件捕获到错误:', error);
    if (error.message.includes('Maximum update depth exceeded')) {
      // 重置渲染状态
      setRenderKey(prev => prev + 1);
      initRef.current = false;
      wsConnectedRef.current = false;
    }
  }, []);

  return (
    <ErrorBoundary onError={handleError}>
      <ThemeProvider>
        <AccessibilityProvider>
          <Router>
            <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-300" key={renderKey}>
              {routes}
              
              {/* Toast通知 */}
              <Toaster position="top-right" richColors />
            </div>
          </Router>
        </AccessibilityProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
};

export default App;
