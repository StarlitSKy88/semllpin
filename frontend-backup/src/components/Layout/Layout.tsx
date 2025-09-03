import { Avatar, Badge, Button, Dropdown, Menu, Space, Layout as AntLayout } from 'antd';
import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '../../stores/authStore';
import useNotificationStore from '../../stores/notificationStore';
import {
  Home,
  BarChart3,
  User,
  LogOut,
  Settings,
  Bell,
  Smile,
  Menu as MenuIcon,
  Crown,
  Radar
} from 'lucide-react';

import LanguageSwitcher from '../LanguageSwitcher/LanguageSwitcher';
import ThemeToggle from '../UI/ThemeToggle';

const { Header, Sider, Content } = AntLayout;

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuthStore();
  const { isConnected, unreadCount } = useNotificationStore();
  
  // 侧边栏状态
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const menuItems = [
    {
      key: '/',
      icon: <Home size={18} />,
      label: t('navigation.home', '首页') },
    {
      key: '/lbs',
      icon: <Radar size={18} />,
      label: t('navigation.lbs', 'LBS奖励') },
    {
      key: '/dashboard',
      icon: <BarChart3 size={18} />,
      label: t('navigation.dashboard', '控制台') },
    {
      key: '/profile',
      icon: <User size={18} />,
      label: t('navigation.profile', '个人资料') },
    {
      key: '/settings',
      icon: <Settings size={18} />,
      label: t('navigation.settings', '设置') },
  ];

  // 管理员菜单项（根据权限显示）
  const adminMenuItems = user && ['admin', 'super_admin', 'moderator'].includes(user.role) ? [
    {
      key: 'admin',
      icon: <Crown size={18} />,
      label: t('navigation.admin', '管理后台'),
      children: [
        {
          key: '/admin/users',
          label: t('navigation.users', '用户管理') },
        {
          key: '/admin/content',
          label: t('navigation.content', '内容审核') },
        {
          key: '/admin/financial',
          label: t('navigation.financial', '财务管理') },
        {
          key: '/admin/analytics',
          label: t('navigation.analytics', '数据分析') },
        {
          key: '/admin/system',
          label: t('navigation.system', '系统配置') },
      ] },
  ] : [];

  // 合并所有菜单项
  const allMenuItems = [...menuItems, ...adminMenuItems];

  const userMenuItems = [
    {
      key: 'profile',
      icon: <User size={16} />,
      label: t('navigation.profile', '个人资料'),
      onClick: () => navigate('/profile') },
    {
      key: 'settings',
      icon: <Settings size={16} />,
      label: t('navigation.settings', '设置'),
      onClick: () => navigate('/settings') },
    {
      type: 'divider' as const },
    {
      key: 'logout',
      icon: <LogOut size={16} />,
      label: t('auth.logout', '退出登录'),
      onClick: handleLogout },
  ];

  // 计算当前标题（支持管理员子菜单）
  const getMenuTitle = (path: string) => {
    const simple = menuItems.find(i => i.key === path)?.label;
    if (simple) return simple;
    const adminChildren = adminMenuItems.flatMap((i: any) => i.children || []);
    return adminChildren.find((i: any) => i.key === path)?.label || t('navigation.home', '首页');
  };

  return (
    <AntLayout className="min-h-screen bg-dark-900">
      {/* 侧边栏 */}
      <Sider 
        trigger={null} 
        collapsible 
        collapsed={!sidebarOpen}
        className="bg-dark-800 shadow-2xl border-r border-dark-700"
        width={240}
        style={{
          background: 'var(--bg-secondary)',
          borderRight: '1px solid var(--border-color)'
        }}
      >
        {/* Logo */}
        <div className="h-16 flex items-center justify-center border-b border-dark-700">
          {sidebarOpen ? (
            <Space>
              <div className="w-8 h-8 bg-gradient-to-r from-accent-500 to-accent-600 rounded-xl flex items-center justify-center shadow-lg">
                <Smile className="text-white" size={20} />
              </div>
              <span className="text-lg font-bold text-light-100">SmellPin</span>
            </Space>
          ) : (
            <div className="w-8 h-8 bg-gradient-to-r from-accent-500 to-accent-600 rounded-xl flex items-center justify-center shadow-lg">
              <Smile className="text-white" size={20} />
            </div>
          )}
        </div>

        {/* 菜单 */}
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          items={allMenuItems}
          className="border-0 bg-transparent"
          onClick={({ key }) => navigate(key)}
          style={{
            background: 'transparent',
            color: 'var(--text-primary)'
          }}
          theme="dark"
        />

        {/* 用户信息 */}
        {sidebarOpen && (
          <div className="absolute bottom-4 left-4 right-4">
            <div className="bg-gradient-to-r from-dark-700 to-dark-600 rounded-xl p-3 border border-dark-600 shadow-lg backdrop-blur-sm">
              <Space>
                <Avatar src={user?.avatar} size="small" className="border-2 border-accent-500">
                  {user?.username?.[0]?.toUpperCase()}
                </Avatar>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-light-100 truncate">
                    {user?.username}
                  </div>
                  <div className="text-xs text-light-400">
                    等级 {user?.level} • {user?.points} 积分
                  </div>
                </div>
              </Space>
            </div>
          </div>
        )}
      </Sider>

      <AntLayout>
        {/* 顶部导航 */}
        <Header 
          className="shadow-lg px-4 flex items-center justify-between border-b border-dark-700"
          style={{
            background: 'var(--bg-secondary)',
            borderBottom: '1px solid var(--border-color)'
          }}
        >
          <Space>
            <Button
              type="text"
              icon={<MenuIcon size={18} />}
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-light-300 hover:text-light-100 hover:bg-dark-700 transition-all duration-200"
              style={{ color: 'var(--text-secondary)' }}
            />
            <div className="text-lg font-semibold text-light-100">
              {getMenuTitle(location.pathname)}
            </div>
          </Space>

          <Space size="large">
            {/* 主题切换器 */}
            <ThemeToggle variant="icon" size="md" />
            
            {/* 语言切换器 */}
            <LanguageSwitcher />
            
            {/* 通知 */}
            <Badge count={unreadCount} size="small">
              <Button 
                type="text" 
                icon={<Bell size={18} />} 
                onClick={() => navigate('/dashboard')}
                className="text-light-300 hover:text-light-100 hover:bg-dark-700 transition-all duration-200"
                style={{ 
                  color: isConnected ? 'var(--accent-primary)' : 'var(--text-tertiary)',
                  fontSize: '16px'
                }}
                title={isConnected ? '实时通知已连接' : '通知服务未连接'}
              />
            </Badge>

            {/* 用户菜单 */}
            <Dropdown 
              menu={{ items: userMenuItems }}
              placement="bottomRight"
              trigger={['click']}
            >
              <Space className="cursor-pointer hover:bg-dark-700 rounded-lg px-3 py-2 transition-all duration-200">
                <Avatar src={user?.avatar} size="small" className="border-2 border-accent-500">
                  {user?.username?.[0]?.toUpperCase()}
                </Avatar>
                <span className="text-light-100 font-medium">{user?.username}</span>
              </Space>
            </Dropdown>
          </Space>
        </Header>

        {/* 主内容区域 */}
        <Content 
          className="overflow-auto"
          style={{
            background: 'var(--bg-primary)',
            minHeight: 'calc(100vh - 64px)'
          }}
        >
          <div className="p-6">
            {children}
          </div>
        </Content>
      </AntLayout>
    </AntLayout>
  );
};

export default Layout;