'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import {
  Users,
  MapPin,
  DollarSign,
  AlertTriangle,
  Shield,
  TrendingUp,
  TrendingDown,
  RefreshCw,
} from 'lucide-react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';

// 组件导入
import { AnalyticsCharts } from '@/components/admin/analytics-charts';
import { EnhancedUserManagement } from '@/components/admin/enhanced-user-management';
import { EnhancedContentModeration } from '@/components/admin/enhanced-content-moderation';
import { AdminLogsViewer } from '@/components/admin/admin-logs-viewer';
import ReportManagement from '@/components/admin/report-management';
import SystemSettings from '@/components/admin/system-settings';

// API导入
import { adminApi, AdminStats } from '@/lib/services/admin-api';

export default function AdminDashboard() {
  const { user } = useAuthStore();
  const router = useRouter();
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(true);

  // 加载统计数据
  const loadStats = async () => {
    try {
      const response = await adminApi.getStats();
      if (response.data.success) {
        setStats(response.data.data);
      } else {
        toast.error('获取统计数据失败');
      }
    } catch (error) {
      console.error('获取统计数据错误:', error);
      toast.error('获取统计数据失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // 检查用户是否为管理员
    if (!user || !['admin', 'super_admin', 'moderator'].includes(user.role)) {
      router.push('/');
      return;
    }
    
    loadStats();
  }, [user, router]);

  if (!user || !['admin', 'super_admin', 'moderator'].includes(user.role)) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Shield className="h-16 w-16 mx-auto text-gray-400 mb-4" />
          <h1 className="text-2xl font-bold text-gray-900 mb-2">访问被拒绝</h1>
          <p className="text-gray-600">您没有权限访问管理后台</p>
        </div>
      </div>
    );
  }



  return (
    <div className="min-h-screen bg-gray-50 p-4 sm:p-6 lg:p-8">
      <div className="max-w-7xl mx-auto">
        {/* 页面标题 */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">管理后台</h1>
              <p className="text-gray-600">SmellPin 平台管理控制台</p>
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="outline" className="text-blue-600 border-blue-600">
                {user.role === 'admin' ? '管理员' : 
                 user.role === 'moderator' ? '版主' : '用户'}
              </Badge>
              <button
                onClick={loadStats}
                disabled={loading}
                className="p-2 text-gray-500 hover:text-gray-700 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>
        </div>

        {/* 统计卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">总用户数</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="animate-pulse">
                  <div className="h-8 bg-gray-200 rounded mb-2"></div>
                  <div className="h-4 bg-gray-200 rounded w-2/3"></div>
                </div>
              ) : (
                <>
                  <div className="text-2xl font-bold">{stats?.totalUsers?.toLocaleString() || 0}</div>
                  <div className="flex items-center text-xs text-muted-foreground">
                    <span>活跃: {stats?.activeUsers || 0}</span>
                    <span className="mx-2">|</span>
                    <span>暂停: {stats?.suspendedUsers || 0}</span>
                    <span className="mx-2">|</span>
                    <span>封禁: {stats?.bannedUsers || 0}</span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">标注统计</CardTitle>
              <MapPin className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="animate-pulse">
                  <div className="h-8 bg-gray-200 rounded mb-2"></div>
                  <div className="h-4 bg-gray-200 rounded w-2/3"></div>
                </div>
              ) : (
                <>
                  <div className="text-2xl font-bold">{stats?.totalAnnotations?.toLocaleString() || 0}</div>
                  <div className="flex items-center text-xs text-muted-foreground">
                    <span className="text-green-600">通过: {stats?.approvedAnnotations || 0}</span>
                    <span className="mx-2">|</span>
                    <span className="text-yellow-600">待审: {stats?.pendingAnnotations || 0}</span>
                    <span className="mx-2">|</span>
                    <span className="text-red-600">拒绝: {stats?.rejectedAnnotations || 0}</span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">收入统计</CardTitle>
              <DollarSign className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="animate-pulse">
                  <div className="h-8 bg-gray-200 rounded mb-2"></div>
                  <div className="h-4 bg-gray-200 rounded w-2/3"></div>
                </div>
              ) : (
                <>
                  <div className="text-2xl font-bold">¥{stats?.totalRevenue?.toLocaleString() || 0}</div>
                  <div className="flex items-center text-xs text-muted-foreground">
                    <TrendingUp className="h-3 w-3 text-green-600 mr-1" />
                    <span>本月: ¥{stats?.monthlyRevenue?.toLocaleString() || 0}</span>
                    <span className="mx-2">|</span>
                    <span>交易: {stats?.totalTransactions || 0}</span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">待处理</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="animate-pulse">
                  <div className="h-8 bg-gray-200 rounded mb-2"></div>
                  <div className="h-4 bg-gray-200 rounded w-2/3"></div>
                </div>
              ) : (
                <>
                  <div className="text-2xl font-bold">{stats?.pendingReports || 0}</div>
                  <p className="text-xs text-muted-foreground">待处理举报</p>
                </>
              )}
            </CardContent>
          </Card>
        </div>

        {/* 主要内容区域 */}
        <Tabs defaultValue="users" className="space-y-6">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="users">用户管理</TabsTrigger>
            <TabsTrigger value="annotations">内容审核</TabsTrigger>
            <TabsTrigger value="reports">举报管理</TabsTrigger>
            <TabsTrigger value="analytics">数据分析</TabsTrigger>
            <TabsTrigger value="logs">操作日志</TabsTrigger>
            <TabsTrigger value="settings">系统设置</TabsTrigger>
          </TabsList>

          {/* 增强的用户管理 */}
          <TabsContent value="users">
            <EnhancedUserManagement />
          </TabsContent>

          {/* 内容审核管理 */}
          <TabsContent value="annotations">
            <EnhancedContentModeration />
          </TabsContent>

          {/* 举报管理 */}
          <TabsContent value="reports">
            <ReportManagement />
          </TabsContent>

          {/* 数据分析 */}
          <TabsContent value="analytics">
            <AnalyticsCharts />
          </TabsContent>

          {/* 管理员日志 */}
          <TabsContent value="logs">
            <AdminLogsViewer />
          </TabsContent>

          {/* 系统设置 */}
          <TabsContent value="settings">
            <SystemSettings />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}