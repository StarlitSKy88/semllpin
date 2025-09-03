'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import {
  Search,
  Filter,
  Eye,
  Calendar,
  User,
  FileText,
  RefreshCw,
  Download,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Clock,
} from 'lucide-react';
import { toast } from 'sonner';
import { adminApi, AdminLog, PaginatedResponse } from '@/lib/services/admin-api';

interface AdminLogsViewerProps {
  className?: string;
}

export function AdminLogsViewer({ className }: AdminLogsViewerProps) {
  const [logs, setLogs] = useState<AdminLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [adminFilter, setAdminFilter] = useState<string>('all');
  const [selectedLog, setSelectedLog] = useState<AdminLog | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [dateFilter, setDateFilter] = useState({
    startDate: '',
    endDate: '',
  });
  
  // 分页状态
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 0,
  });

  // 常见操作类型
  const actionTypes = [
    'update_user_status',
    'content_review',
    'batch_suspend',
    'batch_activate',
    'batch_ban',
    'batch_delete',
    'system_settings_update',
    'data_export',
    'notification_send',
  ];

  // 加载日志列表
  const loadLogs = async () => {
    setLoading(true);
    try {
      const params: any = {
        page: pagination.page,
        limit: pagination.limit,
      };

      if (actionFilter !== 'all') {
        params.action = actionFilter;
      }

      if (adminFilter !== 'all') {
        params.adminId = adminFilter;
      }

      if (dateFilter.startDate) {
        params.startDate = dateFilter.startDate;
      }

      if (dateFilter.endDate) {
        params.endDate = dateFilter.endDate;
      }

      const response = await adminApi.getAdminLogs(params);
      if (response.data.success) {
        setLogs(response.data.data.data);
        setPagination(response.data.data.pagination);
      } else {
        toast.error('获取日志列表失败');
      }
    } catch (error) {
      console.error('获取日志列表错误:', error);
      toast.error('获取日志列表失败');
    } finally {
      setLoading(false);
    }
  };

  // 初始加载和依赖变化时重新加载
  useEffect(() => {
    loadLogs();
  }, [pagination.page, pagination.limit, actionFilter, adminFilter, dateFilter]);

  // 获取操作类型徽章
  const getActionBadge = (action: string) => {
    if (action.includes('batch')) {
      return <Badge variant="secondary" className="bg-purple-100 text-purple-800">批量操作</Badge>;
    } else if (action.includes('user')) {
      return <Badge variant="default" className="bg-blue-100 text-blue-800">用户管理</Badge>;
    } else if (action.includes('content')) {
      return <Badge variant="secondary" className="bg-green-100 text-green-800">内容审核</Badge>;
    } else if (action.includes('system')) {
      return <Badge variant="destructive" className="bg-red-100 text-red-800">系统操作</Badge>;
    } else {
      return <Badge variant="outline">其他</Badge>;
    }
  };

  // 格式化操作名称
  const formatActionName = (action: string) => {
    const actionMap: Record<string, string> = {
      'update_user_status': '更新用户状态',
      'content_review': '内容审核',
      'batch_suspend': '批量暂停',
      'batch_activate': '批量激活',
      'batch_ban': '批量封禁',
      'batch_delete': '批量删除',
      'system_settings_update': '系统设置更新',
      'data_export': '数据导出',
      'notification_send': '发送通知',
    };
    return actionMap[action] || action;
  };

  // 格式化日期
  const formatDate = (dateString: string | Date) => {
    return new Date(dateString).toLocaleString('zh-CN');
  };

  // 搜索防抖
  useEffect(() => {
    const timer = setTimeout(() => {
      if (pagination.page !== 1) {
        setPagination(prev => ({ ...prev, page: 1 }));
      } else {
        loadLogs();
      }
    }, 500);

    return () => clearTimeout(timer);
  }, [searchTerm]);

  // 导出日志
  const exportLogs = async () => {
    try {
      toast.info('正在导出日志...');
      // 这里可以调用导出API
      // const response = await adminApi.exportData('logs', 'csv');
      toast.success('日志导出成功');
    } catch (error) {
      console.error('导出日志错误:', error);
      toast.error('导出日志失败');
    }
  };

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileText className="h-5 w-5" />
            <span>管理员日志</span>
          </CardTitle>
          <CardDescription>查看所有管理员操作记录和系统审计日志</CardDescription>
        </CardHeader>
        <CardContent>
          {/* 搜索和筛选工具栏 */}
          <div className="flex flex-col lg:flex-row gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="搜索操作内容..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            
            <div className="flex gap-2">
              <Select value={actionFilter} onValueChange={setActionFilter}>
                <SelectTrigger className="w-[140px]">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="操作类型" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部操作</SelectItem>
                  {actionTypes.map(action => (
                    <SelectItem key={action} value={action}>
                      {formatActionName(action)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <div className="flex gap-2">
                <Input
                  type="date"
                  placeholder="开始日期"
                  value={dateFilter.startDate}
                  onChange={(e) => setDateFilter(prev => ({ ...prev, startDate: e.target.value }))}
                  className="w-[140px]"
                />
                <Input
                  type="date"
                  placeholder="结束日期"
                  value={dateFilter.endDate}
                  onChange={(e) => setDateFilter(prev => ({ ...prev, endDate: e.target.value }))}
                  className="w-[140px]"
                />
              </div>

              <Button
                variant="outline"
                onClick={loadLogs}
                disabled={loading}
                className="flex items-center space-x-2"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                <span>刷新</span>
              </Button>

              <Button
                variant="outline"
                onClick={exportLogs}
                className="flex items-center space-x-2"
              >
                <Download className="h-4 w-4" />
                <span>导出</span>
              </Button>
            </div>
          </div>

          {/* 日志列表 */}
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>操作时间</TableHead>
                  <TableHead>管理员</TableHead>
                  <TableHead>操作类型</TableHead>
                  <TableHead>目标对象</TableHead>
                  <TableHead>操作详情</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8">
                      <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2" />
                      <span className="text-gray-500">加载中...</span>
                    </TableCell>
                  </TableRow>
                ) : logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-gray-500">
                      没有找到符合条件的日志记录
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell>
                        <div className="flex items-center space-x-2 text-sm">
                          <Clock className="h-3 w-3" />
                          <span>{formatDate(log.created_at)}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <User className="h-4 w-4 text-gray-500" />
                          <span className="font-medium">{log.admin_username || '未知'}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          {getActionBadge(log.action)}
                          <div className="text-xs text-gray-600">
                            {formatActionName(log.action)}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          <div className="font-medium">{log.target_type}</div>
                          <div className="text-gray-500 text-xs font-mono">
                            {log.target_id?.slice(-8) || 'N/A'}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm max-w-xs truncate">
                          {log.details ? (
                            typeof log.details === 'string' 
                              ? log.details 
                              : JSON.stringify(log.details).slice(0, 100) + '...'
                          ) : '无详情'}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSelectedLog(log);
                            setIsDetailOpen(true);
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* 分页控件 */}
          {pagination.totalPages > 1 && (
            <div className="flex items-center justify-between mt-6">
              <div className="text-sm text-gray-500">
                显示第 {((pagination.page - 1) * pagination.limit) + 1} - {Math.min(pagination.page * pagination.limit, pagination.total)} 条，
                共 {pagination.total} 条记录
              </div>
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPagination(prev => ({ ...prev, page: 1 }))}
                  disabled={pagination.page === 1}
                >
                  <ChevronsLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPagination(prev => ({ ...prev, page: Math.max(1, prev.page - 1) }))}
                  disabled={pagination.page === 1}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-sm px-4">
                  第 {pagination.page} / {pagination.totalPages} 页
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPagination(prev => ({ ...prev, page: Math.min(prev.totalPages, prev.page + 1) }))}
                  disabled={pagination.page === pagination.totalPages}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPagination(prev => ({ ...prev, page: prev.totalPages }))}
                  disabled={pagination.page === pagination.totalPages}
                >
                  <ChevronsRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 日志详情弹窗 */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <FileText className="h-5 w-5" />
              <span>操作日志详情</span>
            </DialogTitle>
            <DialogDescription>
              查看管理员操作的详细信息和上下文
            </DialogDescription>
          </DialogHeader>
          
          {selectedLog && (
            <div className="space-y-6">
              {/* 基本信息 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">基本信息</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>日志ID</Label>
                      <div className="p-2 bg-gray-50 rounded font-mono">{selectedLog.id}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>操作时间</Label>
                      <div className="p-2 bg-gray-50 rounded">{formatDate(selectedLog.created_at)}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>管理员</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {selectedLog.admin_username || '未知'} (ID: {selectedLog.admin_id})
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>操作类型</Label>
                      <div className="flex items-center space-x-2">
                        {getActionBadge(selectedLog.action)}
                        <span>{formatActionName(selectedLog.action)}</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 目标对象信息 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">目标对象</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>对象类型</Label>
                      <div className="p-2 bg-gray-50 rounded">{selectedLog.target_type}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>对象ID</Label>
                      <div className="p-2 bg-gray-50 rounded font-mono">{selectedLog.target_id}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 操作详情 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">操作详情</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <Label>详细信息</Label>
                      <div className="mt-2 p-4 bg-gray-50 rounded-lg">
                        <pre className="whitespace-pre-wrap text-sm">
                          {selectedLog.details 
                            ? JSON.stringify(selectedLog.details, null, 2)
                            : '无详细信息'
                          }
                        </pre>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default AdminLogsViewer;