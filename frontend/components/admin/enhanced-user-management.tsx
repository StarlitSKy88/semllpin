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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Search,
  Filter,
  Eye,
  Ban,
  CheckCircle,
  XCircle,
  RefreshCw,
  Download,
  Users,
  Phone,
  Mail,
  User,
  Shield,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';
import { toast } from 'sonner';
import { adminApi, UserManagement as UserManagementType, PaginatedResponse } from '@/lib/services/admin-api';

type UserStatus = 'active' | 'suspended' | 'banned' | 'pending';
type SortBy = 'created_at' | 'username' | 'email' | 'total_annotations' | 'total_spent' | 'reports_count';

interface EnhancedUserManagementProps {
  className?: string;
}

export function EnhancedUserManagement({ className }: EnhancedUserManagementProps) {
  const [users, setUsers] = useState<UserManagementType[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<SortBy>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedUser, setSelectedUser] = useState<UserManagementType | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  
  // 分页状态
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0,
  });

  // 加载用户列表
  const loadUsers = async () => {
    setLoading(true);
    try {
      const params: any = {
        page: pagination.page,
        limit: pagination.limit,
        sortBy,
        sortOrder,
      };

      if (searchTerm.trim()) {
        params.search = searchTerm.trim();
      }

      if (statusFilter !== 'all') {
        params.status = statusFilter;
      }

      const response = await adminApi.getUsers(params);
      if (response.data.success) {
        setUsers(response.data.data.data);
        setPagination(response.data.data.pagination);
      } else {
        toast.error('获取用户列表失败');
      }
    } catch (error) {
      console.error('获取用户列表错误:', error);
      toast.error('获取用户列表失败');
    } finally {
      setLoading(false);
    }
  };

  // 初始加载和依赖变化时重新加载
  useEffect(() => {
    loadUsers();
  }, [pagination.page, pagination.limit, sortBy, sortOrder, statusFilter]);

  // 搜索防抖
  useEffect(() => {
    const timer = setTimeout(() => {
      if (pagination.page !== 1) {
        setPagination(prev => ({ ...prev, page: 1 }));
      } else {
        loadUsers();
      }
    }, 500);

    return () => clearTimeout(timer);
  }, [searchTerm]);

  // 获取状态徽章
  const getStatusBadge = (status: UserStatus) => {
    switch (status) {
      case 'active':
        return <Badge variant="default" className="bg-green-100 text-green-800">正常</Badge>;
      case 'suspended':
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">暂停</Badge>;
      case 'banned':
        return <Badge variant="destructive">封禁</Badge>;
      case 'pending':
        return <Badge variant="outline" className="bg-blue-100 text-blue-800">待审核</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 获取角色徽章
  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'super_admin':
        return <Badge variant="default" className="bg-purple-100 text-purple-800">超级管理员</Badge>;
      case 'admin':
        return <Badge variant="default" className="bg-purple-100 text-purple-800">管理员</Badge>;
      case 'moderator':
        return <Badge variant="secondary" className="bg-blue-100 text-blue-800">版主</Badge>;
      case 'user':
        return <Badge variant="outline">用户</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 更新用户状态
  const updateUserStatus = async (userId: string, newStatus: UserStatus, reason?: string) => {
    try {
      const response = await adminApi.updateUserStatus(userId, newStatus, reason);
      if (response.data.success) {
        toast.success(`用户状态已更新为${getStatusText(newStatus)}`);
        loadUsers(); // 重新加载数据
      } else {
        toast.error('更新用户状态失败');
      }
    } catch (error) {
      console.error('更新用户状态错误:', error);
      toast.error('更新用户状态失败');
    }
  };

  // 批量操作用户
  const batchOperation = async (operation: 'suspend' | 'activate' | 'ban' | 'delete', reason?: string) => {
    if (selectedUsers.length === 0) {
      toast.error('请选择要操作的用户');
      return;
    }

    try {
      const response = await adminApi.batchUserOperation(selectedUsers, operation, reason);
      if (response.data.success) {
        toast.success(`批量${getOperationText(operation)}操作成功`);
        setSelectedUsers([]);
        loadUsers();
      } else {
        toast.error(`批量${getOperationText(operation)}操作失败`);
      }
    } catch (error) {
      console.error('批量操作错误:', error);
      toast.error(`批量${getOperationText(operation)}操作失败`);
    }
  };

  // 获取状态文本
  const getStatusText = (status: UserStatus) => {
    switch (status) {
      case 'active': return '正常';
      case 'suspended': return '暂停';
      case 'banned': return '封禁';
      case 'pending': return '待审核';
      default: return '未知';
    }
  };

  // 获取操作文本
  const getOperationText = (operation: string) => {
    switch (operation) {
      case 'suspend': return '暂停';
      case 'activate': return '激活';
      case 'ban': return '封禁';
      case 'delete': return '删除';
      default: return '操作';
    }
  };

  // 格式化日期
  const formatDate = (dateString: string | Date) => {
    return new Date(dateString).toLocaleString('zh-CN');
  };

  // 处理全选
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedUsers(users.map(user => user.id));
    } else {
      setSelectedUsers([]);
    }
  };

  // 处理单个选择
  const handleSelectUser = (userId: string, checked: boolean) => {
    if (checked) {
      setSelectedUsers(prev => [...prev, userId]);
    } else {
      setSelectedUsers(prev => prev.filter(id => id !== userId));
    }
  };

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>用户管理</span>
          </CardTitle>
          <CardDescription>管理平台用户账户、状态和权限</CardDescription>
        </CardHeader>
        <CardContent>
          {/* 搜索和筛选工具栏 */}
          <div className="flex flex-col lg:flex-row gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="搜索用户名或邮箱..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            
            <div className="flex gap-2">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[140px]">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="状态筛选" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="active">正常</SelectItem>
                  <SelectItem value="suspended">暂停</SelectItem>
                  <SelectItem value="banned">封禁</SelectItem>
                  <SelectItem value="pending">待审核</SelectItem>
                </SelectContent>
              </Select>

              <Select value={`${sortBy}-${sortOrder}`} onValueChange={(value) => {
                const [field, order] = value.split('-') as [SortBy, 'asc' | 'desc'];
                setSortBy(field);
                setSortOrder(order);
              }}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="排序方式" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="created_at-desc">注册时间↓</SelectItem>
                  <SelectItem value="created_at-asc">注册时间↑</SelectItem>
                  <SelectItem value="username-asc">用户名↑</SelectItem>
                  <SelectItem value="username-desc">用户名↓</SelectItem>
                  <SelectItem value="total_annotations-desc">标注数↓</SelectItem>
                  <SelectItem value="total_spent-desc">消费金额↓</SelectItem>
                  <SelectItem value="reports_count-desc">举报数↓</SelectItem>
                </SelectContent>
              </Select>

              <Button
                variant="outline"
                onClick={loadUsers}
                disabled={loading}
                className="flex items-center space-x-2"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                <span>刷新</span>
              </Button>
            </div>
          </div>

          {/* 批量操作工具栏 */}
          {selectedUsers.length > 0 && (
            <div className="mb-4 p-4 bg-blue-50 rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm text-blue-700">
                  已选择 {selectedUsers.length} 个用户
                </span>
                <div className="flex gap-2">
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" size="sm" className="text-green-600">
                        批量激活
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>批量激活用户</AlertDialogTitle>
                        <AlertDialogDescription>
                          确定要激活选中的 {selectedUsers.length} 个用户吗？
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction onClick={() => batchOperation('activate')}>
                          确认激活
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>

                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" size="sm" className="text-yellow-600">
                        批量暂停
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>批量暂停用户</AlertDialogTitle>
                        <AlertDialogDescription>
                          确定要暂停选中的 {selectedUsers.length} 个用户吗？
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction onClick={() => batchOperation('suspend')}>
                          确认暂停
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>

                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" size="sm" className="text-red-600">
                        批量封禁
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>批量封禁用户</AlertDialogTitle>
                        <AlertDialogDescription>
                          确定要封禁选中的 {selectedUsers.length} 个用户吗？此操作不可逆。
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction 
                          onClick={() => batchOperation('ban')}
                          className="bg-red-600 hover:bg-red-700"
                        >
                          确认封禁
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </div>
            </div>
          )}

          {/* 用户列表 */}
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={selectedUsers.length === users.length && users.length > 0}
                      onCheckedChange={handleSelectAll}
                    />
                  </TableHead>
                  <TableHead>用户信息</TableHead>
                  <TableHead>联系方式</TableHead>
                  <TableHead>统计数据</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>角色</TableHead>
                  <TableHead>注册时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8">
                      <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2" />
                      <span className="text-gray-500">加载中...</span>
                    </TableCell>
                  </TableRow>
                ) : users.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-gray-500">
                      没有找到符合条件的用户
                    </TableCell>
                  </TableRow>
                ) : (
                  users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <Checkbox
                          checked={selectedUsers.includes(user.id)}
                          onCheckedChange={(checked) => handleSelectUser(user.id, checked as boolean)}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-3">
                          <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center">
                            <User className="h-4 w-4 text-gray-500" />
                          </div>
                          <div>
                            <div className="font-medium">{user.username}</div>
                            <div className="text-sm text-gray-500">ID: {user.id.slice(-8)}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="flex items-center space-x-1 text-sm">
                            <Mail className="h-3 w-3" />
                            <span>{user.email}</span>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1 text-sm">
                          <div>标注: {user.total_annotations}</div>
                          <div>消费: ¥{user.total_spent.toFixed(2)}</div>
                          <div>收益: ¥{user.total_earned.toFixed(2)}</div>
                          {user.reports_count > 0 && (
                            <div className="text-red-600">举报: {user.reports_count}</div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>{getStatusBadge(user.status)}</TableCell>
                      <TableCell>{getRoleBadge(user.role)}</TableCell>
                      <TableCell>
                        <div className="text-sm">
                          <div>{formatDate(user.created_at)}</div>
                          {user.last_login && (
                            <div className="text-gray-500 text-xs">
                              最后登录: {formatDate(user.last_login)}
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setSelectedUser(user);
                              setIsDetailOpen(true);
                            }}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          
                          {user.status === 'active' && (
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button variant="outline" size="sm" className="text-yellow-600">
                                  <Ban className="h-4 w-4" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>暂停用户</AlertDialogTitle>
                                  <AlertDialogDescription>
                                    确定要暂停用户 "{user.username}" 吗？
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>取消</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => updateUserStatus(user.id, 'suspended')}
                                    className="bg-yellow-600 hover:bg-yellow-700"
                                  >
                                    确认暂停
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          )}
                          
                          {user.status === 'suspended' && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-green-600"
                              onClick={() => updateUserStatus(user.id, 'active')}
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                          )}
                          
                          {user.status !== 'banned' && (
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button variant="outline" size="sm" className="text-red-600">
                                  <XCircle className="h-4 w-4" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>封禁用户</AlertDialogTitle>
                                  <AlertDialogDescription>
                                    确定要封禁用户 "{user.username}" 吗？
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>取消</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => updateUserStatus(user.id, 'banned')}
                                    className="bg-red-600 hover:bg-red-700"
                                  >
                                    确认封禁
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          )}
                        </div>
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

      {/* 用户详情弹窗 */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <User className="h-5 w-5" />
              <span>用户详情</span>
            </DialogTitle>
            <DialogDescription>
              查看用户的详细信息和活动记录
            </DialogDescription>
          </DialogHeader>
          
          {selectedUser && (
            <div className="space-y-6">
              {/* 基本信息 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">基本信息</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>用户名</Label>
                      <div className="p-2 bg-gray-50 rounded">{selectedUser.username}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>用户ID</Label>
                      <div className="p-2 bg-gray-50 rounded font-mono">{selectedUser.id}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>邮箱</Label>
                      <div className="p-2 bg-gray-50 rounded">{selectedUser.email}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>注册时间</Label>
                      <div className="p-2 bg-gray-50 rounded">{formatDate(selectedUser.created_at)}</div>
                    </div>
                    {selectedUser.last_login && (
                      <div className="space-y-2">
                        <Label>最后登录</Label>
                        <div className="p-2 bg-gray-50 rounded">{formatDate(selectedUser.last_login)}</div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* 状态和角色 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">账户状态</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>状态</Label>
                      <div>{getStatusBadge(selectedUser.status)}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>角色</Label>
                      <div>{getRoleBadge(selectedUser.role)}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 活动统计 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">活动统计</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center p-4 bg-blue-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">{selectedUser.total_annotations}</div>
                      <div className="text-sm text-gray-600">创建标注</div>
                    </div>
                    <div className="text-center p-4 bg-green-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">¥{selectedUser.total_earned.toFixed(2)}</div>
                      <div className="text-sm text-gray-600">累计收益</div>
                    </div>
                    <div className="text-center p-4 bg-purple-50 rounded-lg">
                      <div className="text-2xl font-bold text-purple-600">¥{selectedUser.total_spent.toFixed(2)}</div>
                      <div className="text-sm text-gray-600">累计消费</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 风险信息 */}
              {selectedUser.reports_count > 0 && (
                <Card className="border-red-200">
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center space-x-2 text-red-800">
                      <AlertTriangle className="h-5 w-5" />
                      <span>风险提示</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="p-4 bg-red-50 rounded-lg">
                      <div className="text-red-700">
                        该用户被举报 {selectedUser.reports_count} 次，请注意审核相关内容和行为。
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default EnhancedUserManagement;