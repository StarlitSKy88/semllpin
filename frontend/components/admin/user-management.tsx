'use client';

import { useState } from 'react';
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
  DialogTrigger,
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
import {
  Search,
  Filter,
  Eye,
  Ban,
  CheckCircle,
  XCircle,
  DollarSign,
  Calendar,
  MapPin,
  Phone,
  Mail,
  User,
  Shield,
  AlertTriangle,
} from 'lucide-react';
import { toast } from 'sonner';

// 模拟用户数据
const mockUsers = [
  {
    id: '1',
    username: '张三',
    email: 'zhangsan@example.com',
    phone: '13800138001',
    avatar: '/avatars/01.png',
    level: 3,
    points: 1250,
    balance: 89.5,
    status: 'active' as const,
    role: 'user' as const,
    createdAt: '2024-01-15T10:30:00Z',
    lastLoginAt: '2024-01-20T14:22:00Z',
    annotationsCount: 15,
    rewardsEarned: 234.5,
    reportCount: 0,
  },
  {
    id: '2',
    username: '李四',
    email: 'lisi@example.com',
    phone: '13800138002',
    avatar: '/avatars/02.png',
    level: 5,
    points: 2890,
    balance: 156.8,
    status: 'active' as const,
    role: 'user' as const,
    createdAt: '2024-01-10T09:15:00Z',
    lastLoginAt: '2024-01-20T16:45:00Z',
    annotationsCount: 28,
    rewardsEarned: 445.2,
    reportCount: 1,
  },
  {
    id: '3',
    username: '王五',
    email: 'wangwu@example.com',
    phone: '13800138003',
    avatar: '/avatars/03.png',
    level: 2,
    points: 680,
    balance: 23.4,
    status: 'suspended' as const,
    role: 'user' as const,
    createdAt: '2024-01-18T11:20:00Z',
    lastLoginAt: '2024-01-19T13:10:00Z',
    annotationsCount: 8,
    rewardsEarned: 67.8,
    reportCount: 3,
  },
  {
    id: '4',
    username: '赵六',
    email: 'zhaoliu@example.com',
    phone: '13800138004',
    avatar: '/avatars/04.png',
    level: 1,
    points: 120,
    balance: 5.0,
    status: 'banned' as const,
    role: 'user' as const,
    createdAt: '2024-01-19T15:45:00Z',
    lastLoginAt: '2024-01-19T16:30:00Z',
    annotationsCount: 2,
    rewardsEarned: 12.5,
    reportCount: 5,
  },
];

type UserStatus = 'active' | 'suspended' | 'banned';
type UserRole = 'user' | 'admin' | 'moderator';

interface User {
  id: string;
  username: string;
  email: string;
  phone: string;
  avatar: string;
  level: number;
  points: number;
  balance: number;
  status: UserStatus;
  role: UserRole;
  createdAt: string;
  lastLoginAt: string;
  annotationsCount: number;
  rewardsEarned: number;
  reportCount: number;
}

interface UserManagementProps {
  className?: string;
}

export function UserManagement({ className }: UserManagementProps) {
  const [users, setUsers] = useState<User[]>(mockUsers);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [isBalanceDialogOpen, setIsBalanceDialogOpen] = useState(false);
  const [balanceAmount, setBalanceAmount] = useState('');
  const [balanceReason, setBalanceReason] = useState('');

  // 过滤用户
  const filteredUsers = users.filter((user) => {
    const matchesSearch = 
      user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.phone.includes(searchTerm);
    
    const matchesStatus = statusFilter === 'all' || user.status === statusFilter;
    
    return matchesSearch && matchesStatus;
  });

  // 获取状态徽章
  const getStatusBadge = (status: UserStatus) => {
    switch (status) {
      case 'active':
        return <Badge variant="default" className="bg-green-100 text-green-800">正常</Badge>;
      case 'suspended':
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">暂停</Badge>;
      case 'banned':
        return <Badge variant="destructive">封禁</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 获取角色徽章
  const getRoleBadge = (role: UserRole) => {
    switch (role) {
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
  const updateUserStatus = (userId: string, newStatus: UserStatus) => {
    setUsers(users.map(user => 
      user.id === userId ? { ...user, status: newStatus } : user
    ));
    toast.success(`用户状态已更新为${newStatus === 'active' ? '正常' : newStatus === 'suspended' ? '暂停' : '封禁'}`);
  };

  // 调整用户余额
  const adjustUserBalance = () => {
    if (!selectedUser || !balanceAmount) return;
    
    const amount = parseFloat(balanceAmount);
    if (isNaN(amount)) {
      toast.error('请输入有效的金额');
      return;
    }

    setUsers(users.map(user => 
      user.id === selectedUser.id 
        ? { ...user, balance: user.balance + amount }
        : user
    ));
    
    toast.success(`已${amount > 0 ? '增加' : '扣除'}用户余额 ¥${Math.abs(amount)}`);
    setIsBalanceDialogOpen(false);
    setBalanceAmount('');
    setBalanceReason('');
  };

  // 格式化日期
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('zh-CN');
  };

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <CardTitle>用户管理</CardTitle>
          <CardDescription>管理平台用户账户和权限</CardDescription>
        </CardHeader>
        <CardContent>
          {/* 搜索和筛选 */}
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="搜索用户名、邮箱或手机号..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="状态筛选" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部状态</SelectItem>
                <SelectItem value="active">正常</SelectItem>
                <SelectItem value="suspended">暂停</SelectItem>
                <SelectItem value="banned">封禁</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* 用户列表 */}
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>用户</TableHead>
                  <TableHead>联系方式</TableHead>
                  <TableHead>等级/积分</TableHead>
                  <TableHead>余额</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>角色</TableHead>
                  <TableHead>注册时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUsers.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center">
                          <User className="h-4 w-4 text-gray-500" />
                        </div>
                        <div>
                          <div className="font-medium">{user.username}</div>
                          <div className="text-sm text-gray-500">ID: {user.id}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1 text-sm">
                          <Mail className="h-3 w-3" />
                          <span>{user.email}</span>
                        </div>
                        <div className="flex items-center space-x-1 text-sm">
                          <Phone className="h-3 w-3" />
                          <span>{user.phone}</span>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="text-sm font-medium">Lv.{user.level}</div>
                        <div className="text-sm text-gray-500">{user.points} 积分</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium">¥{user.balance.toFixed(2)}</div>
                    </TableCell>
                    <TableCell>{getStatusBadge(user.status)}</TableCell>
                    <TableCell>{getRoleBadge(user.role)}</TableCell>
                    <TableCell>
                      <div className="text-sm">{formatDate(user.createdAt)}</div>
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
                                  确定要暂停用户 "{user.username}" 吗？暂停后用户将无法正常使用平台功能。
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
                                  确定要封禁用户 "{user.username}" 吗？封禁后用户将无法登录和使用平台。
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
                ))}
              </TableBody>
            </Table>
          </div>

          {filteredUsers.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              没有找到符合条件的用户
            </div>
          )}
        </CardContent>
      </Card>

      {/* 用户详情弹窗 */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>用户详情</DialogTitle>
            <DialogDescription>
              查看和管理用户的详细信息
            </DialogDescription>
          </DialogHeader>
          
          {selectedUser && (
            <div className="space-y-6">
              {/* 基本信息 */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>用户名</Label>
                  <div className="p-2 bg-gray-50 rounded">{selectedUser.username}</div>
                </div>
                <div className="space-y-2">
                  <Label>用户ID</Label>
                  <div className="p-2 bg-gray-50 rounded">{selectedUser.id}</div>
                </div>
                <div className="space-y-2">
                  <Label>邮箱</Label>
                  <div className="p-2 bg-gray-50 rounded">{selectedUser.email}</div>
                </div>
                <div className="space-y-2">
                  <Label>手机号</Label>
                  <div className="p-2 bg-gray-50 rounded">{selectedUser.phone}</div>
                </div>
              </div>

              {/* 状态和角色 */}
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

              {/* 统计信息 */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>等级/积分</Label>
                  <div className="p-2 bg-gray-50 rounded">
                    Lv.{selectedUser.level} ({selectedUser.points} 积分)
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>账户余额</Label>
                  <div className="p-2 bg-gray-50 rounded flex items-center justify-between">
                    <span>¥{selectedUser.balance.toFixed(2)}</span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setIsBalanceDialogOpen(true)}
                    >
                      <DollarSign className="h-4 w-4 mr-1" />
                      调整
                    </Button>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>标注数量</Label>
                  <div className="p-2 bg-gray-50 rounded">{selectedUser.annotationsCount} 个</div>
                </div>
                <div className="space-y-2">
                  <Label>累计收益</Label>
                  <div className="p-2 bg-gray-50 rounded">¥{selectedUser.rewardsEarned.toFixed(2)}</div>
                </div>
              </div>

              {/* 时间信息 */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>注册时间</Label>
                  <div className="p-2 bg-gray-50 rounded">{formatDate(selectedUser.createdAt)}</div>
                </div>
                <div className="space-y-2">
                  <Label>最后登录</Label>
                  <div className="p-2 bg-gray-50 rounded">{formatDate(selectedUser.lastLoginAt)}</div>
                </div>
              </div>

              {/* 风险信息 */}
              {selectedUser.reportCount > 0 && (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                  <div className="flex items-center space-x-2 text-red-800">
                    <AlertTriangle className="h-5 w-5" />
                    <span className="font-medium">风险提示</span>
                  </div>
                  <div className="mt-2 text-sm text-red-700">
                    该用户被举报 {selectedUser.reportCount} 次，请注意风险。
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 余额调整弹窗 */}
      <Dialog open={isBalanceDialogOpen} onOpenChange={setIsBalanceDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>调整用户余额</DialogTitle>
            <DialogDescription>
              为用户 "{selectedUser?.username}" 调整账户余额
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>当前余额</Label>
              <div className="p-2 bg-gray-50 rounded">
                ¥{selectedUser?.balance.toFixed(2)}
              </div>
            </div>
            
            <div className="space-y-2">
              <Label>调整金额</Label>
              <Input
                type="number"
                step="0.01"
                placeholder="输入金额（正数为增加，负数为扣除）"
                value={balanceAmount}
                onChange={(e) => setBalanceAmount(e.target.value)}
              />
            </div>
            
            <div className="space-y-2">
              <Label>调整原因</Label>
              <Textarea
                placeholder="请输入调整原因..."
                value={balanceReason}
                onChange={(e) => setBalanceReason(e.target.value)}
              />
            </div>
            
            <div className="flex justify-end space-x-2">
              <Button
                variant="outline"
                onClick={() => setIsBalanceDialogOpen(false)}
              >
                取消
              </Button>
              <Button onClick={adjustUserBalance}>
                确认调整
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default UserManagement;