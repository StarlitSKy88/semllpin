'use client';

import { useEffect, useState } from 'react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { useWalletStore } from '@/lib/stores/wallet-store';
import { annotationApi, authApi, type Annotation } from '@/lib/services/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { toast } from 'sonner';
import {
  User,
  MapPin,
  Calendar,
  Mail,
  Phone,
  Edit,
  Trophy,
  Wallet,
  Star,
  Eye,
  MessageCircle,
  Heart,
  Settings,
  CreditCard
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { zhCN } from 'date-fns/locale';
import { useRouter } from 'next/navigation';


export default function ProfilePage() {
  const { user, isAuthenticated } = useAuthStore();
  const { wallet, loadWallet } = useWalletStore();
  const router = useRouter();
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [loading, setLoading] = useState(true);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editForm, setEditForm] = useState({
    username: '',
    email: '',
  });

  useEffect(() => {
    if (!isAuthenticated) {
      router.push('/');
      return;
    }

    loadWallet();
    loadMyAnnotations();

    if (user) {
      setEditForm({
        username: user.username,
        email: user.email || '',
      });
    }
  }, [isAuthenticated, user, loadWallet, router]);

  const loadMyAnnotations = async () => {
    try {
      setLoading(true);
      const response = await annotationApi.getMyAnnotations();
      setAnnotations(response.data.data);
    } catch (error) {
      toast.error('加载标注失败');
    } finally {
      setLoading(false);
    }
  };

  const handleEditProfile = async () => {
    try {
      const response = await authApi.updateProfile(editForm);
      toast.success('个人信息已更新');
      // 更新本地用户信息
      useAuthStore.setState({ user: response.data.data });
      setEditDialogOpen(false);
    } catch (error) {
      toast.error('更新失败');
    }
  };

  if (!isAuthenticated || !user) {
    return null;
  }

  const stats = [
    {
      label: '创建标注',
      value: annotations.length,
      icon: MapPin,
      color: 'text-blue-600'
    },
    {
      label: '总获赞',
      value: annotations.reduce((sum, ann) => sum + (ann.likesCount || 0), 0),
      icon: Heart,
      color: 'text-red-600'
    },
    {
      label: '总评论',
      value: annotations.reduce((sum, ann) => sum + (ann.commentsCount || 0), 0),
      icon: MessageCircle,
      color: 'text-green-600'
    },
    {
      label: '用户等级',
      value: user.level,
      icon: Trophy,
      color: 'text-yellow-600'
    },
  ];

  return (
    <div className="min-h-screen bg-black pt-20 pb-10">
      <div className="container mx-auto px-4 max-w-6xl">
        {/* 用户信息卡片 */}
        <Card className="mb-8 bg-gray-900/50 border-gray-800">
          <CardHeader>
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
              <Avatar className="h-20 w-20 sm:h-24 sm:w-24">
                <AvatarImage src={user.avatar} alt={user.username} />
                <AvatarFallback className="text-2xl">
                  {user.username.charAt(0).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              
              <div className="flex-1 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                  <h1 className="text-2xl font-bold text-white">{user.username}</h1>
                  <Badge variant="secondary" className="w-fit">
                    等级 {user.level}
                  </Badge>
                </div>
                
                <div className="flex flex-wrap items-center gap-4 text-gray-400">
                  {user.email && (
                    <div className="flex items-center gap-1">
                      <Mail className="h-4 w-4" />
                      <span className="text-sm">{user.email}</span>
                    </div>
                  )}
                  {user.phone && (
                    <div className="flex items-center gap-1">
                      <Phone className="h-4 w-4" />
                      <span className="text-sm">{user.phone}</span>
                    </div>
                  )}
                  <div className="flex items-center gap-1">
                    <Calendar className="h-4 w-4" />
                    <span className="text-sm">
                      加入于 {formatDistanceToNow(new Date(user.createdAt), { 
                        addSuffix: true, 
                        locale: zhCN 
                      })}
                    </span>
                  </div>
                </div>
                
                <div className="flex items-center gap-2 text-sm text-gray-400">
                  <Star className="h-4 w-4 text-yellow-500" />
                  <span>{user.points} 积分</span>
                </div>
              </div>
              
              <div className="flex flex-col sm:flex-row gap-2">
                <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
                  <DialogTrigger asChild>
                    <Button variant="outline" size="sm">
                      <Edit className="h-4 w-4 mr-2" />
                      编辑资料
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="bg-gray-900 border-gray-800">
                    <DialogHeader>
                      <DialogTitle className="text-white">编辑个人资料</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4 pt-4">
                      <div className="space-y-2">
                        <Label htmlFor="username" className="text-white">用户名</Label>
                        <Input
                          id="username"
                          value={editForm.username}
                          onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                          className="bg-gray-800 border-gray-700 text-white"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="email" className="text-white">邮箱</Label>
                        <Input
                          id="email"
                          type="email"
                          value={editForm.email}
                          onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                          className="bg-gray-800 border-gray-700 text-white"
                        />
                      </div>
                      <div className="flex justify-end gap-2 pt-4">
                        <Button 
                          variant="outline" 
                          onClick={() => setEditDialogOpen(false)}
                          className="border-gray-700"
                        >
                          取消
                        </Button>
                        <Button onClick={handleEditProfile}>
                          保存
                        </Button>
                      </div>
                    </div>
                  </DialogContent>
                </Dialog>
                
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => router.push('/settings')}
                >
                  <Settings className="h-4 w-4 mr-2" />
                  设置
                </Button>
              </div>
            </div>
          </CardHeader>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* 统计信息 */}
          <div className="lg:col-span-1 space-y-6">
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">数据统计</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {stats.map((stat, index) => {
                  const Icon = stat.icon;
                  return (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Icon className={`h-4 w-4 ${stat.color}`} />
                        <span className="text-gray-400">{stat.label}</span>
                      </div>
                      <span className="text-white font-medium">{stat.value}</span>
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            {/* 钱包信息 */}
            {wallet && (
              <Card className="bg-gray-900/50 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <CreditCard className="h-5 w-5" />
                    钱包概览
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">余额</span>
                    <span className="text-white font-medium text-lg">
                      ¥{(wallet.balance / 100).toFixed(2)}
                    </span>
                  </div>
                  <Separator className="bg-gray-800" />
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">总收益</span>
                    <span className="text-green-600 font-medium">
                      +¥{(wallet.totalEarned / 100).toFixed(2)}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">总支出</span>
                    <span className="text-red-600 font-medium">
                      -¥{(wallet.totalSpent / 100).toFixed(2)}
                    </span>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* 我的标注 */}
          <div className="lg:col-span-2">
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-white">我的标注</CardTitle>
                    <CardDescription>共 {annotations.length} 个标注</CardDescription>
                  </div>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => router.push('/')}
                  >
                    <MapPin className="h-4 w-4 mr-2" />
                    创建新标注
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="space-y-4">
                    {[...Array(3)].map((_, i) => (
                      <div key={i} className="p-4 border border-gray-800 rounded-lg">
                        <Skeleton className="h-4 w-3/4 mb-2 bg-gray-800" />
                        <Skeleton className="h-3 w-1/2 mb-2 bg-gray-800" />
                        <Skeleton className="h-3 w-1/4 bg-gray-800" />
                      </div>
                    ))}
                  </div>
                ) : annotations.length === 0 ? (
                  <div className="text-center py-12">
                    <MapPin className="h-16 w-16 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-400 mb-4">还没有创建任何标注</p>
                    <Button onClick={() => router.push('/')}>
                      开始创建标注
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {annotations.map((annotation) => (
                      <div 
                        key={annotation.id} 
                        className="p-4 border border-gray-800 rounded-lg hover:border-gray-700 transition-colors cursor-pointer"
                        onClick={() => router.push(`/annotation/${annotation.id}`)}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <h3 className="font-medium text-white line-clamp-1">
                            {annotation.title}
                          </h3>
                          <Badge 
                            variant={
                              annotation.status === 'approved' ? 'default' :
                              annotation.status === 'pending' ? 'secondary' : 'destructive'
                            }
                          >
                            {annotation.status === 'approved' ? '已通过' :
                             annotation.status === 'pending' ? '审核中' : '已拒绝'}
                          </Badge>
                        </div>
                        
                        <p className="text-gray-400 text-sm mb-3 line-clamp-2">
                          {annotation.description}
                        </p>
                        
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <div className="flex items-center gap-4">
                            <span className="flex items-center gap-1">
                              <Heart className="h-3 w-3" />
                              {annotation.likesCount || 0}
                            </span>
                            <span className="flex items-center gap-1">
                              <MessageCircle className="h-3 w-3" />
                              {annotation.commentsCount || 0}
                            </span>
                            <span className="text-green-600">
                              奖励 ¥{(annotation.rewardAmount / 100).toFixed(2)}
                            </span>
                          </div>
                          <span>
                            {formatDistanceToNow(new Date(annotation.createdAt), {
                              addSuffix: true,
                              locale: zhCN
                            })}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}