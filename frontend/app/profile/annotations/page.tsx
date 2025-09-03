'use client';

import { useState } from 'react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  MapPin,
  Calendar,
  Eye,
  DollarSign,
  Search,
  Filter,
  ArrowLeft,
  Star,
  MessageCircle,
  Share2,
  MoreHorizontal,
  Edit,
  Trash2,
  Flag,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react';
import Link from 'next/link';
import Image from 'next/image';

// 模拟标注数据
const mockAnnotations = [
  {
    id: '1',
    title: '这里有个奇怪的味道',
    description: '每次路过这里都能闻到一股奇怪的臭味，不知道是什么原因',
    location: {
      address: '北京市朝阳区三里屯SOHO',
      coordinates: [116.4074, 39.9042]
    },
    images: ['/api/placeholder/300/200'],
    price: 5.20,
    status: 'active' as const,
    discoveryCount: 12,
    viewCount: 156,
    commentCount: 8,
    rating: 4.2,
    createdAt: '2024-01-20T10:30:00Z',
    discoveredAt: null,
    type: 'created' as const,
    category: 'smell'
  },
  {
    id: '2',
    title: '垃圾桶旁边的异味',
    description: '垃圾桶长期没有清理，散发出难闻的气味',
    location: {
      address: '上海市黄浦区南京东路步行街',
      coordinates: [121.4737, 31.2304]
    },
    images: ['/api/placeholder/300/200', '/api/placeholder/300/200'],
    price: 3.80,
    status: 'discovered' as const,
    discoveryCount: 8,
    viewCount: 89,
    commentCount: 5,
    rating: 3.8,
    createdAt: '2024-01-18T14:20:00Z',
    discoveredAt: '2024-01-21T11:20:00Z',
    type: 'discovered' as const,
    category: 'smell',
    creator: {
      id: 'user2',
      name: '用户2',
      avatar: '/api/placeholder/40/40'
    }
  },
  {
    id: '3',
    title: '公厕附近的恶臭',
    description: '公共厕所管理不善，周围环境很差',
    location: {
      address: '广州市天河区珠江新城',
      coordinates: [113.3245, 23.1291]
    },
    images: ['/api/placeholder/300/200'],
    price: 8.50,
    status: 'expired' as const,
    discoveryCount: 0,
    viewCount: 45,
    commentCount: 2,
    rating: 0,
    createdAt: '2024-01-15T09:15:00Z',
    discoveredAt: null,
    type: 'created' as const,
    category: 'smell'
  },
  {
    id: '4',
    title: '餐厅后厨的油烟味',
    description: '餐厅排风系统有问题，油烟味很重',
    location: {
      address: '深圳市南山区科技园',
      coordinates: [113.9547, 22.5431]
    },
    images: [],
    price: 6.00,
    status: 'under_review' as const,
    discoveryCount: 0,
    viewCount: 23,
    commentCount: 1,
    rating: 0,
    createdAt: '2024-01-22T16:45:00Z',
    discoveredAt: null,
    type: 'created' as const,
    category: 'smell'
  },
  {
    id: '5',
    title: '下水道的异味',
    description: '下水道堵塞，散发出刺鼻的味道',
    location: {
      address: '杭州市西湖区文三路',
      coordinates: [120.1551, 30.2741]
    },
    images: ['/api/placeholder/300/200'],
    price: 4.20,
    status: 'discovered' as const,
    discoveryCount: 15,
    viewCount: 234,
    commentCount: 12,
    rating: 4.5,
    createdAt: '2024-01-12T08:30:00Z',
    discoveredAt: '2024-01-19T15:20:00Z',
    type: 'discovered' as const,
    category: 'smell',
    creator: {
      id: 'user3',
      name: '用户3',
      avatar: '/api/placeholder/40/40'
    }
  }
];

function formatDate(dateString: string) {
  return new Date(dateString).toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function getStatusBadge(status: string) {
  switch (status) {
    case 'active':
      return <Badge className="bg-green-100 text-green-800"><CheckCircle className="w-3 h-3 mr-1" />活跃中</Badge>;
    case 'discovered':
      return <Badge className="bg-blue-100 text-blue-800"><Star className="w-3 h-3 mr-1" />已被发现</Badge>;
    case 'expired':
      return <Badge variant="secondary" className="bg-gray-100 text-gray-800"><Clock className="w-3 h-3 mr-1" />已过期</Badge>;
    case 'under_review':
      return <Badge className="bg-yellow-100 text-yellow-800"><AlertTriangle className="w-3 h-3 mr-1" />审核中</Badge>;
    case 'rejected':
      return <Badge variant="destructive" className="bg-red-100 text-red-800"><XCircle className="w-3 h-3 mr-1" />已拒绝</Badge>;
    default:
      return <Badge variant="outline">未知</Badge>;
  }
}

function AnnotationCard({ annotation }: { annotation: typeof mockAnnotations[0] }) {
  const [showDetails, setShowDetails] = useState(false);

  return (
    <Card className="hover:shadow-lg transition-shadow">
      <CardContent className="p-6">
        <div className="flex justify-between items-start mb-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold text-lg">{annotation.title}</h3>
              {getStatusBadge(annotation.status)}
            </div>
            <p className="text-gray-600 text-sm mb-2 line-clamp-2">{annotation.description}</p>
            <div className="flex items-center gap-4 text-sm text-gray-500">
              <div className="flex items-center gap-1">
                <MapPin className="w-4 h-4" />
                <span>{annotation.location.address}</span>
              </div>
              <div className="flex items-center gap-1">
                <Calendar className="w-4 h-4" />
                <span>{formatDate(annotation.createdAt)}</span>
              </div>
            </div>
          </div>
          
          {annotation.images.length > 0 && (
            <div className="ml-4">
              <Image
                src={annotation.images[0]}
                alt={annotation.title}
                width={80}
                height={60}
                className="rounded-lg object-cover"
              />
            </div>
          )}
        </div>

        {/* 创建者信息（仅发现的标注显示） */}
        {annotation.type === 'discovered' && annotation.creator && (
          <div className="flex items-center gap-2 mb-4 p-3 bg-gray-50 rounded-lg">
            <Avatar className="w-8 h-8">
              <AvatarImage src={annotation.creator.avatar} />
              <AvatarFallback>{annotation.creator.name[0]}</AvatarFallback>
            </Avatar>
            <div>
              <p className="text-sm font-medium">创建者：{annotation.creator.name}</p>
              <p className="text-xs text-gray-500">发现时间：{annotation.discoveredAt && formatDate(annotation.discoveredAt)}</p>
            </div>
          </div>
        )}

        {/* 统计信息 */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <div className="flex items-center gap-1">
              <Eye className="w-4 h-4" />
              <span>{annotation.viewCount}</span>
            </div>
            <div className="flex items-center gap-1">
              <Star className="w-4 h-4" />
              <span>{annotation.discoveryCount}</span>
            </div>
            <div className="flex items-center gap-1">
              <MessageCircle className="w-4 h-4" />
              <span>{annotation.commentCount}</span>
            </div>
            {annotation.rating > 0 && (
              <div className="flex items-center gap-1">
                <Star className="w-4 h-4 fill-yellow-400 text-yellow-400" />
                <span>{annotation.rating.toFixed(1)}</span>
              </div>
            )}
          </div>
          
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 text-green-600 font-semibold">
              <DollarSign className="w-4 h-4" />
              <span>¥{annotation.price.toFixed(2)}</span>
            </div>
            
            <Dialog open={showDetails} onOpenChange={setShowDetails}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  查看详情
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>{annotation.title}</DialogTitle>
                  <DialogDescription>
                    {annotation.location.address} • {formatDate(annotation.createdAt)}
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium mb-2">描述</h4>
                    <p className="text-gray-600">{annotation.description}</p>
                  </div>
                  
                  {annotation.images.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">图片</h4>
                      <div className="grid grid-cols-2 gap-2">
                        {annotation.images.map((image, index) => (
                          <Image
                            key={index}
                            src={image}
                            alt={`${annotation.title} - ${index + 1}`}
                            width={200}
                            height={150}
                            className="rounded-lg object-cover"
                          />
                        ))}
                      </div>
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <h4 className="font-medium mb-2">统计信息</h4>
                      <div className="space-y-1 text-sm">
                        <div>浏览次数：{annotation.viewCount}</div>
                        <div>发现次数：{annotation.discoveryCount}</div>
                        <div>评论数量：{annotation.commentCount}</div>
                        {annotation.rating > 0 && <div>评分：{annotation.rating.toFixed(1)}/5.0</div>}
                      </div>
                    </div>
                    <div>
                      <h4 className="font-medium mb-2">状态信息</h4>
                      <div className="space-y-1 text-sm">
                        <div>状态：{getStatusBadge(annotation.status)}</div>
                        <div>奖励金额：¥{annotation.price.toFixed(2)}</div>
                        {annotation.discoveredAt && (
                          <div>发现时间：{formatDate(annotation.discoveredAt)}</div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
            
            <Button variant="ghost" size="sm">
              <MoreHorizontal className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function AnnotationsPage() {
  const { user } = useAuthStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');

  // 过滤和排序标注
  const filteredAnnotations = mockAnnotations
    .filter(annotation => {
      const matchesSearch = annotation.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           annotation.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           annotation.location.address.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesStatus = statusFilter === 'all' || annotation.status === statusFilter;
      
      return matchesSearch && matchesStatus;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'newest':
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        case 'oldest':
          return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
        case 'price_high':
          return b.price - a.price;
        case 'price_low':
          return a.price - b.price;
        case 'popular':
          return b.discoveryCount - a.discoveryCount;
        default:
          return 0;
      }
    });

  const createdAnnotations = filteredAnnotations.filter(a => a.type === 'created');
  const discoveredAnnotations = filteredAnnotations.filter(a => a.type === 'discovered');

  // 统计数据
  const stats = {
    totalCreated: mockAnnotations.filter(a => a.type === 'created').length,
    totalDiscovered: mockAnnotations.filter(a => a.type === 'discovered').length,
    totalEarnings: mockAnnotations
      .filter(a => a.type === 'discovered')
      .reduce((sum, a) => sum + a.price, 0),
    activeAnnotations: mockAnnotations.filter(a => a.type === 'created' && a.status === 'active').length
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-cyan-50 py-8">
      <div className="container mx-auto px-4 max-w-6xl">
        {/* 页面头部 */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/profile">
            <Button variant="outline" size="sm">
              <ArrowLeft className="w-4 h-4 mr-2" />
              返回个人中心
            </Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold">我的标注</h1>
            <p className="text-gray-600">管理您创建和发现的标注</p>
          </div>
        </div>

        {/* 统计卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-2">
                <MapPin className="w-5 h-5 text-blue-500" />
                <div>
                  <p className="text-sm text-gray-600">创建标注</p>
                  <p className="text-2xl font-bold text-blue-600">{stats.totalCreated}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-2">
                <Star className="w-5 h-5 text-yellow-500" />
                <div>
                  <p className="text-sm text-gray-600">发现标注</p>
                  <p className="text-2xl font-bold text-yellow-600">{stats.totalDiscovered}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-2">
                <DollarSign className="w-5 h-5 text-green-500" />
                <div>
                  <p className="text-sm text-gray-600">发现收益</p>
                  <p className="text-2xl font-bold text-green-600">¥{stats.totalEarnings.toFixed(2)}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-purple-500" />
                <div>
                  <p className="text-sm text-gray-600">活跃标注</p>
                  <p className="text-2xl font-bold text-purple-600">{stats.activeAnnotations}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* 搜索和筛选 */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                  <Input
                    placeholder="搜索标注标题、描述或地址..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>
              
              <div className="flex gap-2">
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-32">
                    <Filter className="w-4 h-4 mr-2" />
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部状态</SelectItem>
                    <SelectItem value="active">活跃中</SelectItem>
                    <SelectItem value="discovered">已发现</SelectItem>
                    <SelectItem value="expired">已过期</SelectItem>
                    <SelectItem value="under_review">审核中</SelectItem>
                    <SelectItem value="rejected">已拒绝</SelectItem>
                  </SelectContent>
                </Select>
                
                <Select value={sortBy} onValueChange={setSortBy}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="newest">最新创建</SelectItem>
                    <SelectItem value="oldest">最早创建</SelectItem>
                    <SelectItem value="price_high">价格从高到低</SelectItem>
                    <SelectItem value="price_low">价格从低到高</SelectItem>
                    <SelectItem value="popular">最受欢迎</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* 标注列表 */}
        <Tabs defaultValue="all" className="space-y-6">
          <TabsList>
            <TabsTrigger value="all">全部标注 ({filteredAnnotations.length})</TabsTrigger>
            <TabsTrigger value="created">我创建的 ({createdAnnotations.length})</TabsTrigger>
            <TabsTrigger value="discovered">我发现的 ({discoveredAnnotations.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="all">
            <div className="space-y-4">
              {filteredAnnotations.length > 0 ? (
                filteredAnnotations.map((annotation) => (
                  <AnnotationCard key={annotation.id} annotation={annotation} />
                ))
              ) : (
                <Card>
                  <CardContent className="p-12 text-center">
                    <MapPin className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">暂无标注记录</h3>
                    <p className="text-gray-500 mb-4">您还没有创建或发现任何标注</p>
                    <Link href="/map">
                      <Button>
                        <MapPin className="w-4 h-4 mr-2" />
                        去地图探索
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="created">
            <div className="space-y-4">
              {createdAnnotations.length > 0 ? (
                createdAnnotations.map((annotation) => (
                  <AnnotationCard key={annotation.id} annotation={annotation} />
                ))
              ) : (
                <Card>
                  <CardContent className="p-12 text-center">
                    <MapPin className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">暂无创建的标注</h3>
                    <p className="text-gray-500 mb-4">您还没有创建任何标注</p>
                    <Link href="/map">
                      <Button>
                        <MapPin className="w-4 h-4 mr-2" />
                        创建标注
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="discovered">
            <div className="space-y-4">
              {discoveredAnnotations.length > 0 ? (
                discoveredAnnotations.map((annotation) => (
                  <AnnotationCard key={annotation.id} annotation={annotation} />
                ))
              ) : (
                <Card>
                  <CardContent className="p-12 text-center">
                    <Star className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">暂无发现的标注</h3>
                    <p className="text-gray-500 mb-4">您还没有发现任何标注</p>
                    <Link href="/map">
                      <Button>
                        <Star className="w-4 h-4 mr-2" />
                        去发现标注
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}