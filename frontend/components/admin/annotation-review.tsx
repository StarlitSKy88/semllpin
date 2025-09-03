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
  CheckCircle,
  XCircle,
  MapPin,
  Calendar,
  User,
  DollarSign,
  Clock,
  AlertTriangle,
  Image as ImageIcon,
  MessageSquare,
} from 'lucide-react';
import { toast } from 'sonner';

// 模拟标注数据
const mockAnnotations = [
  {
    id: '1',
    title: '这里有个奇怪的雕像',
    content: '路过发现这个雕像造型很搞笑，大家快来看看！',
    location: {
      address: '北京市朝阳区三里屯',
      latitude: 39.9388,
      longitude: 116.4574,
    },
    amount: 50,
    status: 'pending' as const,
    category: 'funny',
    images: ['/images/annotation1.jpg', '/images/annotation2.jpg'],
    creator: {
      id: 'user1',
      username: '张三',
      level: 3,
    },
    createdAt: '2024-01-20T10:30:00Z',
    reviewedAt: null,
    reviewedBy: null,
    rejectReason: null,
    reportCount: 0,
    viewCount: 25,
  },
  {
    id: '2',
    title: '超市里的搞笑标语',
    content: '这个超市的标语写得太有意思了，哈哈哈',
    location: {
      address: '上海市徐汇区淮海中路',
      latitude: 31.2165,
      longitude: 121.4365,
    },
    amount: 30,
    status: 'pending' as const,
    category: 'funny',
    images: ['/images/annotation3.jpg'],
    creator: {
      id: 'user2',
      username: '李四',
      level: 5,
    },
    createdAt: '2024-01-20T14:15:00Z',
    reviewedAt: null,
    reviewedBy: null,
    rejectReason: null,
    reportCount: 1,
    viewCount: 12,
  },
  {
    id: '3',
    title: '公园里的奇葩健身器材',
    content: '这个健身器材的设计真的很奇特，不知道怎么用',
    location: {
      address: '广州市天河区天河公园',
      latitude: 23.1291,
      longitude: 113.2644,
    },
    amount: 80,
    status: 'approved' as const,
    category: 'weird',
    images: ['/images/annotation4.jpg', '/images/annotation5.jpg', '/images/annotation6.jpg'],
    creator: {
      id: 'user3',
      username: '王五',
      level: 2,
    },
    createdAt: '2024-01-19T16:45:00Z',
    reviewedAt: '2024-01-20T09:20:00Z',
    reviewedBy: 'admin1',
    rejectReason: null,
    reportCount: 0,
    viewCount: 45,
  },
  {
    id: '4',
    title: '违规内容测试',
    content: '这是一个包含不当内容的标注，应该被拒绝',
    location: {
      address: '深圳市南山区科技园',
      latitude: 22.5431,
      longitude: 114.0579,
    },
    amount: 20,
    status: 'rejected' as const,
    category: 'other',
    images: [],
    creator: {
      id: 'user4',
      username: '赵六',
      level: 1,
    },
    createdAt: '2024-01-19T11:30:00Z',
    reviewedAt: '2024-01-19T15:45:00Z',
    reviewedBy: 'admin1',
    rejectReason: '内容不符合社区规范，包含不当信息',
    reportCount: 2,
    viewCount: 8,
  },
];

type AnnotationStatus = 'pending' | 'approved' | 'rejected';

interface Annotation {
  id: string;
  title: string;
  content: string;
  location: {
    address: string;
    latitude: number;
    longitude: number;
  };
  amount: number;
  status: AnnotationStatus;
  category: string;
  images: string[];
  creator: {
    id: string;
    username: string;
    level: number;
  };
  createdAt: string;
  reviewedAt: string | null;
  reviewedBy: string | null;
  rejectReason: string | null;
  reportCount: number;
  viewCount: number;
}

interface AnnotationReviewProps {
  className?: string;
}

export function AnnotationReview({ className }: AnnotationReviewProps) {
  const [annotations, setAnnotations] = useState<Annotation[]>(mockAnnotations);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const [selectedAnnotation, setSelectedAnnotation] = useState<Annotation | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [rejectReason, setRejectReason] = useState('');
  const [isRejectDialogOpen, setIsRejectDialogOpen] = useState(false);

  // 过滤标注
  const filteredAnnotations = annotations.filter((annotation) => {
    const matchesSearch = 
      annotation.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      annotation.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
      annotation.location.address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      annotation.creator.username.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = statusFilter === 'all' || annotation.status === statusFilter;
    
    return matchesSearch && matchesStatus;
  });

  // 获取状态徽章
  const getStatusBadge = (status: AnnotationStatus) => {
    switch (status) {
      case 'pending':
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">待审核</Badge>;
      case 'approved':
        return <Badge variant="default" className="bg-green-100 text-green-800">已通过</Badge>;
      case 'rejected':
        return <Badge variant="destructive">已拒绝</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 获取分类标签
  const getCategoryLabel = (category: string) => {
    const categories: Record<string, string> = {
      funny: '搞笑',
      weird: '奇葩',
      interesting: '有趣',
      other: '其他',
    };
    return categories[category] || category;
  };

  // 审核通过
  const approveAnnotation = (annotationId: string) => {
    setAnnotations(annotations.map(annotation => 
      annotation.id === annotationId 
        ? { 
            ...annotation, 
            status: 'approved' as const,
            reviewedAt: new Date().toISOString(),
            reviewedBy: 'current_admin'
          }
        : annotation
    ));
    toast.success('标注已通过审核');
    setIsDetailOpen(false);
  };

  // 审核拒绝
  const rejectAnnotation = () => {
    if (!selectedAnnotation || !rejectReason.trim()) {
      toast.error('请输入拒绝原因');
      return;
    }

    setAnnotations(annotations.map(annotation => 
      annotation.id === selectedAnnotation.id 
        ? { 
            ...annotation, 
            status: 'rejected' as const,
            reviewedAt: new Date().toISOString(),
            reviewedBy: 'current_admin',
            rejectReason: rejectReason
          }
        : annotation
    ));
    
    toast.success('标注已拒绝');
    setIsRejectDialogOpen(false);
    setIsDetailOpen(false);
    setRejectReason('');
  };

  // 删除标注
  const deleteAnnotation = (annotationId: string) => {
    setAnnotations(annotations.filter(annotation => annotation.id !== annotationId));
    toast.success('标注已删除');
    setIsDetailOpen(false);
  };

  // 格式化日期
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('zh-CN');
  };

  // 计算待审核数量
  const pendingCount = annotations.filter(a => a.status === 'pending').length;

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>标注审核</span>
            {pendingCount > 0 && (
              <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                {pendingCount} 个待审核
              </Badge>
            )}
          </CardTitle>
          <CardDescription>审核用户提交的标注内容</CardDescription>
        </CardHeader>
        <CardContent>
          {/* 搜索和筛选 */}
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="搜索标注标题、内容、地址或创建者..."
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
                <SelectItem value="pending">待审核</SelectItem>
                <SelectItem value="approved">已通过</SelectItem>
                <SelectItem value="rejected">已拒绝</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* 标注列表 */}
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>标注信息</TableHead>
                  <TableHead>位置</TableHead>
                  <TableHead>创建者</TableHead>
                  <TableHead>金额</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead>风险</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAnnotations.map((annotation) => (
                  <TableRow key={annotation.id}>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="font-medium line-clamp-1">{annotation.title}</div>
                        <div className="text-sm text-gray-500 line-clamp-2">{annotation.content}</div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline" className="text-xs">
                            {getCategoryLabel(annotation.category)}
                          </Badge>
                          {annotation.images.length > 0 && (
                            <div className="flex items-center space-x-1 text-xs text-gray-500">
                              <ImageIcon className="h-3 w-3" />
                              <span>{annotation.images.length}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-start space-x-1 text-sm">
                        <MapPin className="h-3 w-3 mt-0.5 text-gray-400" />
                        <span className="line-clamp-2">{annotation.location.address}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1">
                          <User className="h-3 w-3" />
                          <span className="text-sm font-medium">{annotation.creator.username}</span>
                        </div>
                        <div className="text-xs text-gray-500">Lv.{annotation.creator.level}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-1">
                        <DollarSign className="h-3 w-3" />
                        <span className="font-medium">¥{annotation.amount}</span>
                      </div>
                    </TableCell>
                    <TableCell>{getStatusBadge(annotation.status)}</TableCell>
                    <TableCell>
                      <div className="text-sm">{formatDate(annotation.createdAt)}</div>
                    </TableCell>
                    <TableCell>
                      {annotation.reportCount > 0 ? (
                        <div className="flex items-center space-x-1 text-red-600">
                          <AlertTriangle className="h-4 w-4" />
                          <span className="text-sm">{annotation.reportCount}</span>
                        </div>
                      ) : (
                        <span className="text-sm text-gray-400">无</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSelectedAnnotation(annotation);
                            setIsDetailOpen(true);
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        
                        {annotation.status === 'pending' && (
                          <>
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-green-600"
                              onClick={() => approveAnnotation(annotation.id)}
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-red-600"
                              onClick={() => {
                                setSelectedAnnotation(annotation);
                                setIsRejectDialogOpen(true);
                              }}
                            >
                              <XCircle className="h-4 w-4" />
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {filteredAnnotations.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              没有找到符合条件的标注
            </div>
          )}
        </CardContent>
      </Card>

      {/* 标注详情弹窗 */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>标注详情</DialogTitle>
            <DialogDescription>
              查看标注的详细信息并进行审核操作
            </DialogDescription>
          </DialogHeader>
          
          {selectedAnnotation && (
            <div className="space-y-6">
              {/* 基本信息 */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>标注标题</Label>
                    <div className="p-3 bg-gray-50 rounded-lg font-medium">
                      {selectedAnnotation.title}
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>标注内容</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      {selectedAnnotation.content}
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>位置信息</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-start space-x-2">
                        <MapPin className="h-4 w-4 mt-0.5" />
                        <div>
                          <div>{selectedAnnotation.location.address}</div>
                          <div className="text-sm text-gray-500 mt-1">
                            {selectedAnnotation.location.latitude.toFixed(6)}, {selectedAnnotation.location.longitude.toFixed(6)}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>状态</Label>
                      <div>{getStatusBadge(selectedAnnotation.status)}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>分类</Label>
                      <Badge variant="outline">{getCategoryLabel(selectedAnnotation.category)}</Badge>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>标注金额</Label>
                      <div className="p-2 bg-gray-50 rounded flex items-center space-x-1">
                        <DollarSign className="h-4 w-4" />
                        <span className="font-medium">¥{selectedAnnotation.amount}</span>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>浏览次数</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {selectedAnnotation.viewCount} 次
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>创建者</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-2">
                        <User className="h-4 w-4" />
                        <span className="font-medium">{selectedAnnotation.creator.username}</span>
                        <Badge variant="outline" className="text-xs">
                          Lv.{selectedAnnotation.creator.level}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>创建时间</Label>
                    <div className="p-2 bg-gray-50 rounded flex items-center space-x-1">
                      <Calendar className="h-4 w-4" />
                      <span>{formatDate(selectedAnnotation.createdAt)}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* 图片展示 */}
              {selectedAnnotation.images.length > 0 && (
                <div className="space-y-2">
                  <Label>标注图片</Label>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    {selectedAnnotation.images.map((image, index) => (
                      <div key={index} className="aspect-square bg-gray-100 rounded-lg flex items-center justify-center">
                        <ImageIcon className="h-8 w-8 text-gray-400" />
                        <span className="ml-2 text-sm text-gray-500">图片 {index + 1}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 审核信息 */}
              {selectedAnnotation.reviewedAt && (
                <div className="space-y-2">
                  <Label>审核信息</Label>
                  <div className="p-3 bg-gray-50 rounded-lg space-y-2">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-4 w-4" />
                      <span>审核时间: {formatDate(selectedAnnotation.reviewedAt)}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <User className="h-4 w-4" />
                      <span>审核人: {selectedAnnotation.reviewedBy}</span>
                    </div>
                    {selectedAnnotation.rejectReason && (
                      <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded">
                        <div className="text-sm font-medium text-red-800">拒绝原因:</div>
                        <div className="text-sm text-red-700 mt-1">{selectedAnnotation.rejectReason}</div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 风险提示 */}
              {selectedAnnotation.reportCount > 0 && (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                  <div className="flex items-center space-x-2 text-red-800">
                    <AlertTriangle className="h-5 w-5" />
                    <span className="font-medium">风险提示</span>
                  </div>
                  <div className="mt-2 text-sm text-red-700">
                    该标注被举报 {selectedAnnotation.reportCount} 次，请仔细审核内容。
                  </div>
                </div>
              )}

              {/* 操作按钮 */}
              {selectedAnnotation.status === 'pending' && (
                <div className="flex justify-end space-x-3 pt-4 border-t">
                  <Button
                    variant="outline"
                    className="text-red-600"
                    onClick={() => setIsRejectDialogOpen(true)}
                  >
                    <XCircle className="h-4 w-4 mr-2" />
                    拒绝
                  </Button>
                  <Button
                    className="bg-green-600 hover:bg-green-700"
                    onClick={() => approveAnnotation(selectedAnnotation.id)}
                  >
                    <CheckCircle className="h-4 w-4 mr-2" />
                    通过
                  </Button>
                </div>
              )}

              {/* 删除按钮（仅限已拒绝的标注） */}
              {selectedAnnotation.status === 'rejected' && (
                <div className="flex justify-end pt-4 border-t">
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="destructive">
                        删除标注
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>删除标注</AlertDialogTitle>
                        <AlertDialogDescription>
                          确定要永久删除这个标注吗？此操作无法撤销。
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => deleteAnnotation(selectedAnnotation.id)}
                          className="bg-red-600 hover:bg-red-700"
                        >
                          确认删除
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 拒绝原因弹窗 */}
      <Dialog open={isRejectDialogOpen} onOpenChange={setIsRejectDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>拒绝标注</DialogTitle>
            <DialogDescription>
              请输入拒绝该标注的原因，这将发送给标注创建者。
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>拒绝原因</Label>
              <Textarea
                placeholder="请详细说明拒绝的原因..."
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                rows={4}
              />
            </div>
            
            <div className="flex justify-end space-x-2">
              <Button
                variant="outline"
                onClick={() => {
                  setIsRejectDialogOpen(false);
                  setRejectReason('');
                }}
              >
                取消
              </Button>
              <Button
                variant="destructive"
                onClick={rejectAnnotation}
                disabled={!rejectReason.trim()}
              >
                确认拒绝
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default AnnotationReview;