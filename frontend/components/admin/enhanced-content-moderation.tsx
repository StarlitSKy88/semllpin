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
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
  FileText,
  MessageCircle,
  Image,
  User,
  Calendar,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';
import { toast } from 'sonner';
import { adminApi, ContentReview, PaginatedResponse } from '@/lib/services/admin-api';

type ReviewStatus = 'pending' | 'approved' | 'rejected';
type ContentType = 'annotation' | 'comment' | 'media';

interface EnhancedContentModerationProps {
  className?: string;
}

export function EnhancedContentModeration({ className }: EnhancedContentModerationProps) {
  const [reviews, setReviews] = useState<ContentReview[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [selectedReview, setSelectedReview] = useState<ContentReview | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [selectedReviews, setSelectedReviews] = useState<string[]>([]);
  
  // 分页状态
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0,
  });

  // 加载审核列表
  const loadReviews = async () => {
    setLoading(true);
    try {
      const params: any = {
        page: pagination.page,
        limit: pagination.limit,
      };

      if (statusFilter !== 'all') {
        params.status = statusFilter as ReviewStatus;
      }

      if (typeFilter !== 'all') {
        params.type = typeFilter as ContentType;
      }

      const response = await adminApi.getContentReviews(params);
      if (response.data.success) {
        setReviews(response.data.data.data);
        setPagination(response.data.data.pagination);
      } else {
        toast.error('获取审核列表失败');
      }
    } catch (error) {
      console.error('获取审核列表错误:', error);
      toast.error('获取审核列表失败');
    } finally {
      setLoading(false);
    }
  };

  // 初始加载和依赖变化时重新加载
  useEffect(() => {
    loadReviews();
  }, [pagination.page, pagination.limit, statusFilter, typeFilter]);

  // 获取状态徽章
  const getStatusBadge = (status: ReviewStatus) => {
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

  // 获取内容类型图标和文本
  const getContentTypeInfo = (type: ContentType) => {
    switch (type) {
      case 'annotation':
        return { icon: <FileText className="h-4 w-4" />, text: '标注' };
      case 'comment':
        return { icon: <MessageCircle className="h-4 w-4" />, text: '评论' };
      case 'media':
        return { icon: <Image className="h-4 w-4" />, text: '媒体' };
      default:
        return { icon: <FileText className="h-4 w-4" />, text: '未知' };
    }
  };

  // 处理审核
  const handleReview = async (reviewId: string, action: 'approve' | 'reject', reason?: string) => {
    try {
      const response = await adminApi.handleContentReview(reviewId, action, reason);
      if (response.data.success) {
        toast.success(`内容审核${action === 'approve' ? '通过' : '拒绝'}成功`);
        loadReviews(); // 重新加载数据
      } else {
        toast.error('审核操作失败');
      }
    } catch (error) {
      console.error('审核操作错误:', error);
      toast.error('审核操作失败');
    }
  };

  // 批量审核
  const batchReview = async (action: 'approve' | 'reject', reason?: string) => {
    if (selectedReviews.length === 0) {
      toast.error('请选择要操作的审核项');
      return;
    }

    try {
      const promises = selectedReviews.map(reviewId => 
        adminApi.handleContentReview(reviewId, action, reason)
      );
      
      await Promise.all(promises);
      toast.success(`批量${action === 'approve' ? '通过' : '拒绝'}操作成功`);
      setSelectedReviews([]);
      loadReviews();
    } catch (error) {
      console.error('批量审核错误:', error);
      toast.error(`批量${action === 'approve' ? '通过' : '拒绝'}操作失败`);
    }
  };

  // 格式化日期
  const formatDate = (dateString: string | Date) => {
    return new Date(dateString).toLocaleString('zh-CN');
  };

  // 处理全选
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedReviews(reviews.filter(r => r.status === 'pending').map(r => r.id));
    } else {
      setSelectedReviews([]);
    }
  };

  // 处理单个选择
  const handleSelectReview = (reviewId: string, checked: boolean) => {
    if (checked) {
      setSelectedReviews(prev => [...prev, reviewId]);
    } else {
      setSelectedReviews(prev => prev.filter(id => id !== reviewId));
    }
  };

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5" />
            <span>内容审核</span>
          </CardTitle>
          <CardDescription>管理用户举报的内容和待审核项目</CardDescription>
        </CardHeader>
        <CardContent>
          {/* 搜索和筛选工具栏 */}
          <div className="flex flex-col lg:flex-row gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="搜索内容..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            
            <div className="flex gap-2">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[120px]">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="状态" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="pending">待审核</SelectItem>
                  <SelectItem value="approved">已通过</SelectItem>
                  <SelectItem value="rejected">已拒绝</SelectItem>
                </SelectContent>
              </Select>

              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-[120px]">
                  <SelectValue placeholder="类型" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部类型</SelectItem>
                  <SelectItem value="annotation">标注</SelectItem>
                  <SelectItem value="comment">评论</SelectItem>
                  <SelectItem value="media">媒体</SelectItem>
                </SelectContent>
              </Select>

              <Button
                variant="outline"
                onClick={loadReviews}
                disabled={loading}
                className="flex items-center space-x-2"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                <span>刷新</span>
              </Button>
            </div>
          </div>

          {/* 批量操作工具栏 */}
          {selectedReviews.length > 0 && (
            <div className="mb-4 p-4 bg-blue-50 rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm text-blue-700">
                  已选择 {selectedReviews.length} 个审核项
                </span>
                <div className="flex gap-2">
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" size="sm" className="text-green-600">
                        批量通过
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>批量通过审核</AlertDialogTitle>
                        <AlertDialogDescription>
                          确定要通过选中的 {selectedReviews.length} 个审核项吗？
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction onClick={() => batchReview('approve')}>
                          确认通过
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>

                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" size="sm" className="text-red-600">
                        批量拒绝
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>批量拒绝审核</AlertDialogTitle>
                        <AlertDialogDescription>
                          确定要拒绝选中的 {selectedReviews.length} 个审核项吗？
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => batchReview('reject')}
                          className="bg-red-600 hover:bg-red-700"
                        >
                          确认拒绝
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </div>
            </div>
          )}

          {/* 审核列表 */}
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={
                        selectedReviews.length > 0 && 
                        selectedReviews.length === reviews.filter(r => r.status === 'pending').length
                      }
                      onCheckedChange={handleSelectAll}
                    />
                  </TableHead>
                  <TableHead>内容信息</TableHead>
                  <TableHead>举报信息</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2" />
                      <span className="text-gray-500">加载中...</span>
                    </TableCell>
                  </TableRow>
                ) : reviews.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-gray-500">
                      没有找到符合条件的审核项
                    </TableCell>
                  </TableRow>
                ) : (
                  reviews.map((review) => {
                    const typeInfo = getContentTypeInfo(review.type);
                    return (
                      <TableRow key={review.id}>
                        <TableCell>
                          {review.status === 'pending' && (
                            <Checkbox
                              checked={selectedReviews.includes(review.id)}
                              onCheckedChange={(checked) => handleSelectReview(review.id, checked as boolean)}
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="font-medium text-sm truncate max-w-xs">
                              {review.content_preview || '暂无预览'}
                            </div>
                            <div className="text-xs text-gray-500">
                              ID: {review.content_id.slice(-8)}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="space-y-1 text-sm">
                            {review.reporter_username && (
                              <div className="flex items-center space-x-1">
                                <User className="h-3 w-3" />
                                <span>举报人: {review.reporter_username}</span>
                              </div>
                            )}
                            {review.reported_username && (
                              <div className="flex items-center space-x-1">
                                <User className="h-3 w-3" />
                                <span>被举报: {review.reported_username}</span>
                              </div>
                            )}
                            {review.reason && (
                              <div className="text-gray-600 text-xs truncate max-w-xs">
                                原因: {review.reason}
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {typeInfo.icon}
                            <span>{typeInfo.text}</span>
                          </div>
                        </TableCell>
                        <TableCell>{getStatusBadge(review.status)}</TableCell>
                        <TableCell>
                          <div className="text-sm">
                            <div className="flex items-center space-x-1 mb-1">
                              <Calendar className="h-3 w-3" />
                              <span>{formatDate(review.created_at)}</span>
                            </div>
                            {review.reviewed_at && (
                              <div className="text-xs text-gray-500">
                                审核: {formatDate(review.reviewed_at)}
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
                                setSelectedReview(review);
                                setIsDetailOpen(true);
                              }}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            
                            {review.status === 'pending' && (
                              <>
                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button variant="outline" size="sm" className="text-green-600">
                                      <CheckCircle className="h-4 w-4" />
                                    </Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>通过审核</AlertDialogTitle>
                                      <AlertDialogDescription>
                                        确定要通过此审核项吗？
                                      </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>取消</AlertDialogCancel>
                                      <AlertDialogAction
                                        onClick={() => handleReview(review.id, 'approve')}
                                        className="bg-green-600 hover:bg-green-700"
                                      >
                                        确认通过
                                      </AlertDialogAction>
                                    </AlertDialogFooter>
                                  </AlertDialogContent>
                                </AlertDialog>

                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button variant="outline" size="sm" className="text-red-600">
                                      <XCircle className="h-4 w-4" />
                                    </Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>拒绝审核</AlertDialogTitle>
                                      <AlertDialogDescription>
                                        确定要拒绝此审核项吗？
                                      </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>取消</AlertDialogCancel>
                                      <AlertDialogAction
                                        onClick={() => handleReview(review.id, 'reject')}
                                        className="bg-red-600 hover:bg-red-700"
                                      >
                                        确认拒绝
                                      </AlertDialogAction>
                                    </AlertDialogFooter>
                                  </AlertDialogContent>
                                </AlertDialog>
                              </>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })
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

      {/* 审核详情弹窗 */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5" />
              <span>审核详情</span>
            </DialogTitle>
            <DialogDescription>
              查看内容审核的详细信息
            </DialogDescription>
          </DialogHeader>
          
          {selectedReview && (
            <div className="space-y-6">
              {/* 基本信息 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">基本信息</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>审核ID</Label>
                      <div className="p-2 bg-gray-50 rounded font-mono">{selectedReview.id}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>内容ID</Label>
                      <div className="p-2 bg-gray-50 rounded font-mono">{selectedReview.content_id}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>内容类型</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {getContentTypeInfo(selectedReview.type).text}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>状态</Label>
                      <div>{getStatusBadge(selectedReview.status)}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 内容预览 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">内容预览</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="whitespace-pre-wrap break-words">
                      {selectedReview.content_preview || '暂无预览内容'}
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 举报信息 */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">举报信息</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>举报人</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {selectedReview.reporter_username || '匿名'}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>被举报人</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {selectedReview.reported_username || '未知'}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>举报原因</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {selectedReview.reason || '无'}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>举报时间</Label>
                      <div className="p-2 bg-gray-50 rounded">
                        {formatDate(selectedReview.created_at)}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 审核信息 */}
              {selectedReview.reviewed_at && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">审核信息</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>审核时间</Label>
                        <div className="p-2 bg-gray-50 rounded">
                          {formatDate(selectedReview.reviewed_at)}
                        </div>
                      </div>
                      {selectedReview.reviewed_by && (
                        <div className="space-y-2">
                          <Label>审核员</Label>
                          <div className="p-2 bg-gray-50 rounded">
                            {selectedReview.reviewed_by}
                          </div>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* 审核操作 */}
              {selectedReview.status === 'pending' && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">审核操作</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex space-x-4">
                      <Button
                        onClick={() => {
                          handleReview(selectedReview.id, 'approve');
                          setIsDetailOpen(false);
                        }}
                        className="bg-green-600 hover:bg-green-700 text-white"
                      >
                        <CheckCircle className="h-4 w-4 mr-2" />
                        通过审核
                      </Button>
                      <Button
                        onClick={() => {
                          handleReview(selectedReview.id, 'reject');
                          setIsDetailOpen(false);
                        }}
                        variant="destructive"
                      >
                        <XCircle className="h-4 w-4 mr-2" />
                        拒绝审核
                      </Button>
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

export default EnhancedContentModeration;