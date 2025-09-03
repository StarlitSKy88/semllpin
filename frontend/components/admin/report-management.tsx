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
  AlertTriangle,
  User,
  Calendar,
  MessageSquare,
  MapPin,
  Flag,
  Shield,
  Clock,
} from 'lucide-react';
import { toast } from 'sonner';

// 模拟举报数据
const mockReports = [
  {
    id: '1',
    type: 'annotation' as const,
    targetId: 'ann_001',
    targetTitle: '这里有个奇怪的雕像',
    targetContent: '路过发现这个雕像造型很搞笑，大家快来看看！',
    reason: 'inappropriate_content',
    reasonText: '内容不当',
    description: '这个标注包含不适宜的内容，可能会冒犯其他用户',
    reporter: {
      id: 'user_001',
      username: '举报者A',
      level: 3,
    },
    targetCreator: {
      id: 'user_002',
      username: '被举报者B',
      level: 2,
    },
    status: 'pending' as const,
    createdAt: '2024-01-20T10:30:00Z',
    reviewedAt: null,
    reviewedBy: null,
    action: null,
    actionReason: null,
    severity: 'medium' as const,
  },
  {
    id: '2',
    type: 'comment' as const,
    targetId: 'comment_001',
    targetTitle: '评论回复',
    targetContent: '这个地方确实很有意思，我也去过',
    reason: 'spam',
    reasonText: '垃圾信息',
    description: '这个用户一直在发送重复的垃圾评论',
    reporter: {
      id: 'user_003',
      username: '举报者C',
      level: 5,
    },
    targetCreator: {
      id: 'user_004',
      username: '被举报者D',
      level: 1,
    },
    status: 'pending' as const,
    createdAt: '2024-01-20T14:15:00Z',
    reviewedAt: null,
    reviewedBy: null,
    action: null,
    actionReason: null,
    severity: 'low' as const,
  },
  {
    id: '3',
    type: 'annotation' as const,
    targetId: 'ann_002',
    targetTitle: '违规标注内容',
    targetContent: '这是一个包含违规内容的标注',
    reason: 'harassment',
    reasonText: '骚扰他人',
    description: '该标注涉嫌骚扰特定用户群体',
    reporter: {
      id: 'user_005',
      username: '举报者E',
      level: 4,
    },
    targetCreator: {
      id: 'user_006',
      username: '被举报者F',
      level: 2,
    },
    status: 'resolved' as const,
    createdAt: '2024-01-19T16:45:00Z',
    reviewedAt: '2024-01-20T09:20:00Z',
    reviewedBy: 'admin1',
    action: 'content_removed',
    actionReason: '内容确实违反社区规范，已删除相关内容',
    severity: 'high' as const,
  },
  {
    id: '4',
    type: 'comment' as const,
    targetId: 'comment_002',
    targetTitle: '恶意评论',
    targetContent: '这个评论包含恶意攻击内容',
    reason: 'hate_speech',
    reasonText: '仇恨言论',
    description: '评论中包含仇恨言论和歧视性内容',
    reporter: {
      id: 'user_007',
      username: '举报者G',
      level: 6,
    },
    targetCreator: {
      id: 'user_008',
      username: '被举报者H',
      level: 3,
    },
    status: 'dismissed' as const,
    createdAt: '2024-01-19T11:30:00Z',
    reviewedAt: '2024-01-19T15:45:00Z',
    reviewedBy: 'admin2',
    action: 'no_action',
    actionReason: '经审核，该内容未违反社区规范',
    severity: 'low' as const,
  },
];

type ReportStatus = 'pending' | 'resolved' | 'dismissed';
type ReportType = 'annotation' | 'comment';
type ReportSeverity = 'low' | 'medium' | 'high';
type ReportAction = 'no_action' | 'content_removed' | 'user_warned' | 'user_suspended' | 'user_banned';

interface Report {
  id: string;
  type: ReportType;
  targetId: string;
  targetTitle: string;
  targetContent: string;
  reason: string;
  reasonText: string;
  description: string;
  reporter: {
    id: string;
    username: string;
    level: number;
  };
  targetCreator: {
    id: string;
    username: string;
    level: number;
  };
  status: ReportStatus;
  createdAt: string;
  reviewedAt: string | null;
  reviewedBy: string | null;
  action: ReportAction | null;
  actionReason: string | null;
  severity: ReportSeverity;
}

interface ReportManagementProps {
  className?: string;
}

export function ReportManagement({ className }: ReportManagementProps) {
  const [reports, setReports] = useState<Report[]>(mockReports);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [actionReason, setActionReason] = useState('');
  const [selectedAction, setSelectedAction] = useState<ReportAction>('no_action');
  const [isActionDialogOpen, setIsActionDialogOpen] = useState(false);

  // 过滤举报
  const filteredReports = reports.filter((report) => {
    const matchesSearch = 
      report.targetTitle.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.targetContent.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.reporter.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.targetCreator.username.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = statusFilter === 'all' || report.status === statusFilter;
    const matchesType = typeFilter === 'all' || report.type === typeFilter;
    const matchesSeverity = severityFilter === 'all' || report.severity === severityFilter;
    
    return matchesSearch && matchesStatus && matchesType && matchesSeverity;
  });

  // 获取状态徽章
  const getStatusBadge = (status: ReportStatus) => {
    switch (status) {
      case 'pending':
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">待处理</Badge>;
      case 'resolved':
        return <Badge variant="default" className="bg-green-100 text-green-800">已处理</Badge>;
      case 'dismissed':
        return <Badge variant="outline">已驳回</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 获取类型徽章
  const getTypeBadge = (type: ReportType) => {
    switch (type) {
      case 'annotation':
        return <Badge variant="outline" className="bg-blue-50 text-blue-700">标注</Badge>;
      case 'comment':
        return <Badge variant="outline" className="bg-purple-50 text-purple-700">评论</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 获取严重程度徽章
  const getSeverityBadge = (severity: ReportSeverity) => {
    switch (severity) {
      case 'low':
        return <Badge variant="outline" className="bg-gray-50 text-gray-700">低</Badge>;
      case 'medium':
        return <Badge variant="outline" className="bg-orange-50 text-orange-700">中</Badge>;
      case 'high':
        return <Badge variant="destructive">高</Badge>;
      default:
        return <Badge variant="outline">未知</Badge>;
    }
  };

  // 获取举报原因文本
  const getReasonText = (reason: string) => {
    const reasons: Record<string, string> = {
      inappropriate_content: '内容不当',
      spam: '垃圾信息',
      harassment: '骚扰他人',
      hate_speech: '仇恨言论',
      violence: '暴力内容',
      copyright: '版权侵犯',
      privacy: '隐私侵犯',
      other: '其他',
    };
    return reasons[reason] || reason;
  };

  // 获取处理动作文本
  const getActionText = (action: ReportAction) => {
    const actions: Record<ReportAction, string> = {
      no_action: '无需处理',
      content_removed: '删除内容',
      user_warned: '警告用户',
      user_suspended: '暂停用户',
      user_banned: '封禁用户',
    };
    return actions[action];
  };

  // 处理举报
  const handleReport = () => {
    if (!selectedReport || !actionReason.trim()) {
      toast.error('请输入处理原因');
      return;
    }

    const newStatus: ReportStatus = selectedAction === 'no_action' ? 'dismissed' : 'resolved';

    setReports(reports.map(report => 
      report.id === selectedReport.id 
        ? { 
            ...report, 
            status: newStatus,
            reviewedAt: new Date().toISOString(),
            reviewedBy: 'current_admin',
            action: selectedAction,
            actionReason: actionReason
          }
        : report
    ));
    
    toast.success('举报已处理');
    setIsActionDialogOpen(false);
    setIsDetailOpen(false);
    setActionReason('');
    setSelectedAction('no_action');
  };

  // 格式化日期
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('zh-CN');
  };

  // 计算待处理数量
  const pendingCount = reports.filter(r => r.status === 'pending').length;
  const highSeverityCount = reports.filter(r => r.status === 'pending' && r.severity === 'high').length;

  return (
    <div className={className}>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>举报管理</span>
            <div className="flex items-center space-x-2">
              {highSeverityCount > 0 && (
                <Badge variant="destructive">
                  {highSeverityCount} 个高危举报
                </Badge>
              )}
              {pendingCount > 0 && (
                <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                  {pendingCount} 个待处理
                </Badge>
              )}
            </div>
          </CardTitle>
          <CardDescription>处理用户举报的内容和行为</CardDescription>
        </CardHeader>
        <CardContent>
          {/* 搜索和筛选 */}
          <div className="flex flex-col lg:flex-row gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="搜索举报内容、描述或用户..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            <div className="flex flex-col sm:flex-row gap-2">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-full sm:w-[120px]">
                  <SelectValue placeholder="状态" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="pending">待处理</SelectItem>
                  <SelectItem value="resolved">已处理</SelectItem>
                  <SelectItem value="dismissed">已驳回</SelectItem>
                </SelectContent>
              </Select>
              
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-full sm:w-[120px]">
                  <SelectValue placeholder="类型" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部类型</SelectItem>
                  <SelectItem value="annotation">标注</SelectItem>
                  <SelectItem value="comment">评论</SelectItem>
                </SelectContent>
              </Select>
              
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-full sm:w-[120px]">
                  <SelectValue placeholder="严重程度" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部程度</SelectItem>
                  <SelectItem value="high">高危</SelectItem>
                  <SelectItem value="medium">中等</SelectItem>
                  <SelectItem value="low">较低</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* 举报列表 */}
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>举报信息</TableHead>
                  <TableHead>被举报内容</TableHead>
                  <TableHead>举报者</TableHead>
                  <TableHead>被举报者</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>严重程度</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>举报时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredReports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <Flag className="h-4 w-4 text-red-500" />
                          <span className="font-medium">{report.reasonText}</span>
                        </div>
                        <div className="text-sm text-gray-500 line-clamp-2">{report.description}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="font-medium line-clamp-1">{report.targetTitle}</div>
                        <div className="text-sm text-gray-500 line-clamp-2">{report.targetContent}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1">
                          <User className="h-3 w-3" />
                          <span className="text-sm font-medium">{report.reporter.username}</span>
                        </div>
                        <div className="text-xs text-gray-500">Lv.{report.reporter.level}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1">
                          <User className="h-3 w-3" />
                          <span className="text-sm font-medium">{report.targetCreator.username}</span>
                        </div>
                        <div className="text-xs text-gray-500">Lv.{report.targetCreator.level}</div>
                      </div>
                    </TableCell>
                    <TableCell>{getTypeBadge(report.type)}</TableCell>
                    <TableCell>{getSeverityBadge(report.severity)}</TableCell>
                    <TableCell>{getStatusBadge(report.status)}</TableCell>
                    <TableCell>
                      <div className="text-sm">{formatDate(report.createdAt)}</div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSelectedReport(report);
                            setIsDetailOpen(true);
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        
                        {report.status === 'pending' && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-blue-600"
                            onClick={() => {
                              setSelectedReport(report);
                              setIsActionDialogOpen(true);
                            }}
                          >
                            <Shield className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {filteredReports.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              没有找到符合条件的举报
            </div>
          )}
        </CardContent>
      </Card>

      {/* 举报详情弹窗 */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>举报详情</DialogTitle>
            <DialogDescription>
              查看举报的详细信息并进行处理
            </DialogDescription>
          </DialogHeader>
          
          {selectedReport && (
            <div className="space-y-6">
              {/* 举报基本信息 */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>举报原因</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-2">
                        <Flag className="h-4 w-4 text-red-500" />
                        <span className="font-medium">{selectedReport.reasonText}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>举报描述</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      {selectedReport.description}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>内容类型</Label>
                      <div>{getTypeBadge(selectedReport.type)}</div>
                    </div>
                    <div className="space-y-2">
                      <Label>严重程度</Label>
                      <div>{getSeverityBadge(selectedReport.severity)}</div>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>举报者信息</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-2">
                        <User className="h-4 w-4" />
                        <span className="font-medium">{selectedReport.reporter.username}</span>
                        <Badge variant="outline" className="text-xs">
                          Lv.{selectedReport.reporter.level}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>被举报者信息</Label>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-2">
                        <User className="h-4 w-4" />
                        <span className="font-medium">{selectedReport.targetCreator.username}</span>
                        <Badge variant="outline" className="text-xs">
                          Lv.{selectedReport.targetCreator.level}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>举报时间</Label>
                    <div className="p-2 bg-gray-50 rounded flex items-center space-x-1">
                      <Calendar className="h-4 w-4" />
                      <span>{formatDate(selectedReport.createdAt)}</span>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>当前状态</Label>
                    <div>{getStatusBadge(selectedReport.status)}</div>
                  </div>
                </div>
              </div>

              {/* 被举报内容 */}
              <div className="space-y-2">
                <Label>被举报内容</Label>
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                  <div className="space-y-2">
                    <div className="font-medium">{selectedReport.targetTitle}</div>
                    <div className="text-sm text-gray-700">{selectedReport.targetContent}</div>
                    <div className="flex items-center space-x-2 text-xs text-gray-500">
                      {selectedReport.type === 'annotation' ? (
                        <><MapPin className="h-3 w-3" /><span>标注内容</span></>
                      ) : (
                        <><MessageSquare className="h-3 w-3" /><span>评论内容</span></>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* 处理记录 */}
              {selectedReport.reviewedAt && (
                <div className="space-y-2">
                  <Label>处理记录</Label>
                  <div className="p-3 bg-gray-50 rounded-lg space-y-2">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-4 w-4" />
                      <span>处理时间: {formatDate(selectedReport.reviewedAt)}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <User className="h-4 w-4" />
                      <span>处理人: {selectedReport.reviewedBy}</span>
                    </div>
                    {selectedReport.action && (
                      <div className="flex items-center space-x-2">
                        <Shield className="h-4 w-4" />
                        <span>处理动作: {getActionText(selectedReport.action)}</span>
                      </div>
                    )}
                    {selectedReport.actionReason && (
                      <div className="mt-2 p-2 bg-blue-50 border border-blue-200 rounded">
                        <div className="text-sm font-medium text-blue-800">处理原因:</div>
                        <div className="text-sm text-blue-700 mt-1">{selectedReport.actionReason}</div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 操作按钮 */}
              {selectedReport.status === 'pending' && (
                <div className="flex justify-end pt-4 border-t">
                  <Button
                    onClick={() => setIsActionDialogOpen(true)}
                  >
                    <Shield className="h-4 w-4 mr-2" />
                    处理举报
                  </Button>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 处理举报弹窗 */}
      <Dialog open={isActionDialogOpen} onOpenChange={setIsActionDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>处理举报</DialogTitle>
            <DialogDescription>
              选择对此举报的处理方式并说明原因。
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>处理动作</Label>
              <Select value={selectedAction} onValueChange={(value) => setSelectedAction(value as ReportAction)}>
                <SelectTrigger>
                  <SelectValue placeholder="选择处理动作" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="no_action">无需处理</SelectItem>
                  <SelectItem value="content_removed">删除内容</SelectItem>
                  <SelectItem value="user_warned">警告用户</SelectItem>
                  <SelectItem value="user_suspended">暂停用户</SelectItem>
                  <SelectItem value="user_banned">封禁用户</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label>处理原因</Label>
              <Textarea
                placeholder="请详细说明处理的原因..."
                value={actionReason}
                onChange={(e) => setActionReason(e.target.value)}
                rows={4}
              />
            </div>
            
            <div className="flex justify-end space-x-2">
              <Button
                variant="outline"
                onClick={() => {
                  setIsActionDialogOpen(false);
                  setActionReason('');
                  setSelectedAction('no_action');
                }}
              >
                取消
              </Button>
              <Button
                onClick={handleReport}
                disabled={!actionReason.trim()}
              >
                确认处理
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default ReportManagement;