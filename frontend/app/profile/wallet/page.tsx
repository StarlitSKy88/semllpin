'use client';

import { useState } from 'react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { toast } from 'sonner';
import {
  Wallet,
  CreditCard,
  ArrowUpRight,
  ArrowDownLeft,
  DollarSign,
  Gift,
  Star,
  TrendingUp,
  Calendar,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  ArrowLeft,
  Smartphone,
  Building,
  QrCode
} from 'lucide-react';
import Link from 'next/link';

// 模拟交易记录数据
const mockTransactions = [
  {
    id: '1',
    type: 'discovery' as const,
    amount: 5.20,
    status: 'completed' as const,
    description: '标注被发现奖励',
    annotationTitle: '这里有个奇怪的味道',
    createdAt: '2024-01-22T16:30:00Z',
    completedAt: '2024-01-22T16:30:00Z'
  },
  {
    id: '2',
    type: 'withdrawal' as const,
    amount: -15.00,
    status: 'processing' as const,
    description: '提现到支付宝',
    account: '138****8888',
    createdAt: '2024-01-20T14:30:00Z'
  },
  {
    id: '3',
    type: 'discovery' as const,
    amount: 3.80,
    status: 'completed' as const,
    description: '标注被发现奖励',
    annotationTitle: '垃圾桶旁边的异味',
    createdAt: '2024-01-21T11:20:00Z',
    completedAt: '2024-01-21T11:20:00Z'
  },
  {
    id: '4',
    type: 'bonus' as const,
    amount: 10.00,
    status: 'completed' as const,
    description: '新用户注册奖励',
    createdAt: '2024-01-15T08:00:00Z',
    completedAt: '2024-01-15T08:00:00Z'
  },
  {
    id: '5',
    type: 'recharge' as const,
    amount: 50.00,
    status: 'completed' as const,
    description: '账户充值',
    createdAt: '2024-01-10T12:00:00Z',
    completedAt: '2024-01-10T12:00:00Z'
  },
  {
    id: '6',
    type: 'withdrawal' as const,
    amount: -25.00,
    status: 'failed' as const,
    description: '提现到微信',
    account: '微信号：wx123456',
    createdAt: '2024-01-18T09:15:00Z',
    failReason: '账户信息错误'
  }
];

// 模拟提现账户
const mockWithdrawalAccounts = [
  {
    id: '1',
    type: 'alipay' as const,
    account: '138****8888',
    name: '张***',
    isDefault: true
  },
  {
    id: '2',
    type: 'wechat' as const,
    account: 'wx123456',
    name: '张***',
    isDefault: false
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

function getTransactionIcon(type: string) {
  switch (type) {
    case 'discovery':
      return <Gift className="w-4 h-4 text-blue-500" />;
    case 'bonus':
      return <Star className="w-4 h-4 text-yellow-500" />;
    case 'recharge':
      return <ArrowDownLeft className="w-4 h-4 text-green-500" />;
    case 'withdrawal':
      return <ArrowUpRight className="w-4 h-4 text-red-500" />;
    default:
      return <DollarSign className="w-4 h-4 text-gray-500" />;
  }
}

function getStatusBadge(status: string, failReason?: string) {
  switch (status) {
    case 'completed':
      return <Badge variant="default" className="bg-green-100 text-green-800"><CheckCircle className="w-3 h-3 mr-1" />已完成</Badge>;
    case 'processing':
      return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800"><Clock className="w-3 h-3 mr-1" />处理中</Badge>;
    case 'failed':
      return (
        <div className="flex flex-col gap-1">
          <Badge variant="destructive" className="bg-red-100 text-red-800"><XCircle className="w-3 h-3 mr-1" />失败</Badge>
          {failReason && <span className="text-xs text-red-600">{failReason}</span>}
        </div>
      );
    default:
      return <Badge variant="outline"><AlertCircle className="w-3 h-3 mr-1" />未知</Badge>;
  }
}

function getTransactionTypeName(type: string) {
  switch (type) {
    case 'discovery':
      return '发现奖励';
    case 'bonus':
      return '奖励';
    case 'recharge':
      return '充值';
    case 'withdrawal':
      return '提现';
    default:
      return '其他';
  }
}

export default function WalletPage() {
  const { user } = useAuthStore();
  const [showWithdrawDialog, setShowWithdrawDialog] = useState(false);
  const [showRechargeDialog, setShowRechargeDialog] = useState(false);
  const [withdrawAmount, setWithdrawAmount] = useState('');
  const [rechargeAmount, setRechargeAmount] = useState('');
  const [selectedAccount, setSelectedAccount] = useState('');
  const [selectedPaymentMethod, setSelectedPaymentMethod] = useState('');

  const totalIncome = mockTransactions
    .filter(t => t.type !== 'withdrawal' && t.status === 'completed')
    .reduce((sum, t) => sum + t.amount, 0);
  
  const totalWithdrawal = mockTransactions
    .filter(t => t.type === 'withdrawal' && t.status === 'completed')
    .reduce((sum, t) => sum + Math.abs(t.amount), 0);
  
  const pendingWithdrawal = mockTransactions
    .filter(t => t.type === 'withdrawal' && t.status === 'processing')
    .reduce((sum, t) => sum + Math.abs(t.amount), 0);

  const handleWithdraw = async () => {
    const amount = parseFloat(withdrawAmount);
    
    if (!amount || amount <= 0) {
      toast.error('请输入有效的提现金额');
      return;
    }
    
    if (amount < 10) {
      toast.error('最低提现金额为10元');
      return;
    }
    
    if (amount > (user?.balance || 0)) {
      toast.error('余额不足');
      return;
    }
    
    if (!selectedAccount) {
      toast.error('请选择提现账户');
      return;
    }

    try {
      // TODO: 调用API提现
      toast.success('提现申请已提交，预计1-3个工作日到账');
      setShowWithdrawDialog(false);
      setWithdrawAmount('');
      setSelectedAccount('');
    } catch (error) {
      toast.error('提现失败，请重试');
    }
  };

  const handleRecharge = async () => {
    const amount = parseFloat(rechargeAmount);
    
    if (!amount || amount <= 0) {
      toast.error('请输入有效的充值金额');
      return;
    }
    
    if (amount < 1) {
      toast.error('最低充值金额为1元');
      return;
    }
    
    if (!selectedPaymentMethod) {
      toast.error('请选择支付方式');
      return;
    }

    try {
      // TODO: 调用API充值
      toast.success('正在跳转到支付页面...');
      setShowRechargeDialog(false);
      setRechargeAmount('');
      setSelectedPaymentMethod('');
    } catch (error) {
      toast.error('充值失败，请重试');
    }
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
            <h1 className="text-3xl font-bold">我的钱包</h1>
            <p className="text-gray-600">管理您的收益和提现</p>
          </div>
        </div>

        {/* 钱包概览 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* 余额卡片 */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wallet className="w-5 h-5" />
                账户余额
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center space-y-4">
                <div className="text-4xl font-bold text-green-600">
                  ¥{user?.balance?.toFixed(2) || '0.00'}
                </div>
                <div className="flex justify-center gap-4">
                  <Dialog open={showRechargeDialog} onOpenChange={setShowRechargeDialog}>
                    <DialogTrigger asChild>
                      <Button className="flex-1 max-w-32">
                        <ArrowDownLeft className="w-4 h-4 mr-2" />
                        充值
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>账户充值</DialogTitle>
                        <DialogDescription>
                          选择充值金额和支付方式
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label htmlFor="recharge-amount">充值金额</Label>
                          <Input
                            id="recharge-amount"
                            type="number"
                            placeholder="请输入充值金额（最低1元）"
                            value={rechargeAmount}
                            onChange={(e) => setRechargeAmount(e.target.value)}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>支付方式</Label>
                          <Select value={selectedPaymentMethod} onValueChange={setSelectedPaymentMethod}>
                            <SelectTrigger>
                              <SelectValue placeholder="选择支付方式" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="alipay">
                                <div className="flex items-center gap-2">
                                  <Smartphone className="w-4 h-4" />
                                  支付宝
                                </div>
                              </SelectItem>
                              <SelectItem value="wechat">
                                <div className="flex items-center gap-2">
                                  <QrCode className="w-4 h-4" />
                                  微信支付
                                </div>
                              </SelectItem>
                              <SelectItem value="bank">
                                <div className="flex items-center gap-2">
                                  <Building className="w-4 h-4" />
                                  银行卡
                                </div>
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        {/* 快捷金额选择 */}
                        <div className="space-y-2">
                          <Label>快捷选择</Label>
                          <div className="grid grid-cols-3 gap-2">
                            {[10, 50, 100, 200, 500, 1000].map((amount) => (
                              <Button
                                key={amount}
                                variant="outline"
                                size="sm"
                                onClick={() => setRechargeAmount(amount.toString())}
                              >
                                ¥{amount}
                              </Button>
                            ))}
                          </div>
                        </div>
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setShowRechargeDialog(false)}>
                          取消
                        </Button>
                        <Button onClick={handleRecharge}>
                          确认充值
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                  
                  <Dialog open={showWithdrawDialog} onOpenChange={setShowWithdrawDialog}>
                    <DialogTrigger asChild>
                      <Button variant="outline" className="flex-1 max-w-32">
                        <ArrowUpRight className="w-4 h-4 mr-2" />
                        提现
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>申请提现</DialogTitle>
                        <DialogDescription>
                          选择提现金额和账户，预计1-3个工作日到账
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label htmlFor="withdraw-amount">提现金额</Label>
                          <Input
                            id="withdraw-amount"
                            type="number"
                            placeholder="请输入提现金额（最低10元）"
                            value={withdrawAmount}
                            onChange={(e) => setWithdrawAmount(e.target.value)}
                          />
                          <div className="text-sm text-gray-500">
                            可提现余额：¥{user?.balance?.toFixed(2) || '0.00'}
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label>提现账户</Label>
                          <Select value={selectedAccount} onValueChange={setSelectedAccount}>
                            <SelectTrigger>
                              <SelectValue placeholder="选择提现账户" />
                            </SelectTrigger>
                            <SelectContent>
                              {mockWithdrawalAccounts.map((account) => (
                                <SelectItem key={account.id} value={account.id}>
                                  <div className="flex items-center gap-2">
                                    {account.type === 'alipay' && <Smartphone className="w-4 h-4" />}
                                    {account.type === 'wechat' && <QrCode className="w-4 h-4" />}
                                    <span>
                                      {account.type === 'alipay' ? '支付宝' : '微信'} - {account.account}
                                    </span>
                                    {account.isDefault && <Badge variant="secondary" className="text-xs">默认</Badge>}
                                  </div>
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <Alert>
                          <AlertCircle className="h-4 w-4" />
                          <AlertDescription>
                            提现手续费：2%，最低2元。实际到账金额会扣除手续费。
                          </AlertDescription>
                        </Alert>
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setShowWithdrawDialog(false)}>
                          取消
                        </Button>
                        <Button onClick={handleWithdraw}>
                          确认提现
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* 统计卡片 */}
          <div className="space-y-4">
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-5 h-5 text-green-500" />
                  <div>
                    <p className="text-sm text-gray-600">总收入</p>
                    <p className="text-2xl font-bold text-green-600">¥{totalIncome.toFixed(2)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-2">
                  <ArrowUpRight className="w-5 h-5 text-blue-500" />
                  <div>
                    <p className="text-sm text-gray-600">已提现</p>
                    <p className="text-2xl font-bold text-blue-600">¥{totalWithdrawal.toFixed(2)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-2">
                  <Clock className="w-5 h-5 text-yellow-500" />
                  <div>
                    <p className="text-sm text-gray-600">处理中</p>
                    <p className="text-2xl font-bold text-yellow-600">¥{pendingWithdrawal.toFixed(2)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* 交易记录 */}
        <Tabs defaultValue="all" className="space-y-6">
          <TabsList>
            <TabsTrigger value="all">全部记录</TabsTrigger>
            <TabsTrigger value="income">收入</TabsTrigger>
            <TabsTrigger value="withdrawal">提现</TabsTrigger>
            <TabsTrigger value="recharge">充值</TabsTrigger>
          </TabsList>

          <TabsContent value="all">
            <Card>
              <CardHeader>
                <CardTitle>交易记录</CardTitle>
                <CardDescription>查看您的所有交易记录</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>类型</TableHead>
                      <TableHead>金额</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>描述</TableHead>
                      <TableHead>时间</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {mockTransactions.map((transaction) => (
                      <TableRow key={transaction.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getTransactionIcon(transaction.type)}
                            <span>{getTransactionTypeName(transaction.type)}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className={transaction.amount > 0 ? 'text-green-600 font-semibold' : 'text-red-600 font-semibold'}>
                            {transaction.amount > 0 ? '+' : ''}¥{transaction.amount.toFixed(2)}
                          </span>
                        </TableCell>
                        <TableCell>
                          {getStatusBadge(transaction.status, transaction.failReason)}
                        </TableCell>
                        <TableCell>
                          <div>
                            <div>{transaction.description}</div>
                            {transaction.annotationTitle && (
                              <div className="text-sm text-gray-500">{transaction.annotationTitle}</div>
                            )}
                            {transaction.account && (
                              <div className="text-sm text-gray-500">{transaction.account}</div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-sm text-gray-500">
                          <div>{formatDate(transaction.createdAt)}</div>
                          {transaction.completedAt && transaction.completedAt !== transaction.createdAt && (
                            <div className="text-xs text-green-600">
                              完成：{formatDate(transaction.completedAt)}
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="income">
            <Card>
              <CardHeader>
                <CardTitle>收入记录</CardTitle>
                <CardDescription>查看您的收入来源</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>类型</TableHead>
                      <TableHead>金额</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>描述</TableHead>
                      <TableHead>时间</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {mockTransactions
                      .filter(t => t.type !== 'withdrawal')
                      .map((transaction) => (
                        <TableRow key={transaction.id}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {getTransactionIcon(transaction.type)}
                              <span>{getTransactionTypeName(transaction.type)}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <span className="text-green-600 font-semibold">
                              +¥{transaction.amount.toFixed(2)}
                            </span>
                          </TableCell>
                          <TableCell>
                            {getStatusBadge(transaction.status)}
                          </TableCell>
                          <TableCell>
                            <div>
                              <div>{transaction.description}</div>
                              {transaction.annotationTitle && (
                                <div className="text-sm text-gray-500">{transaction.annotationTitle}</div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-gray-500">
                            {formatDate(transaction.createdAt)}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="withdrawal">
            <Card>
              <CardHeader>
                <CardTitle>提现记录</CardTitle>
                <CardDescription>查看您的提现记录</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>金额</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>账户</TableHead>
                      <TableHead>申请时间</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {mockTransactions
                      .filter(t => t.type === 'withdrawal')
                      .map((transaction) => (
                        <TableRow key={transaction.id}>
                          <TableCell>
                            <span className="text-red-600 font-semibold">
                              ¥{Math.abs(transaction.amount).toFixed(2)}
                            </span>
                          </TableCell>
                          <TableCell>
                            {getStatusBadge(transaction.status, transaction.failReason)}
                          </TableCell>
                          <TableCell>
                            <div className="text-sm">
                              {transaction.account}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-gray-500">
                            <div>{formatDate(transaction.createdAt)}</div>
                            {transaction.completedAt && (
                              <div className="text-xs text-green-600">
                                完成：{formatDate(transaction.completedAt)}
                              </div>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="recharge">
            <Card>
              <CardHeader>
                <CardTitle>充值记录</CardTitle>
                <CardDescription>查看您的充值记录</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>金额</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>描述</TableHead>
                      <TableHead>时间</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {mockTransactions
                      .filter(t => t.type === 'recharge')
                      .map((transaction) => (
                        <TableRow key={transaction.id}>
                          <TableCell>
                            <span className="text-green-600 font-semibold">
                              +¥{transaction.amount.toFixed(2)}
                            </span>
                          </TableCell>
                          <TableCell>
                            {getStatusBadge(transaction.status)}
                          </TableCell>
                          <TableCell>
                            {transaction.description}
                          </TableCell>
                          <TableCell className="text-sm text-gray-500">
                            {formatDate(transaction.createdAt)}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}