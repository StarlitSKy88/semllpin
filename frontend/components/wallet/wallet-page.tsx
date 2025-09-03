'use client';

import React, { useEffect, useState } from 'react';
import { usePaymentStore } from '@/lib/stores/payment-store';
import { paymentService } from '@/lib/services/payment-service';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Wallet, 
  CreditCard, 
  History, 
  Download, 
  Plus, 
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface WalletPageProps {
  className?: string;
}

export function WalletPage({ className }: WalletPageProps) {
  const {
    walletBalance,
    isLoadingBalance,
    paymentHistory,
    isLoadingHistory,
    withdrawHistory,
    error,
    loadWalletBalance,
    loadPaymentHistory,
    loadWithdrawHistory,
    clearError
  } = usePaymentStore();

  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    loadWalletBalance();
    loadPaymentHistory();
    loadWithdrawHistory();
  }, [loadWalletBalance, loadPaymentHistory, loadWithdrawHistory]);

  const handleRefresh = () => {
    loadWalletBalance();
    loadPaymentHistory();
    loadWithdrawHistory();
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'succeeded':
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'pending':
      case 'processing':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'failed':
      case 'canceled':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'succeeded':
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'pending':
      case 'processing':
        return 'bg-yellow-100 text-yellow-800';
      case 'failed':
      case 'canceled':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className={cn('container mx-auto p-3 sm:p-4 md:p-6 space-y-4 md:space-y-6', className)}>
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Wallet className="h-5 w-5 sm:h-6 sm:w-6" />
          <h1 className="text-xl sm:text-2xl font-bold">我的钱包</h1>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          disabled={isLoadingBalance || isLoadingHistory}
          className="text-xs sm:text-sm"
        >
          <RefreshCw className={cn('h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2', {
            'animate-spin': isLoadingBalance || isLoadingHistory
          })} />
          <span className="hidden sm:inline">刷新</span>
        </Button>
      </div>

      {/* 错误提示 */}
      {error && (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center space-x-2 text-red-600">
              <XCircle className="h-4 w-4" />
              <span>{error}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearError}
                className="ml-auto text-red-600 hover:text-red-700"
              >
                关闭
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* 余额概览 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">可用余额</CardTitle>
            <Wallet className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-xl md:text-2xl font-bold">
              {isLoadingBalance ? (
                <div className="h-8 w-24 bg-gray-200 animate-pulse rounded" />
              ) : (
                paymentService.formatAmount(walletBalance?.available || 0)
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              上次更新: {walletBalance ? formatDate(walletBalance.lastUpdated) : '--'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">待处理余额</CardTitle>
            <Clock className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-xl md:text-2xl font-bold">
              {isLoadingBalance ? (
                <div className="h-8 w-24 bg-gray-200 animate-pulse rounded" />
              ) : (
                paymentService.formatAmount(walletBalance?.pending || 0)
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              预计1-3个工作日到账
            </p>
          </CardContent>
        </Card>

        <Card className="sm:col-span-2 lg:col-span-1">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">总余额</CardTitle>
            <TrendingUp className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-xl md:text-2xl font-bold">
              {isLoadingBalance ? (
                <div className="h-8 w-24 bg-gray-200 animate-pulse rounded" />
              ) : (
                paymentService.formatAmount(
                  (walletBalance?.available || 0) + (walletBalance?.pending || 0)
                )
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              可用 + 待处理
            </p>
          </CardContent>
        </Card>
      </div>

      {/* 操作按钮 */}
      <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
        <Button className="flex-1 h-12 sm:h-10">
          <Plus className="h-4 w-4 mr-2" />
          充值
        </Button>
        <Button variant="outline" className="flex-1 h-12 sm:h-10">
          <Download className="h-4 w-4 mr-2" />
          提现
        </Button>
      </div>

      {/* 详细信息标签页 */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 h-12 sm:h-10">
          <TabsTrigger value="overview" className="text-xs sm:text-sm">概览</TabsTrigger>
          <TabsTrigger value="history" className="text-xs sm:text-sm">交易记录</TabsTrigger>
          <TabsTrigger value="withdraw" className="text-xs sm:text-sm">提现记录</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <History className="h-5 w-5" />
                <span>最近交易</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoadingHistory ? (
                <div className="space-y-3">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="flex items-center space-x-3">
                      <div className="h-10 w-10 bg-gray-200 animate-pulse rounded-full" />
                      <div className="flex-1 space-y-2">
                        <div className="h-4 w-3/4 bg-gray-200 animate-pulse rounded" />
                        <div className="h-3 w-1/2 bg-gray-200 animate-pulse rounded" />
                      </div>
                      <div className="h-4 w-16 bg-gray-200 animate-pulse rounded" />
                    </div>
                  ))}
                </div>
              ) : paymentHistory.length > 0 ? (
                <div className="space-y-3">
                  {paymentHistory.slice(0, 5).map((payment) => (
                    <div key={payment.id} className="flex items-center justify-between p-2 sm:p-3 border rounded-lg">
                      <div className="flex items-center space-x-2 sm:space-x-3 flex-1 min-w-0">
                        <div className="flex items-center justify-center h-8 w-8 sm:h-10 sm:w-10 rounded-full bg-gray-100 flex-shrink-0">
                          {payment.type === 'payment' ? (
                            <TrendingDown className="h-4 w-4 sm:h-5 sm:w-5 text-red-500" />
                          ) : (
                            <TrendingUp className="h-4 w-4 sm:h-5 sm:w-5 text-green-500" />
                          )}
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="font-medium text-sm sm:text-base truncate">{payment.description}</p>
                          <p className="text-xs sm:text-sm text-muted-foreground">
                            {formatDate(payment.createdAt)}
                          </p>
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className={cn('font-medium text-sm sm:text-base', {
                          'text-red-600': payment.type === 'payment',
                          'text-green-600': payment.type === 'reward'
                        })}>
                          {payment.type === 'payment' ? '-' : '+'}
                          {paymentService.formatAmount(payment.amount)}
                        </p>
                        <Badge className={cn(getStatusColor(payment.status), 'text-xs')}>
                          {paymentService.getPaymentStatusText(payment.status)}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>暂无交易记录</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>交易记录</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoadingHistory ? (
                <div className="space-y-4">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="flex items-center space-x-3 p-4 border rounded-lg">
                      <div className="h-10 w-10 bg-gray-200 animate-pulse rounded-full" />
                      <div className="flex-1 space-y-2">
                        <div className="h-4 w-3/4 bg-gray-200 animate-pulse rounded" />
                        <div className="h-3 w-1/2 bg-gray-200 animate-pulse rounded" />
                      </div>
                      <div className="h-4 w-16 bg-gray-200 animate-pulse rounded" />
                    </div>
                  ))}
                </div>
              ) : paymentHistory.length > 0 ? (
                <div className="space-y-3 sm:space-y-4">
                  {paymentHistory.map((payment) => (
                    <div key={payment.id} className="flex items-center justify-between p-3 sm:p-4 border rounded-lg hover:bg-gray-50 transition-colors">
                      <div className="flex items-center space-x-2 sm:space-x-3 flex-1 min-w-0">
                        {getStatusIcon(payment.status)}
                        <div className="min-w-0 flex-1">
                          <p className="font-medium text-sm sm:text-base truncate">{payment.description}</p>
                          <p className="text-xs sm:text-sm text-muted-foreground">
                            {formatDate(payment.createdAt)} <span className="hidden sm:inline">• ID: {payment.id}</span>
                          </p>
                          {payment.annotationId && (
                            <p className="text-xs text-muted-foreground">
                              标注ID: {payment.annotationId}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className={cn('font-medium text-base sm:text-lg', {
                          'text-red-600': payment.type === 'payment',
                          'text-green-600': payment.type === 'reward'
                        })}>
                          {payment.type === 'payment' ? '-' : '+'}
                          {paymentService.formatAmount(payment.amount)}
                        </p>
                        <Badge className={cn(getStatusColor(payment.status), 'text-xs')}>
                          {paymentService.getPaymentStatusText(payment.status)}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>暂无交易记录</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="withdraw" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>提现记录</CardTitle>
            </CardHeader>
            <CardContent>
              {withdrawHistory.length > 0 ? (
                <div className="space-y-3 sm:space-y-4">
                  {withdrawHistory.map((withdraw) => (
                    <div key={withdraw.id} className="flex items-center justify-between p-3 sm:p-4 border rounded-lg">
                      <div className="flex items-center space-x-2 sm:space-x-3 flex-1 min-w-0">
                        {getStatusIcon(withdraw.status)}
                        <div className="min-w-0 flex-1">
                          <p className="font-medium text-sm sm:text-base truncate">
                            提现到 {withdraw.method === 'alipay' ? '支付宝' : 
                                   withdraw.method === 'wechat_pay' ? '微信' : '银行卡'}
                          </p>
                          <p className="text-xs sm:text-sm text-muted-foreground">
                            {formatDate(withdraw.createdAt)}
                          </p>
                          {withdraw.completedAt && (
                            <p className="text-xs text-green-600">
                              完成时间: {formatDate(withdraw.completedAt)}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className="font-medium text-base sm:text-lg text-red-600">
                          -{paymentService.formatAmount(withdraw.amount)}
                        </p>
                        <Badge className={cn(getStatusColor(withdraw.status), 'text-xs')}>
                          {withdraw.status === 'completed' ? '已完成' :
                           withdraw.status === 'processing' ? '处理中' :
                           withdraw.status === 'pending' ? '待处理' : withdraw.status}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Download className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>暂无提现记录</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default WalletPage;