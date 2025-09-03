'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Wallet, CreditCard, ArrowUpRight, ArrowDownLeft, Clock, CheckCircle, XCircle } from 'lucide-react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { useWalletStore, formatAmount, getTransactionTypeText, getTransactionStatusText } from '@/lib/stores/wallet-store';
import { useGlobalNotifications } from '@/lib/stores';

interface WalletModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function WalletModal({ open, onOpenChange }: WalletModalProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'recharge' | 'withdraw' | 'history'>('overview');
  const [rechargeAmount, setRechargeAmount] = useState('');
  const [withdrawAmount, setWithdrawAmount] = useState('');
  
  const { user, isAuthenticated } = useAuthStore();
  const { addNotification } = useGlobalNotifications();
  const { 
    wallet, 
    transactions, 
    isLoading, 
    error, 
    loadWallet, 
    loadTransactions, 
    recharge, 
    withdraw, 
    clearError 
  } = useWalletStore();

  // 预设充值金额
  const rechargePresets = [10, 50, 100, 200, 500, 1000];
  
  // 初始化数据
  useEffect(() => {
    if (open && isAuthenticated) {
      loadWallet();
      loadTransactions();
    }
  }, [open, isAuthenticated, loadWallet, loadTransactions]);
  
  // 清除错误信息
  useEffect(() => {
    if (error) {
      addNotification({
        type: 'error',
        title: '操作失败',
        message: error
      });
      clearError();
    }
  }, [error, clearError, addNotification]);
  
  // 充值
  const handleRecharge = async () => {
    const amount = parseFloat(rechargeAmount);
    if (!amount || amount < 1) {
      addNotification({
        type: 'error',
        title: '充值金额错误',
        message: '充值金额不能少于1元'
      });
      return;
    }
    
    if (amount > 10000) {
      addNotification({
        type: 'error',
        title: '充值金额错误',
        message: '单次充值金额不能超过10000元'
      });
      return;
    }
    
    try {
      const orderId = await recharge(amount, 'alipay');
      addNotification({
        type: 'success',
        title: '充值成功',
        message: `已成功充值 ¥${amount}`
      });
      setRechargeAmount('');
      setActiveTab('overview');
    } catch (error: any) {
      // 错误已在store中处理并通过useEffect显示
    }
  };
  
  // 提现
  const handleWithdraw = async () => {
    const amount = parseFloat(withdrawAmount);
    if (!amount || amount < 10) {
      addNotification({
        type: 'error',
        title: '提现金额错误',
        message: '提现金额不能少于10元'
      });
      return;
    }
    
    if (!wallet || amount > wallet.balance) {
      addNotification({
        type: 'error',
        title: '余额不足',
        message: '提现金额不能超过可用余额'
      });
      return;
    }
    
    try {
      const orderId = await withdraw(amount, 'alipay_account');
      addNotification({
        type: 'success',
        title: '提现申请已提交',
        message: '预计1-3个工作日到账'
      });
      setWithdrawAmount('');
      setActiveTab('overview');
    } catch (error: any) {
      // 错误已在store中处理并通过useEffect显示
    }
  };
  
  // 获取交易类型图标
  const getTransactionIcon = (type: string) => {
    switch (type) {
      case 'recharge':
        return <ArrowDownLeft className="h-4 w-4 text-green-600" />;
      case 'withdraw':
        return <ArrowUpRight className="h-4 w-4 text-red-600" />;
      case 'payment':
        return <CreditCard className="h-4 w-4 text-blue-600" />;
      case 'reward':
        return <Wallet className="h-4 w-4 text-orange-600" />;
      default:
        return <Clock className="h-4 w-4 text-gray-600" />;
    }
  };
  
  // 获取交易状态图标
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-600" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-600" />;
      default:
        return <Clock className="h-4 w-4 text-gray-600" />;
    }
  };
  
  useEffect(() => {
    if (open && isAuthenticated) {
      loadWallet();
      loadTransactions();
    }
  }, [open, isAuthenticated, loadWallet, loadTransactions]);
  
  if (!isAuthenticated) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-[425px] mx-4">
        <DialogHeader>
          <DialogTitle className="text-lg sm:text-xl">钱包</DialogTitle>
          <DialogDescription className="text-sm sm:text-base">
            请先登录以查看钱包信息
          </DialogDescription>
        </DialogHeader>
        <div className="text-center py-6 sm:py-8">
          <Wallet className="h-12 w-12 sm:h-16 sm:w-16 text-gray-400 mx-auto mb-3 sm:mb-4" />
          <p className="text-gray-600 text-sm sm:text-base">登录后即可使用钱包功能</p>
        </div>
      </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px] max-h-[85vh] overflow-y-auto mx-4">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg sm:text-xl">
            <Wallet className="h-4 w-4 sm:h-5 sm:w-5" />
            我的钱包
          </DialogTitle>
          <DialogDescription className="text-sm sm:text-base">
            管理您的余额、充值和提现
          </DialogDescription>
        </DialogHeader>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4 h-9 sm:h-10">
            <TabsTrigger value="overview" className="text-xs sm:text-sm">概览</TabsTrigger>
            <TabsTrigger value="recharge" className="text-xs sm:text-sm">充值</TabsTrigger>
            <TabsTrigger value="withdraw" className="text-xs sm:text-sm">提现</TabsTrigger>
            <TabsTrigger value="history" className="text-xs sm:text-sm">记录</TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="space-y-3 sm:space-y-4">
            <div className="grid grid-cols-2 gap-3 sm:gap-4">
              <Card>
                <CardHeader className="pb-2 px-3 sm:px-6 pt-3 sm:pt-6">
                  <CardTitle className="text-xs sm:text-sm font-medium text-gray-600">可用余额</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6 pb-3 sm:pb-6">
                  <div className="text-lg sm:text-2xl font-bold text-green-600">
                    ¥{wallet?.balance ? formatAmount(wallet.balance) : '0.00'}
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader className="pb-2 px-3 sm:px-6 pt-3 sm:pt-6">
                  <CardTitle className="text-xs sm:text-sm font-medium text-gray-600">冻结金额</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6 pb-3 sm:pb-6">
                  <div className="text-lg sm:text-2xl font-bold text-orange-600">
                    ¥{wallet?.frozenAmount ? formatAmount(wallet.frozenAmount) : '0.00'}
                  </div>
                </CardContent>
              </Card>
            </div>
            
            <Card>
              <CardHeader className="px-3 sm:px-6 pt-3 sm:pt-6">
                <CardTitle className="text-base sm:text-lg">账户统计</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 sm:space-y-4 px-3 sm:px-6 pb-3 sm:pb-6">
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 text-sm sm:text-base">累计充值</span>
                  <span className="font-medium text-green-600 text-sm sm:text-base">
                    ¥{wallet?.totalIncome ? formatAmount(wallet.totalIncome) : '0.00'}
                  </span>
                </div>
                <Separator />
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 text-sm sm:text-base">累计支出</span>
                  <span className="font-medium text-blue-600 text-sm sm:text-base">
                    ¥{wallet?.totalExpense ? formatAmount(wallet.totalExpense) : '0.00'}
                  </span>
                </div>
                <Separator />
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 text-sm sm:text-base">总资产</span>
                  <span className="font-bold text-base sm:text-lg">
                    ¥{wallet ? formatAmount((wallet.balance || 0) + (wallet.frozenAmount || 0)) : '0.00'}
                  </span>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="recharge" className="space-y-3 sm:space-y-4">
            <Card>
              <CardHeader className="px-3 sm:px-6 pt-3 sm:pt-6">
                <CardTitle className="text-base sm:text-lg">充值金额</CardTitle>
                <CardDescription className="text-sm sm:text-base">
                  选择或输入充值金额，支持支付宝、微信支付
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 sm:space-y-4 px-3 sm:px-6 pb-3 sm:pb-6">
                <div className="grid grid-cols-3 gap-2">
                  {rechargePresets.map((amount) => (
                    <Button
                      key={amount}
                      variant={rechargeAmount === amount.toString() ? 'default' : 'outline'}
                      onClick={() => setRechargeAmount(amount.toString())}
                      className="h-10 sm:h-12 text-xs sm:text-sm"
                    >
                      ¥{amount}
                    </Button>
                  ))}
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="recharge-amount" className="text-sm sm:text-base">自定义金额</Label>
                  <Input
                    id="recharge-amount"
                    type="number"
                    placeholder="请输入充值金额"
                    value={rechargeAmount}
                    onChange={(e) => setRechargeAmount(e.target.value)}
                    className="h-10 sm:h-11 text-sm sm:text-base"
                    min="1"
                    max="10000"
                    step="0.01"
                  />
                </div>
                
                <Button 
                  onClick={handleRecharge}
                  disabled={isLoading || !rechargeAmount || parseFloat(rechargeAmount) < 1}
                  className="w-full h-10 sm:h-12 text-sm sm:text-base"
                >
                  {isLoading ? '处理中...' : `充值 ¥${rechargeAmount || '0'}`}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="withdraw" className="space-y-3 sm:space-y-4">
            <Card>
              <CardHeader className="px-3 sm:px-6 pt-3 sm:pt-6">
                <CardTitle className="text-base sm:text-lg">提现申请</CardTitle>
                <CardDescription className="text-sm sm:text-base">
                  最低提现金额10元，预计1-3个工作日到账
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 sm:space-y-4 px-3 sm:px-6 pb-3 sm:pb-6">
                <div className="bg-blue-50 p-2 sm:p-3 rounded-lg">
                    <div className="flex justify-between items-center text-xs sm:text-sm">
                      <span className="text-gray-600">可提现余额</span>
                      <span className="font-medium text-blue-600">
                        ¥{wallet?.balance ? formatAmount(wallet.balance) : '0.00'}
                      </span>
                    </div>
                  </div>
                
                <div className="space-y-2">
                  <Label htmlFor="withdraw-amount" className="text-sm sm:text-base">提现金额</Label>
                  <Input
                    id="withdraw-amount"
                    type="number"
                    placeholder="请输入提现金额"
                    value={withdrawAmount}
                    onChange={(e) => setWithdrawAmount(e.target.value)}
                    min="10"
                    max={wallet?.balance || 0}
                    step="0.01"
                    className="h-10 sm:h-11 text-sm sm:text-base"
                  />
                </div>
                
                <div className="text-xs text-gray-500 space-y-1">
                  <p>• 最低提现金额：10元</p>
                  <p>• 提现手续费：免费</p>
                  <p>• 到账时间：1-3个工作日</p>
                  <p>• 提现方式：原路返回</p>
                </div>
                
                <Button 
                  onClick={handleWithdraw}
                  disabled={isLoading || !withdrawAmount || parseFloat(withdrawAmount) < 10 || parseFloat(withdrawAmount) > (wallet?.balance || 0)}
                  className="w-full h-10 sm:h-12 text-sm sm:text-base"
                >
                  {isLoading ? '处理中...' : `申请提现 ¥${withdrawAmount || '0'}`}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="history" className="space-y-3 sm:space-y-4">
            <Card>
              <CardHeader className="px-3 sm:px-6 pt-3 sm:pt-6">
                <CardTitle className="text-base sm:text-lg">交易记录</CardTitle>
                <CardDescription className="text-sm sm:text-base">
                  查看您的充值、提现和消费记录
                </CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6 pb-3 sm:pb-6">
                {transactions.length === 0 ? (
                  <div className="text-center py-6 sm:py-8">
                    <Clock className="h-10 w-10 sm:h-12 sm:w-12 text-gray-400 mx-auto mb-2 sm:mb-3" />
                    <p className="text-gray-600 text-sm sm:text-base">暂无交易记录</p>
                  </div>
                ) : (
                  <div className="space-y-2 sm:space-y-3">
                    {transactions.map((transaction) => (
                      <div key={transaction.id} className="flex items-center justify-between p-2 sm:p-3 border rounded-lg">
                        <div className="flex items-center gap-2 sm:gap-3">
                          <div className="w-6 h-6 sm:w-8 sm:h-8 rounded-full bg-gray-100 flex items-center justify-center">
                            {getTransactionIcon(transaction.type)}
                          </div>
                          <div>
                            <div className="font-medium text-xs sm:text-sm">{transaction.description}</div>
                            <div className="text-xs text-gray-500">{transaction.createdAt}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className={`font-medium text-xs sm:text-sm ${
                            transaction.amount > 0 ? 'text-green-600' : 'text-red-600'
                          }`}>
                            {transaction.amount > 0 ? '+' : ''}¥{Math.abs(transaction.amount).toFixed(2)}
                          </div>
                          <div className="flex items-center gap-1 text-xs">
                            {getStatusIcon(transaction.status)}
                            <span className={`${
                              transaction.status === 'completed' ? 'text-green-600' :
                              transaction.status === 'pending' ? 'text-yellow-600' : 'text-red-600'
                            }`}>
                              {getTransactionStatusText(transaction.status)}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}