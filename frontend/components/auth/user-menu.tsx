'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { useAuthStore } from '@/lib/stores/auth-store';
import { useWalletStore, formatAmount } from '@/lib/stores/wallet-store';
import { AuthModal } from './auth-modal';
import { WalletModal } from '../wallet/wallet-modal';
import { 
  User, 
  Wallet, 
  Settings, 
  LogOut, 
  MapPin,
  Trophy,
  CreditCard
} from 'lucide-react';
import { useEffect } from 'react';
import { useGlobalNotifications } from '@/lib/stores';

export function UserMenu() {
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [showWalletModal, setShowWalletModal] = useState(false);
  const { user, isAuthenticated, logout } = useAuthStore();
  const { wallet, loadWallet } = useWalletStore();
  const { addNotification } = useGlobalNotifications();
  
  // 当用户登录时加载钱包信息
  useEffect(() => {
    if (isAuthenticated && !wallet) {
      loadWallet();
    }
  }, [isAuthenticated, wallet, loadWallet]);

  const handleLogout = () => {
    logout();
    addNotification({
      type: 'success',
      title: '退出成功',
      message: '已退出登录'
    });
  };

  if (!isAuthenticated || !user) {
    return (
      <>
        <Button 
          onClick={() => setShowAuthModal(true)}
          variant="outline"
          size="sm"
          className="text-xs sm:text-sm h-8 sm:h-9 px-2 sm:px-3"
        >
          <span className="hidden sm:inline">登录/注册</span>
          <span className="sm:hidden">登录</span>
        </Button>
        <AuthModal 
          open={showAuthModal} 
          onOpenChange={setShowAuthModal} 
        />
      </>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="relative h-8 w-8 sm:h-10 sm:w-10 rounded-full">
          <Avatar className="h-8 w-8 sm:h-10 sm:w-10">
            <AvatarImage src={user.avatar} alt={user.username} />
            <AvatarFallback className="text-xs sm:text-sm">
              {user.username.charAt(0).toUpperCase()}
            </AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      
      <DropdownMenuContent className="w-72 sm:w-80" align="end" forceMount>
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col space-y-2">
            <div className="flex items-center space-x-2">
              <Avatar className="h-7 w-7 sm:h-8 sm:w-8">
                <AvatarImage src={user.avatar} alt={user.username} />
                <AvatarFallback className="text-xs sm:text-sm">
                  {user.username.charAt(0).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <div className="flex flex-col">
                <p className="text-xs sm:text-sm font-medium leading-none">{user.username}</p>
                <p className="text-xs leading-none text-muted-foreground">
                  等级 {user.level} · {user.points} 积分
                </p>
              </div>
            </div>
            
            {wallet && (
              <div className="bg-muted/50 rounded-lg p-2 sm:p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1 sm:space-x-2">
                    <CreditCard className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
                    <span className="text-xs sm:text-sm text-muted-foreground">钱包余额</span>
                  </div>
                  <span className="text-xs sm:text-sm font-medium">
                    {formatAmount(wallet.balance)}
                  </span>
                </div>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-xs text-muted-foreground">总收益</span>
                  <span className="text-xs text-green-600">
                    +{formatAmount(wallet.totalEarned)}
                  </span>
                </div>
              </div>
            )}
          </div>
        </DropdownMenuLabel>
        
        <DropdownMenuSeparator />
        
        <DropdownMenuItem 
          className="cursor-pointer text-sm sm:text-base"
          onClick={() => window.location.href = '/profile'}
        >
          <User className="mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          <span>个人资料</span>
        </DropdownMenuItem>
        
        <DropdownMenuItem className="cursor-pointer text-sm sm:text-base">
          <MapPin className="mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          <span>我的标注</span>
        </DropdownMenuItem>
        
        <DropdownMenuItem className="cursor-pointer text-sm sm:text-base">
          <Trophy className="mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          <span>奖励记录</span>
        </DropdownMenuItem>
        
        <DropdownMenuItem 
          className="cursor-pointer text-sm sm:text-base"
          onClick={() => setShowWalletModal(true)}
        >
          <Wallet className="mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          <span>钱包管理</span>
        </DropdownMenuItem>
        
        <DropdownMenuItem 
          className="cursor-pointer text-sm sm:text-base"
          onClick={() => window.location.href = '/settings'}
        >
          <Settings className="mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          <span>设置</span>
        </DropdownMenuItem>
        
        <DropdownMenuSeparator />
        
        <DropdownMenuItem 
          className="cursor-pointer text-red-600 focus:text-red-600 text-sm sm:text-base"
          onClick={handleLogout}
        >
          <LogOut className="mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          <span>退出登录</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
      
      <WalletModal 
        open={showWalletModal}
        onOpenChange={setShowWalletModal}
      />
    </DropdownMenu>
  );
}