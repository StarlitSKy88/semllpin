'use client';

import { useState } from 'react';
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
import { useAuthStore } from '@/lib/stores/auth-store';
import { useSMSCode } from '@/lib/hooks/use-sms-code';
import { useGlobalNotifications } from '@/lib/stores';

interface AuthModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AuthModal({ open, onOpenChange }: AuthModalProps) {
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');
  const [loginMethod, setLoginMethod] = useState<'phone' | 'email'>('phone');
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const { login, register, emailLogin, emailRegister, isLoading, error, clearError } = useAuthStore();
  const { addNotification } = useGlobalNotifications();
  
  // 使用SMS验证码Hook
  const {
    isLoading: isSendingCode,
    countdown,
    canSend,
    sendCode,
    error: smsError,
    clearError: clearSMSError
  } = useSMSCode({
    phone,
    type: activeTab,
    onSuccess: () => {
      addNotification({
        type: 'success',
        title: '验证码已发送',
        message: '请查收短信'
      });
    },
    onError: (error) => {
      addNotification({
        type: 'error',
        title: '发送失败',
        message: error
      });
    }
  });

  // 发送验证码
  const handleSendCode = async () => {
    await sendCode();
  };

  // 登录
  const handleLogin = async () => {
    if (!phone || !code) {
      addNotification({
        type: 'error',
        title: '信息不完整',
        message: '请填写完整信息'
      });
      return;
    }

    try {
      await login(phone, code);
      addNotification({
        type: 'success',
        title: '登录成功',
        message: '欢迎回来！'
      });
      onOpenChange(false);
      resetForm();
    } catch (error: any) {
      addNotification({
        type: 'error',
        title: '登录失败',
        message: error.message || '登录失败'
      });
    }
  };

  // 注册
  const handleRegister = async () => {
    if (!phone || !code || !username) {
      addNotification({
        type: 'error',
        title: '信息不完整',
        message: '请填写完整信息'
      });
      return;
    }

    if (username.length < 2 || username.length > 20) {
      addNotification({
        type: 'error',
        title: '用户名格式错误',
        message: '用户名长度应在2-20个字符之间'
      });
      return;
    }

    try {
      await register(phone, code, username);
      addNotification({
        type: 'success',
        title: '注册成功',
        message: '欢迎加入SmellPin！'
      });
      onOpenChange(false);
      resetForm();
    } catch (error: any) {
      addNotification({
        type: 'error',
        title: '注册失败',
        message: error.message || '注册失败'
      });
    }
  };

  // 重置表单
  const resetForm = () => {
    setPhone('');
    setEmail('');
    setPassword('');
    setCode('');
    setUsername('');
    clearError();
    clearSMSError();
  };

  // 格式化手机号
  const formatPhone = (value: string) => {
    const cleaned = value.replace(/\D/g, '');
    return cleaned.slice(0, 11);
  };

  // 验证邮箱格式
  const isValidEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  // 邮箱登录
  const handleEmailLogin = async () => {
    if (!email || !password) {
      addNotification({
        type: 'error',
        title: '信息不完整',
        message: '请填写完整信息'
      });
      return;
    }

    if (!isValidEmail(email)) {
      addNotification({
        type: 'error',
        title: '邮箱格式错误',
        message: '请输入正确的邮箱格式'
      });
      return;
    }

    try {
      await login(email, password);
      addNotification({
        type: 'success',
        title: '登录成功',
        message: '欢迎回来！'
      });
      onOpenChange(false);
      resetForm();
    } catch (error: any) {
      addNotification({
        type: 'error',
        title: '登录失败',
        message: error.message || '登录失败'
      });
    }
  };

  // 邮箱注册
  const handleEmailRegister = async () => {
    if (!email || !password || !username) {
      addNotification({
        type: 'error',
        title: '信息不完整',
        message: '请填写完整信息'
      });
      return;
    }

    if (!isValidEmail(email)) {
      addNotification({
        type: 'error',
        title: '邮箱格式错误',
        message: '请输入正确的邮箱格式'
      });
      return;
    }

    if (password.length < 6) {
      addNotification({
        type: 'error',
        title: '密码太短',
        message: '密码长度至少6位'
      });
      return;
    }

    if (username.length < 2 || username.length > 20) {
      addNotification({
        type: 'error',
        title: '用户名长度错误',
        message: '用户名长度应在2-20个字符之间'
      });
      return;
    }

    try {
      await register(email, password, username);
      addNotification({
        type: 'success',
        title: '注册成功',
        message: '欢迎加入 SmellPin！'
      });
      onOpenChange(false);
      resetForm();
    } catch (error: any) {
      addNotification({
        type: 'error',
        title: '注册失败',
        message: error.message || '注册失败，请重试'
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px] max-h-[90vh] overflow-y-auto">
        <DialogHeader className="space-y-2 sm:space-y-3">
          <DialogTitle className="text-lg sm:text-xl">欢迎使用 SmellPin</DialogTitle>
          <DialogDescription className="text-sm sm:text-base">
            发现身边的有趣标注，创造属于你的地图故事
          </DialogDescription>
        </DialogHeader>
        
        <Tabs defaultValue="login" className="w-full">
          <TabsList className="grid w-full grid-cols-2 h-9 sm:h-10">
            <TabsTrigger value="login" className="text-sm sm:text-base">登录</TabsTrigger>
            <TabsTrigger value="register" className="text-sm sm:text-base">注册</TabsTrigger>
          </TabsList>
          
          <TabsContent value="login" className="space-y-3 sm:space-y-4">
            {/* 登录方式切换 */}
            <div className="flex space-x-1 sm:space-x-2 p-1 bg-gray-100 rounded-lg">
              <Button
                type="button"
                variant={loginMethod === 'phone' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setLoginMethod('phone')}
                className="flex-1 text-xs sm:text-sm h-8 sm:h-9"
              >
                手机号登录
              </Button>
              <Button
                type="button"
                variant={loginMethod === 'email' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setLoginMethod('email')}
                className="flex-1 text-xs sm:text-sm h-8 sm:h-9"
              >
                邮箱登录
              </Button>
            </div>

            {loginMethod === 'phone' ? (
              <>
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="login-phone" className="text-sm sm:text-base">手机号</Label>
                  <Input
                    id="login-phone"
                    type="tel"
                    placeholder="请输入手机号"
                    value={phone}
                    onChange={(e) => setPhone(formatPhone(e.target.value))}
                    maxLength={11}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="login-code" className="text-sm sm:text-base">验证码</Label>
                  <div className="flex space-x-2">
                    <Input
                      id="login-code"
                      type="text"
                      placeholder="请输入验证码"
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      maxLength={6}
                      className="flex-1 h-9 sm:h-10 text-sm sm:text-base"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={handleSendCode}
                      disabled={!canSend || isSendingCode}
                      className="whitespace-nowrap text-xs sm:text-sm h-9 sm:h-10 px-2 sm:px-3"
                    >
                      {countdown > 0 ? `${countdown}s` : isSendingCode ? '发送中...' : '发送验证码'}
                    </Button>
                  </div>
                </div>
                
                {(error || smsError) && (
                  <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
                    {error || smsError}
                  </div>
                )}
                
                <Button 
                  onClick={handleLogin} 
                  disabled={isLoading || !phone || !code}
                  className="w-full h-9 sm:h-10 text-sm sm:text-base"
                >
                  {isLoading ? '登录中...' : '登录'}
                </Button>
              </>
            ) : (
              <>
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="login-email" className="text-sm sm:text-base">邮箱</Label>
                  <Input
                    id="login-email"
                    type="email"
                    placeholder="请输入邮箱地址"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="login-password" className="text-sm sm:text-base">密码</Label>
                  <Input
                    id="login-password"
                    type="password"
                    placeholder="请输入密码"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                {error && (
                  <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
                    {error}
                  </div>
                )}
                
                <Button 
                  onClick={handleEmailLogin} 
                  disabled={isLoading || !email || !password}
                  className="w-full h-9 sm:h-10 text-sm sm:text-base"
                >
                  {isLoading ? '登录中...' : '登录'}
                </Button>
              </>
            )}
          </TabsContent>
          
          <TabsContent value="register" className="space-y-3 sm:space-y-4">
            {/* 注册方式切换 */}
            <div className="flex space-x-1 sm:space-x-2 p-1 bg-gray-100 rounded-lg">
              <Button
                type="button"
                variant={loginMethod === 'phone' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setLoginMethod('phone')}
                className="flex-1 text-xs sm:text-sm h-8 sm:h-9"
              >
                手机号注册
              </Button>
              <Button
                type="button"
                variant={loginMethod === 'email' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setLoginMethod('email')}
                className="flex-1 text-xs sm:text-sm h-8 sm:h-9"
              >
                邮箱注册
              </Button>
            </div>

            {loginMethod === 'phone' ? (
              <>
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="register-phone" className="text-sm sm:text-base">手机号</Label>
                  <Input
                    id="register-phone"
                    type="tel"
                    placeholder="请输入手机号"
                    value={phone}
                    onChange={(e) => setPhone(formatPhone(e.target.value))}
                    maxLength={11}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="register-username" className="text-sm sm:text-base">用户名</Label>
                  <Input
                    id="register-username"
                    type="text"
                    placeholder="请输入用户名"
                    value={username}
                    onChange={(e) => setUsername(e.target.value.slice(0, 20))}
                    maxLength={20}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="register-code" className="text-sm sm:text-base">验证码</Label>
                  <div className="flex space-x-2">
                    <Input
                      id="register-code"
                      type="text"
                      placeholder="请输入验证码"
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      maxLength={6}
                      className="flex-1 h-9 sm:h-10 text-sm sm:text-base"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={handleSendCode}
                      disabled={!canSend || isSendingCode}
                      className="whitespace-nowrap text-xs sm:text-sm h-9 sm:h-10 px-2 sm:px-3"
                    >
                      {countdown > 0 ? `${countdown}s` : isSendingCode ? '发送中...' : '发送验证码'}
                    </Button>
                  </div>
                </div>
                
                {(error || smsError) && (
                  <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
                    {error || smsError}
                  </div>
                )}
                
                <Button 
                  onClick={handleRegister} 
                  disabled={isLoading || !phone || !code || !username}
                  className="w-full h-9 sm:h-10 text-sm sm:text-base"
                >
                  {isLoading ? '注册中...' : '注册'}
                </Button>
              </>
            ) : (
              <>
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="register-email" className="text-sm sm:text-base">邮箱</Label>
                  <Input
                    id="register-email"
                    type="email"
                    placeholder="请输入邮箱地址"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="register-username-email" className="text-sm sm:text-base">用户名</Label>
                  <Input
                    id="register-username-email"
                    type="text"
                    placeholder="请输入用户名"
                    value={username}
                    onChange={(e) => setUsername(e.target.value.slice(0, 20))}
                    maxLength={20}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                <div className="space-y-1 sm:space-y-2">
                  <Label htmlFor="register-password" className="text-sm sm:text-base">密码</Label>
                  <Input
                    id="register-password"
                    type="password"
                    placeholder="请输入密码（至少6位）"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-9 sm:h-10 text-sm sm:text-base"
                  />
                </div>
                
                {error && (
                  <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
                    {error}
                  </div>
                )}
                
                <Button 
                  onClick={handleEmailRegister} 
                  disabled={isLoading || !email || !password || !username}
                  className="w-full h-9 sm:h-10 text-sm sm:text-base"
                >
                  {isLoading ? '注册中...' : '注册'}
                </Button>
              </>
            )}
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}