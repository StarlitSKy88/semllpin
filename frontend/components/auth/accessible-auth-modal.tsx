/**
 * 具有完整无障碍性支持的认证模态框
 * 包含ARIA标签、键盘导航、屏幕阅读器支持
 */

'use client';

import { useState, useEffect, useId } from 'react';
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
import { useAccessibility, FocusTrap, LiveRegion, srOnlyClass } from '@/hooks/use-accessibility';
import { Eye, EyeOff, Phone, Mail, User, Lock, MessageCircle } from 'lucide-react';

interface AccessibleAuthModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AccessibleAuthModal({ open, onOpenChange }: AccessibleAuthModalProps) {
  // 状态管理
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');
  const [loginMethod, setLoginMethod] = useState<'phone' | 'email'>('phone');
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // 验证状态
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [fieldTouched, setFieldTouched] = useState<Record<string, boolean>>({});
  
  // Store
  const { login, register, emailLogin, emailRegister, isLoading, error, clearError } = useAuthStore();
  const { addNotification } = useGlobalNotifications();
  
  // SMS验证码Hook
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
        message: '请查收短信验证码'
      });
      announce('验证码已发送到您的手机', 'assertive');
    },
    onError: (error) => {
      addNotification({
        type: 'error',
        title: '发送失败',
        message: error
      });
      announce(`验证码发送失败: ${error}`, 'assertive');
    }
  });

  // 无障碍性Hook
  const { announce, containerRef } = useAccessibility({
    autoFocus: true,
    trapFocus: true,
    restoreFocus: true,
    escapeToClose: true,
    announceChanges: true,
    ariaLabel: '用户认证对话框'
  });

  // 生成唯一ID
  const phoneInputId = useId();
  const emailInputId = useId();
  const passwordInputId = useId();
  const codeInputId = useId();
  const usernameInputId = useId();
  const phoneErrorId = useId();
  const emailErrorId = useId();
  const passwordErrorId = useId();
  const codeErrorId = useId();
  const usernameErrorId = useId();
  const passwordStrengthId = useId();

  // 字段验证函数
  const validateField = (fieldName: string, value: string): string => {
    switch (fieldName) {
      case 'phone':
        if (!value) return '请输入手机号';
        if (!/^1[3-9]\d{9}$/.test(value)) return '请输入有效的手机号码';
        return '';
        
      case 'email':
        if (!value) return '请输入邮箱地址';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return '请输入有效的邮箱地址';
        return '';
        
      case 'password':
        if (!value) return '请输入密码';
        if (value.length < 6) return '密码长度至少6位';
        if (value.length > 50) return '密码长度不能超过50位';
        return '';
        
      case 'code':
        if (!value) return '请输入验证码';
        if (value.length !== 6) return '验证码应为6位数字';
        if (!/^\d{6}$/.test(value)) return '验证码应为6位数字';
        return '';
        
      case 'username':
        if (!value) return '请输入用户名';
        if (value.length < 2) return '用户名至少2个字符';
        if (value.length > 20) return '用户名不能超过20个字符';
        if (!/^[a-zA-Z0-9\u4e00-\u9fa5_-]+$/.test(value)) return '用户名只能包含字母、数字、中文、下划线和连字符';
        return '';
        
      default:
        return '';
    }
  };

  // 计算密码强度
  const getPasswordStrength = (password: string): { level: string; score: number; feedback: string } => {
    if (!password) return { level: '无', score: 0, feedback: '请输入密码' };
    
    let score = 0;
    let feedback: string[] = [];
    
    if (password.length >= 8) score += 1;
    else feedback.push('至少8个字符');
    
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('包含小写字母');
    
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('包含大写字母');
    
    if (/\d/.test(password)) score += 1;
    else feedback.push('包含数字');
    
    if (/[^a-zA-Z0-9]/.test(password)) score += 1;
    else feedback.push('包含特殊字符');
    
    const levels = ['很弱', '弱', '一般', '强', '很强'];
    const level = levels[score] || '很弱';
    
    return {
      level,
      score,
      feedback: feedback.length > 0 ? `建议${feedback.join('、')}` : '密码强度良好'
    };
  };

  // 处理字段更改
  const handleFieldChange = (fieldName: string, value: string) => {
    // 更新值
    switch (fieldName) {
      case 'phone':
        setPhone(formatPhone(value));
        break;
      case 'email':
        setEmail(value);
        break;
      case 'password':
        setPassword(value);
        break;
      case 'code':
        setCode(value.replace(/\D/g, '').slice(0, 6));
        break;
      case 'username':
        setUsername(value);
        break;
    }

    // 标记字段已触摸
    setFieldTouched(prev => ({ ...prev, [fieldName]: true }));

    // 实时验证
    const error = validateField(fieldName, value);
    setValidationErrors(prev => ({
      ...prev,
      [fieldName]: error
    }));
  };

  // 处理字段失焦
  const handleFieldBlur = (fieldName: string, value: string) => {
    setFieldTouched(prev => ({ ...prev, [fieldName]: true }));
    const error = validateField(fieldName, value);
    setValidationErrors(prev => ({
      ...prev,
      [fieldName]: error
    }));

    // 屏幕阅读器反馈
    if (error) {
      announce(`${fieldName}输入错误: ${error}`, 'assertive');
    }
  };

  // 格式化手机号
  const formatPhone = (value: string) => {
    const cleaned = value.replace(/\D/g, '');
    return cleaned.slice(0, 11);
  };

  // 发送验证码
  const handleSendCode = async () => {
    const phoneError = validateField('phone', phone);
    if (phoneError) {
      setValidationErrors(prev => ({ ...prev, phone: phoneError }));
      setFieldTouched(prev => ({ ...prev, phone: true }));
      announce(`无法发送验证码: ${phoneError}`, 'assertive');
      return;
    }

    await sendCode();
  };

  // 登录处理
  const handleLogin = async () => {
    const errors: Record<string, string> = {};

    if (loginMethod === 'phone') {
      errors.phone = validateField('phone', phone);
      errors.code = validateField('code', code);
    } else {
      errors.email = validateField('email', email);
      errors.password = validateField('password', password);
    }

    const hasErrors = Object.values(errors).some(error => error);
    if (hasErrors) {
      setValidationErrors(errors);
      setFieldTouched(Object.keys(errors).reduce((acc, key) => ({ ...acc, [key]: true }), {}));
      
      const errorMessages = Object.entries(errors)
        .filter(([_, error]) => error)
        .map(([field, error]) => `${field}: ${error}`)
        .join('; ');
      
      announce(`登录信息有误: ${errorMessages}`, 'assertive');
      return;
    }

    try {
      if (loginMethod === 'phone') {
        await login(phone, code);
      } else {
        await emailLogin(email, password);
      }
      
      addNotification({
        type: 'success',
        title: '登录成功',
        message: '欢迎回来！'
      });
      
      announce('登录成功，欢迎回来', 'polite');
      onOpenChange(false);
      resetForm();
    } catch (error: any) {
      const errorMessage = error.message || '登录失败，请重试';
      addNotification({
        type: 'error',
        title: '登录失败',
        message: errorMessage
      });
      announce(`登录失败: ${errorMessage}`, 'assertive');
    }
  };

  // 注册处理
  const handleRegister = async () => {
    const errors: Record<string, string> = {};
    
    if (loginMethod === 'phone') {
      errors.phone = validateField('phone', phone);
      errors.code = validateField('code', code);
      errors.username = validateField('username', username);
    } else {
      errors.email = validateField('email', email);
      errors.password = validateField('password', password);
      errors.username = validateField('username', username);
    }

    const hasErrors = Object.values(errors).some(error => error);
    if (hasErrors) {
      setValidationErrors(errors);
      setFieldTouched(Object.keys(errors).reduce((acc, key) => ({ ...acc, [key]: true }), {}));
      
      const errorMessages = Object.entries(errors)
        .filter(([_, error]) => error)
        .map(([field, error]) => `${field}: ${error}`)
        .join('; ');
      
      announce(`注册信息有误: ${errorMessages}`, 'assertive');
      return;
    }

    try {
      if (loginMethod === 'phone') {
        await register(phone, code, username);
      } else {
        await emailRegister(email, password, username);
      }
      
      addNotification({
        type: 'success',
        title: '注册成功',
        message: '欢迎加入SmellPin！'
      });
      
      announce('注册成功，欢迎加入SmellPin', 'polite');
      onOpenChange(false);
      resetForm();
    } catch (error: any) {
      const errorMessage = error.message || '注册失败，请重试';
      addNotification({
        type: 'error',
        title: '注册失败',
        message: errorMessage
      });
      announce(`注册失败: ${errorMessage}`, 'assertive');
    }
  };

  // 重置表单
  const resetForm = () => {
    setPhone('');
    setEmail('');
    setPassword('');
    setCode('');
    setUsername('');
    setValidationErrors({});
    setFieldTouched({});
    setShowPassword(false);
    clearError();
    clearSMSError();
  };

  // 切换标签页时重置表单
  useEffect(() => {
    resetForm();
  }, [activeTab, loginMethod]);

  // 密码强度计算
  const passwordStrength = getPasswordStrength(password);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent 
        ref={containerRef}
        className="sm:max-w-md"
        aria-labelledby="auth-dialog-title"
        aria-describedby="auth-dialog-description"
      >
        <FocusTrap enabled={open}>
          <DialogHeader>
            <DialogTitle id="auth-dialog-title">
              {activeTab === 'login' ? '登录到 SmellPin' : '注册 SmellPin 账户'}
            </DialogTitle>
            <DialogDescription id="auth-dialog-description">
              {activeTab === 'login' 
                ? '登录您的账户以继续使用SmellPin的所有功能' 
                : '创建您的SmellPin账户，开始气味标注之旅'
              }
            </DialogDescription>
          </DialogHeader>

          <Tabs 
            value={activeTab} 
            onValueChange={(value) => setActiveTab(value as 'login' | 'register')}
            className="w-full"
          >
            <TabsList className="grid w-full grid-cols-2" role="tablist">
              <TabsTrigger 
                value="login" 
                role="tab"
                aria-controls="login-panel"
                aria-selected={activeTab === 'login'}
              >
                登录
              </TabsTrigger>
              <TabsTrigger 
                value="register"
                role="tab" 
                aria-controls="register-panel"
                aria-selected={activeTab === 'register'}
              >
                注册
              </TabsTrigger>
            </TabsList>

            {/* 登录标签页 */}
            <TabsContent 
              value="login" 
              id="login-panel"
              role="tabpanel"
              aria-labelledby="login-tab"
              className="space-y-4"
            >
              {/* 登录方式选择 */}
              <div className="flex space-x-2" role="group" aria-label="登录方式选择">
                <Button
                  type="button"
                  variant={loginMethod === 'phone' ? 'default' : 'outline'}
                  onClick={() => setLoginMethod('phone')}
                  className="flex-1"
                  aria-pressed={loginMethod === 'phone'}
                >
                  <Phone className="w-4 h-4 mr-2" aria-hidden="true" />
                  手机号
                </Button>
                <Button
                  type="button"
                  variant={loginMethod === 'email' ? 'default' : 'outline'}
                  onClick={() => setLoginMethod('email')}
                  className="flex-1"
                  aria-pressed={loginMethod === 'email'}
                >
                  <Mail className="w-4 h-4 mr-2" aria-hidden="true" />
                  邮箱
                </Button>
              </div>

              {/* 手机号登录 */}
              {loginMethod === 'phone' && (
                <div className="space-y-4">
                  <div>
                    <Label htmlFor={phoneInputId} className="required">
                      手机号码
                    </Label>
                    <Input
                      id={phoneInputId}
                      type="tel"
                      placeholder="请输入11位手机号码"
                      value={phone}
                      onChange={(e) => handleFieldChange('phone', e.target.value)}
                      onBlur={() => handleFieldBlur('phone', phone)}
                      disabled={isLoading}
                      aria-required="true"
                      aria-invalid={!!validationErrors.phone}
                      aria-describedby={validationErrors.phone ? phoneErrorId : undefined}
                      className={validationErrors.phone ? 'border-red-500' : ''}
                    />
                    {validationErrors.phone && fieldTouched.phone && (
                      <p id={phoneErrorId} className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.phone}
                      </p>
                    )}
                  </div>

                  <div>
                    <Label htmlFor={codeInputId} className="required">
                      验证码
                    </Label>
                    <div className="flex space-x-2">
                      <Input
                        id={codeInputId}
                        type="text"
                        inputMode="numeric"
                        placeholder="请输入6位验证码"
                        value={code}
                        onChange={(e) => handleFieldChange('code', e.target.value)}
                        onBlur={() => handleFieldBlur('code', code)}
                        disabled={isLoading}
                        aria-required="true"
                        aria-invalid={!!validationErrors.code}
                        aria-describedby={validationErrors.code ? codeErrorId : undefined}
                        className={`flex-1 ${validationErrors.code ? 'border-red-500' : ''}`}
                        maxLength={6}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        onClick={handleSendCode}
                        disabled={!canSend || isSendingCode || !phone}
                        aria-label={
                          countdown > 0 
                            ? `${countdown}秒后可重新发送验证码` 
                            : canSend 
                              ? '发送验证码到手机' 
                              : '验证码发送中'
                        }
                      >
                        <MessageCircle className="w-4 h-4 mr-1" aria-hidden="true" />
                        {countdown > 0 ? `${countdown}s` : isSendingCode ? '发送中...' : '发送'}
                      </Button>
                    </div>
                    {validationErrors.code && fieldTouched.code && (
                      <p id={codeErrorId} className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.code}
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* 邮箱登录 */}
              {loginMethod === 'email' && (
                <div className="space-y-4">
                  <div>
                    <Label htmlFor={emailInputId} className="required">
                      邮箱地址
                    </Label>
                    <Input
                      id={emailInputId}
                      type="email"
                      placeholder="请输入邮箱地址"
                      value={email}
                      onChange={(e) => handleFieldChange('email', e.target.value)}
                      onBlur={() => handleFieldBlur('email', email)}
                      disabled={isLoading}
                      aria-required="true"
                      aria-invalid={!!validationErrors.email}
                      aria-describedby={validationErrors.email ? emailErrorId : undefined}
                      className={validationErrors.email ? 'border-red-500' : ''}
                    />
                    {validationErrors.email && fieldTouched.email && (
                      <p id={emailErrorId} className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.email}
                      </p>
                    )}
                  </div>

                  <div>
                    <Label htmlFor={passwordInputId} className="required">
                      密码
                    </Label>
                    <div className="relative">
                      <Input
                        id={passwordInputId}
                        type={showPassword ? 'text' : 'password'}
                        placeholder="请输入密码"
                        value={password}
                        onChange={(e) => handleFieldChange('password', e.target.value)}
                        onBlur={() => handleFieldBlur('password', password)}
                        disabled={isLoading}
                        aria-required="true"
                        aria-invalid={!!validationErrors.password}
                        aria-describedby={validationErrors.password ? passwordErrorId : undefined}
                        className={`pr-10 ${validationErrors.password ? 'border-red-500' : ''}`}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? '隐藏密码' : '显示密码'}
                        tabIndex={-1}
                      >
                        {showPassword ? (
                          <EyeOff className="h-4 w-4" aria-hidden="true" />
                        ) : (
                          <Eye className="h-4 w-4" aria-hidden="true" />
                        )}
                      </Button>
                    </div>
                    {validationErrors.password && fieldTouched.password && (
                      <p id={passwordErrorId} className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.password}
                      </p>
                    )}
                  </div>
                </div>
              )}

              <Button 
                onClick={handleLogin} 
                disabled={isLoading} 
                className="w-full"
                aria-describedby={error ? 'login-error' : undefined}
              >
                {isLoading ? '登录中...' : '登录'}
              </Button>

              {error && (
                <p id="login-error" className="text-sm text-red-600 text-center" role="alert">
                  <span className={srOnlyClass}>登录错误：</span>
                  {error}
                </p>
              )}
            </TabsContent>

            {/* 注册标签页 */}
            <TabsContent 
              value="register"
              id="register-panel" 
              role="tabpanel"
              aria-labelledby="register-tab"
              className="space-y-4"
            >
              {/* 注册方式选择 */}
              <div className="flex space-x-2" role="group" aria-label="注册方式选择">
                <Button
                  type="button"
                  variant={loginMethod === 'phone' ? 'default' : 'outline'}
                  onClick={() => setLoginMethod('phone')}
                  className="flex-1"
                  aria-pressed={loginMethod === 'phone'}
                >
                  <Phone className="w-4 h-4 mr-2" aria-hidden="true" />
                  手机号
                </Button>
                <Button
                  type="button"
                  variant={loginMethod === 'email' ? 'default' : 'outline'}
                  onClick={() => setLoginMethod('email')}
                  className="flex-1"
                  aria-pressed={loginMethod === 'email'}
                >
                  <Mail className="w-4 h-4 mr-2" aria-hidden="true" />
                  邮箱
                </Button>
              </div>

              {/* 用户名字段（通用） */}
              <div>
                <Label htmlFor={usernameInputId} className="required">
                  用户名
                </Label>
                <Input
                  id={usernameInputId}
                  type="text"
                  placeholder="请输入用户名（2-20个字符）"
                  value={username}
                  onChange={(e) => handleFieldChange('username', e.target.value)}
                  onBlur={() => handleFieldBlur('username', username)}
                  disabled={isLoading}
                  aria-required="true"
                  aria-invalid={!!validationErrors.username}
                  aria-describedby={validationErrors.username ? usernameErrorId : undefined}
                  className={validationErrors.username ? 'border-red-500' : ''}
                  maxLength={20}
                />
                {validationErrors.username && fieldTouched.username && (
                  <p id={usernameErrorId} className="text-sm text-red-600 mt-1" role="alert">
                    <span className={srOnlyClass}>错误：</span>
                    {validationErrors.username}
                  </p>
                )}
              </div>

              {/* 手机号注册字段 */}
              {loginMethod === 'phone' && (
                <div className="space-y-4">
                  <div>
                    <Label htmlFor={`${phoneInputId}-register`} className="required">
                      手机号码
                    </Label>
                    <Input
                      id={`${phoneInputId}-register`}
                      type="tel"
                      placeholder="请输入11位手机号码"
                      value={phone}
                      onChange={(e) => handleFieldChange('phone', e.target.value)}
                      onBlur={() => handleFieldBlur('phone', phone)}
                      disabled={isLoading}
                      aria-required="true"
                      aria-invalid={!!validationErrors.phone}
                      aria-describedby={validationErrors.phone ? phoneErrorId : undefined}
                      className={validationErrors.phone ? 'border-red-500' : ''}
                    />
                    {validationErrors.phone && fieldTouched.phone && (
                      <p className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.phone}
                      </p>
                    )}
                  </div>

                  <div>
                    <Label htmlFor={`${codeInputId}-register`} className="required">
                      验证码
                    </Label>
                    <div className="flex space-x-2">
                      <Input
                        id={`${codeInputId}-register`}
                        type="text"
                        inputMode="numeric"
                        placeholder="请输入6位验证码"
                        value={code}
                        onChange={(e) => handleFieldChange('code', e.target.value)}
                        onBlur={() => handleFieldBlur('code', code)}
                        disabled={isLoading}
                        aria-required="true"
                        aria-invalid={!!validationErrors.code}
                        aria-describedby={validationErrors.code ? codeErrorId : undefined}
                        className={`flex-1 ${validationErrors.code ? 'border-red-500' : ''}`}
                        maxLength={6}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        onClick={handleSendCode}
                        disabled={!canSend || isSendingCode || !phone}
                        aria-label={
                          countdown > 0 
                            ? `${countdown}秒后可重新发送验证码` 
                            : canSend 
                              ? '发送验证码到手机' 
                              : '验证码发送中'
                        }
                      >
                        <MessageCircle className="w-4 h-4 mr-1" aria-hidden="true" />
                        {countdown > 0 ? `${countdown}s` : isSendingCode ? '发送中...' : '发送'}
                      </Button>
                    </div>
                    {validationErrors.code && fieldTouched.code && (
                      <p className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.code}
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* 邮箱注册字段 */}
              {loginMethod === 'email' && (
                <div className="space-y-4">
                  <div>
                    <Label htmlFor={`${emailInputId}-register`} className="required">
                      邮箱地址
                    </Label>
                    <Input
                      id={`${emailInputId}-register`}
                      type="email"
                      placeholder="请输入邮箱地址"
                      value={email}
                      onChange={(e) => handleFieldChange('email', e.target.value)}
                      onBlur={() => handleFieldBlur('email', email)}
                      disabled={isLoading}
                      aria-required="true"
                      aria-invalid={!!validationErrors.email}
                      aria-describedby={validationErrors.email ? emailErrorId : undefined}
                      className={validationErrors.email ? 'border-red-500' : ''}
                    />
                    {validationErrors.email && fieldTouched.email && (
                      <p className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.email}
                      </p>
                    )}
                  </div>

                  <div>
                    <Label htmlFor={`${passwordInputId}-register`} className="required">
                      密码
                    </Label>
                    <div className="relative">
                      <Input
                        id={`${passwordInputId}-register`}
                        type={showPassword ? 'text' : 'password'}
                        placeholder="请输入密码（至少6位）"
                        value={password}
                        onChange={(e) => handleFieldChange('password', e.target.value)}
                        onBlur={() => handleFieldBlur('password', password)}
                        disabled={isLoading}
                        aria-required="true"
                        aria-invalid={!!validationErrors.password}
                        aria-describedby={
                          validationErrors.password 
                            ? passwordErrorId 
                            : password 
                              ? passwordStrengthId 
                              : undefined
                        }
                        className={`pr-10 ${validationErrors.password ? 'border-red-500' : ''}`}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? '隐藏密码' : '显示密码'}
                        tabIndex={-1}
                      >
                        {showPassword ? (
                          <EyeOff className="h-4 w-4" aria-hidden="true" />
                        ) : (
                          <Eye className="h-4 w-4" aria-hidden="true" />
                        )}
                      </Button>
                    </div>
                    
                    {/* 密码强度指示器 */}
                    {password && !validationErrors.password && (
                      <div id={passwordStrengthId} className="mt-2" aria-live="polite">
                        <div className="flex items-center space-x-2">
                          <div className="flex space-x-1">
                            {[1, 2, 3, 4, 5].map((level) => (
                              <div
                                key={level}
                                className={`h-1 w-4 rounded ${
                                  level <= passwordStrength.score
                                    ? passwordStrength.score <= 2
                                      ? 'bg-red-500'
                                      : passwordStrength.score <= 3
                                        ? 'bg-yellow-500'
                                        : 'bg-green-500'
                                    : 'bg-gray-200'
                                }`}
                                aria-hidden="true"
                              />
                            ))}
                          </div>
                          <span className="text-xs text-gray-600">
                            强度: {passwordStrength.level}
                          </span>
                        </div>
                        <p className="text-xs text-gray-600 mt-1">
                          {passwordStrength.feedback}
                        </p>
                      </div>
                    )}
                    
                    {validationErrors.password && fieldTouched.password && (
                      <p id={passwordErrorId} className="text-sm text-red-600 mt-1" role="alert">
                        <span className={srOnlyClass}>错误：</span>
                        {validationErrors.password}
                      </p>
                    )}
                  </div>
                </div>
              )}

              <Button 
                onClick={handleRegister} 
                disabled={isLoading} 
                className="w-full"
                aria-describedby={error ? 'register-error' : undefined}
              >
                {isLoading ? '注册中...' : '注册账户'}
              </Button>

              {error && (
                <p id="register-error" className="text-sm text-red-600 text-center" role="alert">
                  <span className={srOnlyClass}>注册错误：</span>
                  {error}
                </p>
              )}
            </TabsContent>
          </Tabs>

          {/* 实时区域用于屏幕阅读器公告 */}
          <LiveRegion priority="assertive">
            {/* 动态状态公告会在这里显示 */}
          </LiveRegion>
        </FocusTrap>
      </DialogContent>
    </Dialog>
  );
}