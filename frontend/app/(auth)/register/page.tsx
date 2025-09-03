'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/lib/stores/auth-store';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

export default function RegisterPage() {
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const { emailRegister, isLoading } = useAuthStore();
  const router = useRouter();

  // 表单验证
  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    // 邮箱验证
    if (!formData.email.trim()) {
      newErrors.email = '邮箱不能为空';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = '请输入有效的邮箱地址';
    }

    // 用户名验证
    if (!formData.username.trim()) {
      newErrors.username = '用户名不能为空';
    } else if (formData.username.length < 2) {
      newErrors.username = '用户名至少需要2个字符';
    } else if (formData.username.length > 20) {
      newErrors.username = '用户名不能超过20个字符';
    } else if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/.test(formData.username)) {
      newErrors.username = '用户名只能包含字母、数字、下划线和中文';
    }

    // 密码验证
    if (!formData.password) {
      newErrors.password = '密码不能为空';
    } else if (formData.password.length < 6) {
      newErrors.password = '密码至少需要6个字符';
    } else if (formData.password.length > 50) {
      newErrors.password = '密码不能超过50个字符';
    }

    // 确认密码验证
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = '请确认密码';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = '两次输入的密码不一致';
    }

    // 服务条款验证
    if (!agreedToTerms) {
      newErrors.terms = '请同意服务条款和隐私政策';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      await emailRegister(formData.email, formData.password, formData.username);
      toast.success('注册成功！欢迎加入 SmellPin');
      router.push('/');
    } catch (error: any) {
      if (error.message.includes('邮箱已存在')) {
        setErrors({ email: '该邮箱已被注册' });
      } else if (error.message.includes('用户名已存在')) {
        setErrors({ username: '该用户名已被使用' });
      } else {
        toast.error(error.message || '注册失败，请重试');
      }
    }
  };

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // 清除对应字段的错误
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  return (
    <div className="bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl">
      {/* 标题 */}
      <div className="text-center mb-8">
        <h1 className="text-2xl font-bold text-white mb-2">
          创建账户
        </h1>
        <p className="text-white/60">
          加入 SmellPin，开始标注气味地图
        </p>
      </div>

      {/* 注册表单 */}
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="space-y-4">
          {/* 邮箱输入 */}
          <div>
            <Input
              type="email"
              placeholder="邮箱地址"
              value={formData.email}
              onChange={(e) => handleInputChange('email', e.target.value)}
              variant="glass-dark"
              className={errors.email ? 'border-red-500/50' : ''}
              disabled={isLoading}
            />
            {errors.email && (
              <p className="text-red-400 text-sm mt-1">{errors.email}</p>
            )}
          </div>

          {/* 用户名输入 */}
          <div>
            <Input
              type="text"
              placeholder="用户名"
              value={formData.username}
              onChange={(e) => handleInputChange('username', e.target.value)}
              variant="glass-dark"
              className={errors.username ? 'border-red-500/50' : ''}
              disabled={isLoading}
            />
            {errors.username && (
              <p className="text-red-400 text-sm mt-1">{errors.username}</p>
            )}
          </div>

          {/* 密码输入 */}
          <div>
            <Input
              type="password"
              placeholder="密码 (至少6个字符)"
              value={formData.password}
              onChange={(e) => handleInputChange('password', e.target.value)}
              variant="glass-dark"
              className={errors.password ? 'border-red-500/50' : ''}
              disabled={isLoading}
            />
            {errors.password && (
              <p className="text-red-400 text-sm mt-1">{errors.password}</p>
            )}
          </div>

          {/* 确认密码输入 */}
          <div>
            <Input
              type="password"
              placeholder="确认密码"
              value={formData.confirmPassword}
              onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
              variant="glass-dark"
              className={errors.confirmPassword ? 'border-red-500/50' : ''}
              disabled={isLoading}
            />
            {errors.confirmPassword && (
              <p className="text-red-400 text-sm mt-1">{errors.confirmPassword}</p>
            )}
          </div>
        </div>

        {/* 服务条款checkbox */}
        <div className="flex items-start gap-3">
          <input
            type="checkbox"
            id="terms"
            checked={agreedToTerms}
            onChange={(e) => {
              setAgreedToTerms(e.target.checked);
              if (errors.terms) {
                setErrors(prev => ({ ...prev, terms: '' }));
              }
            }}
            className="mt-1 h-4 w-4 rounded border border-white/20 bg-white/5 text-blue-500 focus:ring-2 focus:ring-blue-500/20"
            disabled={isLoading}
          />
          <label htmlFor="terms" className="text-sm text-white/60 leading-relaxed">
            我已阅读并同意{' '}
            <Link href="/terms" className="text-blue-400 hover:text-blue-300 underline">
              服务条款
            </Link>{' '}
            和{' '}
            <Link href="/privacy" className="text-blue-400 hover:text-blue-300 underline">
              隐私政策
            </Link>
          </label>
        </div>
        {errors.terms && (
          <p className="text-red-400 text-sm">{errors.terms}</p>
        )}

        {/* 注册按钮 */}
        <Button
          type="submit"
          variant="gradient-green"
          className="w-full"
          disabled={isLoading}
        >
          {isLoading ? (
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white/20"></div>
              注册中...
            </div>
          ) : (
            '创建账户'
          )}
        </Button>

        {/* 分隔线 */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-white/10"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="bg-[#0a0a0a] px-4 text-white/60">或</span>
          </div>
        </div>

        {/* 登录链接 */}
        <div className="text-center">
          <span className="text-white/60">已有账户？</span>{' '}
          <Link 
            href="/login" 
            className="text-blue-400 hover:text-blue-300 font-medium transition-colors"
          >
            立即登录
          </Link>
        </div>
      </form>
    </div>
  );
}