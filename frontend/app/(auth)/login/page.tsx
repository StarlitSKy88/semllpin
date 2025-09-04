'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuthStore } from '@/lib/stores/auth-store';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

export default function LoginPage() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const { emailLogin, isLoading } = useAuthStore();
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTo = searchParams.get('redirect') || '/';

  // 表单验证
  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.email.trim()) {
      newErrors['email'] = '邮箱不能为空';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors['email'] = '请输入有效的邮箱地址';
    }

    if (!formData.password) {
      newErrors['password'] = '密码不能为空';
    } else if (formData.password.length < 6) {
      newErrors['password'] = '密码至少需要6个字符';
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
      await emailLogin(formData.email, formData.password);
      toast.success('登录成功！');
      router.push(redirectTo);
    } catch (error: any) {
      toast.error(error.message || '登录失败，请检查邮箱和密码');
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
          欢迎回来
        </h1>
        <p className="text-white/60">
          登录您的 SmellPin 账户
        </p>
      </div>

      {/* 登录表单 */}
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
              className={errors['email'] ? 'border-red-500/50' : ''}
              disabled={isLoading}
            />
            {errors['email'] && (
              <p className="text-red-400 text-sm mt-1">{errors['email']}</p>
            )}
          </div>

          {/* 密码输入 */}
          <div>
            <Input
              type="password"
              placeholder="密码"
              value={formData.password}
              onChange={(e) => handleInputChange('password', e.target.value)}
              variant="glass-dark"
              className={errors['password'] ? 'border-red-500/50' : ''}
              disabled={isLoading}
            />
            {errors['password'] && (
              <p className="text-red-400 text-sm mt-1">{errors['password']}</p>
            )}
          </div>
        </div>

        {/* 忘记密码链接 */}
        <div className="text-right">
          <Link 
            href="/forgot-password" 
            className="text-blue-400 hover:text-blue-300 text-sm transition-colors"
          >
            忘记密码？
          </Link>
        </div>

        {/* 登录按钮 */}
        <Button
          type="submit"
          variant="gradient"
          className="w-full"
          disabled={isLoading}
        >
          {isLoading ? (
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white/20"></div>
              登录中...
            </div>
          ) : (
            '登录'
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

        {/* 注册链接 */}
        <div className="text-center">
          <span className="text-white/60">还没有账户？</span>{' '}
          <Link 
            href="/register" 
            className="text-blue-400 hover:text-blue-300 font-medium transition-colors"
          >
            立即注册
          </Link>
        </div>
      </form>
    </div>
  );
}