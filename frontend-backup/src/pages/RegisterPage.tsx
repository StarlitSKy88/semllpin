import React, { useEffect } from 'react';
import { App, Button, Form, Input, Typography } from 'antd';
import { User, Lock, Mail } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { FadeIn } from '../components/OptimizedMotion';

import { useAuthStore } from '../stores/authStore';
import { AuthCard } from '../components/Auth/AuthCard';
import { DecorativeElements } from '../components/UI/DecorativeElements';

const { Title, Text } = Typography;

interface RegisterForm {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
  university?: string;
}

const RegisterPage: React.FC = () => {
  
  const navigate = useNavigate();
  const { isLoading, error, isAuthenticated, register, clearError } = useAuthStore();
  const [form] = Form.useForm();
  const { message } = App.useApp();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    if (error) {
      message.error(error);
      clearError();
    }
  }, [error, clearError, message]);

  const handleSubmit = async (values: RegisterForm) => {
    try {
      await register(values.email, values.password, values.username);
      message.success('注册成功！欢迎加入搞笑恶搞世界！');
      navigate('/');
    } catch {
      // 错误已在useEffect中处理
    }
  };

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 via-floral-50 to-pomegranate-100 flex items-center justify-center p-4">
        {/* Background decorative elements */}
        <DecorativeElements variant="background" animate={true} />
        
        {/* Floating decorative elements */}
        <DecorativeElements variant="floating" position="top-left" animate={true} />
        <DecorativeElements variant="floating" position="top-right" animate={true} />
        <DecorativeElements variant="floating" position="bottom-left" animate={true} />
        <DecorativeElements variant="floating" position="bottom-right" animate={true} />
        <FadeIn
          className="w-full max-w-md"
        >


          <FadeIn>
            <AuthCard>
          <div className="p-6">
            <Title level={3} className="text-center mb-6 text-gray-800">
              创建账号
            </Title>
            
            <Form
              form={form}
              name="register"
              onFinish={handleSubmit}
              layout="vertical"
              size="large"
            >
              <Form.Item
                name="username"
                label="用户名"
                rules={[
                  { required: true, message: '请输入用户名！' },
                  { min: 3, message: '用户名至少3个字符！' }
                ]}
              >
                <Input 
                  prefix={<User className="text-gray-400" size={16} />}
                  placeholder="请输入用户名"
                />
              </Form.Item>

              <Form.Item
                name="email"
                label="邮箱"
                rules={[
                  { required: true, message: '请输入邮箱！' },
                  { type: 'email', message: '请输入有效的邮箱地址！' }
                ]}
              >
                <Input 
                  prefix={<Mail className="text-gray-400" size={16} />}
                  placeholder="请输入邮箱"
                />
              </Form.Item>

              <Form.Item
                name="password"
                label="密码"
                rules={[
                  { required: true, message: '请输入密码！' },
                  { min: 8, message: '密码至少8位字符！' },
                  { 
                    pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
                    message: '密码必须包含至少一个大写字母、一个小写字母、一个数字和一个特殊字符！' 
                  }
                ]}
              >
                <Input.Password 
                  prefix={<Lock className="text-gray-400" size={16} />}
                  placeholder="请输入密码"
                />
              </Form.Item>

              <Form.Item
                name="confirmPassword"
                label="确认密码"
                dependencies={['password']}
                rules={[
                  { required: true, message: '请确认密码！' },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || getFieldValue('password') === value) {
                        return Promise.resolve();
                      }
                      return Promise.reject(new Error('两次输入的密码不一致！'));
                    } }),
                ]}
              >
                <Input.Password 
                  prefix={<Lock className="text-gray-400" size={16} />}
                  placeholder="请再次输入密码"
                />
              </Form.Item>

              <Form.Item
                name="university"
                label="大学（可选）"
              >
                <Input placeholder="请输入你的大学" />
              </Form.Item>

              <Form.Item>
                <Button 
                  type="primary" 
                  htmlType="submit" 
                  loading={isLoading}
                  className="w-full h-12 text-lg font-semibold rounded-lg bg-gradient-to-r from-pomegranate-600 to-pomegranate-800 border-0"
                >
                  {isLoading ? '注册中...' : '立即注册'}
                </Button>
              </Form.Item>
            </Form>

            <div className="text-center mt-4">
              <Text className="text-gray-600">
                已有账号？
                <Link to="/login" className="text-pomegranate-600 hover:text-pomegranate-700 ml-1">
                  立即登录
                </Link>
              </Text>
            </div>
          </div>
            </AuthCard>
          </FadeIn>
        </FadeIn>
      </div>
    </ErrorBoundary>
  );
};

export default RegisterPage;