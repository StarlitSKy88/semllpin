import { App, Button, Divider, Form, Input, Space, Typography } from 'antd';
import React, { useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { User, Lock } from 'lucide-react';

import { useAuthStore } from '../stores/authStore';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import AuthLayout from '../components/Auth/AuthLayout';
import { AuthCard } from '../components/Auth/AuthCard';
import { FadeIn, SlideUp } from '../components/OptimizedMotion';
import { DecorativeElements } from '../components/UI/DecorativeElements';

const { Title, Text } = Typography;

interface LoginForm {
  email: string;
  password: string;
}

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { isLoading, error, isAuthenticated, login, clearError } = useAuthStore();
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

  const handleSubmit = async (values: LoginForm) => {
    try {
      await login(values.email, values.password);
      message.success('登录成功！欢迎回到搞笑恶搞世界！');
      navigate('/');
    } catch {
      /* 错误已在 useEffect 中处理 */
    }
  };

  return (
    <ErrorBoundary>
      <AuthLayout>
        {/* Background decorative elements */}
        <DecorativeElements variant="background" animate={true} />
        
        {/* Floating decorative elements */}
        <DecorativeElements variant="floating" position="top-left" animate={true} />
        <DecorativeElements variant="floating" position="top-right" animate={true} />
        <DecorativeElements variant="floating" position="bottom-left" animate={true} />
        <DecorativeElements variant="floating" position="bottom-right" animate={true} />
        <FadeIn className="w-full max-w-md">
          <AuthCard>
            <Title level={2} className="text-center mb-8 text-gray-800">
              欢迎回来！
            </Title>
            <Form
              form={form}
              name="login"
              onFinish={handleSubmit}
              layout="vertical"
              size="large"
              autoComplete="off"
            >
              <Form.Item
                name="email"
                label="邮箱"
                rules={[{ required: true, message: '请输入邮箱！' }, { type: 'email', message: '请输入有效的邮箱地址！' }]}
              >
                <Input
                  prefix={<User className="text-gray-400" size={16} />}
                  placeholder="请输入邮箱"
                  className="rounded-lg h-12"
                />
              </Form.Item>
              <Form.Item
                name="password"
                label="密码"
                rules={[{ required: true, message: '请输入密码！' }, { min: 6, message: '密码至少6位字符！' }]}
              >
                <Input.Password
                  prefix={<Lock className="text-gray-400" size={16} />}
                  placeholder="请输入密码"
                  className="rounded-lg h-12"
                />
              </Form.Item>
              <Form.Item className="mb-6">
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={isLoading}
                  className="w-full h-12 text-lg font-semibold rounded-lg bg-gradient-to-r from-pomegranate-600 to-pomegranate-800 border-0 shadow-lg hover:shadow-xl transform hover:scale-105 transition-all"
                >
                  {isLoading ? '登录中...' : '登录'}
                </Button>
              </Form.Item>
            </Form>
            <Divider className="my-6">
              <Text className="text-gray-500">还没有账号？</Text>
            </Divider>
            <Link to="/register">
              <Button
                type="default"
                size="large"
                className="w-full h-12 text-lg rounded-lg border-2 border-pomegranate-200 text-pomegranate-600 hover:border-pomegranate-400 hover:text-pomegranate-700 transition-all"
              >
                立即注册
              </Button>
            </Link>
          </AuthCard>

          <SlideUp className="text-center mt-6">
            <Space direction="vertical" size="small">
              <Text className="text-gray-500">© 2024 SmellPin. 让世界充满欢声笑语</Text>
              <Space>
                <Link to="/privacy" className="text-gray-400 hover:text-pomegranate-500">
                  隐私政策
                </Link>
                <Divider type="vertical" />
                <Link to="/terms" className="text-gray-400 hover:text-pomegranate-500">
                  服务条款
                </Link>
              </Space>
            </Space>
          </SlideUp>
        </FadeIn>
      </AuthLayout>
    </ErrorBoundary>
  );
};

export default LoginPage;