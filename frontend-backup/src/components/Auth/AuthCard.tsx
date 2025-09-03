import React from 'react';
import { Card } from 'antd';
import clsx from 'clsx';

interface AuthCardProps {
  className?: string;
  children: React.ReactNode;
}

/**
 * 认证表单卡片容器
 *  - 默认宽度适配移动端
 *  - 内置圆角、阴影，与品牌色渐变边框
 */
export const AuthCard: React.FC<AuthCardProps> = ({ children, className }) => {
  return (
    <Card
      className={clsx(
        'shadow-2xl border-0 rounded-2xl overflow-hidden',
        className,
      )}
      bodyStyle={{ padding: 32 }}
    >
      {children}
    </Card>
  );
};