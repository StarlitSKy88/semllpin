import React from 'react';
import { Card, Space, Typography } from 'antd';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;

interface StatsCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: 'up' | 'down';
  trendValue?: string;
  color?: 'green' | 'red' | 'blue' | 'yellow' | 'purple';
}

const StatsCard: React.FC<StatsCardProps> = ({ 
  title, 
  value, 
  icon, 
  trend, 
  trendValue, 
  color = 'blue' 
}) => {
  const colorClasses = {
    green: 'from-green-50 to-emerald-50 border-green-200',
    red: 'from-red-50 to-rose-50 border-red-200',
    blue: 'from-secondary-50 to-secondary-100 border-secondary-200',
    yellow: 'from-yellow-50 to-amber-50 border-yellow-200',
    purple: 'from-purple-50 to-violet-50 border-purple-200',
  };

  return (
    <Card className={`bg-gradient-to-br ${colorClasses[color]} border hover:shadow-lg transition-all`}>
      <Space direction="vertical" className="w-full">
        <div className="flex items-center justify-between">
          <Text className="text-gray-600 font-medium">{title}</Text>
          {icon}
        </div>
        
        <Title level={2} className="mb-0">
          {value}
        </Title>
        
        {trend && trendValue && (
          <div className="flex items-center">
            {trend === 'up' ? (
              <ArrowUpOutlined className="text-green-500 mr-1" />
            ) : (
              <ArrowDownOutlined className="text-red-500 mr-1" />
            )}
            <Text 
              className={`text-sm ${trend === 'up' ? 'text-green-600' : 'text-red-600'}`}
            >
              {trendValue}
            </Text>
            <Text className="text-gray-500 text-sm ml-1">vs 上周</Text>
          </div>
        )}
      </Space>
    </Card>
  );
};

export default StatsCard;