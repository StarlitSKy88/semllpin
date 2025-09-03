import React from 'react';
import { Card, Typography } from 'antd';
import { BarChart3 } from 'lucide-react';
import { DecorativeElements } from '../components/UI/DecorativeElements';

const { Title, Text } = Typography;

const StatsPage: React.FC = () => {
  return (
    <div className="relative p-6 bg-gradient-to-br from-pomegranate-50 to-floral-50">
      <DecorativeElements variant="background" animate />
      <DecorativeElements variant="floating" position="top-left" animate />
      <DecorativeElements variant="floating" position="top-right" animate />
      <DecorativeElements variant="floating" position="bottom-left" animate />
      <DecorativeElements variant="floating" position="bottom-right" animate />
      <Card className="relative text-center py-12 overflow-hidden">
        <DecorativeElements variant="accent" position="center" animate />
        <div className="relative z-10">
          <BarChart3 className="text-6xl text-pomegranate-500 mb-4" size={64} />
          <Title level={2} className="text-pomegranate-900">数据统计</Title>
          <Text className="text-pomegranate-600">
            这里将显示详细的数据统计和分析图表
          </Text>
        </div>
      </Card>
    </div>
  );
};

export default StatsPage;