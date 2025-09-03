import { Button, Card, Col, Row, Space, Typography } from 'antd';

import React from 'react';

import { 
  Plus, 
  MapPin, 
  Search, 
  Gift,
  Share,
  Trophy
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useUIStore } from '../../stores/uiStore';

const { Title } = Typography;

const QuickActions: React.FC = () => {
  const { openModal } = useUIStore();
  const navigate = useNavigate();

  const actions = [
    {
      key: 'create',
      title: '创建恶搞',
      icon: <Plus size={18} />,
      color: 'from-pomegranate-500 to-pomegranate-700',
      onClick: () => openModal({ type: 'prank-create', props: { step: 1 } }) },
    {
      key: 'explore',
      title: '探索地图',
      icon: <MapPin size={18} />,
      color: 'from-pomegranate-400 to-pomegranate-600',
      onClick: () => navigate('/map') },
    {
      key: 'search',
      title: '搜索恶搞',
      icon: <Search size={18} />,
      color: 'from-floral-400 to-floral-600',
      onClick: () => navigate('/map?search=true') },
    {
      key: 'rewards',
      title: '每日奖励',
      icon: <Gift size={18} />,
      color: 'from-pomegranate-300 to-pomegranate-500',
      onClick: () => navigate('/profile?tab=rewards') },
    {
      key: 'share',
      title: '分享应用',
      icon: <Share size={18} />,
      color: 'from-pomegranate-600 to-floral-500',
      onClick: () => {
        if (navigator.share) {
          navigator.share({
            title: 'SmellPin - 臭味地图',
            text: '发现身边的搞笑恶搞标注，分享你的有趣发现！',
            url: window.location.origin
          });
        } else {
          // 降级处理：复制链接到剪贴板
          navigator.clipboard.writeText(window.location.origin);
          alert('链接已复制到剪贴板！');
        }
      } },
    {
      key: 'leaderboard',
      title: '查看排行',
      icon: <Trophy size={18} />,
      color: 'from-floral-300 to-pomegranate-400',
      onClick: () => navigate('/leaderboard') },
  ];

  return (
    <Card>
      <Title level={4} className="mb-4">快速操作</Title>
      <Row gutter={[16, 16]}>
        {actions.map((action) => (
          <Col xs={12} sm={8} md={6} lg={4} key={action.key}>
            <Button
              className={`w-full h-20 bg-gradient-to-r ${action.color} border-0 text-white hover:shadow-lg transform hover:scale-105 transition-all rounded-xl`}
              onClick={action.onClick}
            >
              <Space direction="vertical" size="small" className="w-full">
                <span className="text-2xl">{action.icon}</span>
                <span className="text-sm font-medium">{action.title}</span>
              </Space>
            </Button>
          </Col>
        ))}
      </Row>
    </Card>
  );
};

export default QuickActions;