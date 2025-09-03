import React, { useState } from 'react';
import { Button, Drawer, Space } from 'antd'; // Card, Tabs removed as unused
import { BarChart3, Flame, X } from 'lucide-react';
import EnhancedMapComponent from './EnhancedMapComponent';
import ContentRecommendation from './ContentRecommendation';
import FunnyAnalytics from './FunnyAnalytics';

// const { TabPane } = Tabs; // removed as unused

interface Annotation {
  id: string;
  latitude: number;
  longitude: number;
  smell_intensity: number;
  description?: string;
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
  likes_count: number;
  views_count: number;
  created_at: string;
  media_files?: string[];
  category?: string;
}

interface MapControlPanelProps {
  annotations: Annotation[];
  userLocation?: [number, number];
  onAnnotationClick?: (annotation: Annotation) => void;
  onMapClick?: () => void;
  height?: string;
}

const MapControlPanel: React.FC<MapControlPanelProps> = ({
  annotations,
  userLocation,
  onAnnotationClick,
  onMapClick,
  height = '70vh'
}) => {
  const [activePanel, setActivePanel] = useState<'none' | 'recommendations' | 'analytics'>('none');
  const [drawerVisible, setDrawerVisible] = useState(false);

  const togglePanel = (panel: 'recommendations' | 'analytics') => {
    if (activePanel === panel) {
      setActivePanel('none');
      setDrawerVisible(false);
    } else {
      setActivePanel(panel);
      setDrawerVisible(true);
    }
  };

  const renderPanelContent = () => {
    switch (activePanel) {
      case 'recommendations':
        return (
          <ContentRecommendation
            annotations={annotations}
            userLocation={userLocation}
            onAnnotationSelect={onAnnotationClick}
            visible={true}
          />
        );
      case 'analytics':
        return (
          <FunnyAnalytics
            annotations={annotations}
            visible={true}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="relative">
      {/* 地图组件 */}
      <div className="relative">
        <EnhancedMapComponent
          annotations={annotations}
          height={height}
          center={userLocation}
          onAnnotationClick={onAnnotationClick}
          onMapClick={onMapClick}
        />
        
        {/* 控制按钮 */}
        <div className="absolute top-4 right-4 z-1000">
          <Space direction="vertical">
            <Button
              type={activePanel === 'recommendations' ? 'primary' : 'default'}
              icon={<Flame size={16} />}
              onClick={() => togglePanel('recommendations')}
              className="shadow-lg"
            >
              推荐
            </Button>
            <Button
              type={activePanel === 'analytics' ? 'primary' : 'default'}
              icon={<BarChart3 size={16} />}
              onClick={() => togglePanel('analytics')}
              className="shadow-lg"
            >
              分析
            </Button>
          </Space>
        </div>
      </div>

      {/* 侧边抽屉 */}
      <Drawer
        title={
          <div className="flex items-center justify-between">
            <span>
              {activePanel === 'recommendations' && '🔥 内容推荐'}
              {activePanel === 'analytics' && '📊 数据分析'}
            </span>
            <Button
              type="text"
              icon={<X size={16} />}
              onClick={() => {
                setActivePanel('none');
                setDrawerVisible(false);
              }}
            />
          </div>
        }
        placement="right"
        width={400}
        open={drawerVisible}
        onClose={() => {
          setActivePanel('none');
          setDrawerVisible(false);
        }}
        bodyStyle={{ padding: 0 }}
        headerStyle={{ borderBottom: '1px solid #f0f0f0' }}
      >
        <div className="p-4">
          {renderPanelContent()}
        </div>
      </Drawer>
    </div>
  );
};

export default MapControlPanel;