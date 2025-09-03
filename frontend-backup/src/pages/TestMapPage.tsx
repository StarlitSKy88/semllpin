import { Card, Space, Typography } from 'antd';

import React from 'react';

import { MapPin } from 'lucide-react';
import MapComponent from '../components/Map/MapComponent';

const { Title, Text } = Typography;

// 测试数据
const testAnnotations = [
  {
    id: '1',
    latitude: 39.9042,
    longitude: 116.4074,
    smell_intensity: 8,
    description: '这里有一股神秘的臭豆腐味道！',
    user: {
      id: '1',
      username: '恶搞大师',
      avatar: undefined
    },
    likes_count: 42,
    views_count: 128,
    created_at: new Date().toISOString(),
    media_files: []
  },
  {
    id: '2',
    latitude: 39.9100,
    longitude: 116.4200,
    smell_intensity: 6,
    description: '榴莲味的公交站，太搞笑了！',
    user: {
      id: '2',
      username: '搞笑王',
      avatar: undefined
    },
    likes_count: 23,
    views_count: 89,
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    media_files: []
  },
  {
    id: '3',
    latitude: 39.8950,
    longitude: 116.3950,
    smell_intensity: 9,
    description: '超级臭的垃圾桶，路过要屏住呼吸！',
    user: {
      id: '3',
      username: '臭味猎人',
      avatar: undefined
    },
    likes_count: 67,
    views_count: 234,
    created_at: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
    media_files: []
  }
];

const TestMapPage: React.FC = () => {
  const handleAnnotationClick = (annotation: {
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
  }) => {
    console.log('点击标注:', annotation);
  };

  const handleMapClick = (lat: number, lng: number) => {
    console.log('点击地图:', lat, lng);
  };

  return (
    <div className="p-6 space-y-6">
      <Card>
        <div className="text-center">
          <Title level={2} className="flex items-center justify-center">
            <MapPin className="mr-2 text-primary-500" size={20} />
            地图功能测试
          </Title>
          <Text className="text-gray-600">
            测试地图组件的基本功能，包括标注显示和交互
          </Text>
        </div>
      </Card>

      <Card className="p-0 overflow-hidden">
        <MapComponent 
          annotations={testAnnotations}
          height="600px"
          center={[39.9042, 116.4074]}
          zoom={13}
          onAnnotationClick={handleAnnotationClick}
          onMapClick={handleMapClick}
        />
      </Card>

      <Card>
        <Title level={4}>测试说明</Title>
        <Space direction="vertical" className="w-full">
          <Text>• 地图上显示了3个测试标注点</Text>
          <Text>• 点击标注可以查看详细信息</Text>
          <Text>• 点击地图空白处可以添加新标注</Text>
          <Text>• 不同颜色的标注代表不同的臭味强度</Text>
        </Space>
      </Card>
    </div>
  );
};

export default TestMapPage;