import { Button, Card, Select, Slider, Space, Typography } from 'antd';

import React, { useState, useCallback, useMemo } from 'react';
import { MapContainer, TileLayer, useMapEvents } from 'react-leaflet';

import { 
  Plus, 
  Flame,
  Grid3X3,
  Settings,
  LayoutGrid
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { useUIStore } from '../../stores/uiStore';
import HeatmapLayer from './HeatmapLayer';
import MarkerClusterGroup from './MarkerClusterGroup';
import 'leaflet/dist/leaflet.css';

const { Text } = Typography;
const { Option } = Select;

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
}

interface EnhancedMapComponentProps {
  annotations: Annotation[];
  onAnnotationClick?: (annotation: Annotation) => void;
  onMapClick?: (lat: number, lng: number) => void;
  center?: [number, number];
  zoom?: number;
  height?: string;
}

// 地图点击事件处理组件
const MapClickHandler: React.FC<{ onMapClick?: (lat: number, lng: number) => void }> = ({ onMapClick }) => {
  useMapEvents({
    click: (e) => {
      if (onMapClick) {
        onMapClick(e.latlng.lat, e.latlng.lng);
      }
    } });
  return null;
};

const EnhancedMapComponent: React.FC<EnhancedMapComponentProps> = ({
  annotations,
  onAnnotationClick,
  onMapClick,
  center = [39.9042, 116.4074], // 默认北京
  zoom = 13,
  height = '600px'
}) => {
  const { user } = useAuthStore();
  const { openModal } = useUIStore();
  
  // 地图显示模式状态
  const [viewMode, setViewMode] = useState<'markers' | 'heatmap' | 'both'>('markers');
  const [showControls, setShowControls] = useState(false);
  const [intensityFilter, setIntensityFilter] = useState<[number, number]>([1, 10]);
  const [clusterRadius, setClusterRadius] = useState(80);
  const [heatmapRadius, setHeatmapRadius] = useState(25);
  const [mapStyle, setMapStyle] = useState('standard');

  // 过滤标注数据
  const filteredAnnotations = useMemo(() => {
    return annotations.filter(annotation => 
      annotation.smell_intensity >= intensityFilter[0] && 
      annotation.smell_intensity <= intensityFilter[1]
    );
  }, [annotations, intensityFilter]);

  // 转换为热力图数据
  const heatmapPoints = useMemo(() => {
    return filteredAnnotations.map(annotation => ({
      latitude: annotation.latitude,
      longitude: annotation.longitude,
      intensity: annotation.smell_intensity
    }));
  }, [filteredAnnotations]);

  const handleMapClick = useCallback((lat: number, lng: number) => {
    if (onMapClick) {
      onMapClick(lat, lng);
    } else if (user) {
      openModal({ type: 'prank-create' });
    }
  }, [onMapClick, user, openModal]);

  const handleAnnotationClick = useCallback((annotation: Annotation) => {
    if (onAnnotationClick) {
      onAnnotationClick(annotation);
    } else {
      openModal({ type: 'prank-detail', props: { annotation } });
    }
  }, [onAnnotationClick, openModal]);

  // 地图样式配置
  const mapStyles = {
    standard: {
      url: "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    },
    satellite: {
      url: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
      attribution: '&copy; <a href="https://www.esri.com/">Esri</a>'
    },
    dark: {
      url: "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
    }
  };

  return (
    <div style={{ height, width: '100%' }} className="relative">
      <MapContainer
        center={center}
        zoom={zoom}
        style={{ height: '100%', width: '100%' }}
        className="rounded-lg overflow-hidden"
      >
        <TileLayer
          attribution={mapStyles[mapStyle as keyof typeof mapStyles].attribution}
          url={mapStyles[mapStyle as keyof typeof mapStyles].url}
        />
        
        <MapClickHandler onMapClick={handleMapClick} />
        
        {/* 热力图层 */}
        {(viewMode === 'heatmap' || viewMode === 'both') && (
          <HeatmapLayer 
            points={heatmapPoints}
            options={{
              radius: heatmapRadius,
              blur: 15,
              maxZoom: 18,
              gradient: {
                0.0: '#00ff00',
                0.3: '#ffff00', 
                0.6: '#ff8000',
                1.0: '#ff0000'
              }
            }}
            visible={true}
          />
        )}
        
        {/* 标注聚合层 */}
        {(viewMode === 'markers' || viewMode === 'both') && (
          <MarkerClusterGroup
            annotations={filteredAnnotations}
            onMarkerClick={handleAnnotationClick}
            clusterOptions={{
              maxClusterRadius: clusterRadius,
              disableClusteringAtZoom: 16,
              spiderfyOnMaxZoom: true,
              showCoverageOnHover: false,
              zoomToBoundsOnClick: true
            }}
          />
        )}
      </MapContainer>
      
      {/* 地图控制面板 */}
      <div className="absolute top-4 left-4 z-[1000]">
        <Card 
          size="small" 
          className="bg-white/90 backdrop-blur-sm border-gray-200 shadow-lg"
          bodyStyle={{ padding: '12px' }}
        >
          <Space direction="vertical" size={12}>
            {/* 视图模式切换 */}
            <div>
              <Text strong className="text-sm mb-2 block">显示模式</Text>
              <Space>
                <Button 
                  size="small" 
                  type={viewMode === 'markers' ? 'primary' : 'default'}
                  icon={<Grid3X3 size={14} />}
                  onClick={() => setViewMode('markers')}
                  className={viewMode === 'markers' ? 'bg-blue-500 text-white border-blue-500' : 'bg-white text-gray-700 border-gray-300 hover:bg-blue-50 hover:border-blue-300'}
                >
                  标注
                </Button>
                <Button 
                  size="small" 
                  type={viewMode === 'heatmap' ? 'primary' : 'default'}
                  icon={<Flame size={14} />}
                  onClick={() => setViewMode('heatmap')}
                  className={viewMode === 'heatmap' ? 'bg-orange-500 text-white border-orange-500' : 'bg-white text-gray-700 border-gray-300 hover:bg-orange-50 hover:border-orange-300'}
                >
                  热力图
                </Button>
                <Button 
                  size="small" 
                  type={viewMode === 'both' ? 'primary' : 'default'}
                  icon={<LayoutGrid size={14} />}
                  onClick={() => setViewMode('both')}
                  className={viewMode === 'both' ? 'bg-green-500 text-white border-green-500' : 'bg-white text-gray-700 border-gray-300 hover:bg-green-50 hover:border-green-300'}
                >
                  混合
                </Button>
              </Space>
            </div>

            {/* 高级控制 */}
            <div>
              <Button 
                size="small" 
                icon={<Settings size={14} />}
                onClick={() => setShowControls(!showControls)}
                className="w-full bg-white text-gray-700 border-gray-300 hover:bg-gray-50 hover:border-gray-400"
              >
                {showControls ? '隐藏' : '显示'}高级设置
              </Button>
            </div>

            {showControls && (
              <>
                {/* 臭味强度过滤 */}
                <div>
                  <Text className="text-sm mb-2 block">臭味强度过滤</Text>
                  <Slider
                    range
                    min={1}
                    max={10}
                    value={intensityFilter}
                    onChange={(value) => setIntensityFilter(value as [number, number])}
                    marks={{
                      1: '1',
                      5: '5',
                      10: '10'
                    }}
                  />
                </div>

                {/* 地图样式 */}
                <div>
                  <Text className="text-sm mb-2 block">地图样式</Text>
                  <Select 
                    size="small" 
                    value={mapStyle} 
                    onChange={setMapStyle}
                    className="w-full"
                  >
                    <Option value="standard">标准</Option>
                    <Option value="satellite">卫星</Option>
                    <Option value="dark">暗色</Option>
                  </Select>
                </div>

                {/* 聚合半径 */}
                {(viewMode === 'markers' || viewMode === 'both') && (
                  <div>
                    <Text className="text-sm mb-2 block">聚合半径: {clusterRadius}px</Text>
                    <Slider
                      min={40}
                      max={120}
                      value={clusterRadius}
                      onChange={setClusterRadius}
                    />
                  </div>
                )}

                {/* 热力图半径 */}
                {(viewMode === 'heatmap' || viewMode === 'both') && (
                  <div>
                    <Text className="text-sm mb-2 block">热力图半径: {heatmapRadius}px</Text>
                    <Slider
                      min={15}
                      max={50}
                      value={heatmapRadius}
                      onChange={setHeatmapRadius}
                    />
                  </div>
                )}
              </>
            )}
          </Space>
        </Card>
      </div>
      
      {/* 添加标注提示 */}
      {user && (
        <div className="absolute top-4 right-4 z-[1000]">
          <Card 
            size="small" 
            className="bg-white/90 backdrop-blur-sm border-primary-200"
            bodyStyle={{ padding: '8px 12px' }}
          >
            <div className="flex items-center space-x-2 text-sm">
              <Plus size={16} className="text-primary-500" />
              <Text className="text-gray-600">点击地图添加恶搞标注</Text>
            </div>
          </Card>
        </div>
      )}

      {/* 统计信息 */}
      <div className="absolute bottom-4 left-4 z-[1000]">
        <Card 
          size="small" 
          className="bg-white/90 backdrop-blur-sm border-gray-200"
          bodyStyle={{ padding: '8px 12px' }}
        >
          <Space size={16}>
            <div className="text-center">
              <div className="text-lg font-bold text-primary-600">{filteredAnnotations.length}</div>
              <div className="text-xs text-gray-500">标注总数</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-orange-600">
                {filteredAnnotations.length > 0 
                  ? (filteredAnnotations.reduce((sum, a) => sum + a.smell_intensity, 0) / filteredAnnotations.length).toFixed(1)
                  : '0'
                }
              </div>
              <div className="text-xs text-gray-500">平均强度</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-green-600">
                {filteredAnnotations.reduce((sum, a) => sum + a.views_count, 0)}
              </div>
              <div className="text-xs text-gray-500">总浏览量</div>
            </div>
          </Space>
        </Card>
      </div>
    </div>
  );
};

export default EnhancedMapComponent;