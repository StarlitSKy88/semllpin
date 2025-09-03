import React, { useEffect, useState, useCallback } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMapEvents } from 'react-leaflet';
import { Icon } from 'leaflet';
import { Avatar, Button, Card, Rate, Space, Tag, notification } from 'antd';;
import { 
  Plus, 
  Eye, 
  Heart,
  Share,
  MessageCircle,
  Bell
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { useUIStore } from '../../stores/uiStore';
import CommentModal from '../Social/CommentModal';
import ShareModal from '../Social/ShareModal';
import { mapNotificationService } from '../../services/mapNotificationService';
import useWebSocket from '../../hooks/useWebSocket';
import { notificationSoundService } from '../../services/notificationSoundService';
import { Typography } from 'antd';
import 'leaflet/dist/leaflet.css';

const { Text } = Typography; // Title removed as unused

// 修复 Leaflet 默认图标问题
delete (Icon.Default.prototype as Icon.Default & { _getIconUrl?: () => string })._getIconUrl;
Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// 自定义臭味强度图标
const createSmellIcon = (intensity: number) => {
  const color = intensity >= 8 ? '#ff4d4f' : intensity >= 5 ? '#faad14' : '#52c41a';
  return new Icon({
    iconUrl: `data:image/svg+xml;base64,${btoa(`
      <svg width="25" height="41" viewBox="0 0 25 41" xmlns="http://www.w3.org/2000/svg">
        <path fill="${color}" stroke="#fff" stroke-width="2" d="M12.5 0C5.6 0 0 5.6 0 12.5c0 12.5 12.5 28.5 12.5 28.5s12.5-16 12.5-28.5C25 5.6 19.4 0 12.5 0z"/>
        <circle fill="#fff" cx="12.5" cy="12.5" r="6"/>
        <text x="12.5" y="17" text-anchor="middle" font-size="10" font-weight="bold" fill="${color}">${intensity}</text>
      </svg>
    `)}`,
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
  });
};

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

interface MapComponentProps {
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
    },
  });
  return null;
};

const MapComponent: React.FC<MapComponentProps> = ({
  annotations,
  onAnnotationClick,
  onMapClick,
  center = [39.9042, 116.4074], // 默认北京
  zoom = 13,
  height = '600px'
}) => {
  const { user } = useAuthStore();
  const { openModal } = useUIStore();
  const [commentModalVisible, setCommentModalVisible] = useState(false);
  const [shareModalVisible, setShareModalVisible] = useState(false);
  const [selectedAnnotation, setSelectedAnnotation] = useState<Annotation | null>(null);
  const [mapCenter, setMapCenter] = useState<[number, number]>(center);
  const [mapZoom, setMapZoom] = useState(zoom);
  const [locationTrackingEnabled, setLocationTrackingEnabled] = useState(false);
  
  // WebSocket连接
  const { isConnected } = useWebSocket();

  // 初始化地图通知服务
  const initializeMapNotifications = async () => {
    try {
      const success = await mapNotificationService.initializeLocationTracking();
      setLocationTrackingEnabled(success);
      
      if (success) {
        notification.success({
          message: '地理位置通知已启用',
          description: '您将收到附近活动的实时通知',
          placement: 'topRight'
        });
      }
    } catch (error) {
      console.error('初始化地图通知服务失败:', error);
    }
  };

  useEffect(() => {
    // 初始化地图通知服务
    initializeMapNotifications();
    
    // 监听地图导航事件
    const handleMapNavigate = (event: CustomEvent) => {
      const { latitude, longitude } = event.detail;
      setMapCenter([latitude, longitude]);
      setMapZoom(15);
      
      // 播放导航声音
      notificationSoundService.playNotificationSound('map_notification', 'medium');
    };
    
    window.addEventListener('mapNavigate', handleMapNavigate as EventListener);
    
    return () => {
      window.removeEventListener('mapNavigate', handleMapNavigate as EventListener);
      mapNotificationService.cleanup();
    };
  }, []);

  const handleMarkerClick = useCallback((annotation: Annotation) => {
    if (onAnnotationClick) {
      onAnnotationClick(annotation);
    } else {
      // 默认打开详情模态框
      openModal({ type: 'prank-detail', props: { annotation } });
    }
    
    // 播放标注点击声音
    notificationSoundService.playNotificationSound('info', 'low');
    
    // 创建附近活动通知
    if (locationTrackingEnabled) {
      const mapNotification = mapNotificationService.createNearbyActivityNotification(
        '标注查看',
        { 
          latitude: annotation.latitude, 
          longitude: annotation.longitude,
          address: `${annotation.user.username}的标注` 
        },
        user?.id || 'current_user'
      );
      mapNotificationService.addNotification(mapNotification);
    }
  }, [onAnnotationClick, locationTrackingEnabled, user, openModal]);

  const handleMapClick = useCallback((lat: number, lng: number) => {
    if (onMapClick) {
      onMapClick(lat, lng);
    } else if (user) {
      // 默认打开创建标注模态框
      openModal({ type: 'prank-create' });
    }
    
    // 创建新标注通知
    if (locationTrackingEnabled) {
      const mapNotification = mapNotificationService.createNewAnnotationNotification(
        `temp_${Date.now()}`,
        { latitude: lat, longitude: lng },
        user?.id || 'current_user'
      );
      mapNotificationService.addNotification(mapNotification);
    }
  }, [onMapClick, user, locationTrackingEnabled, openModal]);

  // 打开评论模态框
  const handleOpenComments = useCallback((annotation: Annotation, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setSelectedAnnotation(annotation);
    setCommentModalVisible(true);
  }, []);

  // 关闭评论模态框
  const handleCloseComments = useCallback(() => {
    setCommentModalVisible(false);
    setSelectedAnnotation(null);
  }, []);

  // 打开分享模态框
  const handleOpenShare = useCallback((annotation: Annotation, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setSelectedAnnotation(annotation);
    setShareModalVisible(true);
  }, []);

  // 关闭分享模态框
  const handleCloseShare = useCallback(() => {
    setShareModalVisible(false);
    setSelectedAnnotation(null);
  }, []);

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return '刚刚';
    if (diffInHours < 24) return `${diffInHours}小时前`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}天前`;
    return date.toLocaleDateString('zh-CN');
  };

  // 切换位置跟踪
  const toggleLocationTracking = () => {
    if (locationTrackingEnabled) {
      mapNotificationService.stopLocationTracking();
      setLocationTrackingEnabled(false);
    } else {
      initializeMapNotifications();
    }
  };
  
  return (
    <div style={{ height, width: '100%' }} className="relative">
      {/* 地图控制按钮 */}
      <div className="absolute top-4 left-4 z-[1000] space-y-2">
        <Button
          type={locationTrackingEnabled ? 'primary' : 'default'}
          icon={<Bell size={16} />}
          onClick={toggleLocationTracking}
          className="shadow-lg"
          title={locationTrackingEnabled ? '关闭位置通知' : '开启位置通知'}
        >
          {locationTrackingEnabled ? '通知已开启' : '开启通知'}
        </Button>
        {isConnected && (
          <div className="bg-green-500 text-white px-2 py-1 rounded text-xs">
            实时连接
          </div>
        )}
      </div>
      
      <MapContainer
        center={mapCenter}
        zoom={mapZoom}
        style={{ height: '100%', width: '100%' }}
        className="rounded-lg overflow-hidden"
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        
        <MapClickHandler onMapClick={handleMapClick} />
        
        {annotations.map((annotation) => (
          <Marker
            key={annotation.id}
            position={[annotation.latitude, annotation.longitude]}
            icon={createSmellIcon(annotation.smell_intensity)}
            eventHandlers={{
              click: () => handleMarkerClick(annotation),
            }}
          >
            <Popup className="custom-popup" maxWidth={300}>
              <Card 
                size="small" 
                className="border-0 shadow-none"
                bodyStyle={{ padding: '12px' }}
              >
                <div className="space-y-3">
                  {/* 用户信息 */}
                  <div className="flex items-center space-x-2">
                    <Avatar 
                      size="small" 
                      src={annotation.user.avatar} 
                      className="bg-primary-500"
                    >
                      {annotation.user.username[0]?.toUpperCase()}
                    </Avatar>
                    <div className="flex-1">
                      <Text strong className="text-sm">
                        {annotation.user.username}
                      </Text>
                      <div className="text-xs text-gray-500">
                        {formatTimeAgo(annotation.created_at)}
                      </div>
                    </div>
                  </div>

                  {/* 臭味强度 */}
                  <div className="flex items-center space-x-2">
                    <Text className="text-sm font-medium">臭味强度:</Text>
                    <Rate 
                      disabled 
                      value={annotation.smell_intensity} 
                      count={10} 
                      className="text-xs"
                    />
                    <Tag 
                      color={annotation.smell_intensity >= 8 ? 'red' : 
                             annotation.smell_intensity >= 5 ? 'orange' : 'green'}
                      className="text-xs"
                    >
                      {annotation.smell_intensity}/10
                    </Tag>
                  </div>

                  {/* 描述 */}
                  {annotation.description && (
                    <div>
                      <Text className="text-sm text-gray-700">
                        {annotation.description}
                      </Text>
                    </div>
                  )}

                  {/* 统计信息 */}
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <Space size={12}>
                      <span className="flex items-center space-x-1">
                        <Eye size={14} />
                        <span>{annotation.views_count}</span>
                      </span>
                      <span className="flex items-center space-x-1">
                        <Heart size={14} />
                        <span>{annotation.likes_count}</span>
                      </span>
                    </Space>
                    <Space size={8}>
                      <Button 
                        type="link" 
                        size="small" 
                        icon={<MessageCircle size={14} />}
                        className="p-0 h-auto"
                        onClick={(e) => handleOpenComments(annotation, e)}
                      >
                        评论
                      </Button>
                      <Button 
                         type="link" 
                         size="small" 
                         icon={<Share size={14} />}
                         className="p-0 h-auto"
                         onClick={(e) => handleOpenShare(annotation, e)}
                       >
                         分享
                       </Button>
                    </Space>
                  </div>

                  {/* 查看详情按钮 */}
                  <Button 
                    type="primary" 
                    size="small" 
                    block
                    onClick={() => handleMarkerClick(annotation)}
                  >
                    查看详情
                  </Button>
                </div>
              </Card>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
      
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
      
      {/* 评论模态框 */}
      {selectedAnnotation && (
        <CommentModal
          visible={commentModalVisible}
          onClose={handleCloseComments}
          annotationId={selectedAnnotation.id}
          annotationTitle={selectedAnnotation.description || '臭味标注'}
        />
      )}
      
      {/* 分享模态框 */}
      {selectedAnnotation && shareModalVisible && (
        <ShareModal
          modalId="share-modal"
          annotationId={selectedAnnotation.id}
          annotationTitle={selectedAnnotation.description || '臭味标注'}
          annotationDescription={selectedAnnotation.description}
          onClose={handleCloseShare}
        />
      )}
    </div>
  );
};

export default MapComponent;