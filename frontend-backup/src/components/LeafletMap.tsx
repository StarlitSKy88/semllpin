import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMapEvents } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { EnvironmentOutlined, HeartOutlined, PlusOutlined, UserOutlined, StarOutlined, FilterOutlined, SearchOutlined, CloseOutlined, FullscreenOutlined, CompressOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';

// 修复 Leaflet 默认图标问题
delete (L.Icon.Default.prototype as L.Icon.Default & { _getIconUrl?: () => string })._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
});

interface Annotation {
  id: number;
  title: string;
  description: string;
  intensity: number;
  category: string;
  location: {
    lat: number;
    lng: number;
  };
  likes: number;
  author: string;
  createdAt: string;
  liked?: boolean;
}

interface CreateFormData {
  title: string;
  description: string;
  category: string;
  intensity: number;
}

// 创建自定义图标
const createCustomIcon = (intensity: number) => {
  const getColor = () => {
    if (intensity >= 4) return '#ef4444'; // red
    if (intensity >= 3) return '#f59e0b'; // yellow
    return '#10b981'; // green
  };

  const color = getColor();
  
  return L.divIcon({
    className: 'custom-marker',
    html: `
      <div style="
        background-color: ${color};
        width: 24px;
        height: 24px;
        border-radius: 50%;
        border: 3px solid white;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        color: white;
        font-weight: bold;
      ">
        ${intensity}
      </div>
    `,
    iconSize: [30, 30],
    iconAnchor: [15, 15],
    popupAnchor: [0, -15]
  });
};

// 地图点击事件组件
const MapClickHandler: React.FC<{ 
  onMapClick: (lat: number, lng: number) => void; 
  onMapReady: () => void;
}> = ({ onMapClick, onMapReady }) => {
  const map = useMapEvents({
    click: (e) => {
      onMapClick(e.latlng.lat, e.latlng.lng);
    },
    load: () => {
      console.log('地图加载完成');
      onMapReady();
    }
  });
  
  // 简化的地图设置
  React.useEffect(() => {
    if (map) {
      console.log('地图实例已创建');
      // 确保地图加载完成
      setTimeout(() => {
        onMapReady();
      }, 1000);
    }
  }, [map, onMapReady]);
  
  return null;
};

const LeafletMap: React.FC = () => {
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [loading, setLoading] = useState(true);
  const [mapLoading, setMapLoading] = useState(true);
  const [mapError, setMapError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [formData, setFormData] = useState<CreateFormData>({
    title: '',
    description: '',
    category: '',
    intensity: 0
  });
  const [formErrors, setFormErrors] = useState<Partial<CreateFormData>>({});
  const [selectedLocation, setSelectedLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const navigate = useNavigate();
  const mapRef = useRef<L.Map | null>(null);
  const mapContainerRef = useRef<HTMLDivElement | null>(null);

  // 北京市中心坐标
  const defaultCenter: [number, number] = [39.9042, 116.4074];

  // 地图加载完成回调
  const handleMapReady = () => {
    console.log('handleMapReady called');
    setMapLoading(false);
    setMapError(null);
    setRetryCount(0);
  };



  // 重试加载地图
  const retryMapLoad = () => {
    console.log('重试加载地图');
    setMapLoading(true);
    setMapError(null);
    setRetryCount(prev => prev + 1);
    // 简单重置状态，不强制刷新页面
    setTimeout(() => {
      setMapLoading(false);
    }, 2000);
  };

  useEffect(() => {
    // 检查登录状态
    const token = localStorage.getItem('token');
    setIsLoggedIn(!!token);

  // 模拟获取标注数据
  const fetchAnnotations = async () => {
    setLoading(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 500)); // 减少模拟延迟
        
        // 模拟数据
        const mockData: Annotation[] = [
          {
            id: 1,
            title: '美食街香气',
            description: '这里有一股浓郁的烤肉香味，特别是晚上的时候',
            intensity: 4,
            category: '美食',
            location: { lat: 39.9042, lng: 116.4074 },
            likes: 42,
            author: '美食探索者',
            createdAt: '2024/1/15 18:30:00'
          },
          {
            id: 2,
            title: '花园芳香',
            description: '春天的时候这里花香四溢，非常舒服！',
            intensity: 3,
            category: '自然',
            location: { lat: 39.9100, lng: 116.4200 },
            likes: 23,
            author: '花香爱好者',
            createdAt: '2024/1/15 16:15:00'
          },
          {
            id: 3,
            title: '咖啡店香味',
            description: '路过这家咖啡店总能闻到浓郁的咖啡香',
            intensity: 5,
            category: '饮品',
            location: { lat: 39.8950, lng: 116.3950 },
            likes: 67,
            author: '咖啡控',
            createdAt: '2024/1/15 09:45:00'
          },
          {
            id: 4,
            title: '公园清香',
            description: '早晨跑步时闻到的清新空气',
            intensity: 2,
            category: '自然',
            location: { lat: 39.9200, lng: 116.3900 },
            likes: 15,
            author: '晨跑者',
            createdAt: '2024/1/15 07:20:00'
          }
        ];
        
        setAnnotations(mockData);
      } catch (_error) {
        // 原 showToast DOM 实现已移除，统一使用 sonner 的 toast
        toast.error('获取数据失败');
      } finally {
        setLoading(false);
      }
    };

    fetchAnnotations();
  }, []);

  const handleLike = (id: number) => {
    if (!isLoggedIn) {
      toast.warning('请先登录');
      return;
    }

    setAnnotations(prev => prev.map(annotation => {
      if (annotation.id === id) {
        const isLiked = annotation.liked;
        return {
          ...annotation,
          likes: isLiked ? annotation.likes - 1 : annotation.likes + 1,
          liked: !isLiked
        };
      }
      return annotation;
    }));
  };

  const validateForm = (): boolean => {
    const errors: Partial<CreateFormData> = {};
    
    if (!formData.title.trim()) errors.title = '请输入标题';
    if (!formData.description.trim()) errors.description = '请输入描述';
    if (!formData.category) errors.category = '请选择分类';
    if (formData.intensity === 0) (errors as Record<string, string>).intensity = '请评价强度';
    
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleCreateAnnotation = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!isLoggedIn) {
      toast.warning('请先登录');
      return;
    }

    if (!validateForm()) return;

    if (!selectedLocation) {
      toast.warning('请在地图上选择位置');
      return;
    }

    try {
      // 模拟创建标注
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const newAnnotation: Annotation = {
        id: Date.now(),
        title: formData.title,
        description: formData.description,
        intensity: formData.intensity,
        category: formData.category,
        location: selectedLocation,
        likes: 0,
        author: '当前用户',
        createdAt: new Date().toLocaleString('zh-CN')
      };
      
      setAnnotations(prev => [newAnnotation, ...prev]);
      setShowCreateModal(false);
      setFormData({ title: '', description: '', category: '', intensity: 0 });
      setFormErrors({});
      setSelectedLocation(null);
      toast.success('标注创建成功！');
    } catch (_error) {
      toast.error('创建失败，请重试');
    }
  };

  const handleMapClick = (lat: number, lng: number) => {
    setSelectedLocation({ lat, lng });
    toast.success('位置已选择');
  };

  const toggleFullscreen = () => {
    if (!mapContainerRef.current) return;
    
    if (!isFullscreen) {
      // 进入全屏
      if (mapContainerRef.current.requestFullscreen) {
        mapContainerRef.current.requestFullscreen();
      } else if ((mapContainerRef.current as HTMLElement & { webkitRequestFullscreen?: () => void }).webkitRequestFullscreen) {
        (mapContainerRef.current as unknown as HTMLElement & { webkitRequestFullscreen: () => void }).webkitRequestFullscreen();
      } else if ((mapContainerRef.current as HTMLElement & { msRequestFullscreen?: () => void }).msRequestFullscreen) {
        (mapContainerRef.current as unknown as HTMLElement & { msRequestFullscreen: () => void }).msRequestFullscreen();
      }
    } else {
      // 退出全屏
      if (document.exitFullscreen) {
        document.exitFullscreen();
      } else if ((document as Document & { webkitExitFullscreen?: () => void }).webkitExitFullscreen) {
        (document as Document & { webkitExitFullscreen: () => void }).webkitExitFullscreen();
      } else if ((document as Document & { msExitFullscreen?: () => void }).msExitFullscreen) {
        (document as Document & { msExitFullscreen: () => void }).msExitFullscreen();
      }
    }
  };

  // 监听全屏状态变化
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
      // 全屏状态改变时，重新调整地图大小
      setTimeout(() => {
        if (mapRef.current) {
          mapRef.current.invalidateSize();
        }
      }, 100);
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);
    document.addEventListener('webkitfullscreenchange', handleFullscreenChange);
    document.addEventListener('msfullscreenchange', handleFullscreenChange);

    return () => {
      document.removeEventListener('fullscreenchange', handleFullscreenChange);
      document.removeEventListener('webkitfullscreenchange', handleFullscreenChange);
      document.removeEventListener('msfullscreenchange', handleFullscreenChange);
    };
  }, []);

  const getIntensityColor = (intensity: number) => {
    if (intensity >= 4) return 'bg-error-500';
    if (intensity >= 3) return 'bg-warning-500';
    return 'bg-success-500';
  };

  const getCategoryColor = (category: string) => {
    const colors: { [key: string]: string } = {
      '美食': 'bg-primary-500',
      '自然': 'bg-success-500',
      '饮品': 'bg-accent-500',
      '其他': 'bg-neutral-500'
    };
    return colors[category] || 'bg-neutral-500';
  };

  const filteredAnnotations = annotations.filter(annotation => {
    const matchesSearch = annotation.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         annotation.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || annotation.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  if (!isLoggedIn) {
    return (
      <div className="container flex flex-col items-center justify-center min-h-[60vh] text-center animate-fade-in">
        <div className="card max-w-md animate-scale-in">
          <div className="w-16 h-16 bg-gradient-to-br from-primary-500 to-accent-500 rounded-full flex items-center justify-center mx-auto mb-6 animate-bounce">
            <EnvironmentOutlined className="text-2xl text-white" />
          </div>
          <h2 className="text-2xl font-bold text-primary mb-4 animate-slide-in" style={{animationDelay: '0.2s'}}>请先登录</h2>
          <p className="text-secondary mb-8 animate-fade-in" style={{animationDelay: '0.4s'}}>
            登录后即可查看和创建气味标注，与社区一起探索城市的味道
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center animate-fade-in" style={{animationDelay: '0.6s'}}>
            <button 
              className="btn btn-primary hover-glow"
              onClick={() => navigate('/login')}
            >
              登录
            </button>
            <button 
              className="btn btn-secondary hover-lift"
              onClick={() => navigate('/register')}
            >
              注册
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container py-6 lg:py-8 mt-4 lg:mt-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 sm:gap-4 lg:gap-6 mb-6 sm:mb-8 lg:mb-10 animate-slide-in">
        <div className="text-center sm:text-left flex-1 min-w-0 animate-fade-in" style={{animationDelay: '0.2s'}}>
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-primary mb-2 lg:mb-3 truncate">气味地图</h1>
          <p className="text-base sm:text-lg text-secondary line-clamp-2">发现和分享身边有趣的气味</p>
        </div>
        <div className="flex flex-col sm:flex-row gap-2 sm:gap-3 lg:gap-4 flex-shrink-0">
          <button 
            className="btn btn-primary hover-glow animate-fade-in text-base lg:text-lg px-6 lg:px-8 py-3 lg:py-4"
            onClick={() => setShowCreateModal(true)}
            style={{animationDelay: '0.4s'}}
          >
            <PlusOutlined className="mr-2 text-lg lg:text-xl" />
            创建标注
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 xl:grid-cols-4 gap-4 sm:gap-6 lg:gap-8 xl:gap-10">
        {/* Map Area */}
        <div className="lg:col-span-2 xl:col-span-3 animate-fade-in" style={{animationDelay: '0.6s'}}>
          <div 
            ref={mapContainerRef}
            className={`card p-0 overflow-hidden hover-lift relative ${
              isFullscreen 
                ? 'fixed inset-0 z-[9999] h-screen w-screen rounded-none' 
                : 'h-[400px] sm:h-[500px] md:h-[600px] lg:h-[700px] xl:h-[800px]'
            }`}
          >
            {/* 全屏按钮 */}
            <button
              onClick={toggleFullscreen}
              className="absolute top-2 right-2 sm:top-4 sm:right-4 z-[1000] bg-white/90 backdrop-blur-sm hover:bg-white text-primary-600 p-1.5 sm:p-2 rounded-lg shadow-lg hover:shadow-xl transition-all duration-300 hover-scale"
              title={isFullscreen ? '退出全屏' : '全屏显示'}
            >
              {isFullscreen ? (
                <CompressOutlined className="text-base sm:text-lg" />
              ) : (
                <FullscreenOutlined className="text-base sm:text-lg" />
              )}
            </button>
            
            {/* 地图加载指示器 */}
            {(loading || mapLoading || mapError) && (
              <div className="absolute inset-0 bg-white/80 backdrop-blur-sm flex items-center justify-center z-[1001]">
                <div className="text-center">
                  {mapError ? (
                    <>
                      <div className="text-error-500 text-4xl mb-4">⚠️</div>
                      <p className="text-error-600 font-medium mb-4">
                        地图加载失败: {mapError}
                      </p>
                      {retryCount < 3 && (
                        <button 
                          onClick={retryMapLoad}
                          className="btn btn-primary hover-glow"
                        >
                          重试 ({retryCount}/3)
                        </button>
                      )}
                      {retryCount >= 3 && (
                        <p className="text-secondary text-sm">
                          请检查网络连接或稍后再试
                        </p>
                      )}
                    </>
                  ) : (
                    <>
                      <div className="loading mb-4"></div>
                      <p className="text-primary font-medium">
                        {mapLoading ? '地图初始化中...' : '数据加载中...'}
                      </p>
                      {mapLoading && (
                        <p className="text-secondary text-sm mt-2">
                          首次加载可能需要几秒钟
                        </p>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}
            
            <MapContainer
              center={defaultCenter}
              zoom={13}
              style={{ height: '100%', width: '100%' }}
              ref={mapRef}
              preferCanvas={false}
              zoomControl={true}
              attributionControl={true}
            >
              {/* 使用更可靠的瓦片源 - OpenStreetMap */}
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                subdomains={['a', 'b', 'c']}
                maxZoom={19}
                minZoom={1}
                tileSize={256}
                zoomOffset={0}
                errorTileUrl="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
              />
              
              {/* 地图点击事件处理 */}
              <MapClickHandler onMapClick={handleMapClick} onMapReady={handleMapReady} />
              
              {/* 显示所有标注 */}
              {filteredAnnotations.map((annotation) => (
                <Marker
                  key={annotation.id}
                  position={[annotation.location.lat, annotation.location.lng]}
                  icon={createCustomIcon(annotation.intensity)}
                >
                  <Popup>
                    <div className="p-2 min-w-[200px]">
                      <div className="flex justify-between items-start mb-2">
                        <h4 className="font-medium text-primary text-sm">{annotation.title}</h4>
                        <span className={`px-2 py-1 rounded-full text-xs text-white ${getIntensityColor(annotation.intensity)}`}>
                          强度 {annotation.intensity}
                        </span>
                      </div>
                      
                      <p className="text-xs text-secondary mb-2 leading-relaxed">
                        {annotation.description}
                      </p>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 rounded-full text-xs text-white ${getCategoryColor(annotation.category)}`}>
                            {annotation.category}
                          </span>
                          <span className="text-xs text-secondary flex items-center">
                            <UserOutlined className="mr-1 text-xs" />
                            {annotation.author}
                          </span>
                        </div>
                        
                        <button 
                          onClick={() => handleLike(annotation.id)}
                          className={`flex items-center gap-1 px-2 py-1 rounded-lg transition-all duration-300 ${
                            annotation.liked 
                              ? 'text-error-500 bg-error-50' 
                              : 'text-primary-400 hover:text-error-500 hover:bg-error-50'
                          }`}
                        >
                          <HeartOutlined className={`${annotation.liked ? 'text-error-500' : ''} text-xs`} />
                          <span className="text-xs">{annotation.likes}</span>
                        </button>
                      </div>
                      
                      <div className="text-xs text-secondary mt-2">
                        {annotation.createdAt}
                      </div>
                    </div>
                  </Popup>
                </Marker>
              ))}
              
              {/* 显示选中的位置 */}
              {selectedLocation && (
                <Marker
                  position={[selectedLocation.lat, selectedLocation.lng]}
                  icon={L.divIcon({
                    className: 'selected-location-marker',
                    html: `
                      <div style="
                        background-color: #3b82f6;
                        width: 20px;
                        height: 20px;
                        border-radius: 50%;
                        border: 3px solid white;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                        animation: pulse 2s infinite;
                      "></div>
                    `,
                    iconSize: [26, 26],
                    iconAnchor: [13, 13]
                  })}
                >
                  <Popup>
                    <div className="text-center p-2">
                      <p className="text-sm text-primary font-medium">选中位置</p>
                      <p className="text-xs text-secondary">将在此处创建标注</p>
                    </div>
                  </Popup>
                </Marker>
              )}
            </MapContainer>
          </div>
        </div>

        {/* Annotations Panel */}
        <div className="space-y-4 lg:space-y-6 animate-slide-in" style={{animationDelay: '0.8s'}}>
          {/* Search and Filter */}
          <div className="card hover-lift p-4 sm:p-6 lg:p-8">
            <div className="space-y-4 lg:space-y-6 overflow-y-auto max-h-96">
              {/* Search */}
              <div className="relative animate-fade-in" style={{animationDelay: '1.0s'}}>
                <SearchOutlined className="absolute left-3 lg:left-4 top-1/2 transform -translate-y-1/2 text-primary-400 text-lg lg:text-xl" />
                <input
                  type="text"
                  placeholder="搜索标注..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="form-input pl-10 lg:pl-12 hover-lift transition-all duration-300 text-base lg:text-lg py-3 lg:py-4"
                />
              </div>
              
              {/* Category Filter */}
              <div className="animate-fade-in" style={{animationDelay: '1.2s'}}>
                <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">
                  <FilterOutlined className="mr-1 text-lg lg:text-xl" />
                  分类筛选
                </label>
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="form-input hover-lift transition-all duration-300 text-base lg:text-lg py-3 lg:py-4"
                >
                  <option value="all">全部分类</option>
                  <option value="美食">美食</option>
                  <option value="自然">自然</option>
                  <option value="饮品">饮品</option>
                  <option value="其他">其他</option>
                </select>
              </div>
            </div>
          </div>

          {/* Annotations List */}
          <div className="card p-0 max-h-[500px] lg:max-h-[600px] xl:max-h-[700px] overflow-hidden hover-lift animate-fade-in" style={{animationDelay: '1.4s'}}>
            <div className="p-3 sm:p-4 lg:p-6 border-b border-border">
              <h3 className="font-semibold text-primary text-lg lg:text-xl animate-bounce">附近标注 ({filteredAnnotations.length})</h3>
            </div>
            
            <div className="overflow-y-auto max-h-[400px] lg:max-h-[500px] xl:max-h-[600px]">
              {loading ? (
                <div className="flex items-center justify-center py-12 lg:py-16">
                  <div className="loading"></div>
                </div>
              ) : filteredAnnotations.length === 0 ? (
                <div className="text-center py-12 lg:py-16 text-secondary">
                  <EnvironmentOutlined className="text-4xl lg:text-5xl mb-4 lg:mb-6" />
                  <p className="text-base lg:text-lg">暂无匹配的标注</p>
                </div>
              ) : (
                <div className="space-y-1">
                  {filteredAnnotations.map((annotation, index) => (
                    <div 
                      key={annotation.id}
                      className="p-3 sm:p-4 lg:p-6 hover:bg-surface-hover transition-all duration-300 border-b border-border last:border-b-0 hover-lift animate-fade-in overflow-hidden cursor-pointer"
                      style={{animationDelay: `${1.6 + index * 0.1}s`}}
                      onClick={() => {
                        // 点击标注项时，地图中心移动到该位置
                        if (mapRef.current) {
                          mapRef.current.setView([annotation.location.lat, annotation.location.lng], 15);
                        }
                      }}
                    >
                      <div className="flex justify-between items-start mb-2 lg:mb-3">
                        <h4 className="font-medium text-primary text-base lg:text-lg truncate">{annotation.title}</h4>
                        <span className={`px-2 py-1 lg:px-3 lg:py-2 rounded-full text-xs lg:text-sm text-white ${getIntensityColor(annotation.intensity)}`}>
                          强度 {annotation.intensity}
                        </span>
                      </div>
                      
                      <p className="text-sm lg:text-base text-secondary mb-3 lg:mb-4 leading-relaxed line-clamp-2">
                        {annotation.description}
                      </p>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 lg:gap-3">
                          <span className={`px-2 py-1 lg:px-3 lg:py-2 rounded-full text-xs lg:text-sm text-white ${getCategoryColor(annotation.category)}`}>
                            {annotation.category}
                          </span>
                          <span className="text-xs lg:text-sm text-secondary flex items-center">
                            <UserOutlined className="mr-1 text-sm lg:text-base" />
                            {annotation.author}
                          </span>
                        </div>
                        
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleLike(annotation.id);
                          }}
                          className={`flex items-center gap-1 px-2 py-1 lg:px-3 lg:py-2 rounded-lg transition-all duration-300 hover-scale ${
                            annotation.liked 
                              ? 'text-error-500 bg-error-50 hover:bg-error-100' 
                              : 'text-primary-400 hover:text-error-500 hover:bg-error-50'
                          }`}
                        >
                          <HeartOutlined className={`${annotation.liked ? 'text-error-500' : ''} text-sm lg:text-base`} />
                          <span className="text-sm lg:text-base">{annotation.likes}</span>
                        </button>
                      </div>
                      
                      <div className="text-xs lg:text-sm text-secondary mt-2 lg:mt-3">
                        {annotation.createdAt}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Create Annotation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[10000] p-2 sm:p-4 animate-fade-in">
          <div className="card max-w-md lg:max-w-lg xl:max-w-xl w-full max-h-[90vh] overflow-y-auto animate-scale-in">
            <div className="flex justify-between items-center mb-6 lg:mb-8">
              <h2 className="text-xl lg:text-2xl xl:text-3xl font-bold text-primary animate-slide-in">创建气味标注</h2>
              <button 
                onClick={() => {
                  setShowCreateModal(false);
                  setSelectedLocation(null);
                }}
                className="text-primary-400 hover:text-primary-300 p-1 lg:p-2 hover-scale transition-all duration-300"
              >
                <CloseOutlined className="text-lg lg:text-xl" />
              </button>
            </div>
            
            <div className="mb-4 p-3 bg-primary-50 rounded-lg animate-fade-in">
              <p className="text-sm text-primary">
                💡 提示：{selectedLocation ? '已选择位置，可以创建标注' : '请先在地图上点击选择位置'}
              </p>
            </div>
            
            <form onSubmit={handleCreateAnnotation} className="space-y-4 lg:space-y-6">
              <div className="animate-fade-in" style={{animationDelay: '0.2s'}}>
                <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">标题</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                  className={`form-input hover-lift transition-all duration-300 text-base lg:text-lg py-3 lg:py-4 ${formErrors.title ? 'border-error-500' : ''}`}
                  placeholder="给这个气味起个名字"
                />
                {formErrors.title && <p className="text-error-400 text-sm lg:text-base mt-1">{formErrors.title}</p>}
              </div>
              
              <div className="animate-fade-in" style={{animationDelay: '0.4s'}}>
                <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">描述</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  className={`form-input hover-lift transition-all duration-300 text-base lg:text-lg py-3 lg:py-4 ${formErrors.description ? 'border-error-500' : ''}`}
                  rows={3}
                  placeholder="描述一下这个气味的特点"
                />
                {formErrors.description && <p className="text-error-400 text-sm lg:text-base mt-1">{formErrors.description}</p>}
              </div>
              
              <div className="animate-fade-in" style={{animationDelay: '0.6s'}}>
                <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">分类</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData(prev => ({ ...prev, category: e.target.value }))}
                  className={`form-input hover-lift transition-all duration-300 text-base lg:text-lg py-3 lg:py-4 ${formErrors.category ? 'border-error-500' : ''}`}
                >
                  <option value="">选择气味分类</option>
                  <option value="美食">美食</option>
                  <option value="自然">自然</option>
                  <option value="饮品">饮品</option>
                  <option value="其他">其他</option>
                </select>
                {formErrors.category && <p className="text-error-400 text-sm lg:text-base mt-1">{formErrors.category}</p>}
              </div>
              
              <div className="animate-fade-in" style={{animationDelay: '0.8s'}}>
                <label className="block text-sm lg:text-base font-medium text-primary mb-2 lg:mb-3">强度评价</label>
                <div className="flex gap-1 lg:gap-2">
                  {[1, 2, 3, 4, 5].map(star => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, intensity: star }))}
                      className={`p-1 lg:p-2 transition-all duration-300 hover-scale ${
                        star <= formData.intensity 
                          ? 'text-warning-500' 
                          : 'text-neutral-300 hover:text-warning-400'
                      }`}
                    >
                      <StarOutlined className="text-xl lg:text-2xl" />
                    </button>
                  ))}
                </div>
                {formErrors.intensity && <p className="text-error-400 text-sm lg:text-base mt-1">{formErrors.intensity}</p>}
              </div>
              
              <div className="flex gap-3 lg:gap-4 pt-4 lg:pt-6 animate-fade-in" style={{animationDelay: '1.0s'}}>
                <button 
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false);
                    setSelectedLocation(null);
                  }}
                  className="btn btn-secondary flex-1 hover-lift text-base lg:text-lg py-3 lg:py-4"
                >
                  取消
                </button>
                <button 
                  type="submit"
                  disabled={!selectedLocation}
                  className={`btn flex-1 text-base lg:text-lg py-3 lg:py-4 ${
                    selectedLocation 
                      ? 'btn-primary hover-glow' 
                      : 'btn-secondary opacity-50 cursor-not-allowed'
                  }`}
                >
                  创建
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      
      {/* 添加自定义样式 */}
      <style>{`
        @keyframes pulse {
          0%, 100% {
            transform: scale(1);
            opacity: 1;
          }
          50% {
            transform: scale(1.1);
            opacity: 0.7;
          }
        }
        
        .leaflet-popup-content-wrapper {
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .leaflet-popup-tip {
          background: white;
        }
      `}</style>
    </div>
  );
};

export default LeafletMap;