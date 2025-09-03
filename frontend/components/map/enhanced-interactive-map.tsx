'use client';

import React, { useRef, useCallback, useMemo, useState, useEffect } from 'react';
import { motion, AnimatePresence, useSpring, useTransform, PanInfo, useMotionValue } from 'framer-motion';
import { MapPin, Navigation, Zap, Eye, Target, Layers, Plus, Gift, Star, Award } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface Annotation {
  id: string;
  title: string;
  description: string;
  latitude: number;
  longitude: number;
  rewardAmount: number;
  isDiscovered?: boolean;
  category?: string;
  images?: string[];
  createdAt: string;
  author?: string;
}

interface InteractiveMapProps {
  annotations?: Annotation[];
  center?: [number, number];
  zoom?: number;
  onAnnotationClick?: (annotation: Annotation) => void;
  onMapClick?: (lat: number, lng: number) => void;
  onZoomChange?: (zoom: number) => void;
  onCenterChange?: (center: [number, number]) => void;
  userLocation?: [number, number];
  className?: string;
  showHeatmap?: boolean;
  showClusters?: boolean;
  theme?: 'light' | 'dark' | 'cyberpunk';
}

interface MapMarkerProps {
  annotation: Annotation;
  position: { x: number; y: number };
  isVisible: boolean;
  onClick: () => void;
  isInCluster?: boolean;
  clusterSize?: number;
}

const MapMarker: React.FC<MapMarkerProps> = ({
  annotation,
  position,
  isVisible,
  onClick,
  isInCluster = false,
  clusterSize = 1
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const [ripple, setRipple] = useState(false);

  const getMarkerColor = (reward: number, category?: string) => {
    if (reward >= 20) return 'from-red-500 to-pink-500';
    if (reward >= 10) return 'from-blue-500 to-cyan-500';
    if (reward >= 5) return 'from-yellow-500 to-orange-500';
    return 'from-green-500 to-emerald-500';
  };

  const handleClick = () => {
    setRipple(true);
    setTimeout(() => setRipple(false), 600);
    onClick();
  };

  if (!isVisible) return null;

  return (
    <motion.div
      initial={{ scale: 0, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      exit={{ scale: 0, opacity: 0 }}
      whileHover={{ scale: 1.2, z: 50 }}
      whileTap={{ scale: 0.95 }}
      className="absolute cursor-pointer transform -translate-x-1/2 -translate-y-1/2 z-10"
      style={{
        left: position.x,
        top: position.y,
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={handleClick}
      transition={{
        type: "spring",
        stiffness: 300,
        damping: 20
      }}
    >
      {/* Main marker */}
      <div className="relative">
        <div 
          className={`
            relative w-8 h-8 rounded-full shadow-lg flex items-center justify-center
            bg-gradient-to-r ${getMarkerColor(annotation.rewardAmount, annotation.category)}
            border-2 border-white/80 backdrop-blur-sm
            transition-all duration-300 ease-out
            ${isHovered ? 'shadow-xl' : 'shadow-md'}
          `}
        >
          {annotation.isDiscovered ? (
            <Gift className="w-4 h-4 text-white" />
          ) : (
            <MapPin className="w-4 h-4 text-white" />
          )}
          
          {/* Pulsing ring animation */}
          <div className="absolute inset-0 rounded-full border-2 border-white/40 animate-ping" />
          
          {/* Ripple effect on click */}
          {ripple && (
            <div className="absolute inset-0 rounded-full bg-white/30 animate-ping" />
          )}
          
          {/* Reward indicator */}
          <div className="absolute -top-2 -right-2 bg-yellow-400 text-yellow-900 text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center shadow-sm">
            ¥{annotation.rewardAmount}
          </div>
        </div>

        {/* Hover tooltip */}
        <AnimatePresence>
          {isHovered && (
            <motion.div
              initial={{ opacity: 0, y: 10, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 10, scale: 0.9 }}
              className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 z-20"
              transition={{ duration: 0.15 }}
            >
              <div className="bg-black/90 backdrop-blur-sm text-white px-3 py-2 rounded-xl text-sm whitespace-nowrap shadow-lg border border-white/10">
                <div className="font-semibold">{annotation.title}</div>
                <div className="text-xs text-white/70 flex items-center gap-1 mt-1">
                  <Zap className="w-3 h-3" />
                  ¥{annotation.rewardAmount} 奖励
                  {annotation.isDiscovered && <Eye className="w-3 h-3 text-green-400" />}
                </div>
                <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-2 h-2 bg-black/90 rotate-45" />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Discovery glow effect */}
      {!annotation.isDiscovered && (
        <div className="absolute inset-0 rounded-full bg-blue-400/20 blur-lg animate-pulse-slow" />
      )}
    </motion.div>
  );
};

// Mock data with enhanced structure
const mockAnnotations: Annotation[] = [
  {
    id: "1",
    title: "天安门广场的秘密",
    description: "据说这里埋藏着一个巨大的宝藏，但只有在满月的夜晚才能看到！",
    latitude: 39.9042,
    longitude: 116.4074,
    rewardAmount: 50,
    author: "探险家小王",
    isDiscovered: false,
    category: "historical",
    createdAt: new Date().toISOString()
  },
  {
    id: "2",
    title: "故宫里的猫咪王国",
    description: "传说故宫里的猫咪们有自己的王国，每天晚上都会开会讨论如何统治紫禁城！",
    latitude: 39.9163,
    longitude: 116.3972,
    rewardAmount: 30,
    author: "猫奴小李",
    isDiscovered: true,
    category: "funny",
    createdAt: new Date().toISOString()
  },
  {
    id: "3",
    title: "天坛的回音壁真相",
    description: "回音壁其实是古代的微信群聊，皇帝用它来和大臣们开视频会议！",
    latitude: 39.8848,
    longitude: 116.4199,
    rewardAmount: 25,
    author: "历史达人",
    isDiscovered: false,
    category: "weird",
    createdAt: new Date().toISOString()
  }
];

const EnhancedInteractiveMap: React.FC<InteractiveMapProps> = ({
  annotations = mockAnnotations,
  center = [39.9042, 116.4074],
  zoom = 12,
  onAnnotationClick,
  onMapClick,
  onZoomChange,
  onCenterChange,
  userLocation,
  className = "",
  showHeatmap = false,
  showClusters = true,
  theme = 'cyberpunk'
}) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const [isPanning, setIsPanning] = useState(false);
  const [viewBounds, setViewBounds] = useState({ width: 0, height: 0 });
  const [mapCenter, setMapCenter] = useState(center);
  const [currentZoom, setCurrentZoom] = useState(zoom);
  const [selectedAnnotation, setSelectedAnnotation] = useState<Annotation | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [currentUserLocation, setCurrentUserLocation] = useState<[number, number] | null>(userLocation || null);

  // Spring animations for smooth interactions
  const springConfig = { tension: 300, friction: 30 };
  const x = useSpring(0, springConfig);
  const y = useSpring(0, springConfig);
  const scale = useSpring(1, springConfig);

  // Get user location on mount
  useEffect(() => {
    if (!currentUserLocation && navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const location: [number, number] = [
            position.coords.latitude,
            position.coords.longitude
          ];
          setCurrentUserLocation(location);
        },
        () => {
          // Default to Beijing if location access is denied
          setCurrentUserLocation([39.9042, 116.4074]);
        }
      );
    }
  }, [currentUserLocation]);

  // Update bounds when component mounts
  useEffect(() => {
    if (mapRef.current) {
      const rect = mapRef.current.getBoundingClientRect();
      setViewBounds({ width: rect.width, height: rect.height });
    }
  }, []);

  // Convert lat/lng to screen coordinates
  const coordinateToPixel = useCallback((lat: number, lng: number): { x: number, y: number } => {
    if (!viewBounds.width || !viewBounds.height) return { x: 0, y: 0 };

    const zoomFactor = Math.pow(2, currentZoom - 10);
    const x = ((lng - mapCenter[1]) * zoomFactor * 1000) + viewBounds.width / 2;
    const y = ((mapCenter[0] - lat) * zoomFactor * 1000) + viewBounds.height / 2;

    return { x, y };
  }, [mapCenter, currentZoom, viewBounds]);

  // Convert screen coordinates to lat/lng
  const pixelToCoordinate = useCallback((x: number, y: number): [number, number] => {
    if (!viewBounds.width || !viewBounds.height) return [0, 0];

    const zoomFactor = Math.pow(2, currentZoom - 10);
    const lng = mapCenter[1] + (x - viewBounds.width / 2) / (zoomFactor * 1000);
    const lat = mapCenter[0] - (y - viewBounds.height / 2) / (zoomFactor * 1000);

    return [lat, lng];
  }, [mapCenter, currentZoom, viewBounds]);

  // Handle map click
  const handleMapClick = useCallback((event: React.MouseEvent) => {
    if (isPanning) return;

    const rect = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const [lat, lng] = pixelToCoordinate(x, y);
    
    onMapClick?.(lat, lng);
  }, [isPanning, pixelToCoordinate, onMapClick]);

  // Handle pan gesture
  const handlePan = useCallback((event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    const zoomFactor = Math.pow(2, currentZoom - 10);
    const deltaLat = info.delta.y / (zoomFactor * 1000);
    const deltaLng = -info.delta.x / (zoomFactor * 1000);
    
    const newCenter: [number, number] = [
      mapCenter[0] + deltaLat,
      mapCenter[1] + deltaLng
    ];
    
    setMapCenter(newCenter);
    onCenterChange?.(newCenter);
  }, [mapCenter, currentZoom, onCenterChange]);

  // Handle zoom
  const handleZoom = useCallback((delta: number) => {
    const newZoom = Math.max(1, Math.min(20, currentZoom + delta));
    setCurrentZoom(newZoom);
    onZoomChange?.(newZoom);
  }, [currentZoom, onZoomChange]);

  // Handle wheel zoom
  const handleWheel = useCallback((event: React.WheelEvent) => {
    event.preventDefault();
    const delta = event.deltaY > 0 ? -0.5 : 0.5;
    handleZoom(delta);
  }, [handleZoom]);

  // Filter visible annotations
  const visibleAnnotations = useMemo(() => {
    return annotations.filter(annotation => {
      const pos = coordinateToPixel(annotation.latitude, annotation.longitude);
      return pos.x >= -50 && pos.x <= viewBounds.width + 50 && 
             pos.y >= -50 && pos.y <= viewBounds.height + 50;
    });
  }, [annotations, coordinateToPixel, viewBounds]);

  // Handle annotation discovery
  const handleDiscoverAnnotation = (annotation: Annotation) => {
    if (!currentUserLocation) return;
    
    // Calculate distance (simplified version)
    const distance = Math.sqrt(
      Math.pow(annotation.latitude - currentUserLocation[0], 2) + 
      Math.pow(annotation.longitude - currentUserLocation[1], 2)
    ) * 111000; // Convert to meters

    if (distance < 100) { // Within 100 meters
      setSelectedAnnotation({...annotation, isDiscovered: true});
      alert(`恭喜！您发现了标注"${annotation.title}"并获得¥${annotation.rewardAmount}奖励！`);
    } else {
      alert(`您距离标注还有${Math.round(distance)}米，请靠近后再试！`);
    }
  };

  const themeClasses = {
    light: 'bg-gradient-to-br from-blue-50 to-indigo-100',
    dark: 'bg-gradient-to-br from-gray-900 to-black',
    cyberpunk: 'bg-gradient-to-br from-purple-900 via-blue-900 to-black'
  };

  return (
    <div className={`relative overflow-hidden rounded-2xl ${className} w-full h-[300px] sm:h-[400px] md:h-[500px] lg:h-[600px]`}>
      {/* Map container */}
      <motion.div
        ref={mapRef}
        className={`relative h-full cursor-crosshair select-none ${themeClasses[theme]}`}
        onWheel={handleWheel}
        onClick={handleMapClick}
        drag
        dragConstraints={{ left: 0, right: 0, top: 0, bottom: 0 }}
        onDragStart={() => setIsPanning(true)}
        onDragEnd={() => setTimeout(() => setIsPanning(false), 100)}
        onDrag={handlePan}
        whileDrag={{ cursor: 'grabbing' }}
      >
        {/* Enhanced grid background */}
        <div className="absolute inset-0 opacity-20">
          <div 
            className="w-full h-full" 
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23ffffff' fill-opacity='0.15'%3E%3Cpath d='M0 0h40v40H0V0zm20 20h20v20H20V20z'/%3E%3C/g%3E%3C/svg%3E")`,
              backgroundSize: `${40 * Math.pow(2, currentZoom - 10)}px`
            }}
          />
        </div>

        {/* Heatmap layer */}
        {showHeatmap && (
          <div className="absolute inset-0 pointer-events-none">
            {visibleAnnotations.map((annotation) => {
              const pos = coordinateToPixel(annotation.latitude, annotation.longitude);
              const intensity = annotation.rewardAmount / 50;
              return (
                <motion.div
                  key={`heat-${annotation.id}`}
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: intensity * 0.4, scale: 1 }}
                  className="absolute rounded-full"
                  style={{
                    left: pos.x - 50,
                    top: pos.y - 50,
                    width: 100,
                    height: 100,
                    background: `radial-gradient(circle, rgba(255,100,100,${intensity}) 0%, transparent 70%)`,
                    filter: 'blur(20px)'
                  }}
                />
              );
            })}
          </div>
        )}

        {/* Annotation markers */}
        <AnimatePresence>
          {visibleAnnotations.map((annotation, index) => {
            const position = coordinateToPixel(annotation.latitude, annotation.longitude);
            return (
              <MapMarker
                key={annotation.id}
                annotation={annotation}
                position={position}
                isVisible={true}
                onClick={() => {
                  setSelectedAnnotation(annotation);
                  onAnnotationClick?.(annotation);
                }}
              />
            );
          })}
        </AnimatePresence>

        {/* User location marker with enhanced animation */}
        {currentUserLocation && (
          <motion.div
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="absolute transform -translate-x-1/2 -translate-y-1/2 z-20"
            style={{
              left: coordinateToPixel(currentUserLocation[0], currentUserLocation[1]).x,
              top: coordinateToPixel(currentUserLocation[0], currentUserLocation[1]).y,
            }}
          >
            <div className="relative">
              <motion.div 
                className="w-6 h-6 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full border-2 border-white shadow-lg"
                animate={{ 
                  boxShadow: [
                    "0 0 0 0 rgba(59, 130, 246, 0.7)",
                    "0 0 0 10px rgba(59, 130, 246, 0)",
                  ] 
                }}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
              >
                <Navigation className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-3 h-3 text-white" />
              </motion.div>
              <div className="absolute -top-8 left-1/2 transform -translate-x-1/2 text-xs text-white bg-black/70 px-2 py-1 rounded whitespace-nowrap">
                您的位置
              </div>
            </div>
          </motion.div>
        )}

        {/* Enhanced zoom and control buttons */}
        <motion.div 
          className="absolute top-4 right-4 flex flex-col gap-2 z-30"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Button
            size="sm"
            variant="outline"
            className="w-10 h-10 p-0 bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20 transition-all duration-200"
            onClick={() => handleZoom(1)}
          >
            +
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="w-10 h-10 p-0 bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20 transition-all duration-200"
            onClick={() => handleZoom(-1)}
          >
            −
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="w-10 h-10 p-0 bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20 transition-all duration-200"
            onClick={() => {
              if (currentUserLocation) {
                setMapCenter(currentUserLocation);
                onCenterChange?.(currentUserLocation);
              }
            }}
          >
            <Target className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="w-10 h-10 p-0 bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20 transition-all duration-200"
            onClick={() => setShowCreateForm(true)}
          >
            <Plus className="w-4 h-4" />
          </Button>
        </motion.div>

        {/* Enhanced map info overlay */}
        <motion.div 
          className="absolute bottom-4 left-4 flex items-center gap-2 z-30"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Badge variant="outline" className="bg-white/10 backdrop-blur-md border-white/20 text-white">
            缩放: {currentZoom.toFixed(1)}x
          </Badge>
          <Badge variant="outline" className="bg-white/10 backdrop-blur-md border-white/20 text-white">
            标注: {visibleAnnotations.length}
          </Badge>
          <Badge variant="outline" className="bg-white/10 backdrop-blur-md border-white/20 text-white">
            <Award className="w-3 h-3 mr-1" />
            发现: {visibleAnnotations.filter(a => a.isDiscovered).length}
          </Badge>
        </motion.div>
      </motion.div>

      {/* Enhanced annotation detail modal */}
      <AnimatePresence>
        {selectedAnnotation && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50"
            onClick={() => setSelectedAnnotation(null)}
          >
            <motion.div 
              initial={{ opacity: 0, scale: 0.8, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8, y: 20 }}
              className="bg-white/10 backdrop-blur-xl text-white p-6 rounded-2xl max-w-md w-full border border-white/20 shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start justify-between mb-4">
                <h3 className="text-xl font-bold pr-4">{selectedAnnotation.title}</h3>
                <Badge className={`${selectedAnnotation.isDiscovered ? 'bg-green-500' : 'bg-orange-500'} text-white`}>
                  {selectedAnnotation.isDiscovered ? '已发现' : '未发现'}
                </Badge>
              </div>
              
              <p className="text-white/80 mb-4 leading-relaxed">{selectedAnnotation.description}</p>
              
              <div className="flex justify-between items-center text-sm text-white/60 mb-4">
                <span>创建者: {selectedAnnotation.author}</span>
                <div className="flex items-center gap-1">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  <span className="font-semibold text-yellow-400">¥{selectedAnnotation.rewardAmount}</span>
                </div>
              </div>
              
              <div className="flex gap-3">
                {!selectedAnnotation.isDiscovered && (
                  <Button
                    onClick={() => handleDiscoverAnnotation(selectedAnnotation)}
                    className="flex-1 bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white"
                  >
                    <Gift className="w-4 h-4 mr-2" />
                    发现奖励
                  </Button>
                )}
                <Button
                  onClick={() => setSelectedAnnotation(null)}
                  variant="outline"
                  className="flex-1 bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20"
                >
                  关闭
                </Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Enhanced create form modal */}
      <AnimatePresence>
        {showCreateForm && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50"
            onClick={() => setShowCreateForm(false)}
          >
            <motion.div 
              initial={{ opacity: 0, scale: 0.8, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8, y: 20 }}
              className="bg-white/10 backdrop-blur-xl text-white p-6 rounded-2xl max-w-md w-full border border-white/20 shadow-2xl max-h-[90vh] overflow-y-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-xl font-bold mb-4">创建新标注</h3>
              <div className="space-y-4">
                <input
                  type="text"
                  placeholder="标注标题"
                  className="w-full p-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-xl text-white placeholder-white/60 focus:outline-none focus:border-white/40"
                />
                <textarea
                  placeholder="标注内容（请发挥您的创意！）"
                  rows={3}
                  className="w-full p-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-xl text-white placeholder-white/60 focus:outline-none focus:border-white/40 resize-none"
                />
                <input
                  type="number"
                  placeholder="奖励金额（¥）"
                  className="w-full p-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-xl text-white placeholder-white/60 focus:outline-none focus:border-white/40"
                />
              </div>
              <div className="flex gap-3 mt-6">
                <Button
                  onClick={() => {
                    alert('标注创建成功！等待审核通过后将显示在地图上。');
                    setShowCreateForm(false);
                  }}
                  className="flex-1 bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-white"
                >
                  创建标注
                </Button>
                <Button
                  onClick={() => setShowCreateForm(false)}
                  variant="outline"
                  className="flex-1 bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20"
                >
                  取消
                </Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export { EnhancedInteractiveMap };
export default EnhancedInteractiveMap;