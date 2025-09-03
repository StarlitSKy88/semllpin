/**
 * 地理围栏地图组件
 * 显示用户位置和附近地理围栏的可视化地图
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useEffect, useRef, useState } from 'react';
import { Target, Info } from 'lucide-react';

interface Location {
  longitude: number;
  latitude: number;
  accuracy?: number | null;
  timestamp?: number;
}

interface Geofence {
  id: string;
  name: string;
  description?: string;
  longitude: number;
  latitude: number;
  radius: number;
  rewardType: string;
  baseReward: number;
  distance?: number;
  isActive: boolean;
  metadata?: any;
}

interface GeofenceMapProps {
  center: [number, number]; // [longitude, latitude]
  geofences: Geofence[];
  userLocation?: Location;
  className?: string;
  onGeofenceClick?: (geofence: Geofence) => void;
  showUserAccuracy?: boolean;
  interactive?: boolean;
}

const GeofenceMap: React.FC<GeofenceMapProps> = ({
  center,
  geofences,
  userLocation,
  className = '',
  onGeofenceClick,
  showUserAccuracy = true,
  interactive = true
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedGeofence, setSelectedGeofence] = useState<Geofence | null>(null);
  const [mapScale, setMapScale] = useState(1);
  const [mapOffset, setMapOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [lastMousePos, setLastMousePos] = useState({ x: 0, y: 0 });

  // 地图配置
  const MAP_SIZE = 400;
  const DEFAULT_ZOOM = 0.001; // 约100米的视野范围
  const MIN_ZOOM = 0.0001;
  const MAX_ZOOM = 0.01;

  // 坐标转换：经纬度到画布坐标
  const coordToCanvas = (longitude: number, latitude: number) => {
    const x = ((longitude - center[0]) / DEFAULT_ZOOM) * mapScale + MAP_SIZE / 2 + mapOffset.x;
    const y = ((center[1] - latitude) / DEFAULT_ZOOM) * mapScale + MAP_SIZE / 2 + mapOffset.y;
    return { x, y };
  };



  // 距离转换：米到画布像素
  const metersToPixels = (meters: number) => {
    return (meters / (DEFAULT_ZOOM * 111000)) * mapScale; // 1度约等于111km
  };

  // 绘制地图
  const drawMap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // 清空画布
    ctx.clearRect(0, 0, MAP_SIZE, MAP_SIZE);

    // 绘制背景网格
    ctx.strokeStyle = '#f0f0f0';
    ctx.lineWidth = 1;
    const gridSize = 50;
    for (let i = 0; i <= MAP_SIZE; i += gridSize) {
      ctx.beginPath();
      ctx.moveTo(i, 0);
      ctx.lineTo(i, MAP_SIZE);
      ctx.stroke();
      
      ctx.beginPath();
      ctx.moveTo(0, i);
      ctx.lineTo(MAP_SIZE, i);
      ctx.stroke();
    }

    // 绘制地理围栏
    geofences.forEach((geofence) => {
      const pos = coordToCanvas(geofence.longitude, geofence.latitude);
      const radiusPixels = metersToPixels(geofence.radius);

      // 绘制围栏圆圈
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radiusPixels, 0, 2 * Math.PI);
      
      // 根据奖励类型设置颜色
      let fillColor, strokeColor;
      switch (geofence.rewardType) {
        case 'discovery':
          fillColor = 'rgba(255, 193, 7, 0.2)';
          strokeColor = '#ffc107';
          break;
        case 'checkin':
          fillColor = 'rgba(0, 123, 255, 0.2)';
          strokeColor = '#007bff';
          break;
        case 'duration':
          fillColor = 'rgba(40, 167, 69, 0.2)';
          strokeColor = '#28a745';
          break;
        case 'social':
          fillColor = 'rgba(108, 117, 125, 0.2)';
          strokeColor = '#6c757d';
          break;
        default:
          fillColor = 'rgba(108, 117, 125, 0.2)';
          strokeColor = '#6c757d';
      }

      ctx.fillStyle = fillColor;
      ctx.fill();
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = selectedGeofence?.id === geofence.id ? 3 : 2;
      ctx.stroke();

      // 绘制围栏中心点
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 4, 0, 2 * Math.PI);
      ctx.fillStyle = strokeColor;
      ctx.fill();

      // 绘制围栏名称
      ctx.fillStyle = '#333';
      ctx.font = '12px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(geofence.name, pos.x, pos.y - radiusPixels - 10);

      // 绘制奖励信息
      ctx.font = '10px Arial';
      ctx.fillStyle = '#666';
      ctx.fillText(`${geofence.baseReward}分`, pos.x, pos.y + radiusPixels + 15);
    });

    // 绘制用户位置
    if (userLocation) {
      const userPos = coordToCanvas(userLocation.longitude, userLocation.latitude);
      
      // 绘制精度圆圈
      if (showUserAccuracy && userLocation.accuracy) {
        const accuracyPixels = metersToPixels(userLocation.accuracy);
        ctx.beginPath();
        ctx.arc(userPos.x, userPos.y, accuracyPixels, 0, 2 * Math.PI);
        ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
        ctx.fill();
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 1;
        ctx.setLineDash([5, 5]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // 绘制用户位置点
      ctx.beginPath();
      ctx.arc(userPos.x, userPos.y, 8, 0, 2 * Math.PI);
      ctx.fillStyle = '#3b82f6';
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2;
      ctx.stroke();

      // 绘制用户位置脉冲动画
      const pulseRadius = 12 + Math.sin(Date.now() / 200) * 4;
      ctx.beginPath();
      ctx.arc(userPos.x, userPos.y, pulseRadius, 0, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(59, 130, 246, 0.5)';
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // 绘制比例尺
    const scaleLength = 100; // 像素
    const scaleMeters = Math.round((scaleLength / mapScale) * DEFAULT_ZOOM * 111000);
    ctx.fillStyle = '#333';
    ctx.font = '12px Arial';
    ctx.textAlign = 'left';
    ctx.fillText(`${scaleMeters}m`, 10, MAP_SIZE - 30);
    
    ctx.strokeStyle = '#333';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(10, MAP_SIZE - 20);
    ctx.lineTo(10 + scaleLength, MAP_SIZE - 20);
    ctx.stroke();
  };

  // 处理鼠标点击
  const handleCanvasClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!interactive) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // 检查是否点击了地理围栏
    for (const geofence of geofences) {
      const pos = coordToCanvas(geofence.longitude, geofence.latitude);
      const radiusPixels = metersToPixels(geofence.radius);
      const distance = Math.sqrt((x - pos.x) ** 2 + (y - pos.y) ** 2);
      
      if (distance <= radiusPixels) {
        setSelectedGeofence(geofence);
        onGeofenceClick?.(geofence);
        return;
      }
    }

    // 如果没有点击围栏，清除选择
    setSelectedGeofence(null);
  };

  // 处理鼠标拖拽
  const handleMouseDown = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!interactive) return;
    setIsDragging(true);
    setLastMousePos({ x: event.clientX, y: event.clientY });
  };

  const handleMouseMove = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!interactive || !isDragging) return;
    
    const deltaX = event.clientX - lastMousePos.x;
    const deltaY = event.clientY - lastMousePos.y;
    
    setMapOffset(prev => ({
      x: prev.x + deltaX,
      y: prev.y + deltaY
    }));
    
    setLastMousePos({ x: event.clientX, y: event.clientY });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  // 处理缩放
  const handleWheel = (event: React.WheelEvent<HTMLCanvasElement>) => {
    if (!interactive) return;
    
    event.preventDefault();
    const zoomFactor = event.deltaY > 0 ? 0.9 : 1.1;
    const newScale = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, mapScale * zoomFactor));
    setMapScale(newScale);
  };

  // 重置地图视图
  const resetView = () => {
    setMapScale(1);
    setMapOffset({ x: 0, y: 0 });
    setSelectedGeofence(null);
  };

  // 绘制地图
  useEffect(() => {
    drawMap();
  }, [center, geofences, userLocation, mapScale, mapOffset, selectedGeofence]);

  // 动画循环（用于用户位置脉冲效果）
  useEffect(() => {
    const animate = () => {
      drawMap();
      requestAnimationFrame(animate);
    };
    const animationId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationId);
  }, []);

  return (
    <div className={`relative bg-gray-100 rounded-lg overflow-hidden ${className}`}>
      {/* 地图画布 */}
      <canvas
        ref={canvasRef}
        width={MAP_SIZE}
        height={MAP_SIZE}
        className="w-full h-full cursor-pointer"
        onClick={handleCanvasClick}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      />

      {/* 地图控制按钮 */}
      {interactive && (
        <div className="absolute top-2 right-2 flex flex-col space-y-1">
          <button
            onClick={() => setMapScale(prev => Math.min(MAX_ZOOM, prev * 1.2))}
            className="bg-white hover:bg-gray-50 border border-gray-300 rounded p-1 shadow-sm"
            title="放大"
          >
            <span className="text-sm font-bold">+</span>
          </button>
          <button
            onClick={() => setMapScale(prev => Math.max(MIN_ZOOM, prev * 0.8))}
            className="bg-white hover:bg-gray-50 border border-gray-300 rounded p-1 shadow-sm"
            title="缩小"
          >
            <span className="text-sm font-bold">−</span>
          </button>
          <button
            onClick={resetView}
            className="bg-white hover:bg-gray-50 border border-gray-300 rounded p-1 shadow-sm"
            title="重置视图"
          >
            <Target className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* 图例 */}
      <div className="absolute bottom-2 left-2 bg-white bg-opacity-90 rounded p-2 text-xs space-y-1">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
          <span>用户位置</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 border-2 border-yellow-500 rounded-full"></div>
          <span>发现奖励</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 border-2 border-blue-500 rounded-full"></div>
          <span>签到奖励</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 border-2 border-green-500 rounded-full"></div>
          <span>停留奖励</span>
        </div>
      </div>

      {/* 地理围栏详情弹窗 */}
      {selectedGeofence && (
        <div className="absolute top-2 left-2 bg-white rounded-lg shadow-lg p-4 max-w-xs">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className="font-semibold text-gray-900">{selectedGeofence.name}</h3>
              {selectedGeofence.description && (
                <p className="text-sm text-gray-600 mt-1">{selectedGeofence.description}</p>
              )}
              
              <div className="mt-2 space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">奖励类型:</span>
                  <span className="font-medium">{selectedGeofence.rewardType}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">基础奖励:</span>
                  <span className="font-medium text-green-600">{selectedGeofence.baseReward} 分</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">半径:</span>
                  <span className="font-medium">{selectedGeofence.radius}m</span>
                </div>
                {selectedGeofence.distance !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-gray-600">距离:</span>
                    <span className="font-medium">{Math.round(selectedGeofence.distance)}m</span>
                  </div>
                )}
              </div>
            </div>
            
            <button
              onClick={() => setSelectedGeofence(null)}
              className="text-gray-400 hover:text-gray-600 ml-2"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* 状态信息 */}
      <div className="absolute bottom-2 right-2 bg-white bg-opacity-90 rounded p-2 text-xs">
        <div className="flex items-center space-x-1">
          <Info className="h-3 w-3" />
          <span>缩放: {(mapScale * 100).toFixed(0)}%</span>
        </div>
        {userLocation?.accuracy && (
          <div className="text-gray-600">
            精度: ±{Math.round(userLocation.accuracy)}m
          </div>
        )}
      </div>
    </div>
  );
};

export default GeofenceMap;