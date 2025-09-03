import React, { useEffect, useRef } from 'react';
import { useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet.heat';

// 扩展 Leaflet 类型以包含热力图
interface HeatLayer extends L.Layer {
  addTo(map: L.Map): this;
  remove(): this;
}

declare module 'leaflet' {
  interface L {
    heatLayer(
      latlngs: Array<[number, number, number?]>,
      options?: {
        minOpacity?: number;
        maxZoom?: number;
        max?: number;
        radius?: number;
        blur?: number;
        gradient?: { [key: string]: string };
      }
    ): HeatLayer;
  }
}

interface HeatmapPoint {
  latitude: number;
  longitude: number;
  intensity: number;
}

interface HeatmapLayerProps {
  points: HeatmapPoint[];
  options?: {
    minOpacity?: number;
    maxZoom?: number;
    max?: number;
    radius?: number;
    blur?: number;
    gradient?: { [key: string]: string };
  };
  visible?: boolean;
}

const HeatmapLayer: React.FC<HeatmapLayerProps> = ({ 
  points, 
  options = {},
  visible = true 
}) => {
  const map = useMap();
  const heatLayerRef = useRef<HeatLayer | null>(null);

  useEffect(() => {
    if (!map || !visible) {
      if (heatLayerRef.current) {
        map.removeLayer(heatLayerRef.current);
        heatLayerRef.current = null;
      }
      return;
    }

    // 转换数据格式为热力图所需的格式
    const heatmapData: [number, number, number][] = points.map(point => [
      point.latitude,
      point.longitude,
      point.intensity / 10 // 将强度标准化到 0-1 范围
    ]);

    // 默认热力图配置
    const defaultOptions = {
      minOpacity: 0.4,
      maxZoom: 18,
      max: 1.0,
      radius: 25,
      blur: 15,
      gradient: {
        0.0: '#00ff00',  // 绿色 - 低强度
        0.3: '#ffff00',  // 黄色 - 中等强度
        0.6: '#ff8000',  // 橙色 - 较高强度
        1.0: '#ff0000'   // 红色 - 高强度
      },
      ...options
    };

    // 移除现有的热力图层
    if (heatLayerRef.current) {
      map.removeLayer(heatLayerRef.current);
    }

    // 创建新的热力图层
    if (heatmapData.length > 0) {
      heatLayerRef.current = L.heatLayer(heatmapData, defaultOptions);
      heatLayerRef.current.addTo(map);
    }

    // 清理函数
    return () => {
      if (heatLayerRef.current) {
        map.removeLayer(heatLayerRef.current);
        heatLayerRef.current = null;
      }
    };
  }, [map, points, options, visible]);

  // 当组件卸载时清理热力图层
  useEffect(() => {
    return () => {
      if (heatLayerRef.current && map) {
        map.removeLayer(heatLayerRef.current);
      }
    };
  }, [map]);

  return null;
};

export default HeatmapLayer;