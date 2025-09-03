import React, { useEffect, useRef } from 'react';
import { useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet.markercluster';
import 'leaflet.markercluster/dist/MarkerCluster.css';
import 'leaflet.markercluster/dist/MarkerCluster.Default.css';

// 扩展 Leaflet 类型以包含聚合功能
interface ClusterOptions {
  maxClusterRadius?: number;
  disableClusteringAtZoom?: number;
  spiderfyOnMaxZoom?: boolean;
  showCoverageOnHover?: boolean;
  zoomToBoundsOnClick?: boolean;
  iconCreateFunction?: (cluster: ClusterGroup) => L.DivIcon;
}

interface ClusterGroup {
  getChildCount(): number;
  getAllChildMarkers(): L.Marker[];
}

declare module 'leaflet' {
  interface L {
    MarkerClusterGroup: new (options?: ClusterOptions) => MarkerClusterGroup;
    markerClusterGroup(options?: ClusterOptions): MarkerClusterGroup;
  }
  
  interface MarkerClusterGroup extends LayerGroup {
    addLayer(layer: Layer): this;
    removeLayer(layer: Layer): this;
    clearLayers(): this;
  }
}

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

interface MarkerClusterGroupProps {
  annotations: Annotation[];
  onMarkerClick?: (annotation: Annotation) => void;
  clusterOptions?: {
    maxClusterRadius?: number;
    disableClusteringAtZoom?: number;
    spiderfyOnMaxZoom?: boolean;
    showCoverageOnHover?: boolean;
    zoomToBoundsOnClick?: boolean;
  };
}

// 创建自定义臭味强度图标
const createSmellIcon = (intensity: number) => {
  const color = intensity >= 8 ? '#ff4d4f' : intensity >= 5 ? '#faad14' : '#52c41a';
  return new L.Icon({
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

// 创建聚合图标
const createClusterIcon = (cluster: ClusterGroup) => {
  const count = cluster.getChildCount();
  const markers = cluster.getAllChildMarkers();
  
  // 计算平均臭味强度
  const avgIntensity = markers.reduce((sum: number, marker: L.Marker & { options: { annotation?: Annotation } }) => {
    return sum + (marker.options.annotation?.smell_intensity || 0);
  }, 0) / markers.length;
  
  const size = count < 10 ? 'small' : count < 100 ? 'medium' : 'large';
  const sizeMap = { small: 40, medium: 50, large: 60 };
  const iconSize = sizeMap[size];
  
  const color = avgIntensity >= 8 ? '#ff4d4f' : avgIntensity >= 5 ? '#faad14' : '#52c41a';
  
  return new L.DivIcon({
    html: `
      <div style="
        background: ${color};
        border: 3px solid white;
        border-radius: 50%;
        width: ${iconSize}px;
        height: ${iconSize}px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
        font-size: ${iconSize > 40 ? '14px' : '12px'};
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      ">
        ${count}
      </div>
    `,
    className: 'custom-cluster-icon',
    iconSize: [iconSize, iconSize],
    iconAnchor: [iconSize / 2, iconSize / 2]
  });
};

const MarkerClusterGroup: React.FC<MarkerClusterGroupProps> = ({
  annotations,
  onMarkerClick,
  clusterOptions = {}
}) => {
  const map = useMap();
  const clusterGroupRef = useRef<L.MarkerClusterGroup | null>(null);

  useEffect(() => {
    if (!map) return;

    // 默认聚合配置
    const defaultOptions = {
      maxClusterRadius: 80,
      disableClusteringAtZoom: 16,
      spiderfyOnMaxZoom: true,
      showCoverageOnHover: false,
      zoomToBoundsOnClick: true,
      iconCreateFunction: createClusterIcon,
      ...clusterOptions
    };

    // 创建聚合组
    if (!clusterGroupRef.current) {
      clusterGroupRef.current = (L as typeof L & { markerClusterGroup: (options: ClusterOptions) => L.MarkerClusterGroup }).markerClusterGroup(defaultOptions);
      map.addLayer(clusterGroupRef.current);
    }

    // 清空现有标记
    clusterGroupRef.current.clearLayers();

    // 添加新标记
    annotations.forEach(annotation => {
      const marker = L.marker(
        [annotation.latitude, annotation.longitude],
        {
          icon: createSmellIcon(annotation.smell_intensity),
          annotation // 将标注数据附加到标记上
        } as L.MarkerOptions & { annotation: Annotation }
      );

      // 创建弹窗内容
      const popupContent = `
        <div class="custom-popup-content" style="min-width: 250px;">
          <div style="margin-bottom: 8px;">
            <strong>${annotation.user.username}</strong>
            <span style="color: #666; font-size: 12px; margin-left: 8px;">
              ${new Date(annotation.created_at).toLocaleDateString('zh-CN')}
            </span>
          </div>
          
          <div style="margin-bottom: 8px;">
            <span style="font-weight: 500;">臭味强度: </span>
            <span style="
              background: ${annotation.smell_intensity >= 8 ? '#ff4d4f' : 
                         annotation.smell_intensity >= 5 ? '#faad14' : '#52c41a'};
              color: white;
              padding: 2px 6px;
              border-radius: 4px;
              font-size: 12px;
            ">
              ${annotation.smell_intensity}/10
            </span>
          </div>
          
          ${annotation.description ? `
            <div style="margin-bottom: 8px; color: #333;">
              ${annotation.description}
            </div>
          ` : ''}
          
          <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: #666;">
            <div>
              <span>👁️ ${annotation.views_count}</span>
              <span style="margin-left: 12px;">❤️ ${annotation.likes_count}</span>
            </div>
            <button 
              onclick="window.handleMarkerClick && window.handleMarkerClick('${annotation.id}')"
              style="
                background: #1890ff;
                color: white;
                border: none;
                padding: 4px 8px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
              "
            >
              查看详情
            </button>
          </div>
        </div>
      `;

      marker.bindPopup(popupContent, {
        maxWidth: 300,
        className: 'custom-marker-popup'
      });

      // 添加点击事件
      marker.on('click', () => {
        if (onMarkerClick) {
          onMarkerClick(annotation);
        }
      });

      clusterGroupRef.current!.addLayer(marker);
    });

    // 设置全局点击处理函数
    (window as Window & { handleMarkerClick?: (annotationId: string) => void }).handleMarkerClick = (annotationId: string) => {
      const annotation = annotations.find(a => a.id === annotationId);
      if (annotation && onMarkerClick) {
        onMarkerClick(annotation);
      }
    };

    // 清理函数
    return () => {
      if (clusterGroupRef.current && map) {
        map.removeLayer(clusterGroupRef.current);
        clusterGroupRef.current = null;
      }
      // 清理全局函数
      delete (window as Window & { handleMarkerClick?: (annotationId: string) => void }).handleMarkerClick;
    };
  }, [map, annotations, onMarkerClick, clusterOptions]);

  // 组件卸载时清理
  useEffect(() => {
    return () => {
      if (clusterGroupRef.current && map) {
        map.removeLayer(clusterGroupRef.current);
      }
      delete (window as Window & { handleMarkerClick?: (annotationId: string) => void }).handleMarkerClick;
    };
  }, [map]);

  return null;
};

export default MarkerClusterGroup;