import { create } from 'zustand';
import { Annotation, annotationApi, lbsApi, LBSReward } from '../services/api';

interface MapState {
  // 地图状态
  center: [number, number];
  zoom: number;
  bounds: { north: number; south: number; east: number; west: number } | null;
  
  // 标注数据
  annotations: Annotation[];
  selectedAnnotation: Annotation | null;
  
  // 用户位置
  userLocation: [number, number] | null;
  
  // 视图模式
  mapViewMode: 'markers' | 'heatmap' | 'hybrid';
  showHeatmap: boolean;
  
  // 加载状态
  isLoading: boolean;
  error: string | null;
  
  // 模态框状态
  showCreateModal: boolean;
  showPaymentModal: boolean;
  showAnnotationDetail: boolean;
  createModalPosition: [number, number] | null;
  
  // LBS奖励
  nearbyRewards: LBSReward[];
  
  // 操作
  setCenter: (center: [number, number]) => void;
  setZoom: (zoom: number) => void;
  setBounds: (bounds: { north: number; south: number; east: number; west: number }) => void;
  setUserLocation: (location: [number, number]) => void;
  setMapViewMode: (mode: 'markers' | 'heatmap' | 'hybrid') => void;
  setShowHeatmap: (show: boolean) => void;
  
  // 标注操作
  loadAnnotations: (bounds?: { north: number; south: number; east: number; west: number }) => Promise<void>;
  loadNearbyAnnotations: (latitude: number, longitude: number, radius?: number) => Promise<void>;
  selectAnnotation: (annotation: Annotation | null) => void;
  createAnnotation: (data: {
    title: string;
    description: string;
    latitude: number;
    longitude: number;
    rewardAmount: number;
    smell_type?: string;
    smell_intensity?: number;
    images?: string[];
  }) => Promise<Annotation>;
  
  // 模态框操作
  openCreateModal: (position: [number, number]) => void;
  closeCreateModal: () => void;
  openPaymentModal: () => void;
  closePaymentModal: () => void;
  openAnnotationDetail: () => void;
  closeAnnotationDetail: () => void;
  
  // LBS操作
  reportLocation: (latitude: number, longitude: number) => Promise<void>;
  claimReward: (annotationId: string, latitude: number, longitude: number) => Promise<void>;
  
  // 工具函数
  clearError: () => void;
  setLoading: (loading: boolean) => void;
}

export const useMapStore = create<MapState>((set, get) => ({
  // 初始状态
  center: [39.9042, 116.4074], // 北京天安门
  zoom: 13,
  bounds: null,
  
  annotations: [],
  selectedAnnotation: null,
  
  userLocation: null,
  
  mapViewMode: 'markers',
  showHeatmap: false,
  
  isLoading: false,
  error: null,
  
  showCreateModal: false,
  showPaymentModal: false,
  showAnnotationDetail: false,
  createModalPosition: null,
  
  nearbyRewards: [],
  
  // 基础操作
  setCenter: (center) => set({ center }),
  setZoom: (zoom) => set({ zoom }),
  setBounds: (bounds) => set({ bounds }),
  setUserLocation: (location) => set({ userLocation: location }),
  setMapViewMode: (mode) => {
    set({ 
      mapViewMode: mode,
      showHeatmap: mode === 'heatmap' || mode === 'hybrid'
    });
  },
  setShowHeatmap: (show) => set({ showHeatmap: show }),
  
  // 加载地图标注
  loadAnnotations: async (bounds) => {
    try {
      set({ isLoading: true, error: null });
      const response = await annotationApi.getMapAnnotations(bounds);
      set({ 
        annotations: response.data,
        isLoading: false 
      });
    } catch (error: any) {
      set({ 
        error: error.message || '加载标注失败',
        isLoading: false 
      });
    }
  },
  
  // 加载附近标注
  loadNearbyAnnotations: async (latitude, longitude, radius = 1000) => {
    try {
      set({ isLoading: true, error: null });
      const response = await annotationApi.getNearbyAnnotations(latitude, longitude, radius);
      set({ 
        annotations: response.data,
        isLoading: false 
      });
    } catch (error: any) {
      set({ 
        error: error.message || '加载附近标注失败',
        isLoading: false 
      });
    }
  },
  
  // 选择标注
  selectAnnotation: (annotation) => {
    set({ selectedAnnotation: annotation });
  },
  
  // 创建标注
  createAnnotation: async (data) => {
    try {
      set({ isLoading: true, error: null });
      const response = await annotationApi.createAnnotation(data);
      const newAnnotation = response.data;
      
      // 添加到当前标注列表
      set(state => ({ 
        annotations: [...state.annotations, newAnnotation],
        isLoading: false,
        showCreateModal: false,
        createModalPosition: null
      }));
      
      return newAnnotation;
    } catch (error: any) {
      set({ 
        error: error.message || '创建标注失败',
        isLoading: false 
      });
      throw error;
    }
  },
  
  // 模态框操作
  openCreateModal: (position) => {
    set({ 
      showCreateModal: true,
      createModalPosition: position
    });
  },
  
  closeCreateModal: () => {
    set({ 
      showCreateModal: false,
      createModalPosition: null
    });
  },
  
  openPaymentModal: () => set({ showPaymentModal: true }),
  closePaymentModal: () => set({ showPaymentModal: false }),
  
  openAnnotationDetail: () => set({ showAnnotationDetail: true }),
  closeAnnotationDetail: () => set({ showAnnotationDetail: false }),
  
  // LBS位置上报
  reportLocation: async (latitude, longitude) => {
    try {
      const response = await lbsApi.reportLocation(latitude, longitude);
      set({ nearbyRewards: response.data });
    } catch (error: any) {
      console.error('位置上报失败:', error);
    }
  },
  
  // 领取奖励
  claimReward: async (annotationId, latitude, longitude) => {
    try {
      set({ isLoading: true, error: null });
      await lbsApi.claimReward(annotationId, latitude, longitude);
      
      // 移除已领取的奖励
      set(state => ({
        nearbyRewards: state.nearbyRewards.filter(reward => reward.annotationId !== annotationId),
        isLoading: false
      }));
    } catch (error: any) {
      set({ 
        error: error.message || '领取奖励失败',
        isLoading: false 
      });
      throw error;
    }
  },
  
  // 工具函数
  clearError: () => set({ error: null }),
  setLoading: (loading) => set({ isLoading: loading }),
}));

// 热力图数据生成函数
export const generateHeatmapData = (annotations: Annotation[]) => {
  return annotations.map(annotation => ({
    lat: annotation.latitude,
    lng: annotation.longitude,
    intensity: annotation.smell_intensity ? annotation.smell_intensity / 5 : Math.min(annotation.rewardAmount / 10, 1), // 使用气味强度或奖励金额
    radius: Math.max(20, (annotation.smell_intensity || 3) * 10), // 根据气味强度设置半径
    smellType: annotation.smell_type,
  }));
};

// 热力图颜色生成函数
export const getHeatmapColor = (intensity: number, smellType?: string) => {
  // 根据气味类型选择颜色系
  let colors;
  switch (smellType) {
    case 'food':
      colors = [
        { r: 255, g: 165, b: 0 },   // 橙色
        { r: 255, g: 69, b: 0 },    // 深橙色
        { r: 255, g: 0, b: 0 },     // 红色
      ];
      break;
    case 'chemical':
      colors = [
        { r: 128, g: 0, b: 128 },   // 紫色
        { r: 255, g: 0, b: 255 },   // 品红
        { r: 139, g: 0, b: 139 },   // 深紫色
      ];
      break;
    case 'garbage':
      colors = [
        { r: 139, g: 69, b: 19 },   // 棕色
        { r: 160, g: 82, b: 45 },   // 深棕色
        { r: 128, g: 0, b: 0 },     // 暗红色
      ];
      break;
    default:
      colors = [
        { r: 0, g: 255, b: 0 },     // 绿色 (低强度)
        { r: 255, g: 255, b: 0 },   // 黄色 (中强度)
        { r: 255, g: 0, b: 0 },     // 红色 (高强度)
      ];
  }
  
  const normalizedIntensity = Math.max(0, Math.min(1, intensity));
  const scaledIntensity = normalizedIntensity * (colors.length - 1);
  const index = Math.floor(scaledIntensity);
  const fraction = scaledIntensity - index;
  
  if (index >= colors.length - 1) {
    const color = colors[colors.length - 1];
    return `rgba(${color.r}, ${color.g}, ${color.b}, 0.6)`;
  }
  
  const color1 = colors[index];
  const color2 = colors[index + 1];
  
  const r = Math.round(color1.r + (color2.r - color1.r) * fraction);
  const g = Math.round(color1.g + (color2.g - color1.g) * fraction);
  const b = Math.round(color1.b + (color2.b - color1.b) * fraction);
  
  return `rgba(${r}, ${g}, ${b}, 0.6)`;
};