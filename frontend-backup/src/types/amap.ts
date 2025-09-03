// 高德地图相关类型定义

// 高德地图主对象
export interface AMapInstance {
  plugin: (plugins: string[], callback: () => void) => void;
  add: (overlays: (AMapMarker | AMapCircle)[]) => void;
  remove: (overlays: (AMapMarker | AMapCircle)[]) => void;
  setCenter: (center: [number, number]) => void;
  setZoom: (zoom: number) => void;
  getCenter: () => AMapLngLat;
  getZoom: () => number;
  destroy: () => void;
  on: (event: string, callback: (...args: unknown[]) => void) => void;
  off: (event: string, callback: (...args: unknown[]) => void) => void;
}

// 经纬度对象
export interface AMapLngLat {
  lng: number;
  lat: number;
  getLng: () => number;
  getLat: () => number;
}

// 标记点对象
export interface AMapMarker {
  setPosition: (position: [number, number] | AMapLngLat) => void;
  getPosition: () => AMapLngLat;
  setIcon: (icon: AMapIcon) => void;
  setTitle: (title: string) => void;
  setContent: (content: string | HTMLElement) => void;
  show: () => void;
  hide: () => void;
  destroy: () => void;
  on: (event: string, callback: (...args: unknown[]) => void) => void;
  off: (event: string, callback: (...args: unknown[]) => void) => void;
}

// 图标对象
export interface AMapIcon {
  setImageSize: (size: AMapSize) => void;
  getImageSize: () => AMapSize;
}

// 尺寸对象
export interface AMapSize {
  width: number;
  height: number;
  getWidth: () => number;
  getHeight: () => number;
}

// 圆形对象
export interface AMapCircle {
  setCenter: (center: [number, number] | AMapLngLat) => void;
  getCenter: () => AMapLngLat;
  setRadius: (radius: number) => void;
  getRadius: () => number;
  setOptions: (options: AMapCircleOptions) => void;
  show: () => void;
  hide: () => void;
  destroy: () => void;
}

// 圆形选项
export interface AMapCircleOptions {
  center?: [number, number] | AMapLngLat;
  radius?: number;
  strokeColor?: string;
  strokeWeight?: number;
  strokeOpacity?: number;
  fillColor?: string;
  fillOpacity?: number;
  strokeStyle?: 'solid' | 'dashed';
  zIndex?: number;
}

// 标记点选项
export interface AMapMarkerOptions {
  position?: [number, number] | AMapLngLat;
  icon?: string | AMapIcon;
  title?: string;
  content?: string | HTMLElement;
  anchor?: string;
  offset?: AMapPixel;
  zIndex?: number;
  angle?: number;
  autoRotation?: boolean;
  animation?: string;
  shadow?: AMapIcon;
  clickable?: boolean;
  draggable?: boolean;
  bubble?: boolean;
  zooms?: [number, number];
  cursor?: string;
  topWhenClick?: boolean;
  label?: {
    content: string;
    offset?: AMapPixel;
  };
}

// 像素对象
export interface AMapPixel {
  x: number;
  y: number;
  getX: () => number;
  getY: () => number;
}

// 地图选项
export interface AMapOptions {
  zoom?: number;
  center?: [number, number];
  layers?: Record<string, unknown>[];
  zooms?: [number, number];
  lang?: string;
  cursor?: string;
  crs?: string;
  animateEnable?: boolean;
  isHotspot?: boolean;
  defaultLayer?: Record<string, unknown>;
  rotateEnable?: boolean;
  resizeEnable?: boolean;
  showIndoorMap?: boolean;
  indoorMap?: Record<string, unknown>;
  expandZoomRange?: boolean;
  dragEnable?: boolean;
  zoomEnable?: boolean;
  doubleClickZoom?: boolean;
  keyboardEnable?: boolean;
  jogEnable?: boolean;
  scrollWheel?: boolean;
  touchZoom?: boolean;
  touchZoomCenter?: number;
  mapStyle?: string;
  features?: string[];
  showBuildingBlock?: boolean;
  viewMode?: string;
  pitch?: number;
  pitchEnable?: boolean;
  buildingAnimation?: boolean;
  skyColor?: string;
}

// 全局AMap对象
export interface AMapGlobal {
  Map: new (container: string | HTMLElement, options?: AMapOptions) => AMapInstance;
  Marker: new (options?: AMapMarkerOptions) => AMapMarker;
  Icon: new (options: {
    size?: AMapSize;
    image?: string;
    imageOffset?: AMapPixel;
    imageSize?: AMapSize;
  }) => AMapIcon;
  Circle: new (options?: AMapCircleOptions) => AMapCircle;
  Size: new (width: number, height: number) => AMapSize;
  Pixel: new (x: number, y: number) => AMapPixel;
  LngLat: new (lng: number, lat: number) => AMapLngLat;
  plugin: (plugins: string[], callback: () => void) => void;
  Geolocation?: Record<string, unknown>;
}

// 声明全局AMap变量
declare global {
  interface Window {
    AMap: AMapGlobal;
  }
}

export {};