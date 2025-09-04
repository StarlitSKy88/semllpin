import axios from 'axios';
import { CONFIG } from './config';

// 地理编码配置
const GEOCODING_BASE_URL = CONFIG.API.API_BASE_URL + '/geocoding';

// 客户端缓存配置
interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

class GeocodingCache {
  private cache = new Map<string, CacheEntry<any>>();
  private defaultTTL = CONFIG.CACHE.GEOCODING_TTL; // 1小时

  set<T>(key: string, data: T, ttl?: number): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.defaultTTL
    });
  }

  get<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const isExpired = Date.now() - entry.timestamp > entry.ttl;
    if (isExpired) {
      this.cache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}

const cache = new GeocodingCache();

// 地理编码结果接口
export interface GeocodingResult {
  place_id: string;
  display_name: string;
  formatted_address_zh: string;
  formatted_address_en: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
  address_components: {
    house_number?: string;
    road?: string;
    neighbourhood?: string;
    suburb?: string;
    city?: string;
    county?: string;
    state?: string;
    country?: string;
    country_code?: string;
    postcode?: string;
  };
  bounds: {
    northeast: { lat: number; lng: number };
    southwest: { lat: number; lng: number };
  };
  type: string;
  category: string;
  importance: number;
}

// 反向地理编码结果接口
export interface ReverseGeocodingResult {
  place_id: string;
  display_name: string;
  formatted_address_zh: string;
  formatted_address_en: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
  address_components: {
    house_number?: string;
    road?: string;
    neighbourhood?: string;
    suburb?: string;
    city?: string;
    county?: string;
    state?: string;
    country?: string;
    country_code?: string;
    postcode?: string;
  };
  bounds: {
    northeast: { lat: number; lng: number };
    southwest: { lat: number; lng: number };
  };
  type?: string;
  category?: string;
  place_rank?: number;
  importance?: number;
}

// POI类型定义
export type POIType = 
  | 'restaurant'
  | 'gas_station' 
  | 'atm'
  | 'hospital'
  | 'pharmacy'
  | 'school'
  | 'bank'
  | 'hotel'
  | 'shopping_mall'
  | 'park'
  | 'bus_station'
  | 'subway_station'
  | 'convenience_store';

// POI搜索结果接口
export interface POISearchResult {
  place_id: string;
  name?: string;
  display_name: string;
  formatted_address: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
  distance_km?: number;
  distance_text?: string;
  type: string;
  category: string;
  importance: number;
  address_components: {
    road?: string;
    suburb?: string;
    city?: string;
    country?: string;
  };
}

// IP地理位置结果接口
export interface IPLocationResult {
  ip: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
  address: {
    city: string;
    region: string;
    region_code: string;
    country: string;
    country_code: string;
    postal_code: string;
  };
  timezone: string;
  isp: string;
}

// 地理编码API响应格式
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// 创建axios实例
const api = axios.create({
  baseURL: GEOCODING_BASE_URL,
  timeout: CONFIG.API.REQUEST.TIMEOUT,
  headers: {
    'Content-Type': 'application/json'
  }
});

// 请求拦截器 - 添加认证token
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token') || sessionStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// 响应拦截器 - 统一处理错误
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Geocoding API Error:', error);
    
    if (error.response?.status === 429) {
      throw new Error('请求过于频繁，请稍后再试');
    }
    
    if (error.response?.status === 401) {
      // 清除无效token
      if (typeof window !== 'undefined') {
        localStorage.removeItem('token');
        sessionStorage.removeItem('token');
      }
      throw new Error('认证已过期，请重新登录');
    }

    throw error;
  }
);

/**
 * 地址转坐标 (Geocoding)
 * @param address 要查询的地址
 * @param options 查询选项
 */
export async function geocodeAddress(
  address: string,
  options: {
    country?: string;
    limit?: number;
    useCache?: boolean;
  } = {}
): Promise<GeocodingResult[]> {
  const { country, limit = 5, useCache = true } = options;

  if (!address || address.trim().length === 0) {
    throw new Error('地址不能为空');
  }

  const cacheKey = `geocode:${address}:${country || 'all'}:${limit}`;
  
  // 检查缓存
  if (useCache) {
    const cachedResult = cache.get<GeocodingResult[]>(cacheKey);
    if (cachedResult) {
      return cachedResult;
    }
  }

  try {
    const params: any = { q: address, limit };
    if (country) params.country = country;

    const response = await api.get<ApiResponse<{ results: GeocodingResult[] }>>('/search', { params });

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.error || '地址搜索失败');
    }

    const results = response.data.data.results;

    // 缓存结果
    if (useCache) {
      cache.set(cacheKey, results);
    }

    return results;
  } catch (error: any) {
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error.message || '地址搜索失败');
  }
}

/**
 * 坐标转地址 (Reverse Geocoding)
 * @param lat 纬度
 * @param lng 经度
 * @param options 查询选项
 */
export async function reverseGeocode(
  lat: number,
  lng: number,
  options: {
    zoom?: number;
    useCache?: boolean;
  } = {}
): Promise<ReverseGeocodingResult | null> {
  const { zoom = 18, useCache = true } = options;

  if (!isValidCoordinate(lat, lng)) {
    throw new Error('无效的坐标');
  }

  const cacheKey = `reverse:${lat}:${lng}:${zoom}`;
  
  // 检查缓存
  if (useCache) {
    const cachedResult = cache.get<ReverseGeocodingResult>(cacheKey);
    if (cachedResult) {
      return cachedResult;
    }
  }

  try {
    const params = { lat, lng, zoom };
    const response = await api.get<ApiResponse<{ result: ReverseGeocodingResult }>>('/reverse', { params });

    if (!response.data.success) {
      if (response.data.error?.includes('No address found')) {
        return null;
      }
      throw new Error(response.data.error || '反向地理编码失败');
    }

    const result = response.data.data?.result || null;

    // 缓存结果
    if (useCache && result) {
      cache.set(cacheKey, result);
    }

    return result;
  } catch (error: any) {
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error.message || '反向地理编码失败');
  }
}

/**
 * 搜索附近的POI
 * @param lat 纬度
 * @param lng 经度
 * @param type POI类型
 * @param options 搜索选项
 */
export async function searchNearbyPOIs(
  lat: number,
  lng: number,
  type: POIType,
  options: {
    radius?: number;
    limit?: number;
    useCache?: boolean;
  } = {}
): Promise<POISearchResult[]> {
  const { radius = 5, limit = 10, useCache = true } = options;

  if (!isValidCoordinate(lat, lng)) {
    throw new Error('无效的坐标');
  }

  if (radius <= 0 || radius > 50) {
    throw new Error('搜索半径必须在0.1到50公里之间');
  }

  const cacheKey = `poi:${lat}:${lng}:${type}:${radius}:${limit}`;
  
  // 检查缓存
  if (useCache) {
    const cachedResult = cache.get<POISearchResult[]>(cacheKey);
    if (cachedResult) {
      return cachedResult;
    }
  }

  try {
    const params = { lat, lng, type, radius, limit };
    const response = await api.get<ApiResponse<{ results: POISearchResult[] }>>('/nearby', { params });

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.error || 'POI搜索失败');
    }

    const results = response.data.data.results;

    // 缓存结果
    if (useCache) {
      cache.set(cacheKey, results);
    }

    return results;
  } catch (error: any) {
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error.message || 'POI搜索失败');
  }
}

/**
 * 根据IP地址获取地理位置
 * @param ip IP地址，可选
 * @param useCache 是否使用缓存
 */
export async function getLocationByIP(
  ip?: string,
  useCache: boolean = true
): Promise<IPLocationResult> {
  const cacheKey = `ip:${ip || 'auto'}`;
  
  // 检查缓存
  if (useCache) {
    const cachedResult = cache.get<IPLocationResult>(cacheKey);
    if (cachedResult) {
      return cachedResult;
    }
  }

  try {
    const params = ip ? { ip } : {};
    const response = await api.get<ApiResponse<{ result: IPLocationResult }>>('/ip-location', { params });

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.error || 'IP定位失败');
    }

    const result = response.data.data.result;

    // 缓存结果（较短时间）
    if (useCache) {
      cache.set(cacheKey, result, 1800000); // 30分钟
    }

    return result;
  } catch (error: any) {
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error.message || 'IP定位失败');
  }
}

/**
 * 获取支持的POI类型列表
 */
export async function getPOITypes(): Promise<Array<{
  type: POIType;
  name: string;
  name_en: string;
}>> {
  const cacheKey = 'poi:types';
  
  // 检查缓存
  const cachedResult = cache.get<Array<{ type: POIType; name: string; name_en: string }>>(cacheKey);
  if (cachedResult) {
    return cachedResult;
  }

  try {
    const response = await api.get<ApiResponse<{ poi_types: Array<{ type: POIType; name: string; name_en: string }> }>>('/poi-types');

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.error || '获取POI类型失败');
    }

    const result = response.data.data.poi_types;

    // 缓存结果（长时间缓存）
    cache.set(cacheKey, result, 86400000); // 24小时

    return result;
  } catch (error: any) {
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error.message || '获取POI类型失败');
  }
}

/**
 * 获取用户当前位置
 * @param options 地理位置选项
 */
export function getCurrentPosition(options: PositionOptions = {}): Promise<GeolocationPosition> {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('浏览器不支持地理位置服务'));
      return;
    }

    const defaultOptions: PositionOptions = {
      enableHighAccuracy: true,
      timeout: 10000,
      maximumAge: 300000, // 5分钟
      ...options
    };

    navigator.geolocation.getCurrentPosition(resolve, reject, defaultOptions);
  });
}

/**
 * 监听用户位置变化
 * @param callback 位置变化回调
 * @param errorCallback 错误回调
 * @param options 地理位置选项
 */
export function watchPosition(
  callback: (position: GeolocationPosition) => void,
  errorCallback?: (error: GeolocationPositionError) => void,
  options: PositionOptions = {}
): number {
  if (!navigator.geolocation) {
    throw new Error('浏览器不支持地理位置服务');
  }

  const defaultOptions: PositionOptions = {
    enableHighAccuracy: true,
    timeout: 10000,
    maximumAge: 60000, // 1分钟
    ...options
  };

  return navigator.geolocation.watchPosition(callback, errorCallback, defaultOptions);
}

/**
 * 停止监听位置变化
 * @param watchId 监听ID
 */
export function clearWatch(watchId: number): void {
  if (navigator.geolocation) {
    navigator.geolocation.clearWatch(watchId);
  }
}

/**
 * 计算两点之间的距离（公里）
 * 使用 Haversine 公式
 */
export function calculateDistance(
  lat1: number, 
  lng1: number, 
  lat2: number, 
  lng2: number
): number {
  const R = 6371; // 地球半径（公里）
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = 
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * 
    Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * 格式化距离显示
 */
export function formatDistance(distanceKm: number): string {
  if (distanceKm < 1) {
    return `${Math.round(distanceKm * 1000)}米`;
  } else if (distanceKm < 10) {
    return `${distanceKm.toFixed(1)}公里`;
  } else {
    return `${Math.round(distanceKm)}公里`;
  }
}

/**
 * 验证坐标是否有效
 */
export function isValidCoordinate(lat: number, lng: number): boolean {
  return (
    typeof lat === 'number' && 
    typeof lng === 'number' &&
    lat >= -90 && lat <= 90 &&
    lng >= -180 && lng <= 180 &&
    !isNaN(lat) && !isNaN(lng)
  );
}

/**
 * 角度转弧度
 */
function toRad(deg: number): number {
  return deg * (Math.PI / 180);
}

/**
 * 弧度转角度
 */
export function toDeg(rad: number): number {
  return rad * (180 / Math.PI);
}

/**
 * 判断点是否在边界框内
 */
export function isPointInBounds(
  lat: number,
  lng: number,
  bounds: {
    northeast: { lat: number; lng: number };
    southwest: { lat: number; lng: number };
  }
): boolean {
  return (
    lat >= bounds.southwest.lat &&
    lat <= bounds.northeast.lat &&
    lng >= bounds.southwest.lng &&
    lng <= bounds.northeast.lng
  );
}

/**
 * 创建边界框
 */
export function createBounds(
  center: { lat: number; lng: number },
  radiusKm: number
): {
  northeast: { lat: number; lng: number };
  southwest: { lat: number; lng: number };
} {
  const latDiff = radiusKm / 111; // 纬度1度约111km
  const lngDiff = radiusKm / (111 * Math.cos(toRad(center.lat)));
  
  return {
    northeast: {
      lat: center.lat + latDiff,
      lng: center.lng + lngDiff
    },
    southwest: {
      lat: center.lat - latDiff,
      lng: center.lng - lngDiff
    }
  };
}

/**
 * 缓存管理
 */
export const geocodingCache = {
  /**
   * 清理缓存
   */
  clear: (): void => {
    cache.clear();
  },

  /**
   * 获取缓存大小
   */
  size: (): number => {
    return cache.size();
  },

  /**
   * 获取特定键的缓存
   */
  get: <T>(key: string): T | null => {
    return cache.get<T>(key);
  },

  /**
   * 设置缓存
   */
  set: <T>(key: string, data: T, ttl?: number): void => {
    cache.set(key, data, ttl);
  }
};

/**
 * 错误处理工具
 */
export class GeocodingError extends Error {
  public code: string;
  public details?: any;

  constructor(message: string, code: string = 'GEOCODING_ERROR', details?: any) {
    super(message);
    this.name = 'GeocodingError';
    this.code = code;
    this.details = details;
  }
}

// 导出常用POI类型映射
export const POI_TYPE_MAP = {
  restaurant: { name: '餐厅', icon: '🍽️' },
  gas_station: { name: '加油站', icon: '⛽' },
  atm: { name: 'ATM', icon: '🏧' },
  hospital: { name: '医院', icon: '🏥' },
  pharmacy: { name: '药店', icon: '💊' },
  school: { name: '学校', icon: '🏫' },
  bank: { name: '银行', icon: '🏦' },
  hotel: { name: '酒店', icon: '🏨' },
  shopping_mall: { name: '购物中心', icon: '🛍️' },
  park: { name: '公园', icon: '🌳' },
  bus_station: { name: '公交站', icon: '🚌' },
  subway_station: { name: '地铁站', icon: '🚇' },
  convenience_store: { name: '便利店', icon: '🏪' }
} as const;