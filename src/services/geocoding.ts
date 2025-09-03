import axios from 'axios';
import NodeCache from 'node-cache';
import { logger } from '../utils/logger';

// 地理编码缓存，有效期1小时
const geocodingCache = new NodeCache({ stdTTL: 3600 });

// Nominatim API 配置
const NOMINATIM_BASE_URL = 'https://nominatim.openstreetmap.org';
const DEFAULT_HEADERS = {
  'User-Agent': 'SmellPin/1.0 (https://smellpin.com)',
  'Accept': 'application/json',
  'Accept-Language': 'zh-CN,en-US;q=0.9,en;q=0.8'
};

// API请求限制：每秒最多1个请求
let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 1000;

async function rateLimitedRequest(url: string, params: any) {
  const now = Date.now();
  const timeSinceLastRequest = now - lastRequestTime;
  
  if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
    await new Promise(resolve => setTimeout(resolve, MIN_REQUEST_INTERVAL - timeSinceLastRequest));
  }
  
  lastRequestTime = Date.now();
  
  try {
    const response = await axios.get(url, {
      params,
      headers: DEFAULT_HEADERS,
      timeout: 10000
    });
    
    return response.data;
  } catch (error: any) {
    logger.error('Geocoding API request failed:', {
      url,
      params,
      error: error.message
    });
    throw new Error(`Geocoding API request failed: ${error.message}`);
  }
}

// 地址搜索结果接口
export interface GeocodingResult {
  place_id: string;
  licence: string;
  osm_type: string;
  osm_id: string;
  display_name: string;
  address: {
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
  lat: string;
  lon: string;
  boundingbox: [string, string, string, string];
  importance: number;
  type: string;
  class: string;
}

// 反向地理编码结果接口
export interface ReverseGeocodingResult {
  place_id: string;
  licence: string;
  osm_type: string;
  osm_id: string;
  display_name: string;
  address: {
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
  lat: string;
  lon: string;
  boundingbox: [string, string, string, string];
  category?: string;
  type?: string;
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
  display_name: string;
  name?: string;
  lat: string;
  lon: string;
  type: string;
  class: string;
  importance: number;
  distance?: number;
  address?: {
    road?: string;
    suburb?: string;
    city?: string;
    country?: string;
  };
}

// IP地理位置结果接口
export interface IPLocationResult {
  query: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
}

/**
 * 地址转坐标 (Geocoding)
 * @param address 要查询的地址
 * @param countryCode 国家代码限制，可选
 * @param limit 返回结果数量限制，默认5
 */
export async function geocodeAddress(
  address: string,
  countryCode?: string,
  limit: number = 5
): Promise<GeocodingResult[]> {
  if (!address || address.trim().length === 0) {
    throw new Error('Address cannot be empty');
  }

  const cacheKey = `geocode:${address}:${countryCode || 'all'}:${limit}`;
  
  // 检查缓存
  const cachedResult = geocodingCache.get<GeocodingResult[]>(cacheKey);
  if (cachedResult) {
    logger.info('Geocoding cache hit', { address, cacheKey });
    return cachedResult;
  }

  try {
    logger.info('Geocoding address', { address, countryCode, limit });
    
    const params: any = {
      q: address,
      format: 'json',
      addressdetails: 1,
      limit: Math.min(limit, 10), // 限制最大返回数量
      dedupe: 1,
      namedetails: 1,
      extratags: 1
    };

    if (countryCode) {
      params.countrycodes = countryCode.toLowerCase();
    }

    const url = `${NOMINATIM_BASE_URL}/search`;
    const data = await rateLimitedRequest(url, params);

    if (!Array.isArray(data) || data.length === 0) {
      logger.warn('No geocoding results found', { address, countryCode });
      return [];
    }

    const results = data.map((item: any) => ({
      place_id: item.place_id,
      licence: item.licence,
      osm_type: item.osm_type,
      osm_id: item.osm_id,
      display_name: item.display_name,
      address: item.address || {},
      lat: item.lat,
      lon: item.lon,
      boundingbox: item.boundingbox,
      importance: parseFloat(item.importance) || 0,
      type: item.type,
      class: item.class
    }));

    // 缓存结果
    geocodingCache.set(cacheKey, results);
    
    logger.info('Geocoding successful', { 
      address, 
      resultCount: results.length,
      firstResult: results[0]?.display_name
    });

    return results;
  } catch (error: any) {
    logger.error('Geocoding failed', { address, countryCode, error: error.message });
    throw new Error(`Failed to geocode address: ${error.message}`);
  }
}

/**
 * 坐标转地址 (Reverse Geocoding)
 * @param lat 纬度
 * @param lon 经度
 * @param zoom 详细程度，1-18，值越大越详细
 */
export async function reverseGeocode(
  lat: number,
  lon: number,
  zoom: number = 18
): Promise<ReverseGeocodingResult | null> {
  if (!isValidCoordinate(lat, lon)) {
    throw new Error('Invalid coordinates');
  }

  const cacheKey = `reverse:${lat}:${lon}:${zoom}`;
  
  // 检查缓存
  const cachedResult = geocodingCache.get<ReverseGeocodingResult>(cacheKey);
  if (cachedResult) {
    logger.info('Reverse geocoding cache hit', { lat, lon, cacheKey });
    return cachedResult;
  }

  try {
    logger.info('Reverse geocoding coordinates', { lat, lon, zoom });
    
    const params = {
      lat: lat.toString(),
      lon: lon.toString(),
      format: 'json',
      addressdetails: 1,
      zoom: Math.min(Math.max(zoom, 1), 18), // 限制zoom范围
      namedetails: 1,
      extratags: 1
    };

    const url = `${NOMINATIM_BASE_URL}/reverse`;
    const data = await rateLimitedRequest(url, params);

    if (!data || data.error) {
      logger.warn('No reverse geocoding results found', { lat, lon, error: data?.error });
      return null;
    }

    const result: ReverseGeocodingResult = {
      place_id: data.place_id,
      licence: data.licence,
      osm_type: data.osm_type,
      osm_id: data.osm_id,
      display_name: data.display_name,
      address: data.address || {},
      lat: data.lat,
      lon: data.lon,
      boundingbox: data.boundingbox,
      category: data.category,
      type: data.type,
      place_rank: data.place_rank,
      importance: parseFloat(data.importance) || 0
    };

    // 缓存结果
    geocodingCache.set(cacheKey, result);
    
    logger.info('Reverse geocoding successful', { 
      lat, 
      lon, 
      result: result.display_name 
    });

    return result;
  } catch (error: any) {
    logger.error('Reverse geocoding failed', { lat, lon, error: error.message });
    throw new Error(`Failed to reverse geocode coordinates: ${error.message}`);
  }
}

/**
 * 搜索附近的POI
 * @param lat 纬度
 * @param lon 经度
 * @param type POI类型
 * @param radius 搜索半径（公里）
 * @param limit 返回结果数量限制
 */
export async function searchNearbyPOIs(
  lat: number,
  lon: number,
  type: POIType,
  radius: number = 5,
  limit: number = 10
): Promise<POISearchResult[]> {
  if (!isValidCoordinate(lat, lon)) {
    throw new Error('Invalid coordinates');
  }

  if (radius <= 0 || radius > 50) {
    throw new Error('Radius must be between 0.1 and 50 km');
  }

  const cacheKey = `poi:${lat}:${lon}:${type}:${radius}:${limit}`;
  
  // 检查缓存
  const cachedResult = geocodingCache.get<POISearchResult[]>(cacheKey);
  if (cachedResult) {
    logger.info('POI search cache hit', { lat, lon, type, cacheKey });
    return cachedResult;
  }

  try {
    logger.info('Searching nearby POIs', { lat, lon, type, radius, limit });
    
    // 将POI类型映射到Nominatim查询参数
    const amenityMap: Record<POIType, string> = {
      restaurant: 'restaurant',
      gas_station: 'fuel',
      atm: 'atm',
      hospital: 'hospital',
      pharmacy: 'pharmacy',
      school: 'school',
      bank: 'bank',
      hotel: 'hotel',
      shopping_mall: 'mall',
      park: 'park',
      bus_station: 'bus_station',
      subway_station: 'subway',
      convenience_store: 'convenience'
    };

    const amenity = amenityMap[type];
    if (!amenity) {
      throw new Error(`Unsupported POI type: ${type}`);
    }

    const params = {
      format: 'json',
      amenity,
      limit: Math.min(limit, 20),
      addressdetails: 1,
      namedetails: 1,
      bounded: 1,
      viewbox: getBoundingBox(lat, lon, radius),
      dedupe: 1
    };

    const url = `${NOMINATIM_BASE_URL}/search`;
    const data = await rateLimitedRequest(url, params);

    if (!Array.isArray(data) || data.length === 0) {
      logger.warn('No POI results found', { lat, lon, type, amenity });
      return [];
    }

    const validResults: POISearchResult[] = [];
    
    for (const item of data) {
      const poiLat = parseFloat(item.lat);
      const poiLon = parseFloat(item.lon);
      const distance = calculateDistance(lat, lon, poiLat, poiLon);

      // 过滤超出半径范围的结果
      if (distance > radius) {
        continue;
      }

      validResults.push({
        place_id: item.place_id,
        display_name: item.display_name,
        name: item.namedetails?.name || item.name,
        lat: item.lat,
        lon: item.lon,
        type: item.type,
        class: item.class,
        importance: parseFloat(item.importance) || 0,
        distance: Math.round(distance * 1000) / 1000, // 保留3位小数
        address: {
          road: item.address?.road,
          suburb: item.address?.suburb,
          city: item.address?.city || item.address?.town || item.address?.village,
          country: item.address?.country
        }
      });
    }

    const results = validResults.sort((a: POISearchResult, b: POISearchResult) => {
      // 按距离排序，再按重要性排序
      if (a.distance !== b.distance) {
        return (a.distance || 0) - (b.distance || 0);
      }
      return (b.importance || 0) - (a.importance || 0);
    });

    // 缓存结果
    geocodingCache.set(cacheKey, results);
    
    logger.info('POI search successful', { 
      lat, 
      lon, 
      type, 
      resultCount: results.length 
    });

    return results;
  } catch (error: any) {
    logger.error('POI search failed', { lat, lon, type, error: error.message });
    throw new Error(`Failed to search nearby POIs: ${error.message}`);
  }
}

/**
 * 根据IP地址获取地理位置
 * @param ip IP地址，可选，不提供则使用请求者IP
 */
export async function getLocationByIP(ip?: string): Promise<IPLocationResult> {
  const cacheKey = `ip:${ip || 'auto'}`;
  
  // 检查缓存
  const cachedResult = geocodingCache.get<IPLocationResult>(cacheKey);
  if (cachedResult) {
    logger.info('IP location cache hit', { ip, cacheKey });
    return cachedResult;
  }

  try {
    logger.info('Getting location by IP', { ip });
    
    // 使用免费的ip-api.com服务
    const url = ip ? `http://ip-api.com/json/${ip}` : 'http://ip-api.com/json/';
    
    const response = await axios.get(url, {
      params: {
        lang: 'zh-CN'
      },
      timeout: 5000
    });

    const data = response.data;

    if (data.status !== 'success') {
      throw new Error(`IP location failed: ${data.message || 'Unknown error'}`);
    }

    const result: IPLocationResult = {
      query: data.query,
      country: data.country,
      countryCode: data.countryCode,
      region: data.region,
      regionName: data.regionName,
      city: data.city,
      zip: data.zip,
      lat: data.lat,
      lon: data.lon,
      timezone: data.timezone,
      isp: data.isp
    };

    // 缓存结果（较短时间，因为IP位置可能变化）
    geocodingCache.set(cacheKey, result, 1800); // 30分钟
    
    logger.info('IP location successful', { 
      ip, 
      city: result.city,
      country: result.country 
    });

    return result;
  } catch (error: any) {
    logger.error('IP location failed', { ip, error: error.message });
    throw new Error(`Failed to get location by IP: ${error.message}`);
  }
}

/**
 * 验证坐标是否有效
 */
function isValidCoordinate(lat: number, lon: number): boolean {
  return (
    typeof lat === 'number' && 
    typeof lon === 'number' &&
    lat >= -90 && lat <= 90 &&
    lon >= -180 && lon <= 180 &&
    !isNaN(lat) && !isNaN(lon)
  );
}

/**
 * 计算两点之间的距离（公里）
 * 使用 Haversine 公式
 */
function calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // 地球半径（公里）
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = 
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * 
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * 角度转弧度
 */
function toRad(deg: number): number {
  return deg * (Math.PI / 180);
}

/**
 * 根据中心点和半径生成边界框
 */
function getBoundingBox(lat: number, lon: number, radiusKm: number): string {
  const latDiff = radiusKm / 111; // 纬度1度约111km
  const lonDiff = radiusKm / (111 * Math.cos(toRad(lat))); // 经度1度在不同纬度的距离不同
  
  const minLon = lon - lonDiff;
  const minLat = lat - latDiff;
  const maxLon = lon + lonDiff;
  const maxLat = lat + latDiff;
  
  return `${minLon},${minLat},${maxLon},${maxLat}`;
}

/**
 * 格式化地址显示
 */
export function formatAddress(address: any, lang: 'zh' | 'en' = 'zh'): string {
  if (!address) return '';
  
  const parts: string[] = [];
  
  if (lang === 'zh') {
    // 中文地址格式：国家 省份 城市 区域 道路 门牌号
    if (address.country) parts.push(address.country);
    if (address.state) parts.push(address.state);
    if (address.city || address.town || address.village) {
      parts.push(address.city || address.town || address.village);
    }
    if (address.county && address.county !== (address.city || address.town)) {
      parts.push(address.county);
    }
    if (address.suburb || address.neighbourhood) {
      parts.push(address.suburb || address.neighbourhood);
    }
    if (address.road) parts.push(address.road);
    if (address.house_number) parts.push(address.house_number + '号');
  } else {
    // 英文地址格式：门牌号 道路, 区域, 城市, 省份, 国家
    if (address.house_number && address.road) {
      parts.push(`${address.house_number} ${address.road}`);
    } else if (address.road) {
      parts.push(address.road);
    }
    
    if (address.suburb || address.neighbourhood) {
      parts.push(address.suburb || address.neighbourhood);
    }
    
    if (address.city || address.town || address.village) {
      parts.push(address.city || address.town || address.village);
    }
    
    if (address.state) parts.push(address.state);
    if (address.country) parts.push(address.country);
  }
  
  return parts.filter(Boolean).join(lang === 'zh' ? '' : ', ');
}

// 导出缓存清理函数（用于测试或管理）
export function clearGeocodingCache(): void {
  geocodingCache.flushAll();
  logger.info('Geocoding cache cleared');
}

// 导出缓存统计信息
export function getGeocodingCacheStats() {
  return {
    keys: geocodingCache.keys().length,
    hits: geocodingCache.getStats().hits,
    misses: geocodingCache.getStats().misses,
    ksize: geocodingCache.getStats().ksize,
    vsize: geocodingCache.getStats().vsize
  };
}