import express from 'express';
import { 
  geocodeAddress,
  reverseGeocode,
  searchNearbyPOIs,
  getLocationByIP,
  formatAddress,
  clearGeocodingCache,
  getGeocodingCacheStats,
  type POIType
} from '../services/geocoding';
import { asyncHandler } from '../middleware/asyncHandler';
// import { validateRequest } from '../middleware/validation';
import { rateLimit } from 'express-rate-limit';
import { logger } from '../utils/logger';

const router = express.Router();

// 地理编码API限流配置
const geocodingRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1分钟
  max: 60, // 每分钟最多60次请求
  message: {
    error: 'Too many geocoding requests, please try again later',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: any) => {
    // 使用IP和用户ID（如果已登录）作为限流键
    return req.ip + (req.user?.id || '');
  }
});

// 应用限流到所有地理编码路由
router.use(geocodingRateLimit);

/**
 * 地址搜索 (Geocoding)
 * GET /api/geocoding/search?q=地址&country=CN&limit=5
 */
router.get('/search', asyncHandler(async (req: any, res: any) => {
  const { q: address, country, limit = 5 } = req.query;

  // 参数验证
  if (!address || typeof address !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Address parameter is required'
    });
  }

  if (address.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Address cannot be empty'
    });
  }

  const parsedLimit = parseInt(limit as string, 10);
  if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 20) {
    return res.status(400).json({
      success: false,
      error: 'Limit must be between 1 and 20'
    });
  }

  let countryCode: string | undefined;
  if (country && typeof country === 'string') {
    countryCode = country.toUpperCase();
    // 验证国家代码格式（2位字母）
    if (!/^[A-Z]{2}$/.test(countryCode)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid country code format (must be 2 letters)'
      });
    }
  }

  try {
    logger.info('Geocoding search request', {
      address,
      country: countryCode,
      limit: parsedLimit,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const results = await geocodeAddress(address, countryCode, parsedLimit);

    // 格式化结果
    const formattedResults = results.map(result => ({
      place_id: result.place_id,
      display_name: result.display_name,
      formatted_address_zh: formatAddress(result.address, 'zh'),
      formatted_address_en: formatAddress(result.address, 'en'),
      coordinates: {
        latitude: parseFloat(result.lat),
        longitude: parseFloat(result.lon)
      },
      address_components: result.address,
      bounds: {
        northeast: {
          lat: parseFloat(result.boundingbox[1]),
          lng: parseFloat(result.boundingbox[3])
        },
        southwest: {
          lat: parseFloat(result.boundingbox[0]),
          lng: parseFloat(result.boundingbox[2])
        }
      },
      type: result.type,
      category: result.class,
      importance: result.importance
    }));

    res.json({
      success: true,
      data: {
        query: address,
        results: formattedResults,
        total: formattedResults.length,
        country_filter: countryCode
      }
    });

  } catch (error: any) {
    logger.error('Geocoding search failed', {
      address,
      country: countryCode,
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({
      success: false,
      error: 'Geocoding service error',
      message: process.env['NODE_ENV'] === 'development' ? error.message : undefined
    });
  }
}));

/**
 * 反向地理编码 (Reverse Geocoding)
 * GET /api/geocoding/reverse?lat=39.9042&lng=116.4074&zoom=18
 */
router.get('/reverse', asyncHandler(async (req: any, res: any) => {
  const { lat, lng, lon, zoom = 18 } = req.query;

  // 支持lng或lon参数
  const longitude = lng || lon;

  // 参数验证
  if (!lat || !longitude) {
    return res.status(400).json({
      success: false,
      error: 'Both lat and lng/lon parameters are required'
    });
  }

  const latitude = parseFloat(lat as string);
  const longitudeValue = parseFloat(longitude as string);
  const zoomLevel = parseInt(zoom as string, 10);

  if (isNaN(latitude) || isNaN(longitudeValue)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid coordinate format'
    });
  }

  if (latitude < -90 || latitude > 90) {
    return res.status(400).json({
      success: false,
      error: 'Latitude must be between -90 and 90'
    });
  }

  if (longitudeValue < -180 || longitudeValue > 180) {
    return res.status(400).json({
      success: false,
      error: 'Longitude must be between -180 and 180'
    });
  }

  if (isNaN(zoomLevel) || zoomLevel < 1 || zoomLevel > 18) {
    return res.status(400).json({
      success: false,
      error: 'Zoom level must be between 1 and 18'
    });
  }

  try {
    logger.info('Reverse geocoding request', {
      lat: latitude,
      lng: longitudeValue,
      zoom: zoomLevel,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const result = await reverseGeocode(latitude, longitudeValue, zoomLevel);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: 'No address found for the given coordinates'
      });
    }

    // 格式化结果
    const formattedResult = {
      place_id: result.place_id,
      display_name: result.display_name,
      formatted_address_zh: formatAddress(result.address, 'zh'),
      formatted_address_en: formatAddress(result.address, 'en'),
      coordinates: {
        latitude: parseFloat(result.lat),
        longitude: parseFloat(result.lon)
      },
      address_components: result.address,
      bounds: {
        northeast: {
          lat: parseFloat(result.boundingbox[1]),
          lng: parseFloat(result.boundingbox[3])
        },
        southwest: {
          lat: parseFloat(result.boundingbox[0]),
          lng: parseFloat(result.boundingbox[2])
        }
      },
      type: result.type,
      category: result.category,
      place_rank: result.place_rank,
      importance: result.importance
    };

    res.json({
      success: true,
      data: {
        query: {
          latitude,
          longitude: longitudeValue,
          zoom: zoomLevel
        },
        result: formattedResult
      }
    });

  } catch (error: any) {
    logger.error('Reverse geocoding failed', {
      lat: latitude,
      lng: longitudeValue,
      zoom: zoomLevel,
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({
      success: false,
      error: 'Reverse geocoding service error',
      message: process.env['NODE_ENV'] === 'development' ? error.message : undefined
    });
  }
}));

/**
 * 搜索附近POI
 * GET /api/geocoding/nearby?lat=39.9042&lng=116.4074&type=restaurant&radius=2&limit=10
 */
router.get('/nearby', asyncHandler(async (req: any, res: any) => {
  const { lat, lng, lon, type, radius = 5, limit = 10 } = req.query;

  // 支持lng或lon参数
  const longitude = lng || lon;

  // 参数验证
  if (!lat || !longitude || !type) {
    return res.status(400).json({
      success: false,
      error: 'lat, lng/lon, and type parameters are required'
    });
  }

  const latitude = parseFloat(lat as string);
  const longitudeValue = parseFloat(longitude as string);
  const searchRadius = parseFloat(radius as string);
  const searchLimit = parseInt(limit as string, 10);

  if (isNaN(latitude) || isNaN(longitudeValue)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid coordinate format'
    });
  }

  if (latitude < -90 || latitude > 90) {
    return res.status(400).json({
      success: false,
      error: 'Latitude must be between -90 and 90'
    });
  }

  if (longitudeValue < -180 || longitudeValue > 180) {
    return res.status(400).json({
      success: false,
      error: 'Longitude must be between -180 and 180'
    });
  }

  if (isNaN(searchRadius) || searchRadius <= 0 || searchRadius > 50) {
    return res.status(400).json({
      success: false,
      error: 'Radius must be between 0.1 and 50 km'
    });
  }

  if (isNaN(searchLimit) || searchLimit < 1 || searchLimit > 50) {
    return res.status(400).json({
      success: false,
      error: 'Limit must be between 1 and 50'
    });
  }

  // 验证POI类型
  const validPOITypes: POIType[] = [
    'restaurant', 'gas_station', 'atm', 'hospital', 'pharmacy', 
    'school', 'bank', 'hotel', 'shopping_mall', 'park',
    'bus_station', 'subway_station', 'convenience_store'
  ];

  if (!validPOITypes.includes(type as POIType)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid POI type',
      valid_types: validPOITypes
    });
  }

  try {
    logger.info('Nearby POI search request', {
      lat: latitude,
      lng: longitudeValue,
      type,
      radius: searchRadius,
      limit: searchLimit,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const results = await searchNearbyPOIs(
      latitude,
      longitudeValue,
      type as POIType,
      searchRadius,
      searchLimit
    );

    // 格式化结果
    const formattedResults = results.map(poi => ({
      place_id: poi.place_id,
      name: poi.name,
      display_name: poi.display_name,
      formatted_address: formatAddress(poi.address, 'zh'),
      coordinates: {
        latitude: parseFloat(poi.lat),
        longitude: parseFloat(poi.lon)
      },
      distance_km: poi.distance,
      distance_text: poi.distance ? 
        (poi.distance < 1 ? 
          `${Math.round(poi.distance * 1000)}米` : 
          `${poi.distance.toFixed(1)}公里`
        ) : undefined,
      type: poi.type,
      category: poi.class,
      importance: poi.importance,
      address_components: poi.address
    }));

    res.json({
      success: true,
      data: {
        query: {
          latitude,
          longitude: longitudeValue,
          type,
          radius_km: searchRadius,
          limit: searchLimit
        },
        results: formattedResults,
        total: formattedResults.length,
        center: {
          latitude,
          longitude: longitudeValue
        }
      }
    });

  } catch (error: any) {
    logger.error('Nearby POI search failed', {
      lat: latitude,
      lng: longitudeValue,
      type,
      radius: searchRadius,
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({
      success: false,
      error: 'POI search service error',
      message: process.env['NODE_ENV'] === 'development' ? error.message : undefined
    });
  }
}));

/**
 * IP地理位置查询
 * GET /api/geocoding/ip-location?ip=8.8.8.8 (IP参数可选，不提供则使用请求者IP)
 */
router.get('/ip-location', asyncHandler(async (req: any, res: any) => {
  let { ip } = req.query;

  // 如果没有提供IP，使用请求者的IP
  if (!ip) {
    ip = req.ip;
  }

  // 过滤本地IP地址
  if (ip === '::1' || ip === '127.0.0.1' || (ip as string).startsWith('192.168.') || (ip as string).startsWith('10.')) {
    return res.status(400).json({
      success: false,
      error: 'Cannot locate private/local IP addresses',
      suggestion: 'Try accessing from a public IP address or specify a public IP in the query'
    });
  }

  try {
    logger.info('IP location request', {
      ip: ip as string,
      requestIP: req.ip,
      userAgent: req.get('User-Agent')
    });

    const result = await getLocationByIP(ip as string);

    // 格式化结果
    const formattedResult = {
      ip: result.query,
      coordinates: {
        latitude: result.lat,
        longitude: result.lon
      },
      address: {
        city: result.city,
        region: result.regionName,
        region_code: result.region,
        country: result.country,
        country_code: result.countryCode,
        postal_code: result.zip
      },
      timezone: result.timezone,
      isp: result.isp
    };

    res.json({
      success: true,
      data: {
        query: { ip: ip as string },
        result: formattedResult
      }
    });

  } catch (error: any) {
    logger.error('IP location failed', {
      ip: ip as string,
      requestIP: req.ip,
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({
      success: false,
      error: 'IP location service error',
      message: process.env['NODE_ENV'] === 'development' ? error.message : undefined
    });
  }
}));

/**
 * 获取支持的POI类型列表
 * GET /api/geocoding/poi-types
 */
router.get('/poi-types', (_req: any, res: any) => {
  const poiTypes = [
    { type: 'restaurant', name: '餐厅', name_en: 'Restaurant' },
    { type: 'gas_station', name: '加油站', name_en: 'Gas Station' },
    { type: 'atm', name: 'ATM', name_en: 'ATM' },
    { type: 'hospital', name: '医院', name_en: 'Hospital' },
    { type: 'pharmacy', name: '药店', name_en: 'Pharmacy' },
    { type: 'school', name: '学校', name_en: 'School' },
    { type: 'bank', name: '银行', name_en: 'Bank' },
    { type: 'hotel', name: '酒店', name_en: 'Hotel' },
    { type: 'shopping_mall', name: '购物中心', name_en: 'Shopping Mall' },
    { type: 'park', name: '公园', name_en: 'Park' },
    { type: 'bus_station', name: '公交站', name_en: 'Bus Station' },
    { type: 'subway_station', name: '地铁站', name_en: 'Subway Station' },
    { type: 'convenience_store', name: '便利店', name_en: 'Convenience Store' }
  ];

  res.json({
    success: true,
    data: {
      poi_types: poiTypes,
      total: poiTypes.length
    }
  });
});

/**
 * 缓存管理接口（仅开发环境）
 */
if (process.env['NODE_ENV'] === 'development') {
  // 清理缓存
  router.delete('/cache', asyncHandler(async (_req: any, res: any) => {
    clearGeocodingCache();
    
    res.json({
      success: true,
      message: 'Geocoding cache cleared'
    });
  }));

  // 获取缓存统计
  router.get('/cache/stats', (_req: any, res: any) => {
    const stats = getGeocodingCacheStats();
    
    res.json({
      success: true,
      data: stats
    });
  });
}

export default router;