import React, { useState, useEffect } from 'react';
import {
  geocodeAddress,
  reverseGeocode,
  searchNearbyPOIs,
  getLocationByIP,
  getCurrentPosition,
  calculateDistance,
  formatDistance,
  POI_TYPE_MAP,
  type GeocodingResult,
  type ReverseGeocodingResult,
  type POISearchResult,
  type IPLocationResult,
  type POIType
} from '../lib/geocoding';

/**
 * SmellPin 地理编码服务使用示例组件
 */
export default function GeocodingExample() {
  // 状态管理
  const [address, setAddress] = useState('');
  const [searchResults, setSearchResults] = useState<GeocodingResult[]>([]);
  const [reverseResult, setReverseResult] = useState<ReverseGeocodingResult | null>(null);
  const [poiResults, setPOIResults] = useState<POISearchResult[]>([]);
  const [ipLocation, setIPLocation] = useState<IPLocationResult | null>(null);
  const [userLocation, setUserLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [selectedPOIType, setSelectedPOIType] = useState<POIType>('restaurant');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 清除错误信息
  const clearError = () => setError(null);

  // 地址搜索
  const handleAddressSearch = async () => {
    if (!address.trim()) {
      setError('请输入地址');
      return;
    }

    setLoading(true);
    clearError();

    try {
      const results = await geocodeAddress(address, {
        country: 'CN', // 优先搜索中国地址
        limit: 5
      });

      setSearchResults(results);
      if (results.length === 0) {
        setError('未找到匹配的地址');
      }
    } catch (err: any) {
      setError(err.message || '地址搜索失败');
    } finally {
      setLoading(false);
    }
  };

  // 反向地理编码
  const handleReverseGeocode = async (lat: number, lng: number) => {
    setLoading(true);
    clearError();

    try {
      const result = await reverseGeocode(lat, lng, { zoom: 18 });
      setReverseResult(result);
      
      if (!result) {
        setError('未找到该坐标对应的地址');
      }
    } catch (err: any) {
      setError(err.message || '反向地理编码失败');
    } finally {
      setLoading(false);
    }
  };

  // 搜索附近POI
  const handlePOISearch = async (lat: number, lng: number, type: POIType) => {
    setLoading(true);
    clearError();

    try {
      const results = await searchNearbyPOIs(lat, lng, type, {
        radius: 2, // 2公里范围
        limit: 10
      });

      setPOIResults(results);
      if (results.length === 0) {
        setError(`附近没有找到${POI_TYPE_MAP[type].name}`);
      }
    } catch (err: any) {
      setError(err.message || 'POI搜索失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取用户位置
  const handleGetUserLocation = async () => {
    setLoading(true);
    clearError();

    try {
      const position = await getCurrentPosition({
        enableHighAccuracy: true,
        timeout: 10000
      });

      const { latitude, longitude } = position.coords;
      setUserLocation({ lat: latitude, lng: longitude });

      // 自动进行反向地理编码
      await handleReverseGeocode(latitude, longitude);
    } catch (err: any) {
      let errorMsg = '获取位置失败';
      if (err.code === 1) {
        errorMsg = '用户拒绝了地理位置权限';
      } else if (err.code === 2) {
        errorMsg = '位置信息不可用';
      } else if (err.code === 3) {
        errorMsg = '获取位置超时';
      }
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  // 获取IP位置
  const handleGetIPLocation = async () => {
    setLoading(true);
    clearError();

    try {
      const location = await getLocationByIP();
      setIPLocation(location);
    } catch (err: any) {
      setError(err.message || 'IP定位失败');
    } finally {
      setLoading(false);
    }
  };

  // 组件挂载时获取IP位置
  useEffect(() => {
    handleGetIPLocation();
  }, []);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-8">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h1 className="text-3xl font-bold text-gray-800 mb-2">
          SmellPin 地理编码服务示例
        </h1>
        <p className="text-gray-600 mb-6">
          基于OpenStreetMap Nominatim API的完整地理编码解决方案
        </p>

        {/* 错误提示 */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-md p-4 mb-6">
            <div className="flex">
              <div className="flex-shrink-0">
                <span className="text-red-400">❌</span>
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-800">{error}</p>
              </div>
              <div className="ml-auto pl-3">
                <button
                  onClick={clearError}
                  className="text-red-400 hover:text-red-600"
                >
                  ✕
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 加载状态 */}
        {loading && (
          <div className="bg-blue-50 border border-blue-200 rounded-md p-4 mb-6">
            <div className="flex items-center">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
              <p className="ml-3 text-sm text-blue-800">处理中...</p>
            </div>
          </div>
        )}
      </div>

      {/* 1. 地址搜索 */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          🔍 地址搜索 (Geocoding)
        </h2>
        
        <div className="flex space-x-4 mb-4">
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="输入地址，如：北京天安门、上海外滩..."
            className="flex-1 px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            onKeyPress={(e) => e.key === 'Enter' && handleAddressSearch()}
          />
          <button
            onClick={handleAddressSearch}
            disabled={loading}
            className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            搜索
          </button>
        </div>

        {/* 搜索结果 */}
        {searchResults.length > 0 && (
          <div className="space-y-3">
            <h3 className="font-medium text-gray-700">搜索结果:</h3>
            {searchResults.map((result, index) => (
              <div key={result.place_id} className="border rounded-md p-4 hover:bg-gray-50">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <p className="font-medium text-gray-800">
                      {result.formatted_address_zh}
                    </p>
                    <p className="text-sm text-gray-600 mt-1">
                      {result.formatted_address_en}
                    </p>
                    <p className="text-xs text-gray-500 mt-2">
                      坐标: {result.coordinates.latitude.toFixed(6)}, {result.coordinates.longitude.toFixed(6)}
                    </p>
                  </div>
                  <div className="ml-4 space-x-2">
                    <button
                      onClick={() => handleReverseGeocode(
                        result.coordinates.latitude,
                        result.coordinates.longitude
                      )}
                      className="text-sm px-3 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
                    >
                      反查
                    </button>
                    <button
                      onClick={() => handlePOISearch(
                        result.coordinates.latitude,
                        result.coordinates.longitude,
                        selectedPOIType
                      )}
                      className="text-sm px-3 py-1 bg-green-100 text-green-700 rounded hover:bg-green-200"
                    >
                      找POI
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 2. 用户位置获取 */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          📍 获取当前位置
        </h2>
        
        <div className="flex space-x-4 mb-4">
          <button
            onClick={handleGetUserLocation}
            disabled={loading}
            className="px-6 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
          >
            获取GPS位置
          </button>
          <button
            onClick={handleGetIPLocation}
            disabled={loading}
            className="px-6 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 disabled:opacity-50"
          >
            获取IP位置
          </button>
        </div>

        {/* 用户GPS位置 */}
        {userLocation && (
          <div className="bg-green-50 border border-green-200 rounded-md p-4 mb-4">
            <h3 className="font-medium text-green-800 mb-2">GPS位置:</h3>
            <p className="text-sm text-green-700">
              坐标: {userLocation.lat.toFixed(6)}, {userLocation.lng.toFixed(6)}
            </p>
          </div>
        )}

        {/* IP位置 */}
        {ipLocation && (
          <div className="bg-purple-50 border border-purple-200 rounded-md p-4">
            <h3 className="font-medium text-purple-800 mb-2">IP位置:</h3>
            <p className="text-sm text-purple-700">
              {ipLocation.address.city}, {ipLocation.address.region}, {ipLocation.address.country}
            </p>
            <p className="text-xs text-purple-600 mt-1">
              坐标: {ipLocation.coordinates.latitude}, {ipLocation.coordinates.longitude}
            </p>
            <p className="text-xs text-purple-600">
              ISP: {ipLocation.isp}
            </p>
          </div>
        )}
      </div>

      {/* 3. 反向地理编码 */}
      {reverseResult && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold text-gray-800 mb-4">
            🎯 反向地理编码结果
          </h2>
          
          <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
            <p className="font-medium text-blue-800 mb-2">
              {reverseResult.formatted_address_zh}
            </p>
            <p className="text-sm text-blue-700 mb-2">
              {reverseResult.formatted_address_en}
            </p>
            <div className="text-xs text-blue-600 space-y-1">
              <p>坐标: {reverseResult.coordinates.latitude}, {reverseResult.coordinates.longitude}</p>
              <p>类型: {reverseResult.type} / {reverseResult.category}</p>
              {reverseResult.importance && (
                <p>重要性: {(reverseResult.importance * 100).toFixed(1)}%</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 4. POI搜索 */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          🏪 附近POI搜索
        </h2>
        
        <div className="flex space-x-4 mb-4">
          <select
            value={selectedPOIType}
            onChange={(e) => setSelectedPOIType(e.target.value as POIType)}
            className="px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
          >
            {Object.entries(POI_TYPE_MAP).map(([type, info]) => (
              <option key={type} value={type}>
                {info.icon} {info.name}
              </option>
            ))}
          </select>
          
          {(userLocation || (searchResults.length > 0)) && (
            <button
              onClick={() => {
                const coords = userLocation || {
                  lat: searchResults[0].coordinates.latitude,
                  lng: searchResults[0].coordinates.longitude
                };
                handlePOISearch(coords.lat, coords.lng, selectedPOIType);
              }}
              disabled={loading}
              className="px-6 py-2 bg-orange-600 text-white rounded-md hover:bg-orange-700 disabled:opacity-50"
            >
              搜索附近的{POI_TYPE_MAP[selectedPOIType].name}
            </button>
          )}
        </div>

        {/* POI结果 */}
        {poiResults.length > 0 && (
          <div className="space-y-3">
            <h3 className="font-medium text-gray-700">
              找到 {poiResults.length} 个{POI_TYPE_MAP[selectedPOIType].name}:
            </h3>
            {poiResults.map((poi, index) => (
              <div key={poi.place_id} className="border rounded-md p-4 hover:bg-gray-50">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-lg">{POI_TYPE_MAP[selectedPOIType].icon}</span>
                      <p className="font-medium text-gray-800">
                        {poi.name || poi.display_name}
                      </p>
                    </div>
                    <p className="text-sm text-gray-600">
                      {poi.formatted_address}
                    </p>
                    <div className="text-xs text-gray-500 mt-2 space-x-4">
                      <span>📍 {poi.coordinates.latitude.toFixed(6)}, {poi.coordinates.longitude.toFixed(6)}</span>
                      {poi.distance_text && (
                        <span>📏 {poi.distance_text}</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 5. 距离计算示例 */}
      {userLocation && searchResults.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold text-gray-800 mb-4">
            📏 距离计算
          </h2>
          
          {searchResults.slice(0, 3).map((result, index) => {
            const distance = calculateDistance(
              userLocation.lat,
              userLocation.lng,
              result.coordinates.latitude,
              result.coordinates.longitude
            );
            
            return (
              <div key={result.place_id} className="border-b last:border-b-0 py-3">
                <div className="flex justify-between items-center">
                  <div>
                    <p className="font-medium text-gray-800">
                      {result.formatted_address_zh}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-lg font-semibold text-blue-600">
                      {formatDistance(distance)}
                    </p>
                    <p className="text-xs text-gray-500">
                      从当前位置
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 使用说明 */}
      <div className="bg-gray-50 rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          📚 使用说明
        </h2>
        <div className="grid md:grid-cols-2 gap-6 text-sm text-gray-600">
          <div>
            <h3 className="font-medium text-gray-800 mb-2">功能特性:</h3>
            <ul className="space-y-1">
              <li>• 支持中英文地址查询</li>
              <li>• 反向地理编码（坐标转地址）</li>
              <li>• 附近POI搜索（13种类型）</li>
              <li>• GPS和IP地理定位</li>
              <li>• 距离计算和格式化</li>
              <li>• 自动缓存提升性能</li>
            </ul>
          </div>
          <div>
            <h3 className="font-medium text-gray-800 mb-2">技术栈:</h3>
            <ul className="space-y-1">
              <li>• OpenStreetMap Nominatim API</li>
              <li>• Node.js + TypeScript 后端</li>
              <li>• React + TypeScript 前端</li>
              <li>• Redis 缓存优化</li>
              <li>• 限流和错误处理</li>
              <li>• RESTful API 设计</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}