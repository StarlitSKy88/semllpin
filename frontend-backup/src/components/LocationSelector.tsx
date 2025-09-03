import React, { useState, useEffect, useCallback } from 'react';
import { Search, MapPin, Clock, X } from 'lucide-react';
import locationService from '../services/locationService';
import type { Location, GeocodeResult } from '../services/locationService';

interface LocationSelectorProps {
  coordinates: [number, number]; // [lng, lat]
  isVisible: boolean;
  onLocationSelect: (location: Location) => void;
  onClose: () => void;
}

const LocationSelector: React.FC<LocationSelectorProps> = ({
  coordinates,
  isVisible,
  onLocationSelect,
  onClose
}) => {
  const [locations, setLocations] = useState<Location[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Location[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'nearby' | 'search'>('nearby');

  const loadNearbyLocations = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const result: GeocodeResult = await locationService.reverseGeocode(coordinates);
      
      if (result.success) {
        setLocations(result.locations);
      } else {
        setError(result.error || '获取附近地点失败');
      }
    } catch (_err) {
      setError('网络错误，请重试');
    } finally {
      setIsLoading(false);
    }
  }, [coordinates]);

  // 获取附近地点
  useEffect(() => {
    if (isVisible && coordinates) {
      loadNearbyLocations();
    }
  }, [isVisible, coordinates, loadNearbyLocations]);

  // 搜索地点
  const handleSearch = async (query: string) => {
    if (!query.trim()) {
      setSearchResults([]);
      return;
    }

    setIsSearching(true);
    setError(null);
    
    try {
      const result: GeocodeResult = await locationService.geocode(query);
      
      if (result.success) {
        setSearchResults(result.locations);
      } else {
        setError(result.error || '搜索失败');
        setSearchResults([]);
      }
    } catch (_err) {
      setError('搜索出错，请重试');
      setSearchResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  // 处理搜索输入
  const handleSearchInput = (value: string) => {
    setSearchQuery(value);
    
    // 防抖搜索
    const timeoutId = setTimeout(() => {
      handleSearch(value);
    }, 500);
    
    return () => clearTimeout(timeoutId);
  };

  // 选择地点
  const handleLocationClick = (location: Location) => {
    onLocationSelect(location);
    onClose();
  };

  // 获取地点图标
  const getLocationIcon = (category?: string) => {
    switch (category) {
      case 'coffee':
        return '☕';
      case 'food':
        return '🍽️';
      case 'flower':
        return '🌸';
      case 'nature':
        return '🌳';
      default:
        return '📍';
    }
  };

  // 格式化距离
  const formatDistance = (location: Location) => {
    if (location.distance !== undefined) {
      return location.distance < 1 
        ? `${Math.round(location.distance * 1000)}m`
        : `${location.distance.toFixed(1)}km`;
    }
    
    // 计算距离
    const distance = locationService.calculateDistance(coordinates, location.coordinates);
    return distance < 1 
      ? `${Math.round(distance * 1000)}m`
      : `${distance.toFixed(1)}km`;
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-end justify-center z-50">
      <div className="bg-white rounded-t-2xl w-full max-w-md max-h-[70vh] flex flex-col">
        {/* 头部 */}
        <div className="flex items-center justify-between p-4 border-b">
          <h3 className="text-lg font-semibold text-gray-900">选择地点</h3>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* 标签页 */}
        <div className="flex border-b">
          <button
            onClick={() => setActiveTab('nearby')}
            className={`flex-1 py-3 px-4 text-sm font-medium transition-colors ${
              activeTab === 'nearby'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            附近地点
          </button>
          <button
            onClick={() => setActiveTab('search')}
            className={`flex-1 py-3 px-4 text-sm font-medium transition-colors ${
              activeTab === 'search'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            搜索地点
          </button>
        </div>

        {/* 搜索框 */}
        {activeTab === 'search' && (
          <div className="p-4 border-b">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => handleSearchInput(e.target.value)}
                placeholder="搜索地点名称或地址..."
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        )}

        {/* 内容区域 */}
        <div className="flex-1 overflow-y-auto">
          {/* 错误提示 */}
          {error && (
            <div className="p-4 bg-red-50 border-l-4 border-red-400">
              <p className="text-red-700 text-sm">{error}</p>
            </div>
          )}

          {/* 加载状态 */}
          {(isLoading || isSearching) && (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <span className="ml-2 text-gray-600">
                {activeTab === 'nearby' ? '获取附近地点...' : '搜索中...'}
              </span>
            </div>
          )}

          {/* 地点列表 */}
          {!isLoading && !isSearching && (
            <div className="divide-y divide-gray-200">
              {(activeTab === 'nearby' ? locations : searchResults).map((location) => (
                <button
                  key={location.id}
                  onClick={() => handleLocationClick(location)}
                  className="w-full p-4 text-left hover:bg-gray-50 transition-colors focus:outline-none focus:bg-gray-50"
                >
                  <div className="flex items-start space-x-3">
                    <div className="text-2xl">{getLocationIcon(location.category)}</div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-medium text-gray-900 truncate">
                        {location.name}
                      </h4>
                      <p className="text-xs text-gray-500 mt-1 line-clamp-2">
                        {location.address}
                      </p>
                      <div className="flex items-center mt-2 space-x-4">
                        <div className="flex items-center text-xs text-gray-400">
                          <MapPin className="w-3 h-3 mr-1" />
                          {formatDistance(location)}
                        </div>
                        {location.type && (
                          <div className="flex items-center text-xs text-gray-400">
                            <Clock className="w-3 h-3 mr-1" />
                            {location.type}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* 空状态 */}
          {!isLoading && !isSearching && (
            <>
              {activeTab === 'nearby' && locations.length === 0 && (
                <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                  <MapPin className="w-12 h-12 mb-2 text-gray-300" />
                  <p className="text-sm">附近没有找到地点</p>
                  <p className="text-xs mt-1">尝试搜索具体地点名称</p>
                </div>
              )}
              
              {activeTab === 'search' && searchQuery && searchResults.length === 0 && (
                <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                  <Search className="w-12 h-12 mb-2 text-gray-300" />
                  <p className="text-sm">没有找到匹配的地点</p>
                  <p className="text-xs mt-1">尝试使用不同的关键词</p>
                </div>
              )}
              
              {activeTab === 'search' && !searchQuery && (
                <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                  <Search className="w-12 h-12 mb-2 text-gray-300" />
                  <p className="text-sm">输入地点名称或地址进行搜索</p>
                </div>
              )}
            </>
          )}
        </div>

        {/* 底部提示 */}
        <div className="p-4 bg-gray-50 border-t">
          <p className="text-xs text-gray-500 text-center">
            选择一个地点来创建标注
          </p>
        </div>
      </div>
    </div>
  );
};

export default LocationSelector;