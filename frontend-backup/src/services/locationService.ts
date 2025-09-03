interface Location {
  id: string;
  name: string;
  address: string;
  coordinates: [number, number]; // [lng, lat]
  type: string;
  category?: string;
  distance?: number;
}

interface GeocodeResult {
  locations: Location[];
  success: boolean;
  error?: string;
}

// 为后端与 Nominatim 结果增加明确类型，避免 any
type BackendItem = {
  id?: string;
  name?: string;
  display_name?: string;
  address?: string;
  lng?: number;
  lon?: number;
  longitude?: number | string;
  lat?: number;
  latitude?: number | string;
  type?: string;
  category?: string;
};

interface NominatimSearchItem {
  place_id?: number | string;
  display_name?: string;
  name?: string;
  lon?: string | number;
  lat?: string | number;
  type?: string;
  addresstype?: string;
  category?: string;
}

interface NominatimReverseItem {
  place_id?: number | string;
  display_name?: string;
  name?: string;
  lon?: string | number;
  lat?: string | number;
  type?: string;
  category?: string;
  address?: { type?: string };
  geojson?: { coordinates?: [number, number] };
}

class LocationService {
  private readonly API_BASE_URL = import.meta.env.VITE_API_URL;

  /**
   * 反向地理编码 - 根据坐标获取地点信息
   */
  async reverseGeocode(coordinates: [number, number]): Promise<GeocodeResult> {
    try {
      const [lng, lat] = coordinates;
      
      // 优先使用后端API
      if (this.API_BASE_URL) {
        const response = await fetch(`${this.API_BASE_URL}/api/geocoding/reverse`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ lat, lng })
        });

        if (response.ok) {
          const data = await response.json();
          return {
            locations: this.formatBackendResults(data.results || []),
            success: true
          };
        }
      }

      // 前端回退：使用 Nominatim (OpenStreetMap)
      const nominatimUrl = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&addressdetails=1&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lng)}`;
      const nominatimResp = await fetch(nominatimUrl, {
        headers: {
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
        }
      });
      if (nominatimResp.ok) {
        const result = await nominatimResp.json();
        return {
          locations: this.formatNominatimReverseResult(result),
          success: true
        };
      }

      // 最后备用：模拟数据
      return this.getMockLocations(coordinates);
    } catch (error) {
      console.error('反向地理编码失败:', error);
      return {
        locations: [],
        success: false,
        error: '获取地点信息失败'
      };
    }
  }

  /**
   * 地理编码 - 根据地址搜索地点
   */
  async geocode(query: string): Promise<GeocodeResult> {
    try {
      // 优先使用后端API
      if (this.API_BASE_URL) {
        const response = await fetch(`${this.API_BASE_URL}/api/geocoding/search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ query })
        });

        if (response.ok) {
          const data = await response.json();
          return {
            locations: this.formatBackendResults(data.results || []),
            success: true
          };
        }
      }

      // 前端回退：使用 Nominatim (OpenStreetMap)
      const searchUrl = `https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=10&q=${encodeURIComponent(query)}`;
      const nominatimResp = await fetch(searchUrl, {
        headers: {
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
        }
      });
      if (nominatimResp.ok) {
        const results = await nominatimResp.json();
        return {
          locations: this.formatNominatimResults(results || []),
          success: true
        };
      }

      // 最后备用：模拟搜索结果
      return this.getMockSearchResults(query);
    } catch (error) {
      console.error('地理编码失败:', error);
      return {
        locations: [],
        success: false,
        error: '搜索地点失败'
      };
    }
  }

  /**
   * 格式化后端API结果
   */
  private formatBackendResults(results: unknown[]): Location[] {
    return results.map((result, index) => {
      const item = result as Record<string, unknown> & BackendItem;

      const lon = typeof item.lng === 'number'
        ? item.lng
        : typeof item.lon === 'number'
          ? item.lon
          : typeof item.longitude === 'string' || typeof item.longitude === 'number'
            ? Number(item.longitude)
            : 0;

      const lat = typeof item.lat === 'number'
        ? item.lat
        : typeof item.latitude === 'string' || typeof item.latitude === 'number'
          ? Number(item.latitude)
          : 0;

      return {
        id: (item.id as string) || `backend-${index}`,
        name: (item.name as string) || (item.display_name as string) || '未知地点',
        address: (item.address as string) || (item.display_name as string) || '',
        coordinates: [lon, lat] as [number, number],
        type: (item.type as string) || 'place',
        category: (item.category as string) || undefined
      };
    });
  }

  /**
   * 将 Nominatim 搜索结果格式化为通用 Location 数组
   */
  private formatNominatimResults(results: NominatimSearchItem[]): Location[] {
    return results.map((r: NominatimSearchItem, idx: number) => ({
      id: r.place_id ? String(r.place_id) : `nominatim-${idx}`,
      name: (r.display_name?.split(',')[0] || r.name || '未知地点') as string,
      address: r.display_name || '',
      coordinates: [Number(r.lon), Number(r.lat)] as [number, number],
      type: (r.type || r.addresstype || 'place') as string,
      category: r.category || undefined
    }));
  }

  /**
   * 将 Nominatim 反向地理编码结果格式化为通用 Location 数组
   */
  private formatNominatimReverseResult(result: NominatimReverseItem): Location[] {
    if (!result) return [];
    const name = (result.name || result.display_name?.split(',')[0] || '未知地点') as string;
    const address = result.display_name || '';
    const lon = Number(result.lon ?? result?.geojson?.coordinates?.[0] ?? 0);
    const lat = Number(result.lat ?? result?.geojson?.coordinates?.[1] ?? 0);
    return [
      {
        id: result.place_id ? String(result.place_id) : 'nominatim-reverse-0',
        name,
        address,
        coordinates: [lon, lat],
        type: (result.type || result?.address?.type || 'place') as string,
        category: result.category || undefined
      }
    ];
  }

  /**
   * 获取模拟地点数据（备用方案）
   */
  private getMockLocations(coordinates: [number, number]): GeocodeResult {
    const [lng, lat] = coordinates;
    
    const mockLocations: Location[] = [
      {
        id: 'mock-1',
        name: '星巴克咖啡',
        address: `${lat.toFixed(4)}, ${lng.toFixed(4)}附近`,
        coordinates: [lng + 0.001, lat + 0.001],
        type: 'establishment',
        category: 'coffee'
      },
      {
        id: 'mock-2',
        name: '花店',
        address: `${lat.toFixed(4)}, ${lng.toFixed(4)}附近`,
        coordinates: [lng - 0.001, lat + 0.001],
        type: 'establishment',
        category: 'flower'
      },
      {
        id: 'mock-3',
        name: '烧烤摊',
        address: `${lat.toFixed(4)}, ${lng.toFixed(4)}附近`,
        coordinates: [lng + 0.0005, lat - 0.0005],
        type: 'establishment',
        category: 'food'
      }
    ];

    return {
      locations: mockLocations,
      success: true
    };
  }

  /**
   * 模拟搜索结果（备用方案）
   */
  private getMockSearchResults(query: string): GeocodeResult {
    const baseCoord: [number, number] = [116.4074, 39.9042];
    return {
      locations: [
        {
          id: 'mock-s-1',
          name: `${query} 咖啡店`,
          address: '北京市朝阳区',
          coordinates: [baseCoord[0] + 0.002, baseCoord[1] + 0.002],
          type: 'establishment',
          category: 'coffee'
        },
        {
          id: 'mock-s-2',
          name: `${query} 花园`,
          address: '北京市东城区',
          coordinates: [baseCoord[0] - 0.0015, baseCoord[1] + 0.001],
          type: 'park',
          category: 'nature'
        }
      ],
      success: true
    };
  }

  /**
   * 计算两点之间距离（米）
   */
  calculateDistance(coord1: [number, number], coord2: [number, number]): number {
    const [lng1, lat1] = coord1.map(Number) as [number, number];
    const [lng2, lat2] = coord2.map(Number) as [number, number];

    const toRad = (x: number) => (x * Math.PI) / 180;
    const R = 6371000; // 地球半径（米）
    const dLat = toRad(lat2 - lat1);
    const dLng = toRad(lng2 - lng1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
      Math.sin(dLng / 2) * Math.sin(dLng / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }
}

export default new LocationService();
export type { Location, GeocodeResult };