# OpenStreetMap 地图服务配置指南

SmellPin 项目已从 Google Maps 迁移到 OpenStreetMap (OSM) 作为主要地图服务提供商，以降低成本并提供更开放的地图解决方案。

## 1. OpenStreetMap 服务概述

### 核心服务
- **地图瓦片**: 使用 OpenStreetMap 瓦片服务器
- **地理编码**: 使用 Nominatim 服务进行地址搜索和逆地理编码
- **高级功能**: 可选使用 Mapbox 提供增强功能
- **备用服务**: 中国地区支持高德地图和百度地图

### 服务优势
- ✅ **免费开源**: 无 API 调用费用
- ✅ **全球覆盖**: 世界范围内的地图数据
- ✅ **社区驱动**: 活跃的开源社区维护
- ✅ **数据自主**: 无供应商锁定

## 2. 基础配置

### 2.1 OpenStreetMap 瓦片服务

OpenStreetMap 提供免费的瓦片服务，无需 API 密钥：

```bash
# 环境变量配置
NEXT_PUBLIC_OSM_TILE_URL=https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png
```

#### 瓦片服务器选择

| 服务器 | URL | 特点 |
|--------|-----|------|
| OpenStreetMap | `https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png` | 官方服务器，免费 |
| OpenTopoMap | `https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png` | 地形图 |
| CartoDB | `https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}.png` | 简洁风格 |

### 2.2 Nominatim 地理编码服务

Nominatim 提供地址搜索和逆地理编码服务：

```bash
# 环境变量配置
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org
```

#### 使用限制
- 最大请求频率: 1 请求/秒
- 包含 User-Agent 头部
- 遵循使用条款

### 2.3 Mapbox 增强服务 (可选)

对于需要高级功能的场景，可以配置 Mapbox：

```bash
# Mapbox 配置 (可选)
NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=pk.your_mapbox_access_token_here
```

#### Mapbox 功能
- 🗺️ 高质量地图样式
- 🔍 高级搜索功能
- 🛣️ 路线规划
- 📍 批量地理编码

## 3. 环境变量配置

### 3.1 前端配置

在 `.env` 文件中添加以下配置：

```bash
# === OpenStreetMap 地图服务配置 ===

# OSM 瓦片服务器
NEXT_PUBLIC_OSM_TILE_URL=https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png

# Nominatim 地理编码服务
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org

# Mapbox 服务 (可选，用于高级功能)
NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=pk.optional_mapbox_token_here

# 地图默认设置
NEXT_PUBLIC_MAP_DEFAULT_LAT=39.9042
NEXT_PUBLIC_MAP_DEFAULT_LNG=116.4074
NEXT_PUBLIC_MAP_DEFAULT_ZOOM=10
```

### 3.2 后端配置

对于服务器端地理编码：

```bash
# === 后端地理编码服务 ===

# Nominatim 服务配置
NOMINATIM_URL=https://nominatim.openstreetmap.org
NOMINATIM_USER_AGENT=SmellPin/1.0 (contact@smellpin.com)
NOMINATIM_RATE_LIMIT=1000  # 每小时请求限制

# 中国地区备用服务
AMAP_KEY=your_amap_key_for_china_region
BAIDU_MAP_AK=your_baidu_map_ak_for_china_region
```

### 3.3 生产环境配置

```bash
# === 生产环境地图服务配置 ===

# 使用自建瓦片服务器 (推荐)
NEXT_PUBLIC_OSM_TILE_URL=https://tiles.yourdomain.com/{z}/{x}/{y}.png

# 自建 Nominatim 实例
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.yourdomain.com

# Mapbox 生产环境配置
NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=pk.production_token_here
```

## 4. 代码集成示例

### 4.1 基础地图组件

```typescript
// components/Map/OSMMap.tsx
import { useEffect, useRef } from 'react';
import L from 'leaflet';

interface OSMMapProps {
  latitude: number;
  longitude: number;
  zoom?: number;
  markers?: Array<{lat: number, lng: number, popup?: string}>;
}

export const OSMMap: React.FC<OSMMapProps> = ({
  latitude,
  longitude,
  zoom = 13,
  markers = []
}) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapRef.current) return;

    // 初始化地图
    mapInstance.current = L.map(mapRef.current).setView([latitude, longitude], zoom);

    // 添加 OSM 瓦片层
    L.tileLayer(process.env.NEXT_PUBLIC_OSM_TILE_URL!, {
      attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 19
    }).addTo(mapInstance.current);

    // 添加标记
    markers.forEach(marker => {
      const leafletMarker = L.marker([marker.lat, marker.lng])
        .addTo(mapInstance.current!);
      
      if (marker.popup) {
        leafletMarker.bindPopup(marker.popup);
      }
    });

    return () => {
      if (mapInstance.current) {
        mapInstance.current.remove();
      }
    };
  }, [latitude, longitude, zoom, markers]);

  return <div ref={mapRef} className="h-full w-full" />;
};
```

### 4.2 地理编码服务

```typescript
// services/geocoding.ts
interface GeocodeResponse {
  lat: number;
  lng: number;
  display_name: string;
  address: {
    city?: string;
    country?: string;
    postcode?: string;
  };
}

export class GeocodingService {
  private baseUrl = process.env.NEXT_PUBLIC_NOMINATIM_URL;
  private userAgent = 'SmellPin/1.0';

  async searchAddress(query: string): Promise<GeocodeResponse[]> {
    const url = new URL('/search', this.baseUrl);
    url.searchParams.set('q', query);
    url.searchParams.set('format', 'json');
    url.searchParams.set('addressdetails', '1');
    url.searchParams.set('limit', '5');

    const response = await fetch(url.toString(), {
      headers: {
        'User-Agent': this.userAgent,
      }
    });

    if (!response.ok) {
      throw new Error(`Geocoding failed: ${response.statusText}`);
    }

    const data = await response.json();
    
    return data.map((item: any) => ({
      lat: parseFloat(item.lat),
      lng: parseFloat(item.lon),
      display_name: item.display_name,
      address: item.address || {}
    }));
  }

  async reverseGeocode(lat: number, lng: number): Promise<GeocodeResponse> {
    const url = new URL('/reverse', this.baseUrl);
    url.searchParams.set('lat', lat.toString());
    url.searchParams.set('lon', lng.toString());
    url.searchParams.set('format', 'json');
    url.searchParams.set('addressdetails', '1');

    const response = await fetch(url.toString(), {
      headers: {
        'User-Agent': this.userAgent,
      }
    });

    if (!response.ok) {
      throw new Error(`Reverse geocoding failed: ${response.statusText}`);
    }

    const data = await response.json();
    
    return {
      lat: parseFloat(data.lat),
      lng: parseFloat(data.lon),
      display_name: data.display_name,
      address: data.address || {}
    };
  }
}
```

### 4.3 Mapbox 增强功能 (可选)

```typescript
// services/mapbox.ts
export class MapboxService {
  private accessToken = process.env.NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN;
  private baseUrl = 'https://api.mapbox.com';

  async searchPlaces(query: string, proximity?: [number, number]): Promise<any[]> {
    if (!this.accessToken) {
      throw new Error('Mapbox access token not configured');
    }

    const url = new URL('/geocoding/v5/mapbox.places', this.baseUrl);
    url.pathname += `/${encodeURIComponent(query)}.json`;
    url.searchParams.set('access_token', this.accessToken);
    url.searchParams.set('limit', '5');
    
    if (proximity) {
      url.searchParams.set('proximity', proximity.join(','));
    }

    const response = await fetch(url.toString());
    
    if (!response.ok) {
      throw new Error(`Mapbox search failed: ${response.statusText}`);
    }

    const data = await response.json();
    return data.features || [];
  }
}
```

## 5. 中国地区备用配置

### 5.1 高德地图配置

```typescript
// services/amap.ts
export class AmapService {
  private key = process.env.AMAP_KEY;
  private baseUrl = 'https://restapi.amap.com/v3';

  async geocode(address: string): Promise<any> {
    const url = new URL('/geocode/geo', this.baseUrl);
    url.searchParams.set('key', this.key!);
    url.searchParams.set('address', address);

    const response = await fetch(url.toString());
    const data = await response.json();
    
    return data;
  }
}
```

### 5.2 区域检测和服务切换

```typescript
// utils/mapService.ts
export class MapServiceManager {
  private isChina(): boolean {
    // 检测用户是否在中国地区
    return navigator.language.includes('zh-CN');
  }

  getGeocodingService() {
    if (this.isChina()) {
      return new AmapService();
    }
    return new GeocodingService();
  }
}
```

## 6. 性能优化

### 6.1 瓦片缓存

```nginx
# Nginx 配置示例
location ~* \.(png|jpg|jpeg)$ {
    expires 7d;
    add_header Cache-Control "public, immutable";
    proxy_pass https://tile.openstreetmap.org;
}
```

### 6.2 请求限制

```typescript
// utils/rateLimiter.ts
class RateLimiter {
  private requests: number[] = [];
  private maxRequests = 1; // 每秒最大请求数
  private timeWindow = 1000; // 1秒

  async throttle(): Promise<void> {
    const now = Date.now();
    
    // 清理过期请求
    this.requests = this.requests.filter(time => now - time < this.timeWindow);
    
    if (this.requests.length >= this.maxRequests) {
      const waitTime = this.timeWindow - (now - this.requests[0]);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.requests.push(now);
  }
}
```

## 7. 部署配置

### 7.1 Docker 环境变量

```yaml
# docker-compose.yml
services:
  frontend:
    environment:
      - NEXT_PUBLIC_OSM_TILE_URL=https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png
      - NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org
      - NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=${MAPBOX_ACCESS_TOKEN}
```

### 7.2 Vercel 部署

```json
// vercel.json
{
  "env": {
    "NEXT_PUBLIC_OSM_TILE_URL": "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    "NEXT_PUBLIC_NOMINATIM_URL": "https://nominatim.openstreetmap.org"
  }
}
```

## 8. 监控和维护

### 8.1 服务监控

```typescript
// utils/serviceMonitor.ts
export class ServiceMonitor {
  async checkOSMHealth(): Promise<boolean> {
    try {
      const response = await fetch('https://tile.openstreetmap.org/0/0/0.png');
      return response.ok;
    } catch {
      return false;
    }
  }

  async checkNominatimHealth(): Promise<boolean> {
    try {
      const response = await fetch('https://nominatim.openstreetmap.org/status');
      return response.ok;
    } catch {
      return false;
    }
  }
}
```

### 8.2 错误处理

```typescript
// utils/mapErrorHandler.ts
export class MapErrorHandler {
  static handleTileLoadError(error: Error) {
    console.warn('Map tile load failed, switching to backup server', error);
    // 切换到备用瓦片服务器
  }

  static handleGeocodingError(error: Error) {
    console.warn('Geocoding service failed, trying backup service', error);
    // 切换到备用地理编码服务
  }
}
```

## 9. 迁移检查清单

- [ ] 移除所有 Google Maps API 密钥引用
- [ ] 更新环境变量配置
- [ ] 测试地图瓦片加载
- [ ] 验证地理编码功能
- [ ] 测试标记和弹窗功能
- [ ] 检查移动端响应性
- [ ] 验证中国地区备用服务
- [ ] 更新文档和部署配置
- [ ] 进行性能测试
- [ ] 配置监控和告警

## 10. 故障排除

### 10.1 常见问题

**瓦片加载失败**
```javascript
// 解决方案：使用备用瓦片服务器
const backupTileUrls = [
  'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
  'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}.png'
];
```

**地理编码请求频率限制**
```javascript
// 解决方案：实现请求节流
const rateLimiter = new RateLimiter();
await rateLimiter.throttle();
```

**CORS 跨域问题**
```javascript
// 解决方案：使用代理或自建服务
const proxyUrl = '/api/nominatim/search';
```

### 10.2 性能问题

- 使用 CDN 缓存瓦片
- 实现瓦片预加载
- 优化标记聚类
- 限制同时显示的标记数量

## 11. 相关资源

- [OpenStreetMap 官网](https://www.openstreetmap.org/)
- [Nominatim 文档](https://nominatim.org/release-docs/latest/)
- [Leaflet 地图库](https://leafletjs.com/)
- [Mapbox GL JS](https://docs.mapbox.com/mapbox-gl-js/)
- [OSM 瓦片服务器列表](https://wiki.openstreetmap.org/wiki/Tile_servers)

---

**注意**: OpenStreetMap 服务是免费的，但请遵循使用条款，避免过度请求。在生产环境中建议自建服务或使用商业服务以获得更好的性能和稳定性。