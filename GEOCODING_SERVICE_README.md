# SmellPin 地理编码服务

SmellPin项目的完整地理编码解决方案，基于OpenStreetMap的Nominatim API，提供高性能、多语言支持的地理编码服务。

## 🌟 功能特性

### 核心功能
- **地址转坐标 (Geocoding)** - 将地址文本转换为精确的经纬度坐标
- **坐标转地址 (Reverse Geocoding)** - 将经纬度坐标转换为可读的地址信息
- **附近POI搜索** - 搜索指定位置附近的兴趣点（餐厅、酒店、ATM等）
- **IP地理定位** - 根据IP地址获取大概的地理位置

### 技术特性
- **多语言支持** - 支持中文和英文地址查询和返回
- **智能缓存** - Redis缓存机制，提高查询性能
- **限流保护** - API请求限流，防止滥用
- **错误处理** - 完善的错误处理和重试机制
- **类型安全** - 完整的TypeScript类型定义

## 📁 项目结构

```
/src/services/geocoding.ts         # 后端地理编码服务核心逻辑
/src/routes/geocoding.ts           # 地理编码API路由定义
/frontend/lib/geocoding.ts         # 前端地理编码工具库
/frontend/types/index.ts           # TypeScript类型定义
/frontend/examples/               # 使用示例
test-geocoding-api.js             # API测试脚本
```

## 🚀 快速开始

### 1. 环境配置

确保在 `.env` 文件中配置了以下环境变量：

```env
# OpenStreetMap Nominatim API
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org

# 数据库和缓存配置
DATABASE_URL=your_database_url
REDIS_URL=your_redis_url
```

### 2. 安装依赖

```bash
# 后端依赖
npm install node-cache axios

# 前端依赖已包含在项目中
```

### 3. 启动服务

```bash
# 启动后端服务
npm run dev

# 启动前端服务（新终端窗口）
cd frontend && npm run dev
```

## 📚 API 文档

### 基础URL
```
http://localhost:3000/api/v1/geocoding
```

### 1. 地址搜索 (Geocoding)

**请求**
```http
GET /search?q=北京天安门&country=CN&limit=5
```

**参数**
- `q` (required): 要搜索的地址
- `country` (optional): 国家代码限制（如: CN, US）
- `limit` (optional): 返回结果数量限制（1-20，默认5）

**响应示例**
```json
{
  "success": true,
  "data": {
    "query": "北京天安门",
    "results": [
      {
        "place_id": "123456",
        "display_name": "天安门广场, 东城区, 北京市, 中国",
        "formatted_address_zh": "中国北京市东城区天安门广场",
        "formatted_address_en": "Tiananmen Square, Dongcheng District, Beijing, China",
        "coordinates": {
          "latitude": 39.9042,
          "longitude": 116.4074
        },
        "address_components": {
          "road": "天安门广场",
          "city": "北京市",
          "country": "中国",
          "country_code": "cn"
        },
        "bounds": {
          "northeast": { "lat": 39.9052, "lng": 116.4084 },
          "southwest": { "lat": 39.9032, "lng": 116.4064 }
        },
        "type": "attraction",
        "category": "tourism",
        "importance": 0.9
      }
    ],
    "total": 1
  }
}
```

### 2. 反向地理编码 (Reverse Geocoding)

**请求**
```http
GET /reverse?lat=39.9042&lng=116.4074&zoom=18
```

**参数**
- `lat` (required): 纬度
- `lng` (required): 经度
- `zoom` (optional): 详细程度（1-18，默认18）

**响应示例**
```json
{
  "success": true,
  "data": {
    "query": {
      "latitude": 39.9042,
      "longitude": 116.4074,
      "zoom": 18
    },
    "result": {
      "place_id": "123456",
      "display_name": "天安门广场, 东城区, 北京市, 中国",
      "formatted_address_zh": "中国北京市东城区天安门广场",
      "formatted_address_en": "Tiananmen Square, Dongcheng District, Beijing, China",
      "coordinates": {
        "latitude": 39.9042,
        "longitude": 116.4074
      },
      "address_components": {
        "road": "天安门广场",
        "suburb": "东城区",
        "city": "北京市",
        "country": "中国",
        "country_code": "cn"
      }
    }
  }
}
```

### 3. 附近POI搜索

**请求**
```http
GET /nearby?lat=39.9042&lng=116.4074&type=restaurant&radius=2&limit=10
```

**参数**
- `lat` (required): 纬度
- `lng` (required): 经度
- `type` (required): POI类型（见下方支持类型）
- `radius` (optional): 搜索半径（0.1-50公里，默认5）
- `limit` (optional): 返回结果数量（1-50，默认10）

**支持的POI类型**
```typescript
type POIType = 
  | 'restaurant'        // 餐厅
  | 'gas_station'      // 加油站
  | 'atm'              // ATM
  | 'hospital'         // 医院
  | 'pharmacy'         // 药店
  | 'school'           // 学校
  | 'bank'             // 银行
  | 'hotel'            // 酒店
  | 'shopping_mall'    // 购物中心
  | 'park'             // 公园
  | 'bus_station'      // 公交站
  | 'subway_station'   // 地铁站
  | 'convenience_store'; // 便利店
```

**响应示例**
```json
{
  "success": true,
  "data": {
    "query": {
      "latitude": 39.9042,
      "longitude": 116.4074,
      "type": "restaurant",
      "radius_km": 2,
      "limit": 10
    },
    "results": [
      {
        "place_id": "789012",
        "name": "全聚德烤鸭店",
        "display_name": "全聚德烤鸭店, 前门大街, 东城区, 北京市",
        "formatted_address": "中国北京市东城区前门大街全聚德烤鸭店",
        "coordinates": {
          "latitude": 39.9028,
          "longitude": 116.4055
        },
        "distance_km": 0.18,
        "distance_text": "180米",
        "type": "restaurant",
        "category": "amenity",
        "importance": 0.8
      }
    ],
    "total": 1,
    "center": {
      "latitude": 39.9042,
      "longitude": 116.4074
    }
  }
}
```

### 4. IP地理定位

**请求**
```http
GET /ip-location?ip=8.8.8.8
```

**参数**
- `ip` (optional): IP地址，不提供则使用请求者IP

**响应示例**
```json
{
  "success": true,
  "data": {
    "query": { "ip": "8.8.8.8" },
    "result": {
      "ip": "8.8.8.8",
      "coordinates": {
        "latitude": 37.419200,
        "longitude": -122.057400
      },
      "address": {
        "city": "Mountain View",
        "region": "California",
        "region_code": "CA",
        "country": "United States",
        "country_code": "US",
        "postal_code": "94043"
      },
      "timezone": "America/Los_Angeles",
      "isp": "Google LLC"
    }
  }
}
```

### 5. 获取POI类型列表

**请求**
```http
GET /poi-types
```

**响应示例**
```json
{
  "success": true,
  "data": {
    "poi_types": [
      { "type": "restaurant", "name": "餐厅", "name_en": "Restaurant" },
      { "type": "gas_station", "name": "加油站", "name_en": "Gas Station" },
      // ... 更多类型
    ],
    "total": 13
  }
}
```

## 🛠️ 前端使用示例

### 基本用法

```typescript
import {
  geocodeAddress,
  reverseGeocode,
  searchNearbyPOIs,
  getCurrentPosition
} from '@/lib/geocoding';

// 地址搜索
const results = await geocodeAddress('北京天安门', {
  country: 'CN',
  limit: 5
});

// 反向地理编码
const address = await reverseGeocode(39.9042, 116.4074);

// 搜索附近餐厅
const restaurants = await searchNearbyPOIs(
  39.9042, 116.4074, 'restaurant', {
    radius: 2,
    limit: 10
  }
);

// 获取用户位置
const position = await getCurrentPosition();
```

### React Hook 使用

```typescript
import { useState } from 'react';
import { geocodeAddress } from '@/lib/geocoding';

export function useGeocoding() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const search = async (address: string) => {
    setLoading(true);
    setError(null);
    
    try {
      const data = await geocodeAddress(address);
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return { results, loading, error, search };
}
```

## 🧪 测试

### 运行API测试

```bash
node test-geocoding-api.js
```

测试脚本将自动测试所有API端点，包括：
- 地址搜索功能
- 反向地理编码功能
- POI搜索功能
- IP地理定位功能
- 缓存性能测试

### 手动测试示例

```bash
# 测试地址搜索
curl "http://localhost:3000/api/v1/geocoding/search?q=北京天安门"

# 测试反向地理编码
curl "http://localhost:3000/api/v1/geocoding/reverse?lat=39.9042&lng=116.4074"

# 测试POI搜索
curl "http://localhost:3000/api/v1/geocoding/nearby?lat=39.9042&lng=116.4074&type=restaurant&radius=2"
```

## ⚡ 性能优化

### 缓存策略
- **地址搜索**: 1小时缓存
- **反向地理编码**: 1小时缓存
- **POI搜索**: 1小时缓存
- **IP定位**: 30分钟缓存

### 限流配置
- **每用户每分钟**: 60次请求
- **Nominatim API**: 每秒1次请求（符合使用条款）

### 最佳实践
1. 尽量使用缓存机制（`useCache: true`）
2. 合理设置查询限制（`limit` 参数）
3. 避免频繁的精确坐标查询
4. 使用适当的搜索半径

## 🚨 错误处理

### 常见错误代码
- `400 Bad Request` - 参数错误
- `404 Not Found` - 未找到结果
- `429 Too Many Requests` - 请求过于频繁
- `500 Internal Server Error` - 服务器内部错误

### 错误响应格式
```json
{
  "success": false,
  "error": "Error message",
  "message": "Detailed error description"
}
```

## 🔧 配置说明

### 环境变量
```env
# Nominatim API配置
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org

# 缓存配置
REDIS_URL=redis://localhost:6379

# API限流配置
GEOCODING_RATE_LIMIT_WINDOW_MS=60000
GEOCODING_RATE_LIMIT_MAX_REQUESTS=60
```

### 服务配置
```typescript
// 缓存TTL配置
const CACHE_TTL = {
  geocoding: 3600,      // 1小时
  reverse: 3600,        // 1小时
  poi: 3600,           // 1小时
  ip: 1800             // 30分钟
};

// API请求配置
const API_CONFIG = {
  timeout: 10000,       // 10秒超时
  retries: 3,          // 重试3次
  rateLimit: 1000      // 1秒间隔
};
```

## 📄 许可证

本项目遵循OpenStreetMap的使用条款：
- 数据来源：© OpenStreetMap contributors
- API服务：Nominatim API
- 使用限制：每秒最多1次请求
- 商业使用：需遵循相应条款

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/geocoding-enhancement`)
3. 提交更改 (`git commit -m 'Add geocoding feature'`)
4. 推送到分支 (`git push origin feature/geocoding-enhancement`)
5. 开启 Pull Request

## 📞 技术支持

如有问题或需要支持，请：
1. 查看本文档
2. 运行测试脚本诊断
3. 检查服务器日志
4. 提交 Issue

---

**SmellPin 地理编码服务** - 为您的应用提供准确、快速、可靠的地理位置服务 🌍