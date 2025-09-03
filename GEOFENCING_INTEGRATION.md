# SmellPin LBS地理围栏检测系统集成指南

## 系统概述

SmellPin的地理围栏检测系统是一个高精度、高性能的位置基服务(LBS)核心组件，专门用于检测用户是否在标注的奖励范围内。该系统支持双架构部署，同时在Cloudflare Workers和Node.js后端中实现。

### 核心特性

- **高精度地理计算**: 实现了Haversine和Vincenty两种算法，确保厘米级精度
- **PostGIS空间查询**: 优化的数据库空间索引，支持大规模并发查询
- **可配置奖励半径**: 支持为不同类型的标注设置不同的奖励半径
- **智能缓存系统**: 内存缓存提升查询性能，支持TTL过期机制
- **批处理支持**: 一次性检查多个标注，优化移动端性能
- **后备策略**: PostGIS不可用时自动降级到纯算法计算

### 技术架构

```
┌─────────────────┐    ┌─────────────────┐
│ Cloudflare      │    │ Node.js Backend │
│ Workers API     │    │ Express API     │
│ (边缘计算)        │    │ (主服务器)        │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────┬───────────┘
                     │
           ┌─────────────────┐
           │ Neon PostgreSQL │
           │ + PostGIS       │
           │ (地理空间数据库)   │
           └─────────────────┘
```

## API接口文档

### Workers API (Cloudflare边缘)

#### 基础URL
```
https://your-workers-domain.workers.dev
```

#### 1. 初始化地理围栏表
```http
POST /geofencing/init-tables
```

**响应示例:**
```json
{
  "success": true,
  "message": "Geofencing tables initialized successfully",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

#### 2. 单个标注地理围栏检测
```http
POST /geofencing/check
Content-Type: application/json

{
  "user_location": {
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "annotation_id": "550e8400-e29b-41d4-a716-446655440000",
  "custom_radius": 150
}
```

**响应示例:**
```json
{
  "success": true,
  "data": {
    "is_within_geofence": true,
    "distance_meters": 45.23,
    "reward_eligible": true,
    "reward_radius": 150,
    "annotation": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "location": {
        "latitude": 40.7128,
        "longitude": -74.0060
      },
      "reward_type": "standard"
    }
  },
  "message": "User is within 150m geofence (45.2m away)",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

#### 3. 批量地理围栏检测
```http
POST /geofencing/check-batch
Content-Type: application/json

{
  "user_location": {
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "annotation_ids": [
    "550e8400-e29b-41d4-a716-446655440001",
    "550e8400-e29b-41d4-a716-446655440002"
  ],
  "max_distance": 2000
}
```

**响应示例:**
```json
{
  "success": true,
  "data": [
    {
      "is_within_geofence": true,
      "distance_meters": 45.23,
      "reward_eligible": true,
      "reward_radius": 100,
      "annotation": {
        "id": "550e8400-e29b-41d4-a716-446655440001",
        "location": {
          "latitude": 40.7128,
          "longitude": -74.0060
        }
      }
    }
  ],
  "summary": {
    "total_checked": 2,
    "results_returned": 1,
    "within_geofence": 1,
    "reward_eligible": 1,
    "average_distance_meters": 45.23
  }
}
```

#### 4. 附近标注发现
```http
POST /geofencing/nearby
Content-Type: application/json

{
  "user_location": {
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "search_radius": 500,
  "limit": 20,
  "annotation_types": ["food", "restaurant"]
}
```

#### 5. 配置标注奖励半径 (需要认证)
```http
POST /geofencing/configure-radius
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "annotation_id": "550e8400-e29b-41d4-a716-446655440000",
  "reward_radius": 200,
  "annotation_type": "premium"
}
```

### Backend API (Node.js Express)

#### 基础URL
```
https://your-backend-domain.com/api
```

Backend API端点与Workers API相同，但路径前缀为 `/api/geofencing`。

## 集成示例

### 移动端集成 (React Native)

```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';
import Geolocation from '@react-native-community/geolocation';

class GeofencingClient {
  private baseUrl: string;
  
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async checkNearbyRewards(annotationIds: string[]): Promise<GeofenceResult[]> {
    return new Promise((resolve, reject) => {
      Geolocation.getCurrentPosition(
        async (position) => {
          try {
            const response = await fetch(`${this.baseUrl}/geofencing/check-batch`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                user_location: {
                  latitude: position.coords.latitude,
                  longitude: position.coords.longitude
                },
                annotation_ids: annotationIds,
                max_distance: 2000
              })
            });

            const result = await response.json();
            if (result.success) {
              resolve(result.data);
            } else {
              reject(new Error(result.message));
            }
          } catch (error) {
            reject(error);
          }
        },
        (error) => reject(error),
        {
          enableHighAccuracy: true,
          timeout: 15000,
          maximumAge: 10000
        }
      );
    });
  }

  async findNearbyAnnotations(radius: number = 500): Promise<GeofenceResult[]> {
    return new Promise((resolve, reject) => {
      Geolocation.getCurrentPosition(
        async (position) => {
          try {
            const response = await fetch(`${this.baseUrl}/geofencing/nearby`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                user_location: {
                  latitude: position.coords.latitude,
                  longitude: position.coords.longitude
                },
                search_radius: radius,
                limit: 50
              })
            });

            const result = await response.json();
            if (result.success) {
              resolve(result.data.all_results);
            } else {
              reject(new Error(result.message));
            }
          } catch (error) {
            reject(error);
          }
        },
        (error) => reject(error),
        { enableHighAccuracy: true, timeout: 15000 }
      );
    });
  }
}

// 使用示例
const geofencingClient = new GeofencingClient('https://your-api-domain.com');

// 检查用户是否在已知标注的奖励范围内
const rewardEligibleAnnotations = await geofencingClient.checkNearbyRewards([
  'annotation-id-1',
  'annotation-id-2'
]);

// 发现附近的新标注
const nearbyAnnotations = await geofencingClient.findNearbyAnnotations(1000);
```

### 前端Web集成 (Vue.js)

```vue
<template>
  <div class="geofencing-component">
    <button @click="checkNearbyRewards" :disabled="loading">
      检查附近奖励 {{ loading ? '...' : '' }}
    </button>
    
    <div v-if="results.length > 0" class="rewards-list">
      <h3>可获得奖励的标注:</h3>
      <div 
        v-for="result in eligibleRewards" 
        :key="result.annotation.id"
        class="reward-item"
      >
        <p>距离: {{ result.distance_meters.toFixed(1) }}米</p>
        <p>奖励半径: {{ result.reward_radius }}米</p>
        <p>类型: {{ result.annotation.reward_type }}</p>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'GeofencingComponent',
  data() {
    return {
      loading: false,
      results: [],
      userLocation: null
    }
  },
  computed: {
    eligibleRewards() {
      return this.results.filter(r => r.reward_eligible);
    }
  },
  methods: {
    async getCurrentLocation() {
      return new Promise((resolve, reject) => {
        if (navigator.geolocation) {
          navigator.geolocation.getCurrentPosition(
            (position) => {
              resolve({
                latitude: position.coords.latitude,
                longitude: position.coords.longitude
              });
            },
            (error) => reject(error),
            { enableHighAccuracy: true, timeout: 10000 }
          );
        } else {
          reject(new Error('Geolocation is not supported'));
        }
      });
    },

    async checkNearbyRewards() {
      this.loading = true;
      try {
        this.userLocation = await this.getCurrentLocation();
        
        const response = await fetch('/api/geofencing/nearby', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            user_location: this.userLocation,
            search_radius: 1000,
            limit: 20
          })
        });

        const result = await response.json();
        if (result.success) {
          this.results = result.data.all_results;
        } else {
          throw new Error(result.message);
        }
      } catch (error) {
        console.error('检查附近奖励失败:', error);
        alert('获取位置信息失败，请确保已允许位置权限');
      } finally {
        this.loading = false;
      }
    }
  }
}
</script>
```

### 后端服务集成 (Node.js)

```typescript
import { BackendGeofencingService } from './services/geofencing';
import { getDatabase } from './config/database';

class LBSRewardService {
  private geofencingService: BackendGeofencingService;

  constructor() {
    const pool = getDatabase();
    this.geofencingService = new BackendGeofencingService(pool);
  }

  async processCheckIn(userId: string, location: { latitude: number, longitude: number }) {
    try {
      // 1. 查找附近的标注
      const nearbyAnnotations = await this.geofencingService.findNearbyAnnotations({
        user_location: location,
        search_radius: 2000, // 2公里搜索半径
        limit: 100
      });

      // 2. 筛选出符合奖励条件的标注
      const eligibleRewards = nearbyAnnotations.filter(annotation => 
        annotation.reward_eligible && annotation.distance_meters <= annotation.reward_radius
      );

      // 3. 为每个符合条件的标注发放奖励
      const rewards = [];
      for (const eligible of eligibleRewards) {
        const reward = await this.issueReward(userId, eligible);
        rewards.push(reward);
      }

      return {
        success: true,
        rewards_issued: rewards.length,
        total_points: rewards.reduce((sum, r) => sum + r.points, 0),
        nearby_annotations: nearbyAnnotations.length,
        eligible_count: eligibleRewards.length
      };

    } catch (error) {
      console.error('处理签到失败:', error);
      throw new Error(`签到处理失败: ${error.message}`);
    }
  }

  private async issueReward(userId: string, geofenceResult: GeofenceResult) {
    // 计算奖励积分 (基于距离和标注类型)
    const basePoints = 10;
    const distanceBonus = Math.max(0, (geofenceResult.reward_radius - geofenceResult.distance_meters) / 10);
    const typeMultiplier = this.getTypeMultiplier(geofenceResult.annotation.reward_type);
    
    const totalPoints = Math.round((basePoints + distanceBonus) * typeMultiplier);

    // 记录奖励到数据库
    const pool = getDatabase();
    const client = await pool.connect();
    
    try {
      const result = await client.query(`
        INSERT INTO lbs_rewards (
          user_id, annotation_id, points_earned, distance_meters, 
          reward_radius, location, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
        RETURNING *
      `, [
        userId,
        geofenceResult.annotation.id,
        totalPoints,
        geofenceResult.distance_meters,
        geofenceResult.reward_radius,
        JSON.stringify(geofenceResult.annotation.location)
      ]);

      return {
        id: result.rows[0].id,
        points: totalPoints,
        annotation_id: geofenceResult.annotation.id,
        distance: geofenceResult.distance_meters
      };

    } finally {
      client.release();
    }
  }

  private getTypeMultiplier(rewardType: string): number {
    const multipliers = {
      'standard': 1.0,
      'premium': 1.5,
      'event': 2.0,
      'historical': 1.2,
      'rare': 3.0
    };
    
    return multipliers[rewardType] || 1.0;
  }
}

export { LBSRewardService };
```

## 性能优化建议

### 1. 缓存策略

```typescript
// Redis缓存集成示例
import Redis from 'ioredis';

class CachedGeofencingService {
  private redis: Redis;
  private geofencingService: BackendGeofencingService;
  
  constructor(redisConfig: any, geofencingService: BackendGeofencingService) {
    this.redis = new Redis(redisConfig);
    this.geofencingService = geofencingService;
  }

  async checkGeofenceWithCache(params: any): Promise<GeofenceResult> {
    const cacheKey = `geofence:${params.annotation_id}:${params.user_location.latitude}:${params.user_location.longitude}`;
    
    // 尝试从缓存获取
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // 缓存未命中，调用服务
    const result = await this.geofencingService.checkGeofence(params);
    
    // 缓存结果 (5分钟TTL)
    await this.redis.setex(cacheKey, 300, JSON.stringify(result));
    
    return result;
  }
}
```

### 2. 批处理优化

```typescript
// 批处理队列
class GeofencingQueue {
  private queue: Array<{
    params: any;
    resolve: Function;
    reject: Function;
  }> = [];
  
  private batchSize = 50;
  private batchTimeout = 100; // 毫秒

  async checkGeofence(params: any): Promise<GeofenceResult> {
    return new Promise((resolve, reject) => {
      this.queue.push({ params, resolve, reject });
      
      if (this.queue.length >= this.batchSize) {
        this.processBatch();
      } else if (this.queue.length === 1) {
        setTimeout(() => this.processBatch(), this.batchTimeout);
      }
    });
  }

  private async processBatch() {
    const batch = this.queue.splice(0, this.batchSize);
    const annotationIds = batch.map(item => item.params.annotation_id);
    const userLocation = batch[0].params.user_location;

    try {
      const results = await this.geofencingService.checkMultipleGeofences({
        user_location: userLocation,
        annotation_ids: annotationIds
      });

      // 将结果匹配回对应的Promise
      batch.forEach((item, index) => {
        const result = results.find(r => r.annotation.id === item.params.annotation_id);
        if (result) {
          item.resolve(result);
        } else {
          item.reject(new Error('Annotation not found'));
        }
      });

    } catch (error) {
      batch.forEach(item => item.reject(error));
    }
  }
}
```

### 3. 数据库索引优化

```sql
-- 创建空间索引 (PostGIS)
CREATE INDEX CONCURRENTLY idx_annotations_location_gist 
ON annotations USING GIST(
  ST_Point((location->>'longitude')::float, (location->>'latitude')::float)
);

-- 创建复合索引
CREATE INDEX CONCURRENTLY idx_annotations_status_visibility_location 
ON annotations (status, visibility) 
WHERE location IS NOT NULL;

-- 地理围栏配置索引
CREATE INDEX CONCURRENTLY idx_geofence_configs_annotation_type 
ON geofence_configs (annotation_type, reward_radius);
```

## 监控和调试

### 1. 性能监控

```typescript
class GeofencingMetrics {
  private prometheus: any; // Prometheus客户端

  constructor(prometheus: any) {
    this.prometheus = prometheus;
    this.setupMetrics();
  }

  private setupMetrics() {
    this.checkLatency = new this.prometheus.Histogram({
      name: 'geofencing_check_duration_seconds',
      help: 'Duration of geofence checks',
      labelNames: ['method', 'status']
    });

    this.checkCounter = new this.prometheus.Counter({
      name: 'geofencing_checks_total',
      help: 'Total number of geofence checks',
      labelNames: ['method', 'result']
    });

    this.cacheHits = new this.prometheus.Counter({
      name: 'geofencing_cache_hits_total',
      help: 'Number of cache hits'
    });
  }

  measureCheckLatency(method: string) {
    const startTime = Date.now();
    
    return (status: string, result: string) => {
      const duration = (Date.now() - startTime) / 1000;
      this.checkLatency.labels(method, status).observe(duration);
      this.checkCounter.labels(method, result).inc();
    };
  }

  recordCacheHit() {
    this.cacheHits.inc();
  }
}
```

### 2. 调试日志

```typescript
class GeofencingLogger {
  static logGeofenceCheck(params: any, result: GeofenceResult, duration: number) {
    console.log('Geofence Check:', {
      annotation_id: params.annotation_id,
      user_location: params.user_location,
      distance_meters: result.distance_meters,
      is_within_geofence: result.is_within_geofence,
      reward_radius: result.reward_radius,
      duration_ms: duration,
      timestamp: new Date().toISOString()
    });
  }

  static logBatchCheck(params: any, results: GeofenceResult[], duration: number) {
    console.log('Batch Geofence Check:', {
      batch_size: params.annotation_ids.length,
      results_count: results.length,
      eligible_count: results.filter(r => r.reward_eligible).length,
      average_distance: results.reduce((sum, r) => sum + r.distance_meters, 0) / results.length,
      duration_ms: duration,
      timestamp: new Date().toISOString()
    });
  }
}
```

## 故障排除

### 常见问题

1. **PostGIS扩展未安装**
   ```bash
   # 在PostgreSQL中安装PostGIS
   CREATE EXTENSION IF NOT EXISTS postgis;
   ```

2. **位置权限被拒绝**
   ```typescript
   // 检查并请求位置权限
   if (navigator.permissions) {
     const result = await navigator.permissions.query({name: 'geolocation'});
     console.log('Geolocation permission:', result.state);
   }
   ```

3. **高并发性能问题**
   - 启用连接池
   - 增加缓存TTL
   - 使用批处理API

4. **精度问题**
   - 使用Vincenty算法替代Haversine
   - 检查GPS精度设置
   - 考虑设备校准

### 调试命令

```bash
# 检查数据库表
psql -d your_database -c "SELECT COUNT(*) FROM geofence_configs;"

# 检查PostGIS扩展
psql -d your_database -c "SELECT PostGIS_Version();"

# 性能分析
psql -d your_database -c "EXPLAIN ANALYZE SELECT * FROM annotations WHERE ST_DWithin(...);"
```

## 部署检查清单

- [ ] 数据库连接配置正确
- [ ] PostGIS扩展已安装
- [ ] 地理围栏表已初始化
- [ ] 空间索引已创建
- [ ] 环境变量已设置
- [ ] API认证已配置
- [ ] 监控指标已启用
- [ ] 缓存系统已配置
- [ ] 错误日志已设置
- [ ] 性能测试已通过

## 总结

SmellPin地理围栏检测系统提供了完整的LBS奖励功能，包括高精度地理计算、智能缓存、批处理优化等特性。通过合理的集成和配置，可以支撑大规模用户的实时位置检测需求。

如需更多技术支持，请查看源码中的详细注释或联系开发团队。