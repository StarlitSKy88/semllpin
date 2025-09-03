// CDN和缓存策略配置
// 支持CloudFlare、AWS CloudFront、阿里云CDN等

const CDN_CONFIG = {
  // CloudFlare配置
  cloudflare: {
    // Zone ID和API Token从环境变量获取
    zoneId: process.env.CLOUDFLARE_ZONE_ID,
    apiToken: process.env.CLOUDFLARE_API_TOKEN,
    
    // 缓存规则配置
    cacheRules: {
      // 静态资源缓存
      static: {
        patterns: ['*.js', '*.css', '*.png', '*.jpg', '*.jpeg', '*.gif', '*.ico', '*.svg', '*.woff', '*.woff2', '*.ttf', '*.eot'],
        ttl: 31536000, // 1年
        browserTtl: 31536000,
        edgeTtl: 31536000,
        cacheLevel: 'cache_everything'
      },
      
      // API响应缓存
      api: {
        patterns: ['/api/v1/annotations/nearby', '/api/v1/lbs/discover'],
        ttl: 300, // 5分钟
        browserTtl: 60, // 1分钟
        edgeTtl: 300,
        cacheLevel: 'cache_everything',
        cacheByDeviceType: true
      },
      
      // 用户相关API不缓存
      noCache: {
        patterns: ['/api/v1/auth/*', '/api/v1/user/*', '/api/v1/payment/*'],
        ttl: 0,
        cacheLevel: 'bypass'
      },
      
      // HTML页面缓存
      html: {
        patterns: ['*.html', '/'],
        ttl: 3600, // 1小时
        browserTtl: 1800, // 30分钟
        edgeTtl: 3600,
        cacheLevel: 'cache_everything'
      }
    },
    
    // 安全设置
    security: {
      // SSL设置
      ssl: {
        mode: 'strict', // off, flexible, full, strict
        minTlsVersion: '1.2',
        ciphers: ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384']
      },
      
      // WAF规则
      waf: {
        enabled: true,
        mode: 'challenge', // off, simulate, challenge, block
        sensitivityLevel: 'medium' // low, medium, high
      },
      
      // DDoS保护
      ddosProtection: {
        enabled: true,
        sensitivityLevel: 'medium'
      },
      
      // Bot管理
      botManagement: {
        enabled: true,
        allowGoodBots: true,
        blockBadBots: true
      }
    },
    
    // 性能优化
    performance: {
      // 自动压缩
      compression: {
        enabled: true,
        algorithms: ['gzip', 'brotli']
      },
      
      // 图片优化
      imageOptimization: {
        enabled: true,
        formats: ['webp', 'avif'],
        quality: 85
      },
      
      // HTTP/2推送
      http2Push: {
        enabled: true,
        resources: ['/css/main.css', '/js/main.js']
      },
      
      // 预加载
      preload: {
        enabled: true,
        resources: ['/api/v1/user/profile']
      }
    }
  },
  
  // AWS CloudFront配置
  cloudfront: {
    distributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'us-east-1',
    
    // 缓存行为
    cacheBehaviors: {
      default: {
        targetOriginId: 'SmellPin-Origin',
        viewerProtocolPolicy: 'redirect-to-https',
        cachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad', // Managed-CachingOptimized
        compress: true,
        allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'POST', 'PATCH', 'DELETE'],
        cachedMethods: ['GET', 'HEAD', 'OPTIONS']
      },
      
      static: {
        pathPattern: '/static/*',
        cachePolicyId: '658327ea-f89d-4fab-a63d-7e88639e58f6', // Managed-CachingOptimizedForUncompressedObjects
        compress: true,
        ttl: {
          default: 86400, // 1天
          max: 31536000, // 1年
          min: 0
        }
      },
      
      api: {
        pathPattern: '/api/*',
        cachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
        originRequestPolicyId: '88a5eaf4-2fd4-4709-b370-b4c650ea3fcf', // Managed-CORS-S3Origin
        compress: true
      }
    }
  },
  
  // 阿里云CDN配置
  alicloud: {
    accessKeyId: process.env.ALICLOUD_ACCESS_KEY_ID,
    accessKeySecret: process.env.ALICLOUD_ACCESS_KEY_SECRET,
    domainName: process.env.ALICLOUD_CDN_DOMAIN,
    
    // 缓存配置
    cacheConfig: {
      rules: [
        {
          pathPattern: '*.js,*.css,*.png,*.jpg,*.gif,*.ico',
          ttl: 31536000, // 1年
          ignoreParams: false
        },
        {
          pathPattern: '/api/v1/annotations/nearby',
          ttl: 300, // 5分钟
          ignoreParams: true
        },
        {
          pathPattern: '/api/v1/auth/*',
          ttl: 0, // 不缓存
          ignoreParams: false
        }
      ]
    }
  }
};

// 缓存策略配置
const CACHE_STRATEGIES = {
  // Redis缓存配置
  redis: {
    // 连接配置
    connection: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379,
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB) || 0,
      keyPrefix: 'smellpin:',
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3
    },
    
    // 缓存策略
    strategies: {
      // 用户会话缓存
      session: {
        keyPattern: 'session:{userId}',
        ttl: 86400, // 24小时
        serialize: true
      },
      
      // API响应缓存
      apiResponse: {
        keyPattern: 'api:{endpoint}:{params}',
        ttl: 300, // 5分钟
        serialize: true,
        compress: true
      },
      
      // 地理位置缓存
      location: {
        keyPattern: 'location:{lat}:{lng}:{radius}',
        ttl: 1800, // 30分钟
        serialize: true
      },
      
      // 用户配置缓存
      userConfig: {
        keyPattern: 'config:{userId}',
        ttl: 3600, // 1小时
        serialize: true
      },
      
      // 热点数据缓存
      hotData: {
        keyPattern: 'hot:{type}:{id}',
        ttl: 600, // 10分钟
        serialize: true,
        updateOnHit: true
      }
    }
  },
  
  // 内存缓存配置
  memory: {
    // LRU缓存配置
    lru: {
      max: 1000, // 最大条目数
      maxAge: 300000, // 5分钟
      updateAgeOnGet: true
    },
    
    // 缓存类型
    types: {
      // 配置缓存
      config: {
        max: 100,
        maxAge: 3600000 // 1小时
      },
      
      // 用户权限缓存
      permissions: {
        max: 500,
        maxAge: 1800000 // 30分钟
      },
      
      // 地理编码缓存
      geocoding: {
        max: 1000,
        maxAge: 86400000 // 24小时
      }
    }
  },
  
  // 浏览器缓存配置
  browser: {
    // 静态资源
    static: {
      maxAge: 31536000, // 1年
      immutable: true,
      cacheControl: 'public, max-age=31536000, immutable'
    },
    
    // API响应
    api: {
      maxAge: 300, // 5分钟
      cacheControl: 'public, max-age=300, must-revalidate'
    },
    
    // HTML页面
    html: {
      maxAge: 3600, // 1小时
      cacheControl: 'public, max-age=3600, must-revalidate'
    },
    
    // 用户相关数据
    private: {
      maxAge: 0,
      cacheControl: 'private, no-cache, no-store, must-revalidate'
    }
  }
};

// 缓存失效策略
const CACHE_INVALIDATION = {
  // 自动失效规则
  autoInvalidation: {
    // 用户数据更新时失效相关缓存
    userUpdate: {
      patterns: ['session:{userId}', 'config:{userId}', 'api:user:*']
    },
    
    // 标注数据更新时失效地理位置缓存
    annotationUpdate: {
      patterns: ['location:*', 'api:annotations:*', 'hot:annotation:*']
    },
    
    // 支付状态更新时失效用户相关缓存
    paymentUpdate: {
      patterns: ['session:{userId}', 'api:user:*', 'api:payment:*']
    }
  },
  
  // 手动失效接口
  manualInvalidation: {
    // 清除用户缓存
    clearUserCache: (userId) => [
      `session:${userId}`,
      `config:${userId}`,
      `api:user:${userId}:*`
    ],
    
    // 清除地理位置缓存
    clearLocationCache: (lat, lng, radius = 1000) => [
      `location:${lat}:${lng}:${radius}`,
      'api:annotations:nearby:*',
      'api:lbs:discover:*'
    ],
    
    // 清除所有缓存
    clearAllCache: () => ['*']
  }
};

// 缓存监控配置
const CACHE_MONITORING = {
  // 性能指标
  metrics: {
    // 命中率阈值
    hitRateThreshold: 0.8, // 80%
    
    // 响应时间阈值
    responseTimeThreshold: 100, // 100ms
    
    // 内存使用阈值
    memoryUsageThreshold: 0.8, // 80%
    
    // 连接数阈值
    connectionThreshold: 100
  },
  
  // 告警配置
  alerts: {
    // 命中率过低
    lowHitRate: {
      enabled: true,
      threshold: 0.6, // 60%
      duration: 300 // 5分钟
    },
    
    // 响应时间过长
    highResponseTime: {
      enabled: true,
      threshold: 200, // 200ms
      duration: 180 // 3分钟
    },
    
    // 内存使用过高
    highMemoryUsage: {
      enabled: true,
      threshold: 0.9, // 90%
      duration: 120 // 2分钟
    },
    
    // 连接失败
    connectionFailure: {
      enabled: true,
      threshold: 5, // 5次失败
      duration: 60 // 1分钟
    }
  }
};

// 导出配置
module.exports = {
  CDN_CONFIG,
  CACHE_STRATEGIES,
  CACHE_INVALIDATION,
  CACHE_MONITORING
};

// 环境特定配置
if (process.env.NODE_ENV === 'production') {
  // 生产环境优化
  CACHE_STRATEGIES.redis.strategies.apiResponse.ttl = 600; // 增加到10分钟
  CACHE_STRATEGIES.browser.static.maxAge = 31536000; // 1年
} else if (process.env.NODE_ENV === 'development') {
  // 开发环境优化
  CACHE_STRATEGIES.redis.strategies.apiResponse.ttl = 60; // 减少到1分钟
  CACHE_STRATEGIES.browser.static.maxAge = 0; // 不缓存
}