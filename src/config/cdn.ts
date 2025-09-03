import { config } from './config';
import { logger } from '@/utils/logger';

// CDN配置接口
export interface CDNConfig {
  enabled: boolean;
  baseUrl: string;
  regions: string[];
  cacheTTL: {
    images: number;
    videos: number;
    static: number;
    api: number;
  };
  compression: {
    enabled: boolean;
    quality: {
      images: number;
      videos: number;
    };
    formats: {
      images: string[];
      videos: string[];
    };
  };
  security: {
    hotlinkProtection: boolean;
    allowedDomains: string[];
    signedUrls: boolean;
  };
}

// CDN配置
export const cdnConfig: CDNConfig = {
  enabled: (config as any).cdn?.enabled || false,
  baseUrl: (config as any).cdn?.baseUrl || '',
  regions: (config as any).cdn?.regions || ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
  cacheTTL: {
    images: 86400 * 30, // 30天
    videos: 86400 * 7,  // 7天
    static: 86400 * 365, // 1年
    api: 300,           // 5分钟
  },
  compression: {
    enabled: true,
    quality: {
      images: 85,
      videos: 80,
    },
    formats: {
      images: ['webp', 'avif', 'jpeg', 'png'],
      videos: ['mp4', 'webm'],
    },
  },
  security: {
    hotlinkProtection: true,
    allowedDomains: [
      (config as any).app?.domain,
      'localhost',
      '127.0.0.1',
    ].filter(Boolean),
    signedUrls: config.nodeEnv === 'production',
  },
};

// 文件类型映射
export const FILE_TYPES = {
  IMAGES: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg'],
  VIDEOS: ['mp4', 'webm', 'avi', 'mov', 'wmv'],
  DOCUMENTS: ['pdf', 'doc', 'docx', 'txt'],
  AUDIO: ['mp3', 'wav', 'ogg', 'aac'],
} as const;

// CDN URL生成器
export class CDNManager {
  private config: CDNConfig;

  constructor(config: CDNConfig) {
    this.config = config;
  }

  // 生成CDN URL
  generateUrl(filePath: string, options: {
    width?: number;
    height?: number;
    quality?: number;
    format?: string;
    crop?: 'fill' | 'fit' | 'scale';
    signed?: boolean;
  } = {}): string {
    if (!this.config.enabled || !this.config.baseUrl) {
      return filePath;
    }

    const baseUrl = this.config.baseUrl.replace(/\/$/, '');
    const cleanPath = filePath.replace(/^\//, '');

    // 构建查询参数
    const params = new URLSearchParams();

    if (options.width) {
      params.set('w', options.width.toString());
    }
    if (options.height) {
      params.set('h', options.height.toString());
    }
    if (options.quality) {
      params.set('q', options.quality.toString());
    }
    if (options.format) {
      params.set('f', options.format);
    }
    if (options.crop) {
      params.set('c', options.crop);
    }

    // 生成签名URL（如果需要）
    if (options.signed && this.config.security.signedUrls) {
      const signature = this.generateSignature(cleanPath, params.toString());
      params.set('s', signature);
    }

    const queryString = params.toString();
    const url = `${baseUrl}/${cleanPath}${queryString ? `?${queryString}` : ''}`;

    logger.debug('CDN URL generated', { originalPath: filePath, cdnUrl: url });
    return url;
  }

  // 生成图片URL
  generateImageUrl(filePath: string, options: {
    width?: number;
    height?: number;
    quality?: number;
    format?: 'webp' | 'avif' | 'jpeg' | 'png';
    crop?: 'fill' | 'fit' | 'scale';
  } = {}): string {
    const defaultQuality = this.config.compression.quality.images;
    return this.generateUrl(filePath, {
      quality: defaultQuality,
      format: 'webp', // 默认使用webp格式
      ...options,
    });
  }

  // 生成视频URL
  generateVideoUrl(filePath: string, options: {
    quality?: number;
    format?: 'mp4' | 'webm';
  } = {}): string {
    const defaultQuality = this.config.compression.quality.videos;
    return this.generateUrl(filePath, {
      quality: defaultQuality,
      format: 'mp4', // 默认使用mp4格式
      ...options,
    });
  }

  // 生成缩略图URL
  generateThumbnailUrl(filePath: string, size: number = 150): string {
    return this.generateImageUrl(filePath, {
      width: size,
      height: size,
      crop: 'fill',
      quality: 80,
    });
  }

  // 生成响应式图片URL集合
  generateResponsiveImageUrls(filePath: string, sizes: number[] = [320, 640, 1024, 1920]): {
    srcSet: string;
    sizes: string;
    src: string;
  } {
    const srcSet = sizes.map(size => {
      const url = this.generateImageUrl(filePath, { width: size as number });
      return `${url} ${size}w`;
    }).join(', ');

    const sizesAttr = sizes.map((size, index) => {
      if (index === sizes.length - 1) {
        return `${size}px`;
      }
      return `(max-width: ${size}px) ${size}px`;
    }).join(', ');

    const src = this.generateImageUrl(filePath, sizes[0] ? { width: sizes[0] } : {});

    return {
      srcSet,
      sizes: sizesAttr,
      src,
    };
  }

  // 预加载关键资源
  preloadCriticalResources(resources: Array<{
    url: string;
    type: 'image' | 'video' | 'font' | 'script' | 'style';
    crossorigin?: boolean;
  }>): string[] {
    return resources.map(resource => {
      const cdnUrl = this.generateUrl(resource.url);
      const crossorigin = resource.crossorigin ? ' crossorigin' : '';
      return `<link rel="preload" href="${cdnUrl}" as="${resource.type}"${crossorigin}>`;
    });
  }

  // 生成签名
  private generateSignature(path: string, params: string): string {
    // 这里应该使用实际的签名算法，比如HMAC-SHA256
    // 为了示例，我们使用简单的哈希
    const crypto = require('crypto');
    const secret = (config as any).cdn?.secret || 'default-secret';
    const data = `${path}?${params}`;
    return crypto.createHmac('sha256', secret).update(data).digest('hex').substring(0, 16);
  }

  // 验证文件类型
  validateFileType(filename: string, allowedTypes: string[]): boolean {
    const extension = filename.split('.').pop()?.toLowerCase();
    return extension ? allowedTypes.includes(extension) : false;
  }

  // 获取文件类型
  getFileType(filename: string): 'image' | 'video' | 'document' | 'audio' | 'unknown' {
    const extension = filename.split('.').pop()?.toLowerCase();
    if (!extension) {
      return 'unknown';
    }

    if (FILE_TYPES.IMAGES.includes(extension as any)) {
      return 'image';
    }
    if (FILE_TYPES.VIDEOS.includes(extension as any)) {
      return 'video';
    }
    if (FILE_TYPES.DOCUMENTS.includes(extension as any)) {
      return 'document';
    }
    if (FILE_TYPES.AUDIO.includes(extension as any)) {
      return 'audio';
    }

    return 'unknown';
  }

  // 获取推荐的缓存TTL
  getRecommendedTTL(filename: string): number {
    const fileType = this.getFileType(filename);

    switch (fileType) {
      case 'image':
        return this.config.cacheTTL.images;
      case 'video':
        return this.config.cacheTTL.videos;
      default:
        return this.config.cacheTTL.static;
    }
  }

  // 生成缓存控制头
  generateCacheHeaders(filename: string): Record<string, string> {
    const ttl = this.getRecommendedTTL(filename);
    const fileType = this.getFileType(filename);

    const headers: Record<string, string> = {
      'Cache-Control': `public, max-age=${ttl}`,
      'Expires': new Date(Date.now() + ttl * 1000).toUTCString(),
    };

    // 为图片和视频添加额外的优化头
    if (fileType === 'image' || fileType === 'video') {
      headers['Vary'] = 'Accept, Accept-Encoding';
    }

    return headers;
  }

  // 检查CDN健康状态
  async checkHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    latency: number;
    regions: Record<string, { status: string; latency: number }>;
  }> {
    if (!this.config.enabled) {
      return {
        status: 'healthy',
        latency: 0,
        regions: {},
      };
    }

    const results: Record<string, { status: string; latency: number }> = {};
    let totalLatency = 0;
    let healthyRegions = 0;

    for (const region of this.config.regions) {
      try {
        const start = Date.now();
        // 这里应该实际检查CDN区域的健康状态
        // 为了示例，我们模拟检查
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
        const latency = Date.now() - start;

        results[region] = {
          status: 'healthy',
          latency,
        };

        totalLatency += latency;
        healthyRegions++;
      } catch (error) {
        results[region] = {
          status: 'unhealthy',
          latency: -1,
        };
        logger.error('CDN region health check failed', { region, error: (error as Error).message });
      }
    }

    const avgLatency = healthyRegions > 0 ? totalLatency / healthyRegions : -1;
    const healthyRatio = healthyRegions / this.config.regions.length;

    let status: 'healthy' | 'degraded' | 'unhealthy';
    if (healthyRatio >= 0.8) {
      status = 'healthy';
    } else if (healthyRatio >= 0.5) {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }

    return {
      status,
      latency: avgLatency,
      regions: results,
    };
  }
}

// 创建CDN管理器实例
export const cdn = new CDNManager(cdnConfig);

// 中间件：自动CDN URL转换
export const cdnMiddleware = (_req: any, res: any, next: any) => {
  // 重写res.json以自动转换URL
  const originalJson = res.json;
  res.json = function (data: any) {
    if (cdnConfig.enabled && data) {
      data = transformUrlsInObject(data);
    }
    return originalJson.call(this, data);
  };

  next();
};

// 递归转换对象中的URL
function transformUrlsInObject(obj: any): any {
  if (typeof obj === 'string') {
    // 检查是否是文件URL
    if (obj.match(/\.(jpg|jpeg|png|gif|webp|avif|svg|mp4|webm|pdf)$/i)) {
      return cdn.generateUrl(obj);
    }
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(transformUrlsInObject);
  }

  if (obj && typeof obj === 'object') {
    const transformed: any = {};
    for (const [key, value] of Object.entries(obj)) {
      // 特殊处理已知的文件字段
      if (['image_url', 'video_url', 'file_url', 'avatar_url', 'thumbnail_url'].includes(key)) {
        transformed[key] = typeof value === 'string' ? cdn.generateUrl(value) : value;
      } else {
        transformed[key] = transformUrlsInObject(value);
      }
    }
    return transformed;
  }

  return obj;
}

export default cdn;
