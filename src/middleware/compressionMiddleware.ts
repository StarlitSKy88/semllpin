import { Request, Response, NextFunction } from 'express';
import { createGzip, createBrotliCompress, constants as zlibConstants } from 'zlib';
import { pipeline } from 'stream';
import { promisify } from 'util';
import { logger } from '../utils/logger';

const pipelineAsync = promisify(pipeline);

// 压缩配置接口
export interface CompressionConfig {
  threshold: number; // 最小压缩大小（字节）
  level: number; // 压缩级别 (1-9)
  memLevel: number; // 内存级别 (1-9)
  windowBits: number; // 窗口位数
  strategy: number; // 压缩策略
  chunkSize: number; // 块大小
  enableBrotli: boolean; // 启用Brotli压缩
  excludeTypes: string[]; // 排除的MIME类型
  includeTypes: string[]; // 包含的MIME类型
  maxSize: number; // 最大压缩文件大小
  cacheCompressed: boolean; // 缓存压缩结果
}

// 默认压缩配置
const DEFAULT_CONFIG: CompressionConfig = {
  threshold: 1024, // 1KB
  level: 6, // 平衡压缩率和速度
  memLevel: 8,
  windowBits: 15,
  strategy: zlibConstants.Z_DEFAULT_STRATEGY,
  chunkSize: 16 * 1024, // 16KB
  enableBrotli: true,
  excludeTypes: [
    'image/*',
    'video/*',
    'audio/*',
    'application/zip',
    'application/gzip',
    'application/x-rar-compressed',
    'application/pdf',
  ],
  includeTypes: [
    'text/*',
    'application/json',
    'application/javascript',
    'application/xml',
    'application/x-javascript',
    'application/xhtml+xml',
    'application/rss+xml',
    'application/atom+xml',
  ],
  maxSize: 10 * 1024 * 1024, // 10MB
  cacheCompressed: true,
};

// 压缩统计
interface CompressionStats {
  originalSize: number;
  compressedSize: number;
  compressionRatio: number;
  algorithm: string;
  processingTime: number;
}

// 内存中的压缩缓存
const compressionCache = new Map<string, {
  data: Buffer;
  encoding: string;
  etag: string;
  timestamp: number;
  stats: CompressionStats;
}>();

// 清理过期的压缩缓存
setInterval(() => {
  const now = Date.now();
  const maxAge = 30 * 60 * 1000; // 30分钟

  for (const [key, value] of compressionCache.entries()) {
    if (now - value.timestamp > maxAge) {
      compressionCache.delete(key);
    }
  }
}, 5 * 60 * 1000); // 每5分钟清理一次

// 高级压缩中间件类
export class AdvancedCompressionMiddleware {
  private config: CompressionConfig;
  private stats: Map<string, CompressionStats[]> = new Map();

  constructor(config: Partial<CompressionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // 检查是否应该压缩
  private shouldCompress(req: Request, res: Response): boolean {
    const contentType = res.getHeader('content-type') as string || '';
    const contentLength = parseInt(res.getHeader('content-length') as string || '0', 10);

    // 检查大小阈值
    if (contentLength && contentLength < this.config.threshold) {
      return false;
    }

    // 检查最大大小限制
    if (contentLength && contentLength > this.config.maxSize) {
      return false;
    }

    // 检查排除类型
    for (const excludeType of this.config.excludeTypes) {
      const pattern = excludeType.replace('*', '.*');
      const regex = new RegExp(pattern, 'i');
      if (regex.test(contentType)) {
        return false;
      }
    }

    // 检查包含类型
    if (this.config.includeTypes.length > 0) {
      let shouldInclude = false;
      for (const includeType of this.config.includeTypes) {
        const pattern = includeType.replace('*', '.*');
        const regex = new RegExp(pattern, 'i');
        if (regex.test(contentType)) {
          shouldInclude = true;
          break;
        }
      }
      if (!shouldInclude) {
        return false;
      }
    }

    // 检查客户端是否支持压缩
    const acceptEncoding = req.headers['accept-encoding'] as string || '';
    return acceptEncoding.includes('gzip') || acceptEncoding.includes('br');
  }

  // 选择压缩算法
  private selectCompressionAlgorithm(req: Request): 'br' | 'gzip' | null {
    const acceptEncoding = req.headers['accept-encoding'] as string || '';
    
    if (this.config.enableBrotli && acceptEncoding.includes('br')) {
      return 'br';
    } else if (acceptEncoding.includes('gzip')) {
      return 'gzip';
    }
    
    return null;
  }

  // 生成缓存键
  private generateCacheKey(data: Buffer, algorithm: string): string {
    const crypto = require('crypto');
    return `${algorithm}:${crypto.createHash('md5').update(data).digest('hex')}`;
  }

  // Brotli压缩
  private async compressBrotli(data: Buffer): Promise<{ compressed: Buffer; stats: CompressionStats }> {
    const startTime = Date.now();
    const brotli = createBrotliCompress({
      params: {
        [zlibConstants.BROTLI_PARAM_QUALITY]: Math.min(this.config.level, 6), // Brotli质量级别0-11
        [zlibConstants.BROTLI_PARAM_SIZE_HINT]: data.length,
      },
    });

    const chunks: Buffer[] = [];
    brotli.on('data', (chunk) => chunks.push(chunk));
    
    const compressed = await new Promise<Buffer>((resolve, reject) => {
      brotli.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      brotli.on('error', reject);
      brotli.end(data);
    });

    const processingTime = Date.now() - startTime;
    const stats: CompressionStats = {
      originalSize: data.length,
      compressedSize: compressed.length,
      compressionRatio: Math.round((1 - compressed.length / data.length) * 100 * 100) / 100,
      algorithm: 'br',
      processingTime,
    };

    return { compressed, stats };
  }

  // Gzip压缩
  private async compressGzip(data: Buffer): Promise<{ compressed: Buffer; stats: CompressionStats }> {
    const startTime = Date.now();
    const gzip = createGzip({
      level: this.config.level,
      memLevel: this.config.memLevel,
      windowBits: this.config.windowBits,
      strategy: this.config.strategy,
      chunkSize: this.config.chunkSize,
    });

    const chunks: Buffer[] = [];
    gzip.on('data', (chunk) => chunks.push(chunk));
    
    const compressed = await new Promise<Buffer>((resolve, reject) => {
      gzip.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      gzip.on('error', reject);
      gzip.end(data);
    });

    const processingTime = Date.now() - startTime;
    const stats: CompressionStats = {
      originalSize: data.length,
      compressedSize: compressed.length,
      compressionRatio: Math.round((1 - compressed.length / data.length) * 100 * 100) / 100,
      algorithm: 'gzip',
      processingTime,
    };

    return { compressed, stats };
  }

  // 记录统计信息
  private recordStats(url: string, stats: CompressionStats): void {
    if (!this.stats.has(url)) {
      this.stats.set(url, []);
    }
    
    const urlStats = this.stats.get(url)!;
    urlStats.push(stats);
    
    // 保持最近100个统计记录
    if (urlStats.length > 100) {
      urlStats.shift();
    }
  }

  // 获取统计信息
  public getStats(): Record<string, any> {
    const totalStats = {
      totalRequests: 0,
      totalOriginalSize: 0,
      totalCompressedSize: 0,
      avgCompressionRatio: 0,
      avgProcessingTime: 0,
      algorithmUsage: { gzip: 0, br: 0 },
      cacheHitRate: 0,
    };

    let allStats: CompressionStats[] = [];
    
    for (const urlStats of this.stats.values()) {
      allStats = allStats.concat(urlStats);
    }

    if (allStats.length === 0) {
      return totalStats;
    }

    totalStats.totalRequests = allStats.length;
    totalStats.totalOriginalSize = allStats.reduce((sum, stat) => sum + stat.originalSize, 0);
    totalStats.totalCompressedSize = allStats.reduce((sum, stat) => sum + stat.compressedSize, 0);
    totalStats.avgCompressionRatio = allStats.reduce((sum, stat) => sum + stat.compressionRatio, 0) / allStats.length;
    totalStats.avgProcessingTime = allStats.reduce((sum, stat) => sum + stat.processingTime, 0) / allStats.length;

    // 算法使用统计
    allStats.forEach(stat => {
      if (stat.algorithm === 'gzip') {
        totalStats.algorithmUsage.gzip++;
      } else if (stat.algorithm === 'br') {
        totalStats.algorithmUsage.br++;
      }
    });

    return {
      ...totalStats,
      cacheSize: compressionCache.size,
      urlStats: Object.fromEntries(
        Array.from(this.stats.entries()).map(([url, stats]) => [
          url,
          {
            requests: stats.length,
            avgCompressionRatio: stats.reduce((sum, s) => sum + s.compressionRatio, 0) / stats.length,
            avgProcessingTime: stats.reduce((sum, s) => sum + s.processingTime, 0) / stats.length,
          }
        ])
      ),
    };
  }

  // 主压缩中间件
  public middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      // 检查是否应该压缩
      if (!this.shouldCompress(req, res)) {
        return next();
      }

      const algorithm = this.selectCompressionAlgorithm(req);
      if (!algorithm) {
        return next();
      }

      // 重写res.send和res.json方法
      const originalSend = res.send;
      const originalJson = res.json;

      res.send = async function(data: any) {
        if (res.headersSent) {
          return originalSend.call(res, data);
        }

        try {
          const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data.toString(), 'utf8');
          
          // 检查缓存
          let cacheKey: string | null = null;
          if (this.config.cacheCompressed) {
            cacheKey = this.generateCacheKey(buffer, algorithm);
            const cached = compressionCache.get(cacheKey);
            
            if (cached && Date.now() - cached.timestamp < 30 * 60 * 1000) { // 30分钟缓存
              res.setHeader('Content-Encoding', cached.encoding);
              res.setHeader('Content-Length', cached.data.length);
              res.setHeader('X-Compression-Cache', 'HIT');
              res.setHeader('X-Compression-Ratio', cached.stats.compressionRatio.toString());
              
              this.recordStats(req.originalUrl, cached.stats);
              return originalSend.call(res, cached.data);
            }
          }

          // 执行压缩
          let compressed: Buffer;
          let stats: CompressionStats;

          if (algorithm === 'br') {
            const result = await this.compressBrotli(buffer);
            compressed = result.compressed;
            stats = result.stats;
          } else {
            const result = await this.compressGzip(buffer);
            compressed = result.compressed;
            stats = result.stats;
          }

          // 缓存压缩结果
          if (this.config.cacheCompressed && cacheKey) {
            const crypto = require('crypto');
            const etag = crypto.createHash('md5').update(compressed).digest('hex');
            
            compressionCache.set(cacheKey, {
              data: compressed,
              encoding: algorithm,
              etag,
              timestamp: Date.now(),
              stats,
            });
          }

          // 设置响应头
          res.setHeader('Content-Encoding', algorithm);
          res.setHeader('Content-Length', compressed.length);
          res.setHeader('X-Compression-Cache', 'MISS');
          res.setHeader('X-Compression-Ratio', stats.compressionRatio.toString());
          res.setHeader('X-Compression-Time', stats.processingTime.toString());
          res.setHeader('Vary', 'Accept-Encoding');

          // 记录统计
          this.recordStats(req.originalUrl, stats);

          // 记录日志
          if (stats.compressionRatio > 50) { // 压缩率超过50%
            logger.info('High compression achieved', {
              url: req.originalUrl,
              algorithm,
              originalSize: stats.originalSize,
              compressedSize: stats.compressedSize,
              compressionRatio: stats.compressionRatio,
              processingTime: stats.processingTime,
            });
          }

          return originalSend.call(res, compressed);
        } catch (error) {
          logger.error('Compression error', {
            url: req.originalUrl,
            algorithm,
            error: (error as Error).message,
          });
          
          // 压缩失败，发送原始数据
          return originalSend.call(res, data);
        }
      };

      res.json = function(obj: any): Response {
        const jsonString = JSON.stringify(obj);
        return res.send(jsonString);
      };

      next();
    };
  }

  // 预压缩静态资源
  public async precompressStatic(filePath: string): Promise<void> {
    const fs = require('fs').promises;
    const path = require('path');
    
    try {
      const data = await fs.readFile(filePath);
      const algorithm = this.config.enableBrotli ? 'br' : 'gzip';
      
      let result: { compressed: Buffer; stats: CompressionStats };
      if (algorithm === 'br') {
        result = await this.compressBrotli(data);
      } else {
        result = await this.compressGzip(data);
      }
      
      const outputPath = `${filePath}.${algorithm}`;
      await fs.writeFile(outputPath, result.compressed);
      
      logger.info('Static file precompressed', {
        filePath,
        algorithm,
        originalSize: result.stats.originalSize,
        compressedSize: result.stats.compressedSize,
        compressionRatio: result.stats.compressionRatio,
        outputPath,
      });
    } catch (error) {
      logger.error('Static file precompression failed', {
        filePath,
        error: (error as Error).message,
      });
    }
  }
}

// 创建默认压缩中间件实例
export const advancedCompressionMiddleware = new AdvancedCompressionMiddleware();

// 预设配置
export const CompressionPresets = {
  // 开发环境 - 快速压缩
  development: {
    level: 1,
    enableBrotli: false,
    cacheCompressed: false,
  },

  // 生产环境 - 平衡性能
  production: {
    level: 6,
    enableBrotli: true,
    cacheCompressed: true,
    threshold: 1024,
  },

  // 高压缩率 - 适用于带宽敏感场景
  highCompression: {
    level: 9,
    enableBrotli: true,
    cacheCompressed: true,
    threshold: 512,
  },

  // 高性能 - 适用于高并发场景
  highPerformance: {
    level: 3,
    enableBrotli: false,
    cacheCompressed: true,
    threshold: 2048,
  },
};