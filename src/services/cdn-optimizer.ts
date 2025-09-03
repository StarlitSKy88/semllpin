import { logger } from '@/utils/logger';
import sharp from 'sharp';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';

// CDN Configuration
export interface CDNConfig {
  provider: 'cloudflare' | 'aws' | 'azure' | 'gcp';
  endpoint: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  region?: string;
  bucket?: string;
  zone?: string;
  domain?: string;
  enableCompression: boolean;
  enableWebP: boolean;
  enableAVIF: boolean;
  cacheControl: string;
}

export interface ImageOptimizationOptions {
  quality: number;
  width?: number;
  height?: number;
  format?: 'webp' | 'avif' | 'jpeg' | 'png';
  progressive?: boolean;
  interlace?: boolean;
}

export interface AssetOptimizationResult {
  originalSize: number;
  optimizedSize: number;
  compressionRatio: number;
  format: string;
  url: string;
  cdnUrl: string;
  hash: string;
}

// Image Optimization Pipeline
export class ImageOptimizer {
  private config: CDNConfig;
  private supportedFormats = ['jpeg', 'jpg', 'png', 'webp', 'avif', 'gif', 'svg'];

  constructor(config: CDNConfig) {
    this.config = config;
  }

  // Generate responsive images with multiple sizes and formats
  async generateResponsiveImages(
    inputBuffer: Buffer,
    baseName: string,
    options: Partial<ImageOptimizationOptions> = {}
  ): Promise<Array<AssetOptimizationResult>> {
    const results: AssetOptimizationResult[] = [];
    
    // Responsive breakpoints
    const breakpoints = [
      { width: 320, suffix: 'mobile' },
      { width: 640, suffix: 'tablet' },
      { width: 1024, suffix: 'desktop' },
      { width: 1920, suffix: 'desktop-hd' },
    ];

    // Modern formats to generate
    const formats: Array<'webp' | 'avif' | 'jpeg'> = ['jpeg'];
    if (this.config.enableWebP) formats.push('webp');
    if (this.config.enableAVIF) formats.push('avif');

    const originalSize = inputBuffer.length;

    for (const breakpoint of breakpoints) {
      for (const format of formats) {
        try {
          const optimizedBuffer = await this.optimizeImage(inputBuffer, {
            ...options,
            width: breakpoint.width,
            format,
            quality: this.getQualityForFormat(format, options.quality || 80),
          });

          const fileName = `${baseName}-${breakpoint.suffix}.${format}`;
          const hash = this.generateHash(optimizedBuffer);
          const cdnUrl = await this.uploadToCDN(optimizedBuffer, fileName, format);

          results.push({
            originalSize,
            optimizedSize: optimizedBuffer.length,
            compressionRatio: ((originalSize - optimizedBuffer.length) / originalSize) * 100,
            format,
            url: fileName,
            cdnUrl,
            hash,
          });

          logger.debug('Image optimized', {
            fileName,
            format,
            width: breakpoint.width,
            originalSize,
            optimizedSize: optimizedBuffer.length,
            compressionRatio: results[results.length - 1].compressionRatio.toFixed(2) + '%',
          });
        } catch (error) {
          logger.error('Image optimization failed', {
            breakpoint: breakpoint.suffix,
            format,
            error: (error as Error).message,
          });
        }
      }
    }

    return results;
  }

  // Optimize single image
  async optimizeImage(
    inputBuffer: Buffer,
    options: ImageOptimizationOptions
  ): Promise<Buffer> {
    let pipeline = sharp(inputBuffer);

    // Resize if dimensions specified
    if (options.width || options.height) {
      pipeline = pipeline.resize(options.width, options.height, {
        fit: 'inside',
        withoutEnlargement: true,
      });
    }

    // Format-specific optimizations
    switch (options.format) {
      case 'webp':
        pipeline = pipeline.webp({
          quality: options.quality,
          progressive: options.progressive,
          effort: 6, // Max compression effort
        });
        break;

      case 'avif':
        pipeline = pipeline.avif({
          quality: options.quality,
          effort: 6,
          chromaSubsampling: '4:2:0',
        });
        break;

      case 'jpeg':
        pipeline = pipeline.jpeg({
          quality: options.quality,
          progressive: options.progressive || true,
          mozjpeg: true, // Use mozjpeg encoder for better compression
        });
        break;

      case 'png':
        pipeline = pipeline.png({
          compressionLevel: 9,
          progressive: options.interlace || true,
          palette: true, // Convert to palette if possible
        });
        break;

      default:
        throw new Error(`Unsupported format: ${options.format}`);
    }

    return pipeline.toBuffer();
  }

  // Upload to CDN
  async uploadToCDN(buffer: Buffer, fileName: string, format: string): Promise<string> {
    const contentType = this.getContentType(format);
    const cacheControl = this.config.cacheControl || 'public, max-age=31536000, immutable';

    try {
      switch (this.config.provider) {
        case 'cloudflare':
          return this.uploadToCloudflare(buffer, fileName, contentType, cacheControl);
        
        case 'aws':
          return this.uploadToAWS(buffer, fileName, contentType, cacheControl);
        
        default:
          throw new Error(`CDN provider ${this.config.provider} not implemented`);
      }
    } catch (error) {
      logger.error('CDN upload failed', {
        fileName,
        provider: this.config.provider,
        error: (error as Error).message,
      });
      throw error;
    }
  }

  private async uploadToCloudflare(
    buffer: Buffer,
    fileName: string,
    contentType: string,
    cacheControl: string
  ): Promise<string> {
    // Cloudflare R2 or Images API integration
    const endpoint = `${this.config.endpoint}/${fileName}`;
    
    const response = await fetch(endpoint, {
      method: 'PUT',
      body: buffer,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': cacheControl,
        'Authorization': `Bearer ${process.env.CLOUDFLARE_TOKEN}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Cloudflare upload failed: ${response.statusText}`);
    }

    return `${this.config.domain}/${fileName}`;
  }

  private async uploadToAWS(
    buffer: Buffer,
    fileName: string,
    contentType: string,
    cacheControl: string
  ): Promise<string> {
    // AWS S3 integration would go here
    // For now, return a mock URL
    return `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com/${fileName}`;
  }

  private getQualityForFormat(format: string, baseQuality: number): number {
    // Adjust quality based on format efficiency
    switch (format) {
      case 'avif':
        return Math.max(50, baseQuality - 20); // AVIF is very efficient
      case 'webp':
        return Math.max(60, baseQuality - 10); // WebP is more efficient than JPEG
      case 'jpeg':
      default:
        return baseQuality;
    }
  }

  private getContentType(format: string): string {
    const contentTypes: Record<string, string> = {
      jpeg: 'image/jpeg',
      jpg: 'image/jpeg',
      png: 'image/png',
      webp: 'image/webp',
      avif: 'image/avif',
      gif: 'image/gif',
      svg: 'image/svg+xml',
    };

    return contentTypes[format] || 'application/octet-stream';
  }

  private generateHash(buffer: Buffer): string {
    return crypto.createHash('sha256').update(buffer).digest('hex').substring(0, 16);
  }

  // Generate picture element HTML for responsive images
  generatePictureElement(
    results: AssetOptimizationResult[],
    alt: string,
    className?: string
  ): string {
    const sources: string[] = [];
    
    // Group by format
    const resultsByFormat = results.reduce((acc, result) => {
      if (!acc[result.format]) acc[result.format] = [];
      acc[result.format].push(result);
      return acc;
    }, {} as Record<string, AssetOptimizationResult[]>);

    // Generate source elements for modern formats
    ['avif', 'webp'].forEach(format => {
      if (resultsByFormat[format]) {
        const srcset = resultsByFormat[format]
          .map(result => `${result.cdnUrl} ${this.getWidthFromUrl(result.url)}w`)
          .join(', ');
        
        sources.push(`<source type="image/${format}" srcset="${srcset}">`);
      }
    });

    // Fallback JPEG source
    const jpegResults = resultsByFormat['jpeg'] || [];
    const jpegSrcset = jpegResults
      .map(result => `${result.cdnUrl} ${this.getWidthFromUrl(result.url)}w`)
      .join(', ');

    const fallbackSrc = jpegResults[0]?.cdnUrl || '';

    return `
      <picture${className ? ` class="${className}"` : ''}>
        ${sources.join('\n        ')}
        <img
          src="${fallbackSrc}"
          srcset="${jpegSrcset}"
          sizes="(max-width: 640px) 320px, (max-width: 1024px) 640px, (max-width: 1920px) 1024px, 1920px"
          alt="${alt}"
          loading="lazy"
          decoding="async"
        >
      </picture>
    `.trim();
  }

  private getWidthFromUrl(url: string): number {
    const match = url.match(/-(\d+)px-/);
    return match ? parseInt(match[1]) : 1920;
  }
}

// Static Asset Optimizer
export class StaticAssetOptimizer {
  private config: CDNConfig;
  private imageOptimizer: ImageOptimizer;

  constructor(config: CDNConfig) {
    this.config = config;
    this.imageOptimizer = new ImageOptimizer(config);
  }

  // Process and optimize all static assets
  async optimizeStaticAssets(assetsDir: string): Promise<{
    images: AssetOptimizationResult[];
    css: AssetOptimizationResult[];
    js: AssetOptimizationResult[];
    totalSavings: number;
  }> {
    logger.info('Starting static asset optimization', { assetsDir });

    const images: AssetOptimizationResult[] = [];
    const css: AssetOptimizationResult[] = [];
    const js: AssetOptimizationResult[] = [];

    try {
      // Find all static assets
      const imageFiles = await this.findFiles(assetsDir, /\.(jpg|jpeg|png|webp|gif)$/i);
      const cssFiles = await this.findFiles(assetsDir, /\.css$/i);
      const jsFiles = await this.findFiles(assetsDir, /\.js$/i);

      // Process images
      for (const imagePath of imageFiles) {
        try {
          const buffer = await fs.readFile(imagePath);
          const baseName = path.parse(imagePath).name;
          const optimizedImages = await this.imageOptimizer.generateResponsiveImages(buffer, baseName);
          images.push(...optimizedImages);
        } catch (error) {
          logger.error('Image processing failed', {
            file: imagePath,
            error: (error as Error).message,
          });
        }
      }

      // Process CSS files
      for (const cssPath of cssFiles) {
        try {
          const result = await this.optimizeCSS(cssPath);
          css.push(result);
        } catch (error) {
          logger.error('CSS processing failed', {
            file: cssPath,
            error: (error as Error).message,
          });
        }
      }

      // Process JS files
      for (const jsPath of jsFiles) {
        try {
          const result = await this.optimizeJS(jsPath);
          js.push(result);
        } catch (error) {
          logger.error('JS processing failed', {
            file: jsPath,
            error: (error as Error).message,
          });
        }
      }

      const allResults = [...images, ...css, ...js];
      const totalSavings = allResults.reduce(
        (sum, result) => sum + (result.originalSize - result.optimizedSize),
        0
      );

      logger.info('Asset optimization completed', {
        images: images.length,
        css: css.length,
        js: js.length,
        totalSavings: `${(totalSavings / 1024 / 1024).toFixed(2)} MB`,
      });

      return { images, css, js, totalSavings };
    } catch (error) {
      logger.error('Asset optimization failed', { error: (error as Error).message });
      throw error;
    }
  }

  private async findFiles(dir: string, pattern: RegExp): Promise<string[]> {
    const files: string[] = [];
    
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          const subFiles = await this.findFiles(fullPath, pattern);
          files.push(...subFiles);
        } else if (pattern.test(entry.name)) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      logger.error('File search failed', { dir, error: (error as Error).message });
    }
    
    return files;
  }

  private async optimizeCSS(filePath: string): Promise<AssetOptimizationResult> {
    const content = await fs.readFile(filePath, 'utf-8');
    const originalSize = Buffer.byteLength(content, 'utf-8');

    // Basic CSS optimization (in production, use postcss + cssnano)
    const optimized = content
      .replace(/\/\*[\s\S]*?\*\//g, '') // Remove comments
      .replace(/\s+/g, ' ') // Collapse whitespace
      .replace(/;\s*}/g, '}') // Remove unnecessary semicolons
      .replace(/\s*{\s*/g, '{')
      .replace(/;\s*/g, ';')
      .trim();

    const optimizedSize = Buffer.byteLength(optimized, 'utf-8');
    const fileName = path.basename(filePath);
    const hash = crypto.createHash('sha256').update(optimized).digest('hex').substring(0, 16);

    // Upload to CDN
    const cdnUrl = await this.imageOptimizer.uploadToCDN(
      Buffer.from(optimized, 'utf-8'),
      `${hash}-${fileName}`,
      'css'
    );

    return {
      originalSize,
      optimizedSize,
      compressionRatio: ((originalSize - optimizedSize) / originalSize) * 100,
      format: 'css',
      url: fileName,
      cdnUrl,
      hash,
    };
  }

  private async optimizeJS(filePath: string): Promise<AssetOptimizationResult> {
    const content = await fs.readFile(filePath, 'utf-8');
    const originalSize = Buffer.byteLength(content, 'utf-8');

    // Basic JS optimization (in production, use terser)
    const optimized = content
      .replace(/\/\*[\s\S]*?\*\//g, '') // Remove block comments
      .replace(/\/\/.*$/gm, '') // Remove line comments
      .replace(/\s+/g, ' ') // Collapse whitespace
      .trim();

    const optimizedSize = Buffer.byteLength(optimized, 'utf-8');
    const fileName = path.basename(filePath);
    const hash = crypto.createHash('sha256').update(optimized).digest('hex').substring(0, 16);

    // Upload to CDN
    const cdnUrl = await this.imageOptimizer.uploadToCDN(
      Buffer.from(optimized, 'utf-8'),
      `${hash}-${fileName}`,
      'js'
    );

    return {
      originalSize,
      optimizedSize,
      compressionRatio: ((originalSize - optimizedSize) / originalSize) * 100,
      format: 'js',
      url: fileName,
      cdnUrl,
      hash,
    };
  }
}

// CDN Manager
export class CDNManager {
  private config: CDNConfig;
  private imageOptimizer: ImageOptimizer;
  private assetOptimizer: StaticAssetOptimizer;

  constructor(config: CDNConfig) {
    this.config = config;
    this.imageOptimizer = new ImageOptimizer(config);
    this.assetOptimizer = new StaticAssetOptimizer(config);
  }

  // Purge cache for specific URLs
  async purgeCache(urls: string[]): Promise<boolean> {
    try {
      switch (this.config.provider) {
        case 'cloudflare':
          return this.purgeCloudflareCache(urls);
        case 'aws':
          return this.purgeAWSCache(urls);
        default:
          logger.warn('Cache purge not implemented for provider', { provider: this.config.provider });
          return false;
      }
    } catch (error) {
      logger.error('Cache purge failed', {
        urls,
        provider: this.config.provider,
        error: (error as Error).message,
      });
      return false;
    }
  }

  private async purgeCloudflareCache(urls: string[]): Promise<boolean> {
    const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${this.config.zone}/purge_cache`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.CLOUDFLARE_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ files: urls }),
    });

    return response.ok;
  }

  private async purgeAWSCache(urls: string[]): Promise<boolean> {
    // AWS CloudFront invalidation would go here
    logger.info('AWS cache purge requested', { urls });
    return true;
  }

  // Get CDN statistics
  async getStats(): Promise<{
    bandwidth: number;
    requests: number;
    hitRatio: number;
    coverage: Record<string, number>;
  }> {
    // This would integrate with your CDN provider's analytics API
    return {
      bandwidth: 0,
      requests: 0,
      hitRatio: 0,
      coverage: {},
    };
  }
}

// Factory function to create CDN optimizer based on configuration
export const createCDNOptimizer = (): CDNManager => {
  const config: CDNConfig = {
    provider: (process.env.CDN_PROVIDER as 'cloudflare' | 'aws') || 'cloudflare',
    endpoint: process.env.CDN_ENDPOINT || '',
    domain: process.env.CDN_DOMAIN || '',
    zone: process.env.CLOUDFLARE_ZONE || '',
    bucket: process.env.AWS_S3_BUCKET || '',
    region: process.env.AWS_REGION || 'us-east-1',
    enableCompression: true,
    enableWebP: true,
    enableAVIF: process.env.ENABLE_AVIF !== 'false',
    cacheControl: 'public, max-age=31536000, immutable',
  };

  return new CDNManager(config);
};

export const cdnManager = createCDNOptimizer();