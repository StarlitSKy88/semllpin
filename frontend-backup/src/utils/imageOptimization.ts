// 图片和视频优化工具

// 图片压缩配置
export interface ImageCompressionOptions {
  maxWidth?: number;
  maxHeight?: number;
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp';
  progressive?: boolean;
}

// 视频压缩配置
export interface VideoCompressionOptions {
  maxWidth?: number;
  maxHeight?: number;
  quality?: number;
  format?: 'mp4' | 'webm';
  bitrate?: number;
}

// 默认压缩配置
const DEFAULT_IMAGE_OPTIONS: ImageCompressionOptions = {
  maxWidth: 1920,
  maxHeight: 1080,
  quality: 0.8,
  format: 'webp',
  progressive: true,
};

// const DEFAULT_VIDEO_OPTIONS: VideoCompressionOptions = {
//   maxWidth: 1280,
//   maxHeight: 720,
//   quality: 0.7,
//   format: 'mp4',
//   bitrate: 1000000, // 1Mbps
// };

// 图片压缩类
export class ImageOptimizer {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;

  constructor() {
    this.canvas = document.createElement('canvas');
    this.ctx = this.canvas.getContext('2d')!;
  }

  // 压缩图片
  async compressImage(
    file: File,
    options: ImageCompressionOptions = {}
  ): Promise<{ file: File; originalSize: number; compressedSize: number; compressionRatio: number }> {
    const opts = { ...DEFAULT_IMAGE_OPTIONS, ...options };
    const originalSize = file.size;

    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        try {
          // 计算新的尺寸
          const { width, height } = this.calculateDimensions(
            img.width,
            img.height,
            opts.maxWidth!,
            opts.maxHeight!
          );

          // 设置画布尺寸
          this.canvas.width = width;
          this.canvas.height = height;

          // 绘制图片
          this.ctx.drawImage(img, 0, 0, width, height);

          // 转换为Blob
          this.canvas.toBlob(
            (blob) => {
              if (!blob) {
                reject(new Error('Failed to compress image'));
                return;
              }

              const compressedSize = blob.size;
              const compressionRatio = ((originalSize - compressedSize) / originalSize) * 100;

              // 创建新的File对象
              const compressedFile = new File(
                [blob],
                this.generateOptimizedFilename(file.name, opts.format!),
                { type: blob.type }
              );

              resolve({
                file: compressedFile,
                originalSize,
                compressedSize,
                compressionRatio,
              });
            },
            this.getMimeType(opts.format!),
            opts.quality
          );
        } catch (error) {
          reject(error);
        }
      };

      img.onerror = () => reject(new Error('Failed to load image'));
      img.src = URL.createObjectURL(file);
    });
  }

  // 批量压缩图片
  async compressImages(
    files: File[],
    options: ImageCompressionOptions = {},
    onProgress?: (progress: number, current: number, total: number) => void
  ): Promise<Array<{
    file: File;
    originalSize: number;
    compressedSize: number;
    compressionRatio: number;
    error?: string;
  }>> {
    const results = [];
    
    for (let i = 0; i < files.length; i++) {
      try {
        const result = await this.compressImage(files[i], options);
        results.push(result);
      } catch (error) {
        results.push({
          file: files[i],
          originalSize: files[i].size,
          compressedSize: files[i].size,
          compressionRatio: 0,
          error: (error as Error).message,
        });
      }
      
      if (onProgress) {
        onProgress(((i + 1) / files.length) * 100, i + 1, files.length);
      }
    }
    
    return results;
  }

  // 生成缩略图
  async generateThumbnail(
    file: File,
    size: number = 150
  ): Promise<File> {
    const result = await this.compressImage(file, {
      maxWidth: size,
      maxHeight: size,
      quality: 0.8,
      format: 'webp',
    });
    
    return new File(
      [result.file],
      `thumb_${file.name}`,
      { type: result.file.type }
    );
  }

  // 计算新的尺寸（保持宽高比）
  private calculateDimensions(
    originalWidth: number,
    originalHeight: number,
    maxWidth: number,
    maxHeight: number
  ): { width: number; height: number } {
    const { width, height } = { width: originalWidth, height: originalHeight };

    // 如果图片尺寸小于最大尺寸，不需要缩放
    if (width <= maxWidth && height <= maxHeight) {
      return { width, height };
    }

    // 计算缩放比例
    const widthRatio = maxWidth / width;
    const heightRatio = maxHeight / height;
    const ratio = Math.min(widthRatio, heightRatio);

    return {
      width: Math.round(width * ratio),
      height: Math.round(height * ratio),
    };
  }

  // 获取MIME类型
  private getMimeType(format: string): string {
    const mimeTypes: Record<string, string> = {
      jpeg: 'image/jpeg',
      png: 'image/png',
      webp: 'image/webp',
    };
    return mimeTypes[format] || 'image/jpeg';
  }

  // 生成优化后的文件名
  private generateOptimizedFilename(originalName: string, format: string): string {
    const nameWithoutExt = originalName.replace(/\.[^/.]+$/, '');
    return `${nameWithoutExt}_optimized.${format}`;
  }
}

// 视频优化类（基础实现）
export class VideoOptimizer {
  // 获取视频信息
  async getVideoInfo(file: File): Promise<{
    duration: number;
    width: number;
    height: number;
    size: number;
    type: string;
  }> {
    return new Promise((resolve, reject) => {
      const video = document.createElement('video');
      video.preload = 'metadata';
      
      video.onloadedmetadata = () => {
        resolve({
          duration: video.duration,
          width: video.videoWidth,
          height: video.videoHeight,
          size: file.size,
          type: file.type,
        });
        URL.revokeObjectURL(video.src);
      };
      
      video.onerror = () => {
        reject(new Error('Failed to load video metadata'));
        URL.revokeObjectURL(video.src);
      };
      
      video.src = URL.createObjectURL(file);
    });
  }

  // 生成视频缩略图
  async generateVideoThumbnail(
    file: File,
    timeInSeconds: number = 1,
    width: number = 320,
    height: number = 240
  ): Promise<File> {
    return new Promise((resolve, reject) => {
      const video = document.createElement('video');
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d')!;
      
      video.onloadedmetadata = () => {
        canvas.width = width;
        canvas.height = height;
        video.currentTime = Math.min(timeInSeconds, video.duration);
      };
      
      video.onseeked = () => {
        ctx.drawImage(video, 0, 0, width, height);
        
        canvas.toBlob((blob) => {
          if (!blob) {
            reject(new Error('Failed to generate thumbnail'));
            return;
          }
          
          const thumbnailFile = new File(
            [blob],
            `${file.name}_thumbnail.webp`,
            { type: 'image/webp' }
          );
          
          resolve(thumbnailFile);
          URL.revokeObjectURL(video.src);
        }, 'image/webp', 0.8);
      };
      
      video.onerror = () => {
        reject(new Error('Failed to load video'));
        URL.revokeObjectURL(video.src);
      };
      
      video.src = URL.createObjectURL(file);
    });
  }

  // 检查视频是否需要压缩
  shouldCompress(file: File, maxSize: number = 10 * 1024 * 1024): boolean {
    return file.size > maxSize;
  }
}

// 文件类型检测
export class FileTypeDetector {
  // 检查是否为图片
  static isImage(file: File): boolean {
    return file.type.startsWith('image/');
  }

  // 检查是否为视频
  static isVideo(file: File): boolean {
    return file.type.startsWith('video/');
  }

  // 检查是否支持的图片格式
  static isSupportedImage(file: File): boolean {
    const supportedTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/bmp',
    ];
    return supportedTypes.includes(file.type);
  }

  // 检查是否支持的视频格式
  static isSupportedVideo(file: File): boolean {
    const supportedTypes = [
      'video/mp4',
      'video/webm',
      'video/ogg',
      'video/avi',
      'video/mov',
    ];
    return supportedTypes.includes(file.type);
  }

  // 获取文件扩展名
  static getFileExtension(filename: string): string {
    return filename.split('.').pop()?.toLowerCase() || '';
  }

  // 根据文件内容检测类型（魔数检测）
  static async detectFileType(file: File): Promise<string> {
    const buffer = await file.slice(0, 12).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    
    // JPEG
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
      return 'image/jpeg';
    }
    
    // PNG
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
      return 'image/png';
    }
    
    // GIF
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
      return 'image/gif';
    }
    
    // WebP
    if (bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
      return 'image/webp';
    }
    
    // MP4
    if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
      return 'video/mp4';
    }
    
    return 'unknown';
  }
}

// 媒体优化管理器
export class MediaOptimizer {
  private imageOptimizer: ImageOptimizer;
  private videoOptimizer: VideoOptimizer;

  constructor() {
    this.imageOptimizer = new ImageOptimizer();
    this.videoOptimizer = new VideoOptimizer();
  }

  // 自动优化媒体文件
  async optimizeMedia(
    file: File,
    options: {
      image?: ImageCompressionOptions;
      video?: VideoCompressionOptions;
      generateThumbnail?: boolean;
    } = {}
  ): Promise<{
    optimizedFile: File;
    thumbnail?: File;
    originalSize: number;
    optimizedSize: number;
    compressionRatio: number;
    type: 'image' | 'video' | 'unknown';
  }> {
    let optimizedFile = file;
    let thumbnail: File | undefined;
    let compressionRatio = 0;
    let type: 'image' | 'video' | 'unknown' = 'unknown';

    if (FileTypeDetector.isImage(file) && FileTypeDetector.isSupportedImage(file)) {
      type = 'image';
      const result = await this.imageOptimizer.compressImage(file, options.image);
      optimizedFile = result.file;
      compressionRatio = result.compressionRatio;
      
      if (options.generateThumbnail) {
        thumbnail = await this.imageOptimizer.generateThumbnail(file);
      }
    } else if (FileTypeDetector.isVideo(file) && FileTypeDetector.isSupportedVideo(file)) {
      type = 'video';
      // 视频压缩需要更复杂的处理，这里只生成缩略图
      if (options.generateThumbnail) {
        thumbnail = await this.videoOptimizer.generateVideoThumbnail(file);
      }
    }

    return {
      optimizedFile,
      thumbnail,
      originalSize: file.size,
      optimizedSize: optimizedFile.size,
      compressionRatio,
      type,
    };
  }

  // 批量优化媒体文件
  async optimizeMediaBatch(
    files: File[],
    options: {
      image?: ImageCompressionOptions;
      video?: VideoCompressionOptions;
      generateThumbnail?: boolean;
    } = {},
    onProgress?: (progress: number, current: number, total: number) => void
  ): Promise<Array<{
    optimizedFile: File;
    thumbnail?: File;
    originalSize: number;
    optimizedSize: number;
    compressionRatio: number;
    type: 'image' | 'video' | 'unknown';
    error?: string;
  }>> {
    const results = [];
    
    for (let i = 0; i < files.length; i++) {
      try {
        const result = await this.optimizeMedia(files[i], options);
        results.push(result);
      } catch (error) {
        results.push({
          optimizedFile: files[i],
          originalSize: files[i].size,
          optimizedSize: files[i].size,
          compressionRatio: 0,
          type: 'unknown' as const,
          error: (error as Error).message,
        });
      }
      
      if (onProgress) {
        onProgress(((i + 1) / files.length) * 100, i + 1, files.length);
      }
    }
    
    return results;
  }
}

// 创建全局实例
export const imageOptimizer = new ImageOptimizer();
export const videoOptimizer = new VideoOptimizer();
export const mediaOptimizer = new MediaOptimizer();

// 工具函数
export const mediaUtils = {
  // 格式化文件大小
  formatFileSize: (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  },

  // 计算压缩比
  calculateCompressionRatio: (originalSize: number, compressedSize: number): number => {
    return ((originalSize - compressedSize) / originalSize) * 100;
  },

  // 检查浏览器支持的格式
  getSupportedFormats: (): {
    webp: boolean;
    avif: boolean;
    heic: boolean;
  } => {
    const canvas = document.createElement('canvas');
    return {
      webp: canvas.toDataURL('image/webp').indexOf('data:image/webp') === 0,
      avif: canvas.toDataURL('image/avif').indexOf('data:image/avif') === 0,
      heic: false, // HEIC support is limited in browsers
    };
  },
};

export default {
  ImageOptimizer,
  VideoOptimizer,
  FileTypeDetector,
  MediaOptimizer,
  imageOptimizer,
  videoOptimizer,
  mediaOptimizer,
  mediaUtils,
};