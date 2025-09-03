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
export declare const cdnConfig: CDNConfig;
export declare const FILE_TYPES: {
    readonly IMAGES: readonly ["jpg", "jpeg", "png", "gif", "webp", "avif", "svg"];
    readonly VIDEOS: readonly ["mp4", "webm", "avi", "mov", "wmv"];
    readonly DOCUMENTS: readonly ["pdf", "doc", "docx", "txt"];
    readonly AUDIO: readonly ["mp3", "wav", "ogg", "aac"];
};
export declare class CDNManager {
    private config;
    constructor(config: CDNConfig);
    generateUrl(filePath: string, options?: {
        width?: number;
        height?: number;
        quality?: number;
        format?: string;
        crop?: 'fill' | 'fit' | 'scale';
        signed?: boolean;
    }): string;
    generateImageUrl(filePath: string, options?: {
        width?: number;
        height?: number;
        quality?: number;
        format?: 'webp' | 'avif' | 'jpeg' | 'png';
        crop?: 'fill' | 'fit' | 'scale';
    }): string;
    generateVideoUrl(filePath: string, options?: {
        quality?: number;
        format?: 'mp4' | 'webm';
    }): string;
    generateThumbnailUrl(filePath: string, size?: number): string;
    generateResponsiveImageUrls(filePath: string, sizes?: number[]): {
        srcSet: string;
        sizes: string;
        src: string;
    };
    preloadCriticalResources(resources: Array<{
        url: string;
        type: 'image' | 'video' | 'font' | 'script' | 'style';
        crossorigin?: boolean;
    }>): string[];
    private generateSignature;
    validateFileType(filename: string, allowedTypes: string[]): boolean;
    getFileType(filename: string): 'image' | 'video' | 'document' | 'audio' | 'unknown';
    getRecommendedTTL(filename: string): number;
    generateCacheHeaders(filename: string): Record<string, string>;
    checkHealth(): Promise<{
        status: 'healthy' | 'degraded' | 'unhealthy';
        latency: number;
        regions: Record<string, {
            status: string;
            latency: number;
        }>;
    }>;
}
export declare const cdn: CDNManager;
export declare const cdnMiddleware: (_req: any, res: any, next: any) => void;
export default cdn;
//# sourceMappingURL=cdn.d.ts.map