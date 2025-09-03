"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cdnMiddleware = exports.cdn = exports.CDNManager = exports.FILE_TYPES = exports.cdnConfig = void 0;
const config_1 = require("./config");
const logger_1 = require("@/utils/logger");
exports.cdnConfig = {
    enabled: config_1.config.cdn?.enabled || false,
    baseUrl: config_1.config.cdn?.baseUrl || '',
    regions: config_1.config.cdn?.regions || ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    cacheTTL: {
        images: 86400 * 30,
        videos: 86400 * 7,
        static: 86400 * 365,
        api: 300,
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
            config_1.config.app?.domain,
            'localhost',
            '127.0.0.1',
        ].filter(Boolean),
        signedUrls: config_1.config.nodeEnv === 'production',
    },
};
exports.FILE_TYPES = {
    IMAGES: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg'],
    VIDEOS: ['mp4', 'webm', 'avi', 'mov', 'wmv'],
    DOCUMENTS: ['pdf', 'doc', 'docx', 'txt'],
    AUDIO: ['mp3', 'wav', 'ogg', 'aac'],
};
class CDNManager {
    constructor(config) {
        this.config = config;
    }
    generateUrl(filePath, options = {}) {
        if (!this.config.enabled || !this.config.baseUrl) {
            return filePath;
        }
        const baseUrl = this.config.baseUrl.replace(/\/$/, '');
        const cleanPath = filePath.replace(/^\//, '');
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
        if (options.signed && this.config.security.signedUrls) {
            const signature = this.generateSignature(cleanPath, params.toString());
            params.set('s', signature);
        }
        const queryString = params.toString();
        const url = `${baseUrl}/${cleanPath}${queryString ? `?${queryString}` : ''}`;
        logger_1.logger.debug('CDN URL generated', { originalPath: filePath, cdnUrl: url });
        return url;
    }
    generateImageUrl(filePath, options = {}) {
        const defaultQuality = this.config.compression.quality.images;
        return this.generateUrl(filePath, {
            quality: defaultQuality,
            format: 'webp',
            ...options,
        });
    }
    generateVideoUrl(filePath, options = {}) {
        const defaultQuality = this.config.compression.quality.videos;
        return this.generateUrl(filePath, {
            quality: defaultQuality,
            format: 'mp4',
            ...options,
        });
    }
    generateThumbnailUrl(filePath, size = 150) {
        return this.generateImageUrl(filePath, {
            width: size,
            height: size,
            crop: 'fill',
            quality: 80,
        });
    }
    generateResponsiveImageUrls(filePath, sizes = [320, 640, 1024, 1920]) {
        const srcSet = sizes.map(size => {
            const url = this.generateImageUrl(filePath, { width: size });
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
    preloadCriticalResources(resources) {
        return resources.map(resource => {
            const cdnUrl = this.generateUrl(resource.url);
            const crossorigin = resource.crossorigin ? ' crossorigin' : '';
            return `<link rel="preload" href="${cdnUrl}" as="${resource.type}"${crossorigin}>`;
        });
    }
    generateSignature(path, params) {
        const crypto = require('crypto');
        const secret = config_1.config.cdn?.secret || 'default-secret';
        const data = `${path}?${params}`;
        return crypto.createHmac('sha256', secret).update(data).digest('hex').substring(0, 16);
    }
    validateFileType(filename, allowedTypes) {
        const extension = filename.split('.').pop()?.toLowerCase();
        return extension ? allowedTypes.includes(extension) : false;
    }
    getFileType(filename) {
        const extension = filename.split('.').pop()?.toLowerCase();
        if (!extension) {
            return 'unknown';
        }
        if (exports.FILE_TYPES.IMAGES.includes(extension)) {
            return 'image';
        }
        if (exports.FILE_TYPES.VIDEOS.includes(extension)) {
            return 'video';
        }
        if (exports.FILE_TYPES.DOCUMENTS.includes(extension)) {
            return 'document';
        }
        if (exports.FILE_TYPES.AUDIO.includes(extension)) {
            return 'audio';
        }
        return 'unknown';
    }
    getRecommendedTTL(filename) {
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
    generateCacheHeaders(filename) {
        const ttl = this.getRecommendedTTL(filename);
        const fileType = this.getFileType(filename);
        const headers = {
            'Cache-Control': `public, max-age=${ttl}`,
            'Expires': new Date(Date.now() + ttl * 1000).toUTCString(),
        };
        if (fileType === 'image' || fileType === 'video') {
            headers['Vary'] = 'Accept, Accept-Encoding';
        }
        return headers;
    }
    async checkHealth() {
        if (!this.config.enabled) {
            return {
                status: 'healthy',
                latency: 0,
                regions: {},
            };
        }
        const results = {};
        let totalLatency = 0;
        let healthyRegions = 0;
        for (const region of this.config.regions) {
            try {
                const start = Date.now();
                await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
                const latency = Date.now() - start;
                results[region] = {
                    status: 'healthy',
                    latency,
                };
                totalLatency += latency;
                healthyRegions++;
            }
            catch (error) {
                results[region] = {
                    status: 'unhealthy',
                    latency: -1,
                };
                logger_1.logger.error('CDN region health check failed', { region, error: error.message });
            }
        }
        const avgLatency = healthyRegions > 0 ? totalLatency / healthyRegions : -1;
        const healthyRatio = healthyRegions / this.config.regions.length;
        let status;
        if (healthyRatio >= 0.8) {
            status = 'healthy';
        }
        else if (healthyRatio >= 0.5) {
            status = 'degraded';
        }
        else {
            status = 'unhealthy';
        }
        return {
            status,
            latency: avgLatency,
            regions: results,
        };
    }
}
exports.CDNManager = CDNManager;
exports.cdn = new CDNManager(exports.cdnConfig);
const cdnMiddleware = (_req, res, next) => {
    const originalJson = res.json;
    res.json = function (data) {
        if (exports.cdnConfig.enabled && data) {
            data = transformUrlsInObject(data);
        }
        return originalJson.call(this, data);
    };
    next();
};
exports.cdnMiddleware = cdnMiddleware;
function transformUrlsInObject(obj) {
    if (typeof obj === 'string') {
        if (obj.match(/\.(jpg|jpeg|png|gif|webp|avif|svg|mp4|webm|pdf)$/i)) {
            return exports.cdn.generateUrl(obj);
        }
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(transformUrlsInObject);
    }
    if (obj && typeof obj === 'object') {
        const transformed = {};
        for (const [key, value] of Object.entries(obj)) {
            if (['image_url', 'video_url', 'file_url', 'avatar_url', 'thumbnail_url'].includes(key)) {
                transformed[key] = typeof value === 'string' ? exports.cdn.generateUrl(value) : value;
            }
            else {
                transformed[key] = transformUrlsInObject(value);
            }
        }
        return transformed;
    }
    return obj;
}
exports.default = exports.cdn;
//# sourceMappingURL=cdn.js.map