"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.advancedSearch = exports.getPopularSearchTerms = exports.searchAnnotationsByContent = exports.searchAnnotationsByLocation = void 0;
const database_1 = require("@/config/database");
const errorHandler_1 = require("@/middleware/errorHandler");
const errorHandler_2 = require("@/middleware/errorHandler");
const logger_1 = require("@/utils/logger");
const redis_1 = require("@/config/redis");
exports.searchAnnotationsByLocation = (0, errorHandler_2.asyncHandler)(async (req, res) => {
    const { lat, lng, latitude, longitude, radius = 5000, smellIntensity, category, keyword, sortBy = 'created_at', sortOrder = 'desc', page = 1, limit = 20, } = req.query;
    const finalLatitude = lat || latitude;
    const finalLongitude = lng || longitude;
    if (!finalLatitude || !finalLongitude) {
        throw (0, errorHandler_1.createValidationError)('location', '经纬度不能为空');
    }
    logger_1.logger.info('开始地理位置搜索', { finalLatitude, finalLongitude, radius });
    try {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const radiusInDegrees = parseInt(radius) / 111000;
        let query = (0, database_1.db)('annotations')
            .select('annotations.*')
            .whereIn('annotations.status', ['approved', 'pending']);
        if (finalLatitude && finalLongitude) {
            query = query.whereRaw('ABS(annotations.latitude - ?) < ? AND ABS(annotations.longitude - ?) < ?', [
                parseFloat(finalLatitude), radiusInDegrees,
                parseFloat(finalLongitude), radiusInDegrees,
            ]);
        }
        if (smellIntensity) {
            if (smellIntensity.min !== undefined) {
                query = query.where('annotations.smell_intensity', '>=', parseInt(smellIntensity.min));
            }
            if (smellIntensity.max !== undefined) {
                query = query.where('annotations.smell_intensity', '<=', parseInt(smellIntensity.max));
            }
        }
        if (keyword) {
            query = query.where(function () {
                this.where('annotations.description', 'like', `%${keyword}%`)
                    .orWhere('annotations.address', 'like', `%${keyword}%`)
                    .orWhere('annotations.city', 'like', `%${keyword}%`);
            });
        }
        switch (sortBy) {
            case 'distance':
                query = query.orderByRaw(`
          (ABS(annotations.latitude - ${parseFloat(finalLatitude)}) + ABS(annotations.longitude - ${parseFloat(finalLongitude)})) ${sortOrder.toUpperCase()}
        `);
                break;
            case 'smell_intensity':
                query = query.orderBy('annotations.smell_intensity', sortOrder);
                break;
            case 'popularity':
                query = query.orderBy('annotations.view_count', sortOrder);
                break;
            default:
                query = query.orderBy('annotations.created_at', sortOrder);
        }
        logger_1.logger.info('执行查询前', { query: query.toSQL() });
        const totalQuery = query.clone().clearSelect().clearOrder().count('* as count').first();
        logger_1.logger.info('开始执行主查询');
        const results = await query.limit(parseInt(limit)).offset(offset);
        logger_1.logger.info('主查询完成，开始执行计数查询');
        const totalCount = await totalQuery;
        logger_1.logger.info('查询完成', { resultsCount: results.length, totalCount });
        const annotationsWithDistance = results.map(annotation => {
            const distance = Math.sqrt(Math.pow((annotation.latitude - parseFloat(finalLatitude)) * 111000, 2) +
                Math.pow((annotation.longitude - parseFloat(finalLongitude)) * 111000, 2));
            return {
                ...annotation,
                distance: Math.round(distance),
                user: {
                    username: annotation.username,
                    display_name: annotation.display_name,
                    avatar_url: annotation.avatar_url,
                },
            };
        });
        const cacheKey = `search:location:${finalLatitude}:${finalLongitude}:${radius}:${JSON.stringify(req.query)}`;
        await redis_1.cacheService.set(cacheKey, JSON.stringify(annotationsWithDistance), 300);
        logger_1.logger.info('地理位置搜索成功', {
            latitude: finalLatitude,
            longitude: finalLongitude,
            radius,
            count: annotationsWithDistance.length,
        });
        res.json({
            success: true,
            message: '地理位置搜索成功',
            data: {
                annotations: annotationsWithDistance,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: parseInt(totalCount?.['count'] || '0'),
                    totalPages: Math.ceil(parseInt(totalCount?.['count'] || '0') / parseInt(limit)),
                },
                filters: {
                    latitude: parseFloat(finalLatitude),
                    longitude: parseFloat(finalLongitude),
                    radius: parseInt(radius),
                    smellIntensity,
                    category,
                    keyword,
                    sortBy,
                    sortOrder,
                },
            },
        });
    }
    catch (error) {
        logger_1.logger.error('地理位置搜索失败', { error });
        throw error;
    }
});
exports.searchAnnotationsByContent = (0, errorHandler_2.asyncHandler)(async (req, res) => {
    const { keyword, category, smellIntensity, sortBy = 'relevance', sortOrder = 'desc', page = 1, limit = 20, } = req.query;
    if (!keyword) {
        throw (0, errorHandler_1.createValidationError)('keyword', '搜索关键词不能为空');
    }
    try {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        let query = (0, database_1.db)('annotations')
            .leftJoin('users', 'annotations.user_id', 'users.id')
            .leftJoin('media_files', 'annotations.id', 'media_files.annotation_id')
            .select('annotations.*', 'users.username', 'users.display_name', 'users.avatar_url', database_1.db.raw('COUNT(DISTINCT media_files.id) as media_count'), database_1.db.raw(`
          (
            CASE WHEN annotations.description LIKE '%${keyword}%' THEN 3 ELSE 0 END +
            CASE WHEN annotations.address LIKE '%${keyword}%' THEN 2 ELSE 0 END +
            CASE WHEN annotations.city LIKE '%${keyword}%' THEN 1 ELSE 0 END
          ) as relevance_score
        `))
            .where('annotations.status', 'approved')
            .where(function () {
            this.where('annotations.description', 'like', `%${keyword}%`)
                .orWhere('annotations.address', 'like', `%${keyword}%`)
                .orWhere('annotations.city', 'like', `%${keyword}%`);
        })
            .groupBy('annotations.id', 'users.id');
        if (smellIntensity) {
            if (smellIntensity.min !== undefined) {
                query = query.where('annotations.smell_intensity', '>=', parseInt(smellIntensity.min));
            }
            if (smellIntensity.max !== undefined) {
                query = query.where('annotations.smell_intensity', '<=', parseInt(smellIntensity.max));
            }
        }
        switch (sortBy) {
            case 'relevance':
                query = query.orderByRaw('relevance_score DESC, annotations.created_at DESC');
                break;
            case 'smell_intensity':
                query = query.orderBy('annotations.smell_intensity', sortOrder);
                break;
            case 'popularity':
                query = query.orderBy('annotations.view_count', sortOrder);
                break;
            default:
                query = query.orderBy('annotations.created_at', sortOrder);
        }
        const totalQuery = query.clone().clearSelect().clearOrder().count('* as count').first();
        const results = await query.limit(parseInt(limit)).offset(offset);
        const totalCount = await totalQuery;
        const annotationsWithRelevance = results.map(annotation => ({
            ...annotation,
            user: {
                username: annotation.username,
                display_name: annotation.display_name,
                avatar_url: annotation.avatar_url,
            },
        }));
        const cacheKey = `search:content:${keyword}:${JSON.stringify(req.query)}`;
        await redis_1.cacheService.set(cacheKey, JSON.stringify(annotationsWithRelevance), 300);
        logger_1.logger.info('内容搜索成功', { keyword, count: annotationsWithRelevance.length });
        res.json({
            success: true,
            message: '内容搜索成功',
            data: {
                annotations: annotationsWithRelevance,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: parseInt(totalCount?.['count'] || '0'),
                    totalPages: Math.ceil(parseInt(totalCount?.['count'] || '0') / parseInt(limit)),
                },
                filters: {
                    keyword,
                    category,
                    smellIntensity,
                    sortBy,
                    sortOrder,
                },
            },
        });
    }
    catch (error) {
        logger_1.logger.error('内容搜索失败', { error });
        throw error;
    }
});
exports.getPopularSearchTerms = (0, errorHandler_2.asyncHandler)(async (_req, res) => {
    try {
        const popularCategories = await (0, database_1.db)('annotations')
            .select('category')
            .count('* as count')
            .where('status', 'approved')
            .whereNotNull('category')
            .groupBy('category')
            .orderBy('count', 'desc')
            .limit(10);
        const popularLocations = await (0, database_1.db)('annotations')
            .select('location_name')
            .count('* as count')
            .where('status', 'approved')
            .whereNotNull('location_name')
            .groupBy('location_name')
            .orderBy('count', 'desc')
            .limit(10);
        const smellIntensityDistribution = await (0, database_1.db)('annotations')
            .select('smell_intensity')
            .count('* as count')
            .where('status', 'approved')
            .groupBy('smell_intensity')
            .orderBy('smell_intensity', 'asc');
        const cacheKey = 'search:popular_terms';
        const results = {
            categories: popularCategories,
            locations: popularLocations,
            smellIntensityDistribution,
        };
        await redis_1.cacheService.set(cacheKey, JSON.stringify(results), 3600);
        logger_1.logger.info('热门搜索词获取成功');
        res.json({
            success: true,
            message: '热门搜索词获取成功',
            data: results,
        });
    }
    catch (error) {
        logger_1.logger.error('热门搜索词获取失败', { error });
        throw error;
    }
});
exports.advancedSearch = (0, errorHandler_2.asyncHandler)(async (req, res) => {
    const { latitude, longitude, radius = 5000, keyword, category, smellIntensity, dateRange, hasMedia, sortBy = 'created_at', sortOrder = 'desc', page = 1, limit = 20, } = req.body;
    try {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        let query = (0, database_1.db)('annotations')
            .leftJoin('users', 'annotations.user_id', 'users.id')
            .leftJoin('media_files', 'annotations.id', 'media_files.annotation_id')
            .select('annotations.*', 'users.username', 'users.display_name', 'users.avatar_url', database_1.db.raw('COUNT(DISTINCT media_files.id) as media_count'))
            .where('annotations.status', 'approved')
            .groupBy('annotations.id', 'users.id');
        if (latitude && longitude) {
            const radiusInDegrees = parseInt(radius) / 111000;
            query = query.whereRaw('ABS(annotations.latitude - ?) < ? AND ABS(annotations.longitude - ?) < ?', [
                parseFloat(latitude), radiusInDegrees,
                parseFloat(longitude), radiusInDegrees,
            ]);
        }
        if (keyword) {
            query = query.where(function () {
                this.where('annotations.title', 'like', `%${keyword}%`)
                    .orWhere('annotations.description', 'like', `%${keyword}%`)
                    .orWhere('annotations.location_name', 'like', `%${keyword}%`);
            });
        }
        if (category) {
            query = query.where('annotations.category', category);
        }
        if (smellIntensity) {
            if (smellIntensity.min !== undefined) {
                query = query.where('annotations.smell_intensity', '>=', parseInt(smellIntensity.min));
            }
            if (smellIntensity.max !== undefined) {
                query = query.where('annotations.smell_intensity', '<=', parseInt(smellIntensity.max));
            }
        }
        if (dateRange) {
            if (dateRange.start) {
                query = query.where('annotations.created_at', '>=', new Date(dateRange.start));
            }
            if (dateRange.end) {
                query = query.where('annotations.created_at', '<=', new Date(dateRange.end));
            }
        }
        if (hasMedia !== undefined) {
            if (hasMedia) {
                query = query.having(database_1.db.raw('COUNT(DISTINCT media_files.id)'), '>', 0);
            }
            else {
                query = query.having(database_1.db.raw('COUNT(DISTINCT media_files.id)'), '=', 0);
            }
        }
        switch (sortBy) {
            case 'distance':
                if (latitude && longitude) {
                    query = query.orderByRaw(`
            (ABS(annotations.latitude - ${parseFloat(latitude)}) + ABS(annotations.longitude - ${parseFloat(longitude)})) ${sortOrder.toUpperCase()}
          `);
                }
                else {
                    query = query.orderBy('annotations.created_at', sortOrder);
                }
                break;
            case 'smell_intensity':
                query = query.orderBy('annotations.smell_intensity', sortOrder);
                break;
            case 'popularity':
                query = query.orderBy('annotations.view_count', sortOrder);
                break;
            default:
                query = query.orderBy('annotations.created_at', sortOrder);
        }
        const totalQuery = query.clone().clearSelect().clearOrder().count('* as count').first();
        const results = await query.limit(parseInt(limit)).offset(offset);
        const totalCount = await totalQuery;
        const annotationsWithExtras = results.map(annotation => {
            const result = {
                ...annotation,
                user: {
                    username: annotation.username,
                    display_name: annotation.display_name,
                    avatar_url: annotation.avatar_url,
                },
            };
            if (latitude && longitude) {
                const distance = Math.sqrt(Math.pow((annotation.latitude - parseFloat(latitude)) * 111000, 2) +
                    Math.pow((annotation.longitude - parseFloat(longitude)) * 111000, 2));
                result.distance = Math.round(distance);
            }
            return result;
        });
        logger_1.logger.info('高级搜索成功', {
            filters: req.body,
            count: annotationsWithExtras.length,
        });
        res.json({
            success: true,
            message: '高级搜索成功',
            data: {
                annotations: annotationsWithExtras,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: parseInt(totalCount?.['count'] || '0'),
                    totalPages: Math.ceil(parseInt(totalCount?.['count'] || '0') / parseInt(limit)),
                },
                filters: req.body,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('高级搜索失败', { error });
        throw error;
    }
});
exports.default = {
    searchAnnotationsByLocation: exports.searchAnnotationsByLocation,
    searchAnnotationsByContent: exports.searchAnnotationsByContent,
    getPopularSearchTerms: exports.getPopularSearchTerms,
    advancedSearch: exports.advancedSearch,
};
//# sourceMappingURL=searchController.js.map