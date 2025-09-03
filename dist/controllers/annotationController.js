"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.moderateAnnotation = exports.deleteAnnotation = exports.getAnnotationStats = exports.getUserAnnotations = exports.unlikeAnnotation = exports.likeAnnotation = exports.getNearbyAnnotations = exports.getMapData = exports.getAnnotationsList = exports.updateAnnotation = exports.getAnnotationById = exports.createAnnotation = exports.createPaidPrankAnnotation = exports.handlePaidAnnotationSuccess = exports.getModerationStats = exports.batchModerateAnnotations = exports.getPendingAnnotations = exports.getAnnotationDetails = void 0;
const Annotation_1 = require("../models/Annotation");
const errorHandler_1 = require("../middleware/errorHandler");
const errorHandler_2 = require("../middleware/errorHandler");
const logger_1 = require("../utils/logger");
const redis_1 = require("../config/redis");
const database_1 = require("../config/database");
const stripe_1 = __importDefault(require("stripe"));
const config_1 = require("../config/config");
const stripe = new stripe_1.default(config_1.config.payment.stripe.secretKey, {
    apiVersion: '2023-10-16',
});
exports.getAnnotationDetails = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const userId = req.user?.id;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    try {
        const annotation = await Annotation_1.AnnotationModel.findById(id);
        if (!annotation) {
            throw (0, errorHandler_1.createNotFoundError)('标注不存在');
        }
        const result = { annotation };
        logger_1.logger.info('获取标注详情', {
            annotationId: id,
            userId,
            fromCache: false
        });
        res.json({
            success: true,
            data: result,
        });
    }
    catch (error) {
        if (error.message === 'Annotation not found') {
            throw (0, errorHandler_1.createNotFoundError)('标注不存在');
        }
        throw error;
    }
});
exports.getPendingAnnotations = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc', } = req.query;
    const annotations = await Annotation_1.AnnotationModel.getList({
        page: Number(page),
        limit: Number(limit),
        sortBy: sortBy,
        sortOrder: sortOrder,
        filters: { status: 'pending' },
    });
    const totalResult = await (0, database_1.db)('annotations')
        .where('status', 'pending')
        .count('* as count')
        .first();
    const total = Number(totalResult?.['count'] || 0);
    logger_1.logger.info('获取待审核标注列表', {
        page: Number(page),
        limit: Number(limit),
        total,
    });
    res.json({
        success: true,
        data: {
            annotations,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total,
                pages: Math.ceil(total / Number(limit)),
            },
        },
    });
});
exports.batchModerateAnnotations = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { annotationIds, action, reason } = req.body;
    const moderatorId = req.user?.id;
    if (!moderatorId) {
        throw (0, errorHandler_1.createAuthError)('管理员未认证');
    }
    if (!annotationIds || !Array.isArray(annotationIds) || annotationIds.length === 0) {
        throw (0, errorHandler_1.createValidationError)('annotationIds', '标注ID列表不能为空');
    }
    if (!['approve', 'reject', 'flag'].includes(action)) {
        throw (0, errorHandler_1.createValidationError)('action', '无效的审核操作');
    }
    const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'flagged';
    const updateData = {
        status,
        moderated_by: moderatorId,
        moderated_at: new Date(),
        updated_at: new Date(),
    };
    if (reason) {
        updateData.moderation_reason = reason;
    }
    await (0, database_1.db)('annotations')
        .whereIn('id', annotationIds)
        .where('status', 'pending')
        .update(updateData);
    for (const id of annotationIds) {
        await redis_1.cacheService.del(`annotation:${id}`);
    }
    logger_1.logger.info('批量审核标注', {
        moderatorId,
        annotationIds,
        action,
        reason,
    });
    res.json({
        success: true,
        message: `成功${action === 'approve' ? '通过' : action === 'reject' ? '拒绝' : '标记'}${annotationIds.length}个标注`,
        data: {
            processedCount: annotationIds.length,
            action,
            status,
        },
    });
});
exports.getModerationStats = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { timeRange = '7d' } = req.query;
    const dateFilter = new Date();
    switch (timeRange) {
        case '1d':
            dateFilter.setDate(dateFilter.getDate() - 1);
            break;
        case '7d':
            dateFilter.setDate(dateFilter.getDate() - 7);
            break;
        case '30d':
            dateFilter.setDate(dateFilter.getDate() - 30);
            break;
        default:
            dateFilter.setDate(dateFilter.getDate() - 7);
    }
    const stats = await (0, database_1.db)('annotations')
        .select('status')
        .count('* as count')
        .where('created_at', '>=', dateFilter)
        .groupBy('status');
    const paidStats = await (0, database_1.db)('annotations')
        .join('payments', 'annotations.id', 'payments.annotation_id')
        .select('payments.status as payment_status')
        .count('* as count')
        .where('annotations.created_at', '>=', dateFilter)
        .groupBy('payments.status');
    const moderatorStats = await (0, database_1.db)('annotations')
        .select('moderated_by')
        .count('* as count')
        .whereNotNull('moderated_by')
        .where('moderated_at', '>=', dateFilter)
        .groupBy('moderated_by');
    const result = {
        timeRange,
        annotationStats: stats.reduce((acc, stat) => {
            acc[stat.status] = Number(stat.count);
            return acc;
        }, {}),
        paymentStats: paidStats.reduce((acc, stat) => {
            acc[stat.payment_status] = Number(stat.count);
            return acc;
        }, {}),
        moderatorActivity: moderatorStats.map((stat) => ({
            moderatorId: stat.moderated_by,
            count: Number(stat.count),
        })),
    };
    logger_1.logger.info('获取审核统计', { timeRange });
    res.json({
        success: true,
        data: result,
    });
});
exports.handlePaidAnnotationSuccess = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { sessionId } = req.body;
    if (!sessionId) {
        throw (0, errorHandler_1.createValidationError)('sessionId', '支付会话ID不能为空');
    }
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid') {
        throw (0, errorHandler_1.createValidationError)('payment', '支付未完成');
    }
    const metadata = session.metadata;
    if (!metadata || metadata['type'] !== 'prank_annotation') {
        throw (0, errorHandler_1.createValidationError)('session', '无效的支付会话');
    }
    const annotationData = {
        user_id: metadata['userId'] || '',
        latitude: parseFloat(metadata['latitude'] || '0'),
        longitude: parseFloat(metadata['longitude'] || '0'),
        smell_intensity: parseInt(metadata['smellIntensity'] || '5'),
        description: metadata['description'] || '',
        media_files: JSON.parse(metadata['mediaFiles'] || '[]'),
    };
    const annotation = await Annotation_1.AnnotationModel.create(annotationData);
    await (0, database_1.db)('payments')
        .where('payment_intent_id', sessionId)
        .update({
        annotation_id: annotation.id,
        status: 'completed',
        processed_at: new Date(),
        updated_at: new Date(),
    });
    await redis_1.cacheService.set(`annotation:${annotation.id}`, JSON.stringify(annotation), 3600);
    logger_1.logger.info('付费恶搞标注创建成功', {
        annotationId: annotation.id,
        userId: metadata['userId'],
        sessionId,
        amount: (session.amount_total || 0) / 100,
    });
    res.status(201).json({
        success: true,
        message: '付费恶搞标注创建成功',
        data: {
            annotation: {
                id: annotation.id,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                status: annotation.status,
                isPaid: true,
                mediaFiles: annotation.media_files,
                createdAt: annotation.created_at,
            },
            payment: {
                sessionId,
                amount: (session.amount_total || 0) / 100,
                currency: session.currency,
            },
        },
    });
});
exports.createPaidPrankAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const { latitude, longitude, smellIntensity, description, mediaFiles, amount, currency = 'usd', paymentDescription, } = req.body;
    if (!amount || amount < 1 || amount > 100) {
        throw (0, errorHandler_1.createValidationError)('amount', '支付金额必须在 $1-$100 之间');
    }
    const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
                price_data: {
                    currency,
                    product_data: {
                        name: '恶搞标注创建',
                        description: paymentDescription || `创建恶搞标注 - 臭味强度: ${smellIntensity}`,
                    },
                    unit_amount: Math.round(amount * 100),
                },
                quantity: 1,
            }],
        mode: 'payment',
        success_url: `${process.env['FRONTEND_URL'] || 'http://localhost:5176'}/prank-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env['FRONTEND_URL'] || 'http://localhost:5176'}/map`,
        metadata: {
            userId,
            latitude: latitude.toString(),
            longitude: longitude.toString(),
            smellIntensity: smellIntensity.toString(),
            description: description || '',
            mediaFiles: JSON.stringify(mediaFiles || []),
            type: 'prank_annotation',
        },
    });
    const dbClient = process.env['DB_CLIENT'] || 'sqlite3';
    if (dbClient === 'postgresql') {
        await (0, database_1.db)('payments').insert({
            user_id: userId,
            amount,
            currency: currency.toUpperCase(),
            payment_method: 'stripe',
            payment_intent_id: session.id,
            status: 'pending',
            description: paymentDescription || `恶搞标注创建 - 臭味强度: ${smellIntensity}`,
            metadata: {
                sessionId: session.id,
                annotationData: {
                    latitude,
                    longitude,
                    smellIntensity,
                    description,
                    mediaFiles,
                },
            },
            created_at: new Date(),
            updated_at: new Date(),
        });
    }
    else {
        await (0, database_1.db)('payments').insert({
            id: require('uuid').v4(),
            user_id: userId,
            amount,
            currency: currency.toUpperCase(),
            payment_method: 'stripe',
            payment_intent_id: session.id,
            status: 'pending',
            description: paymentDescription || `恶搞标注创建 - 臭味强度: ${smellIntensity}`,
            created_at: new Date(),
            updated_at: new Date(),
        });
    }
    logger_1.logger.info('付费恶搞标注支付会话创建成功', {
        sessionId: session.id,
        userId,
        amount,
        currency,
    });
    res.status(201).json({
        success: true,
        message: '支付会话创建成功',
        data: {
            sessionId: session.id,
            paymentUrl: session.url,
            amount,
            currency,
        },
    });
});
exports.createAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const { latitude, longitude, smellIntensity, description, mediaFiles } = req.body;
    const annotationData = {
        user_id: userId,
        latitude,
        longitude,
        smell_intensity: smellIntensity,
        description,
        media_files: mediaFiles,
    };
    const annotation = await Annotation_1.AnnotationModel.create(annotationData);
    await redis_1.cacheService.set(`annotation:${annotation.id}`, JSON.stringify(annotation), 3600);
    logger_1.logger.info('标注创建成功', {
        annotationId: annotation.id,
        userId,
        intensity: annotation.smell_intensity,
    });
    res.status(201).json({
        success: true,
        message: '标注创建成功',
        data: {
            annotation: {
                id: annotation.id,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                status: annotation.status,
                mediaFiles: annotation.media_files,
                createdAt: annotation.created_at,
            },
        },
    });
});
exports.getAnnotationById = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    const cached = await redis_1.cacheService.get(`annotation:${id}`);
    if (cached) {
        try {
            const annotation = JSON.parse(cached);
            Annotation_1.AnnotationModel.incrementViewCount(id).catch((error) => {
                logger_1.logger.error('增加浏览次数失败', { annotationId: id, error });
            });
            res.json({
                success: true,
                data: { annotation },
            });
            return;
        }
        catch (parseError) {
            logger_1.logger.error('缓存数据解析失败', { annotationId: id, cached, error: parseError });
            await redis_1.cacheService.del(`annotation:${id}`);
        }
    }
    const annotation = await Annotation_1.AnnotationModel.findById(id);
    if (!annotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    await redis_1.cacheService.set(`annotation:${id}`, JSON.stringify(annotation), 3600);
    Annotation_1.AnnotationModel.incrementViewCount(id).catch((error) => {
        logger_1.logger.error('增加浏览次数失败', { annotationId: id, error });
    });
    res.json({
        success: true,
        data: {
            annotation: {
                id: annotation.id,
                userId: annotation.user_id,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                country: annotation.country,
                region: annotation.region,
                city: annotation.city,
                status: annotation.status,
                mediaFiles: annotation.media_files,
                viewCount: annotation.view_count,
                likeCount: annotation.like_count,
                commentCount: annotation.comment_count,
                createdAt: annotation.created_at,
                updatedAt: annotation.updated_at,
            },
        },
    });
});
exports.updateAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const userId = req.user?.id;
    const userRole = req.user?.role;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const annotation = await Annotation_1.AnnotationModel.findById(id);
    if (!annotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    if (annotation.user_id !== userId && userRole !== 'admin' && userRole !== 'moderator') {
        throw (0, errorHandler_1.createForbiddenError)('只能修改自己的标注');
    }
    const { smellIntensity, description } = req.body;
    const updateData = {};
    if (smellIntensity !== undefined) {
        updateData.smell_intensity = smellIntensity;
    }
    if (description !== undefined) {
        updateData.description = description;
    }
    const updatedAnnotation = await Annotation_1.AnnotationModel.update(id, updateData);
    if (!updatedAnnotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    await redis_1.cacheService.del(`annotation:${id}`);
    logger_1.logger.info('标注更新成功', { annotationId: id, userId });
    res.json({
        success: true,
        message: '标注更新成功',
        data: {
            annotation: {
                id: updatedAnnotation.id,
                latitude: updatedAnnotation.latitude,
                longitude: updatedAnnotation.longitude,
                smellIntensity: updatedAnnotation.smell_intensity,
                description: updatedAnnotation.description,
                status: updatedAnnotation.status,
                mediaFiles: updatedAnnotation.media_files,
                updatedAt: updatedAnnotation.updated_at,
            },
        },
    });
});
exports.getAnnotationsList = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc', latitude, longitude, radius = 1000, intensityMin, intensityMax, country, region, city, startDate, endDate, } = req.query;
    const filters = {};
    if (latitude && longitude) {
        filters.latitude = parseFloat(latitude);
        filters.longitude = parseFloat(longitude);
        filters.radius = parseInt(radius, 10);
    }
    if (intensityMin) {
        filters.intensityMin = parseInt(intensityMin, 10);
    }
    if (intensityMax) {
        filters.intensityMax = parseInt(intensityMax, 10);
    }
    if (country) {
        filters.country = country;
    }
    if (region) {
        filters.region = region;
    }
    if (city) {
        filters.city = city;
    }
    if (startDate) {
        filters.startDate = new Date(startDate);
    }
    if (endDate) {
        filters.endDate = new Date(endDate);
    }
    const { annotations, total } = await Annotation_1.AnnotationModel.getList({
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        sortBy: sortBy,
        sortOrder: sortOrder,
        filters,
    });
    res.json({
        success: true,
        data: {
            annotations: annotations.map(annotation => ({
                id: annotation.id,
                userId: annotation.user_id,
                username: annotation.username,
                displayName: annotation.display_name,
                avatarUrl: annotation.avatar_url,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                country: annotation.country,
                region: annotation.region,
                city: annotation.city,
                status: annotation.status,
                mediaFiles: annotation.media_files,
                viewCount: annotation.view_count,
                likeCount: annotation.like_count,
                commentCount: annotation.comment_count,
                createdAt: annotation.created_at,
            })),
            pagination: {
                page: parseInt(page, 10),
                limit: parseInt(limit, 10),
                total,
                pages: Math.ceil(total / parseInt(limit, 10)),
            },
        },
    });
});
exports.getMapData = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { north, south, east, west, zoom = 10, intensityMin, intensityMax, } = req.query;
    if (!north || !south || !east || !west) {
        throw (0, errorHandler_1.createValidationError)('bounds', '地图边界参数缺失');
    }
    const bounds = {
        north: parseFloat(north),
        south: parseFloat(south),
        east: parseFloat(east),
        west: parseFloat(west),
    };
    const options = {
        zoom: parseInt(zoom, 10),
    };
    if (intensityMin) {
        options.intensityMin = parseInt(intensityMin, 10);
    }
    if (intensityMax) {
        options.intensityMax = parseInt(intensityMax, 10);
    }
    const cacheKey = `map_data:${JSON.stringify({ bounds, options })}`;
    const cached = await redis_1.cacheService.get(cacheKey);
    if (cached) {
        try {
            const cachedData = JSON.parse(cached);
            res.json({
                success: true,
                data: {
                    annotations: cachedData,
                },
            });
            return;
        }
        catch (parseError) {
            logger_1.logger.warn('缓存数据解析失败，将重新获取数据', { cacheKey, error: parseError });
            await redis_1.cacheService.del(cacheKey);
        }
    }
    const annotations = await Annotation_1.AnnotationModel.getMapData(bounds, options);
    await redis_1.cacheService.set(cacheKey, JSON.stringify(annotations), 300);
    res.json({
        success: true,
        data: {
            annotations: annotations.map(annotation => ({
                id: annotation.id,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                createdAt: annotation.created_at,
            })),
        },
    });
});
exports.getNearbyAnnotations = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { latitude, longitude, radius = 1000, limit = 10, } = req.query;
    if (!latitude || !longitude) {
        throw (0, errorHandler_1.createValidationError)('coordinates', '经纬度参数缺失');
    }
    const annotations = await Annotation_1.AnnotationModel.getNearby(parseFloat(latitude), parseFloat(longitude), parseInt(radius, 10), parseInt(limit, 10));
    res.json({
        success: true,
        data: {
            annotations: annotations.map(annotation => ({
                id: annotation.id,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                distance: annotation.distance,
                createdAt: annotation.created_at,
            })),
        },
    });
});
exports.likeAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const userId = req.user?.id;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const annotation = await Annotation_1.AnnotationModel.findById(id);
    if (!annotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    const likeKey = `like:${userId}:${id}`;
    const alreadyLiked = await redis_1.cacheService.get(likeKey);
    if (alreadyLiked) {
        throw (0, errorHandler_1.createValidationError)('like', '已经点赞过了');
    }
    await Annotation_1.AnnotationModel.incrementLikeCount(id);
    await redis_1.cacheService.set(likeKey, 'true', 24 * 3600);
    await redis_1.cacheService.del(`annotation:${id}`);
    logger_1.logger.info('标注点赞成功', { annotationId: id, userId });
    res.json({
        success: true,
        message: '点赞成功',
    });
});
exports.unlikeAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const userId = req.user?.id;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const annotation = await Annotation_1.AnnotationModel.findById(id);
    if (!annotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    const likeKey = `like:${userId}:${id}`;
    const alreadyLiked = await redis_1.cacheService.get(likeKey);
    if (!alreadyLiked) {
        throw (0, errorHandler_1.createValidationError)('like', '还没有点赞');
    }
    await Annotation_1.AnnotationModel.decrementLikeCount(id);
    await redis_1.cacheService.del(likeKey);
    await redis_1.cacheService.del(`annotation:${id}`);
    logger_1.logger.info('标注取消点赞成功', { annotationId: id, userId });
    res.json({
        success: true,
        message: '取消点赞成功',
    });
});
exports.getUserAnnotations = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { page = 1, limit = 20, status, } = req.query;
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const options = {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
    };
    if (status) {
        options.status = status;
    }
    const { annotations, total } = await Annotation_1.AnnotationModel.getUserAnnotations(userId, options);
    res.json({
        success: true,
        data: {
            annotations: annotations.map(annotation => ({
                id: annotation.id,
                latitude: annotation.latitude,
                longitude: annotation.longitude,
                smellIntensity: annotation.smell_intensity,
                description: annotation.description,
                status: annotation.status,
                mediaFiles: annotation.media_files,
                viewCount: annotation.view_count,
                likeCount: annotation.like_count,
                commentCount: annotation.comment_count,
                createdAt: annotation.created_at,
                updatedAt: annotation.updated_at,
            })),
            pagination: {
                page: parseInt(page, 10),
                limit: parseInt(limit, 10),
                total,
                pages: Math.ceil(total / parseInt(limit, 10)),
            },
        },
    });
});
exports.getAnnotationStats = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { userId, startDate, endDate, } = req.query;
    const filters = {};
    if (userId) {
        filters.userId = userId;
    }
    if (startDate) {
        filters.startDate = new Date(startDate);
    }
    if (endDate) {
        filters.endDate = new Date(endDate);
    }
    const cacheKey = `stats:annotations:${JSON.stringify(filters)}`;
    const cached = await redis_1.cacheService.get(cacheKey);
    if (cached) {
        res.json({
            success: true,
            data: JSON.parse(cached),
        });
        return;
    }
    const stats = await Annotation_1.AnnotationModel.getStats(filters);
    await redis_1.cacheService.set(cacheKey, JSON.stringify(stats), 600);
    res.json({
        success: true,
        data: stats,
    });
});
exports.deleteAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const userId = req.user?.id;
    const userRole = req.user?.role;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const annotation = await Annotation_1.AnnotationModel.findById(id);
    if (!annotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    if (annotation.user_id !== userId && userRole !== 'admin' && userRole !== 'moderator') {
        throw (0, errorHandler_1.createForbiddenError)('只能删除自己的标注');
    }
    const success = await Annotation_1.AnnotationModel.delete(id);
    if (!success) {
        throw new errorHandler_1.AppError('标注删除失败', 500);
    }
    await redis_1.cacheService.del(`annotation:${id}`);
    logger_1.logger.info('标注删除成功', { annotationId: id, userId });
    res.json({
        success: true,
        message: '标注删除成功',
    });
});
exports.moderateAnnotation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const { status, reason } = req.body;
    const moderatorId = req.user?.id;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '标注ID不能为空');
    }
    if (!moderatorId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const annotation = await Annotation_1.AnnotationModel.moderate(id, status, moderatorId, reason);
    if (!annotation) {
        throw (0, errorHandler_1.createNotFoundError)('标注不存在');
    }
    await redis_1.cacheService.del(`annotation:${id}`);
    logger_1.logger.info('标注审核完成', {
        annotationId: id,
        moderatorId,
        status,
        reason,
    });
    res.json({
        success: true,
        message: '标注审核完成',
        data: {
            annotation: {
                id: annotation.id,
                status: annotation.status,
                moderationReason: annotation.moderation_reason,
                moderatedBy: annotation.moderated_by,
                moderatedAt: annotation.moderated_at,
            },
        },
    });
});
exports.default = {
    createAnnotation: exports.createAnnotation,
    createPaidPrankAnnotation: exports.createPaidPrankAnnotation,
    handlePaidAnnotationSuccess: exports.handlePaidAnnotationSuccess,
    getAnnotationDetails: exports.getAnnotationDetails,
    getPendingAnnotations: exports.getPendingAnnotations,
    batchModerateAnnotations: exports.batchModerateAnnotations,
    getModerationStats: exports.getModerationStats,
    getAnnotationById: exports.getAnnotationById,
    updateAnnotation: exports.updateAnnotation,
    getAnnotationsList: exports.getAnnotationsList,
    getMapData: exports.getMapData,
    getNearbyAnnotations: exports.getNearbyAnnotations,
    likeAnnotation: exports.likeAnnotation,
    unlikeAnnotation: exports.unlikeAnnotation,
    getUserAnnotations: exports.getUserAnnotations,
    getAnnotationStats: exports.getAnnotationStats,
    deleteAnnotation: exports.deleteAnnotation,
    moderateAnnotation: exports.moderateAnnotation,
};
//# sourceMappingURL=annotationController.js.map