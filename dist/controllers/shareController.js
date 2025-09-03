"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateShareLink = exports.getPopularShares = exports.getUserShareHistory = exports.getAnnotationShareStats = exports.createShareRecord = void 0;
const uuid_1 = require("uuid");
const database_1 = __importDefault(require("../config/database"));
const UserFeed_1 = require("../models/UserFeed");
const createShareRecord = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const { platform, shareUrl, shareData } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        if (!platform) {
            return res.status(400).json({ error: '分享平台不能为空' });
        }
        const annotation = await (0, database_1.default)('annotations').where('id', annotationId).first();
        if (!annotation) {
            return res.status(404).json({ error: '标注不存在' });
        }
        const validPlatforms = ['twitter', 'instagram', 'tiktok', 'wechat', 'weibo', 'facebook', 'linkedin', 'other'];
        if (!validPlatforms.includes(platform)) {
            return res.status(400).json({ error: '不支持的分享平台' });
        }
        const shareId = (0, uuid_1.v4)();
        await (0, database_1.default)('share_records').insert({
            id: shareId,
            user_id: userId,
            annotation_id: annotationId,
            platform,
            share_url: shareUrl || null,
            share_data: shareData ? JSON.stringify(shareData) : null,
            created_at: new Date(),
        });
        const userInfo = await (0, database_1.default)('users').where('id', userId).first();
        if (annotation.user_id !== userId && annotationId) {
            await createNotification({
                user_id: annotation.user_id,
                from_user_id: userId,
                type: 'share',
                title: '标注被分享',
                content: `${userInfo.username} 分享了你的标注到 ${getPlatformName(platform)}`,
                related_id: annotationId,
                related_type: 'annotation',
            });
        }
        try {
            if (annotation.user_id && annotationId) {
                await UserFeed_1.UserFeedModel.createShareFeed(userId, annotationId, platform, annotation.user_id);
            }
        }
        catch (error) {
            console.error('创建分享动态失败:', error);
        }
        return res.status(201).json({
            message: '分享记录创建成功',
            shareId,
            platform,
            shareUrl: shareUrl || generateShareUrl(annotationId || '', platform),
        });
    }
    catch (error) {
        console.error('创建分享记录失败:', error);
        return res.status(500).json({ error: '创建分享记录失败' });
    }
};
exports.createShareRecord = createShareRecord;
const getAnnotationShareStats = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const annotation = await (0, database_1.default)('annotations').where('id', annotationId).first();
        if (!annotation) {
            return res.status(404).json({ error: '标注不存在' });
        }
        const shareStats = await (0, database_1.default)('share_records')
            .where('annotation_id', annotationId)
            .select('platform')
            .count('* as count')
            .groupBy('platform');
        const totalShares = await (0, database_1.default)('share_records')
            .where('annotation_id', annotationId)
            .count('* as total')
            .first();
        const recentShares = await (0, database_1.default)('share_records')
            .join('users', 'share_records.user_id', 'users.id')
            .where('share_records.annotation_id', annotationId)
            .select('share_records.platform', 'share_records.created_at', 'users.username', 'users.avatar_url')
            .orderBy('share_records.created_at', 'desc')
            .limit(10);
        const platformStats = shareStats.reduce((acc, stat) => {
            acc[stat.platform] = Number(stat.count);
            return acc;
        }, {});
        return res.json({
            totalShares: Number(totalShares?.['total']) || 0,
            platformStats,
            recentShares: recentShares.map(share => ({
                platform: share.platform,
                platformName: getPlatformName(share.platform),
                createdAt: share.created_at,
                user: {
                    username: share.username,
                    avatarUrl: share.avatar_url,
                },
            })),
        });
    }
    catch (error) {
        console.error('获取分享统计失败:', error);
        return res.status(500).json({ error: '获取分享统计失败' });
    }
};
exports.getAnnotationShareStats = getAnnotationShareStats;
const getUserShareHistory = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { page = 1, limit = 20, platform } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        let query = (0, database_1.default)('share_records')
            .join('annotations', 'share_records.annotation_id', 'annotations.id')
            .where('share_records.user_id', userId)
            .select('share_records.*', 'annotations.description', 'annotations.smell_intensity', 'annotations.latitude', 'annotations.longitude');
        if (platform) {
            query = query.where('share_records.platform', platform);
        }
        const shares = await query
            .orderBy('share_records.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const totalQuery = (0, database_1.default)('share_records').where('user_id', userId);
        if (platform) {
            totalQuery.where('platform', platform);
        }
        const total = await totalQuery.count('* as count').first();
        return res.json({
            shares: shares.map(share => ({
                id: share.id,
                platform: share.platform,
                platformName: getPlatformName(share.platform),
                shareUrl: share.share_url,
                createdAt: share.created_at,
                annotation: {
                    id: share.annotation_id,
                    description: share.description,
                    smellIntensity: share.smell_intensity,
                    latitude: share.latitude,
                    longitude: share.longitude,
                },
            })),
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取分享历史失败:', error);
        return res.status(500).json({ error: '获取分享历史失败' });
    }
};
exports.getUserShareHistory = getUserShareHistory;
const getPopularShares = async (req, res) => {
    try {
        const { timeRange = '7d', limit = 10 } = req.query;
        const startDate = new Date();
        switch (timeRange) {
            case '1d':
                startDate.setDate(startDate.getDate() - 1);
                break;
            case '7d':
                startDate.setDate(startDate.getDate() - 7);
                break;
            case '30d':
                startDate.setDate(startDate.getDate() - 30);
                break;
            default:
                startDate.setDate(startDate.getDate() - 7);
        }
        const popularShares = await (0, database_1.default)('share_records')
            .join('annotations', 'share_records.annotation_id', 'annotations.id')
            .join('users', 'annotations.user_id', 'users.id')
            .where('share_records.created_at', '>=', startDate)
            .select('annotations.id', 'annotations.description', 'annotations.smell_intensity', 'annotations.latitude', 'annotations.longitude', 'annotations.likes_count', 'annotations.views_count', 'users.username', 'users.avatar_url')
            .count('share_records.id as share_count')
            .groupBy('annotations.id')
            .orderBy('share_count', 'desc')
            .limit(Number(limit));
        return res.json({
            popularShares: popularShares.map(item => ({
                annotation: {
                    id: item['id'],
                    description: item['description'],
                    smellIntensity: item['smell_intensity'],
                    latitude: item['latitude'],
                    longitude: item['longitude'],
                    likesCount: item['likes_count'],
                    viewsCount: item['views_count'],
                    user: {
                        username: item['username'],
                        avatarUrl: item['avatar_url'],
                    },
                },
                shareCount: Number(item['share_count']),
            })),
            timeRange,
            generatedAt: new Date().toISOString(),
        });
    }
    catch (error) {
        console.error('获取热门分享失败:', error);
        return res.status(500).json({ error: '获取热门分享失败' });
    }
};
exports.getPopularShares = getPopularShares;
const generateShareLink = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const { platform = 'general' } = req.query;
        const annotation = await (0, database_1.default)('annotations')
            .join('users', 'annotations.user_id', 'users.id')
            .where('annotations.id', annotationId)
            .select('annotations.*', 'users.username')
            .first();
        if (!annotation) {
            return res.status(404).json({ error: '标注不存在' });
        }
        if (!annotationId) {
            return res.status(400).json({ error: '标注ID不能为空' });
        }
        const shareUrl = generateShareUrl(annotationId, platform);
        const shareText = generateShareText(annotation, platform);
        return res.json({
            shareUrl,
            shareText,
            platform,
            annotation: {
                id: annotation.id,
                description: annotation.description,
                smellIntensity: annotation.smell_intensity,
                username: annotation.username,
            },
        });
    }
    catch (error) {
        console.error('生成分享链接失败:', error);
        return res.status(500).json({ error: '生成分享链接失败' });
    }
};
exports.generateShareLink = generateShareLink;
const getPlatformName = (platform) => {
    const platformNames = {
        twitter: 'Twitter',
        instagram: 'Instagram',
        tiktok: 'TikTok',
        wechat: '微信',
        weibo: '微博',
        facebook: 'Facebook',
        linkedin: 'LinkedIn',
        other: '其他',
    };
    return platformNames[platform] || platform;
};
const generateShareUrl = (annotationId, platform) => {
    const baseUrl = process.env['FRONTEND_URL'] || 'https://smellpin.com';
    const annotationUrl = `${baseUrl}/annotation/${annotationId}`;
    switch (platform) {
        case 'twitter':
            return `https://twitter.com/intent/tweet?url=${encodeURIComponent(annotationUrl)}`;
        case 'facebook':
            return `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(annotationUrl)}`;
        case 'linkedin':
            return `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(annotationUrl)}`;
        case 'weibo':
            return `https://service.weibo.com/share/share.php?url=${encodeURIComponent(annotationUrl)}`;
        default:
            return annotationUrl;
    }
};
const generateShareText = (annotation, platform) => {
    const intensity = annotation.smell_intensity;
    const intensityText = intensity >= 8 ? '超强' : intensity >= 6 ? '强烈' : intensity >= 4 ? '中等' : '轻微';
    const baseText = `发现了一个${intensityText}的臭味点！${annotation.description ? ` - ${annotation.description}` : ''}`;
    switch (platform) {
        case 'twitter':
            return `${baseText} #臭味地图 #SmellPin`;
        case 'wechat':
        case 'weibo':
            return `${baseText} 快来看看这个有趣的发现！`;
        default:
            return baseText;
    }
};
const createNotification = async (notificationData) => {
    try {
        const notificationId = (0, uuid_1.v4)();
        await (0, database_1.default)('notifications').insert({
            id: notificationId,
            ...notificationData,
            is_read: false,
            created_at: new Date(),
        });
        return notificationId;
    }
    catch (error) {
        console.error('创建通知失败:', error);
        return undefined;
    }
};
//# sourceMappingURL=shareController.js.map