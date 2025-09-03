"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.markAllNotificationsAsRead = exports.markNotificationAsRead = exports.getUserNotifications = exports.getUserFavorites = exports.unfavoriteAnnotation = exports.favoriteAnnotation = exports.unlikeAnnotation = exports.likeAnnotation = exports.getFollowers = exports.getFollowing = exports.unfollowUser = exports.followUser = void 0;
const uuid_1 = require("uuid");
const database_1 = __importDefault(require("../config/database"));
const emailService_1 = require("../services/emailService");
const websocketManager_1 = require("../services/websocketManager");
const followUser = async (req, res) => {
    try {
        const { userId: followingId } = req.params;
        const followerId = req.user?.id;
        if (!followerId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        if (followerId === followingId) {
            return res.status(400).json({ error: '不能关注自己' });
        }
        const existingFollow = await (0, database_1.default)('user_follows')
            .where({ follower_id: followerId, following_id: followingId })
            .first();
        if (existingFollow) {
            return res.status(400).json({ error: '已经关注该用户' });
        }
        const followId = (0, uuid_1.v4)();
        await (0, database_1.default)('user_follows').insert({
            id: followId,
            follower_id: followerId,
            following_id: followingId,
            created_at: new Date(),
        });
        if (followingId) {
            const followerInfo = await (0, database_1.default)('users').where('id', followerId).first();
            await createNotification({
                user_id: followingId,
                from_user_id: followerId,
                type: 'follow',
                title: '新的关注者',
                content: `${followerInfo.username} 关注了你`,
                related_id: followId,
                related_type: 'follow',
            });
        }
        return res.json({ message: '关注成功', followId });
    }
    catch (error) {
        console.error('关注用户失败:', error);
        return res.status(500).json({ error: '关注失败' });
    }
};
exports.followUser = followUser;
const unfollowUser = async (req, res) => {
    try {
        const { userId: followingId } = req.params;
        const followerId = req.user?.id;
        if (!followerId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const deleted = await (0, database_1.default)('user_follows')
            .where({ follower_id: followerId, following_id: followingId })
            .del();
        if (deleted === 0) {
            return res.status(404).json({ error: '未找到关注记录' });
        }
        return res.json({ message: '取消关注成功' });
    }
    catch (error) {
        console.error('取消关注失败:', error);
        return res.status(500).json({ error: '取消关注失败' });
    }
};
exports.unfollowUser = unfollowUser;
const getFollowing = async (req, res) => {
    try {
        const { userId } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const following = await (0, database_1.default)('user_follows')
            .join('users', 'user_follows.following_id', 'users.id')
            .where('user_follows.follower_id', userId)
            .select('users.id', 'users.username', 'users.avatar_url', 'users.bio', 'user_follows.created_at as followed_at')
            .orderBy('user_follows.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const total = await (0, database_1.default)('user_follows')
            .where('follower_id', userId)
            .count('* as count')
            .first();
        return res.json({
            following,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取关注列表失败:', error);
        return res.status(500).json({ error: '获取关注列表失败' });
    }
};
exports.getFollowing = getFollowing;
const getFollowers = async (req, res) => {
    try {
        const { userId } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const followers = await (0, database_1.default)('user_follows')
            .join('users', 'user_follows.follower_id', 'users.id')
            .where('user_follows.following_id', userId)
            .select('users.id', 'users.username', 'users.avatar_url', 'users.bio', 'user_follows.created_at as followed_at')
            .orderBy('user_follows.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const total = await (0, database_1.default)('user_follows')
            .where('following_id', userId)
            .count('* as count')
            .first();
        return res.json({
            followers,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取粉丝列表失败:', error);
        return res.status(500).json({ error: '获取粉丝列表失败' });
    }
};
exports.getFollowers = getFollowers;
const likeAnnotation = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const existingLike = await (0, database_1.default)('annotation_likes')
            .where({ annotation_id: annotationId, user_id: userId })
            .first();
        if (existingLike) {
            return res.status(400).json({ error: '已经点赞过该标注' });
        }
        const likeId = (0, uuid_1.v4)();
        await (0, database_1.default)('annotation_likes').insert({
            id: likeId,
            annotation_id: annotationId,
            user_id: userId,
            created_at: new Date(),
        });
        await (0, database_1.default)('annotations')
            .where('id', annotationId)
            .increment('likes_count', 1);
        const annotation = await (0, database_1.default)('annotations').where('id', annotationId).first();
        if (annotation && annotation.user_id !== userId) {
            const userInfo = await (0, database_1.default)('users').where('id', userId).first();
            if (annotationId) {
                await createNotification({
                    user_id: annotation.user_id,
                    from_user_id: userId,
                    type: 'like',
                    title: '标注获得点赞',
                    content: `${userInfo.username} 点赞了你的标注`,
                    related_id: annotationId,
                    related_type: 'annotation',
                });
            }
        }
        return res.json({ message: '点赞成功', likeId });
    }
    catch (error) {
        console.error('点赞标注失败:', error);
        return res.status(500).json({ error: '点赞失败' });
    }
};
exports.likeAnnotation = likeAnnotation;
const unlikeAnnotation = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const deleted = await (0, database_1.default)('annotation_likes')
            .where({ annotation_id: annotationId, user_id: userId })
            .del();
        if (deleted === 0) {
            return res.status(404).json({ error: '未找到点赞记录' });
        }
        await (0, database_1.default)('annotations')
            .where('id', annotationId)
            .decrement('likes_count', 1);
        return res.json({ message: '取消点赞成功' });
    }
    catch (error) {
        console.error('取消点赞失败:', error);
        return res.status(500).json({ error: '取消点赞失败' });
    }
};
exports.unlikeAnnotation = unlikeAnnotation;
const favoriteAnnotation = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const existingFavorite = await (0, database_1.default)('user_favorites')
            .where({ user_id: userId, annotation_id: annotationId })
            .first();
        if (existingFavorite) {
            return res.status(400).json({ error: '已经收藏过该标注' });
        }
        const favoriteId = (0, uuid_1.v4)();
        await (0, database_1.default)('user_favorites').insert({
            id: favoriteId,
            user_id: userId,
            annotation_id: annotationId,
            created_at: new Date(),
        });
        return res.json({ message: '收藏成功', favoriteId });
    }
    catch (error) {
        console.error('收藏标注失败:', error);
        return res.status(500).json({ error: '收藏失败' });
    }
};
exports.favoriteAnnotation = favoriteAnnotation;
const unfavoriteAnnotation = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const deleted = await (0, database_1.default)('user_favorites')
            .where({ user_id: userId, annotation_id: annotationId })
            .del();
        if (deleted === 0) {
            return res.status(404).json({ error: '未找到收藏记录' });
        }
        return res.json({ message: '取消收藏成功' });
    }
    catch (error) {
        console.error('取消收藏失败:', error);
        return res.status(500).json({ error: '取消收藏失败' });
    }
};
exports.unfavoriteAnnotation = unfavoriteAnnotation;
const getUserFavorites = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const favorites = await (0, database_1.default)('user_favorites')
            .join('annotations', 'user_favorites.annotation_id', 'annotations.id')
            .join('users', 'annotations.user_id', 'users.id')
            .where('user_favorites.user_id', userId)
            .select('annotations.*', 'users.username', 'users.avatar_url', 'user_favorites.created_at as favorited_at')
            .orderBy('user_favorites.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const total = await (0, database_1.default)('user_favorites')
            .where('user_id', userId)
            .count('* as count')
            .first();
        return res.json({
            favorites,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取收藏列表失败:', error);
        return res.status(500).json({ error: '获取收藏列表失败' });
    }
};
exports.getUserFavorites = getUserFavorites;
const createNotification = async (notificationData) => {
    try {
        const notificationId = (0, uuid_1.v4)();
        await (0, database_1.default)('notifications').insert({
            id: notificationId,
            ...notificationData,
            is_read: false,
            created_at: new Date(),
        });
        setImmediate(async () => {
            try {
                const user = await (0, database_1.default)('users')
                    .select('email', 'username', 'email_notifications')
                    .where('id', notificationData.user_id)
                    .first();
                let fromUser = undefined;
                if (notificationData.from_user_id) {
                    fromUser = await (0, database_1.default)('users')
                        .select('id', 'username', 'avatar_url')
                        .where('id', notificationData.from_user_id)
                        .first();
                }
                const baseUrl = process.env['FRONTEND_URL'] || 'http://localhost:5176';
                let actionUrl = undefined;
                if (notificationData.related_type === 'annotation') {
                    actionUrl = `${baseUrl}/map?annotation=${notificationData.related_id}`;
                }
                else if (notificationData.related_type === 'user' && notificationData.from_user_id) {
                    actionUrl = `${baseUrl}/users/${notificationData.from_user_id}`;
                }
                if (user && user.email && user.email_notifications) {
                    await emailService_1.emailService.sendNotificationEmail(user.email, {
                        type: notificationData.type,
                        title: notificationData.title,
                        content: notificationData.content,
                        fromUsername: fromUser?.username,
                        actionUrl,
                    });
                }
                await (0, websocketManager_1.sendRealtimeNotification)(notificationData.user_id, {
                    type: notificationData.type,
                    title: notificationData.title,
                    message: notificationData.content,
                    data: {
                        sender: fromUser ? {
                            id: fromUser.id,
                            username: fromUser.username,
                            avatar_url: fromUser.avatar_url,
                        } : null,
                        actionUrl,
                        createdAt: new Date().toISOString(),
                    },
                });
            }
            catch (error) {
                console.error('发送通知失败:', error);
            }
        });
        return notificationId;
    }
    catch (error) {
        console.error('创建通知失败:', error);
        return undefined;
    }
};
const getUserNotifications = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { page = 1, limit = 20, unread_only = false } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        let query = (0, database_1.default)('notifications')
            .leftJoin('users', 'notifications.from_user_id', 'users.id')
            .where('notifications.user_id', userId)
            .select('notifications.*', 'users.username as from_username', 'users.avatar_url as from_avatar_url');
        if (unread_only === 'true') {
            query = query.where('notifications.is_read', false);
        }
        const notifications = await query
            .orderBy('notifications.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const totalQuery = (0, database_1.default)('notifications').where('user_id', userId);
        if (unread_only === 'true') {
            totalQuery.where('is_read', false);
        }
        const total = await totalQuery.count('* as count').first();
        return res.json({
            notifications,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取通知失败:', error);
        return res.status(500).json({ error: '获取通知失败' });
    }
};
exports.getUserNotifications = getUserNotifications;
const markNotificationAsRead = async (req, res) => {
    try {
        const { notificationId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const updated = await (0, database_1.default)('notifications')
            .where({ id: notificationId, user_id: userId })
            .update({ is_read: true });
        if (updated === 0) {
            return res.status(404).json({ error: '未找到通知' });
        }
        return res.json({ message: '标记为已读成功' });
    }
    catch (error) {
        console.error('标记通知已读失败:', error);
        return res.status(500).json({ error: '标记已读失败' });
    }
};
exports.markNotificationAsRead = markNotificationAsRead;
const markAllNotificationsAsRead = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        await (0, database_1.default)('notifications')
            .where({ user_id: userId, is_read: false })
            .update({ is_read: true });
        return res.json({ message: '所有通知已标记为已读' });
    }
    catch (error) {
        console.error('标记所有通知已读失败:', error);
        return res.status(500).json({ error: '标记已读失败' });
    }
};
exports.markAllNotificationsAsRead = markAllNotificationsAsRead;
//# sourceMappingURL=socialController.js.map