"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMutualFollows = exports.checkFollowStatus = exports.getUserFollowers = exports.getUserFollowing = exports.unfollowUser = exports.followUser = void 0;
const database_1 = __importDefault(require("../config/database"));
const followUser = async (req, res) => {
    try {
        const { userId: targetUserId } = req.params;
        const followerId = req.user?.id;
        if (!followerId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        if (followerId === targetUserId) {
            return res.status(400).json({ error: '不能关注自己' });
        }
        const targetUser = await (0, database_1.default)('users').where('id', targetUserId).first();
        if (!targetUser) {
            return res.status(404).json({ error: '用户不存在' });
        }
        const existingFollow = await (0, database_1.default)('user_follows')
            .where({
            follower_id: followerId,
            following_id: targetUserId,
        })
            .first();
        if (existingFollow) {
            return res.status(400).json({ error: '已经关注该用户' });
        }
        await (0, database_1.default)('user_follows').insert({
            follower_id: followerId,
            following_id: targetUserId,
            created_at: new Date(),
        });
        await database_1.default.transaction(async (trx) => {
            await trx('users')
                .where('id', followerId)
                .increment('following_count', 1);
            await trx('users')
                .where('id', targetUserId)
                .increment('followers_count', 1);
        });
        const followerInfo = await (0, database_1.default)('users').where('id', followerId).first();
        if (followerInfo && targetUserId) {
            await createNotification({
                user_id: targetUserId,
                from_user_id: followerId,
                type: 'follow',
                title: '新粉丝',
                content: `${followerInfo.username} 关注了你`,
                related_id: followerId,
                related_type: 'user',
            });
        }
        return res.status(201).json({
            message: '关注成功',
            data: {
                follower_id: followerId,
                following_id: targetUserId,
            },
        });
    }
    catch (error) {
        console.error('关注用户失败:', error);
        return res.status(500).json({ error: '关注用户失败' });
    }
};
exports.followUser = followUser;
const unfollowUser = async (req, res) => {
    try {
        const { userId: targetUserId } = req.params;
        const followerId = req.user?.id;
        if (!followerId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const existingFollow = await (0, database_1.default)('user_follows')
            .where({
            follower_id: followerId,
            following_id: targetUserId,
        })
            .first();
        if (!existingFollow) {
            return res.status(400).json({ error: '未关注该用户' });
        }
        await (0, database_1.default)('user_follows')
            .where({
            follower_id: followerId,
            following_id: targetUserId,
        })
            .del();
        await database_1.default.transaction(async (trx) => {
            await trx('users')
                .where('id', followerId)
                .decrement('following_count', 1);
            await trx('users')
                .where('id', targetUserId)
                .decrement('followers_count', 1);
        });
        return res.json({
            message: '取消关注成功',
        });
    }
    catch (error) {
        console.error('取消关注失败:', error);
        return res.status(500).json({ error: '取消关注失败' });
    }
};
exports.unfollowUser = unfollowUser;
const getUserFollowing = async (req, res) => {
    try {
        const { userId } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const user = await (0, database_1.default)('users').where('id', userId).first();
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        const following = await (0, database_1.default)('user_follows')
            .join('users', 'user_follows.following_id', 'users.id')
            .where('user_follows.follower_id', userId)
            .select('users.id', 'users.username', 'users.display_name', 'users.avatar_url', 'users.bio', 'users.followers_count', 'users.following_count', 'user_follows.created_at as followed_at')
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
exports.getUserFollowing = getUserFollowing;
const getUserFollowers = async (req, res) => {
    try {
        const { userId } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const user = await (0, database_1.default)('users').where('id', userId).first();
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        const followers = await (0, database_1.default)('user_follows')
            .join('users', 'user_follows.follower_id', 'users.id')
            .where('user_follows.following_id', userId)
            .select('users.id', 'users.username', 'users.display_name', 'users.avatar_url', 'users.bio', 'users.followers_count', 'users.following_count', 'user_follows.created_at as followed_at')
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
exports.getUserFollowers = getUserFollowers;
const checkFollowStatus = async (req, res) => {
    try {
        const { userId: targetUserId } = req.params;
        const currentUserId = req.user?.id;
        if (!currentUserId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const isFollowing = await (0, database_1.default)('user_follows')
            .where({
            follower_id: currentUserId,
            following_id: targetUserId,
        })
            .first();
        const isFollowedBy = await (0, database_1.default)('user_follows')
            .where({
            follower_id: targetUserId,
            following_id: currentUserId,
        })
            .first();
        return res.json({
            isFollowing: !!isFollowing,
            isFollowedBy: !!isFollowedBy,
            isMutual: !!isFollowing && !!isFollowedBy,
        });
    }
    catch (error) {
        console.error('检查关注状态失败:', error);
        return res.status(500).json({ error: '检查关注状态失败' });
    }
};
exports.checkFollowStatus = checkFollowStatus;
const getMutualFollows = async (req, res) => {
    try {
        const { userId } = req.params;
        const currentUserId = req.user?.id;
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        if (!currentUserId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const mutualFollows = await (0, database_1.default)('user_follows as f1')
            .join('user_follows as f2', function () {
            this.on('f1.following_id', '=', 'f2.follower_id')
                .andOn('f1.follower_id', '=', 'f2.following_id');
        })
            .join('users', 'f1.following_id', 'users.id')
            .where('f1.follower_id', userId)
            .select('users.id', 'users.username', 'users.display_name', 'users.avatar_url', 'users.bio', 'users.followers_count', 'users.following_count')
            .limit(Number(limit))
            .offset(offset);
        const total = await (0, database_1.default)('user_follows as f1')
            .join('user_follows as f2', function () {
            this.on('f1.following_id', '=', 'f2.follower_id')
                .andOn('f1.follower_id', '=', 'f2.following_id');
        })
            .where('f1.follower_id', userId)
            .count('* as count')
            .first();
        return res.json({
            mutualFollows,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取互相关注列表失败:', error);
        return res.status(500).json({ error: '获取互相关注列表失败' });
    }
};
exports.getMutualFollows = getMutualFollows;
const createNotification = async (notificationData) => {
    if (!notificationData.user_id) {
        console.error('user_id is required for creating notification');
        return undefined;
    }
    try {
        const notificationId = await (0, database_1.default)('notifications').insert({
            id: require('uuid').v4(),
            ...notificationData,
            is_read: false,
            created_at: new Date(),
        }).returning('id');
        return notificationId[0];
    }
    catch (error) {
        console.error('创建通知失败:', error);
        return undefined;
    }
};
//# sourceMappingURL=followController.js.map