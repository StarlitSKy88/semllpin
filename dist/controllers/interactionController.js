"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPopularContent = exports.getUserActivityStats = exports.getUserFavorites = exports.getUserLikes = exports.getInteractionStats = exports.unfavoriteAnnotation = exports.favoriteAnnotation = exports.unlikeAnnotation = exports.likeAnnotation = exports.FavoriteType = exports.LikeType = void 0;
const Interaction_1 = require("../models/Interaction");
Object.defineProperty(exports, "LikeType", { enumerable: true, get: function () { return Interaction_1.LikeType; } });
Object.defineProperty(exports, "FavoriteType", { enumerable: true, get: function () { return Interaction_1.FavoriteType; } });
const likeAnnotation = async (req, res) => {
    try {
        const { targetId, targetType } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({
                success: false,
                message: '用户未登录',
            });
            return;
        }
        const existingLike = await Interaction_1.LikeModel.exists(userId, targetId, targetType);
        if (existingLike) {
            res.status(400).json({
                success: false,
                message: '已经点赞过了',
            });
            return;
        }
        const newLike = await Interaction_1.LikeModel.create({
            userId,
            targetId,
            targetType: targetType,
        });
        res.json({
            code: 200,
            message: '点赞成功',
            data: newLike,
        });
    }
    catch (error) {
        console.error('点赞失败:', error);
        res.status(500).json({
            code: 500,
            message: '点赞失败',
            data: null,
        });
    }
};
exports.likeAnnotation = likeAnnotation;
const unlikeAnnotation = async (req, res) => {
    try {
        const { targetId, targetType } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未认证',
                data: null,
            });
            return;
        }
        const deleted = await Interaction_1.LikeModel.delete(userId, targetId, targetType);
        if (!deleted) {
            res.status(400).json({
                code: 400,
                message: '未找到点赞记录',
                data: null,
            });
            return;
        }
        res.json({
            code: 200,
            message: '取消点赞成功',
            data: null,
        });
    }
    catch (error) {
        console.error('取消点赞失败:', error);
        res.status(500).json({
            code: 500,
            message: '取消点赞失败',
            data: null,
        });
    }
};
exports.unlikeAnnotation = unlikeAnnotation;
const favoriteAnnotation = async (req, res) => {
    try {
        const { targetId, targetType } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未认证',
                data: null,
            });
            return;
        }
        const existingFavorite = await Interaction_1.FavoriteModel.exists(userId, targetId, targetType);
        if (existingFavorite) {
            res.status(400).json({
                code: 400,
                message: '已经收藏过了',
                data: null,
            });
            return;
        }
        const newFavorite = await Interaction_1.FavoriteModel.create({
            userId,
            targetId,
            targetType: targetType,
        });
        res.json({
            code: 200,
            message: '收藏成功',
            data: newFavorite,
        });
    }
    catch (error) {
        console.error('收藏失败:', error);
        res.status(500).json({
            code: 500,
            message: '收藏失败',
            data: null,
        });
    }
};
exports.favoriteAnnotation = favoriteAnnotation;
const unfavoriteAnnotation = async (req, res) => {
    try {
        const { targetId, targetType } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未认证',
                data: null,
            });
            return;
        }
        const deleted = await Interaction_1.FavoriteModel.delete(userId, targetId, targetType);
        if (!deleted) {
            res.status(400).json({
                code: 400,
                message: '未找到收藏记录',
                data: null,
            });
            return;
        }
        res.json({
            code: 200,
            message: '取消收藏成功',
            data: null,
        });
    }
    catch (error) {
        console.error('取消收藏失败:', error);
        res.status(500).json({
            code: 500,
            message: '取消收藏失败',
            data: null,
        });
    }
};
exports.unfavoriteAnnotation = unfavoriteAnnotation;
const getInteractionStats = async (req, res) => {
    try {
        const { targetId, targetType } = req.query;
        const userId = req.user?.id;
        if (!targetId || !targetType) {
            res.status(400).json({
                code: 400,
                message: '缺少必要参数',
                data: null,
            });
            return;
        }
        const stats = await Interaction_1.InteractionModel.getInteractionStats(targetId, targetType, userId);
        res.json({
            code: 200,
            message: '获取统计成功',
            data: stats,
        });
    }
    catch (error) {
        console.error('获取互动统计失败:', error);
        res.status(500).json({
            code: 500,
            message: '获取统计失败',
            data: null,
        });
    }
};
exports.getInteractionStats = getInteractionStats;
const getUserLikes = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { page = 1, limit = 10, type } = req.query;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未认证',
                data: null,
            });
            return;
        }
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const result = await Interaction_1.LikeModel.getUserLikes(userId, {
            page: pageNum,
            limit: limitNum,
            targetType: type,
        });
        res.json({
            code: 200,
            message: '获取点赞历史成功',
            data: result,
        });
    }
    catch (error) {
        console.error('获取用户点赞历史失败:', error);
        res.status(500).json({
            code: 500,
            message: '获取点赞历史失败',
            data: null,
        });
    }
};
exports.getUserLikes = getUserLikes;
const getUserFavorites = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { page = 1, limit = 10, type } = req.query;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未认证',
                data: null,
            });
            return;
        }
        const result = await Interaction_1.FavoriteModel.getUserFavorites(userId, {
            page: parseInt(page) || 1,
            limit: parseInt(limit) || 20,
            targetType: type,
        });
        res.json({
            code: 200,
            message: '获取收藏列表成功',
            data: result,
        });
    }
    catch (error) {
        console.error('获取用户收藏列表失败:', error);
        res.status(500).json({
            code: 500,
            message: '获取收藏列表失败',
            data: null,
        });
    }
};
exports.getUserFavorites = getUserFavorites;
const getUserActivityStats = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { timeRange } = req.query;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未认证',
                data: null,
            });
            return;
        }
        const stats = await Interaction_1.InteractionModel.getUserActivityStats(userId, timeRange || '7d');
        res.json({
            code: 200,
            message: '获取活跃度统计成功',
            data: stats,
        });
    }
    catch (error) {
        console.error('获取用户活跃度统计失败:', error);
        res.status(500).json({
            code: 500,
            message: '获取活跃度统计失败',
            data: null,
        });
    }
};
exports.getUserActivityStats = getUserActivityStats;
const getPopularContent = async (req, res) => {
    try {
        const { type, timeRange = '7d', limit = 10 } = req.query;
        const limitNum = parseInt(limit);
        const content = await Interaction_1.LikeModel.getPopularContent({ targetType: type, timeRange: timeRange, limit: limitNum });
        res.json({
            code: 200,
            message: '获取热门内容成功',
            data: {
                content,
                timeRange,
                total: content.length,
            },
        });
    }
    catch (error) {
        console.error('获取热门内容失败:', error);
        res.status(500).json({
            code: 500,
            message: '获取热门内容失败',
            data: null,
        });
    }
};
exports.getPopularContent = getPopularContent;
//# sourceMappingURL=interactionController.js.map