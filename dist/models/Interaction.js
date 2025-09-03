"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InteractionModel = exports.FavoriteModel = exports.LikeModel = exports.FavoriteType = exports.LikeType = void 0;
const database_1 = require("../config/database");
const logger_1 = require("../utils/logger");
var LikeType;
(function (LikeType) {
    LikeType["ANNOTATION"] = "annotation";
    LikeType["COMMENT"] = "comment";
    LikeType["USER"] = "user";
})(LikeType || (exports.LikeType = LikeType = {}));
var FavoriteType;
(function (FavoriteType) {
    FavoriteType["ANNOTATION"] = "annotation";
    FavoriteType["USER"] = "user";
})(FavoriteType || (exports.FavoriteType = FavoriteType = {}));
class LikeModel {
    static async create(data) {
        try {
            const id = `like_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            const now = new Date();
            const query = `
        INSERT INTO likes (id, user_id, target_id, target_type, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `;
            const result = await database_1.db.raw(query, [
                id,
                data.userId,
                data.targetId,
                data.targetType,
                now,
                now,
            ]);
            logger_1.logger.info('点赞创建成功', { likeId: id, userId: data.userId, targetId: data.targetId });
            return this.mapRowToLike(result.rows[0]);
        }
        catch (error) {
            logger_1.logger.error('创建点赞失败', { error, data });
            throw error;
        }
    }
    static async delete(userId, targetId, targetType) {
        try {
            const query = `
        DELETE FROM likes 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;
            const result = await database_1.db.raw(query, [userId, targetId, targetType]);
            logger_1.logger.info('点赞删除成功', { userId, targetId, targetType });
            return result.rowCount > 0;
        }
        catch (error) {
            logger_1.logger.error('删除点赞失败', { error, userId, targetId, targetType });
            throw error;
        }
    }
    static async exists(userId, targetId, targetType) {
        try {
            const query = `
        SELECT 1 FROM likes 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;
            const result = await database_1.db.raw(query, [userId, targetId, targetType]);
            return result.rowCount > 0;
        }
        catch (error) {
            logger_1.logger.error('检查点赞状态失败', { error, userId, targetId, targetType });
            throw error;
        }
    }
    static async getUserLikes(userId, options = {}) {
        try {
            const { page = 1, limit = 20, targetType } = options;
            const offset = (page - 1) * limit;
            let whereClause = 'WHERE l.user_id = $1';
            const params = [userId];
            if (targetType) {
                whereClause += ' AND l.target_type = $2';
                params.push(targetType);
            }
            const countQuery = `
        SELECT COUNT(*) as total
        FROM likes l
        ${whereClause}
      `;
            const countResult = await database_1.db.raw(countQuery, params);
            const total = parseInt(countResult.rows[0].total);
            const dataQuery = `
        SELECT l.*, u.username, u.avatar
        FROM likes l
        LEFT JOIN users u ON l.user_id = u.id
        ${whereClause}
        ORDER BY l.created_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;
            params.push(limit, offset);
            const result = await database_1.db.raw(dataQuery, params);
            const likes = result.rows.map((row) => this.mapRowToLike(row));
            return { likes, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户点赞列表失败', { error, userId, options });
            throw error;
        }
    }
    static async getTargetLikeCount(targetId, targetType) {
        try {
            const query = `
        SELECT COUNT(*) as count
        FROM likes
        WHERE target_id = $1 AND target_type = $2
      `;
            const result = await database_1.db.raw(query, [targetId, targetType]);
            return parseInt(result.rows[0].count);
        }
        catch (error) {
            logger_1.logger.error('获取点赞统计失败', { error, targetId, targetType });
            throw error;
        }
    }
    static async getPopularContent(options = {}) {
        try {
            const { targetType, limit = 10, timeRange = '7d' } = options;
            let timeFilter = '';
            if (timeRange !== 'all') {
                const days = timeRange === '1d' ? 1 : timeRange === '7d' ? 7 : 30;
                timeFilter = `AND l.created_at >= NOW() - INTERVAL '${days} days'`;
            }
            let whereClause = 'WHERE 1=1';
            const params = [];
            if (targetType) {
                whereClause += ' AND l.target_type = $1';
                params.push(targetType);
            }
            const query = `
        SELECT 
          l.target_id,
          l.target_type,
          COUNT(*) as like_count,
          ARRAY_AGG(
            JSON_BUILD_OBJECT(
              'id', l.id,
              'userId', l.user_id,
              'createdAt', l.created_at,
              'user', JSON_BUILD_OBJECT(
                'id', u.id,
                'username', u.username,
                'avatar', u.avatar
              )
            ) ORDER BY l.created_at DESC
          ) as recent_likes
        FROM likes l
        LEFT JOIN users u ON l.user_id = u.id
        ${whereClause} ${timeFilter}
        GROUP BY l.target_id, l.target_type
        ORDER BY like_count DESC
        LIMIT $${params.length + 1}
      `;
            params.push(limit);
            const result = await database_1.db.raw(query, params);
            return result.rows.map((row) => ({
                targetId: row.target_id,
                targetType: row.target_type,
                likeCount: parseInt(row.like_count),
                recentLikes: row.recent_likes.slice(0, 5),
            }));
        }
        catch (error) {
            logger_1.logger.error('获取热门内容失败', { error, options });
            throw error;
        }
    }
    static mapRowToLike(row) {
        const like = {
            id: row.id,
            userId: row.user_id,
            targetId: row.target_id,
            targetType: row.target_type,
            createdAt: new Date(row.created_at),
            updatedAt: new Date(row.updated_at),
        };
        if (row.username) {
            like.user = {
                id: row.user_id,
                username: row.username,
                avatar: row.avatar,
            };
        }
        return like;
    }
}
exports.LikeModel = LikeModel;
class FavoriteModel {
    static async create(data) {
        try {
            const id = `favorite_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            const now = new Date();
            const query = `
        INSERT INTO favorites (id, user_id, target_id, target_type, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `;
            const result = await database_1.db.raw(query, [
                id,
                data.userId,
                data.targetId,
                data.targetType,
                now,
                now,
            ]);
            logger_1.logger.info('收藏创建成功', { favoriteId: id, userId: data.userId, targetId: data.targetId });
            return this.mapRowToFavorite(result.rows[0]);
        }
        catch (error) {
            logger_1.logger.error('创建收藏失败', { error, data });
            throw error;
        }
    }
    static async delete(userId, targetId, targetType) {
        try {
            const query = `
        DELETE FROM favorites 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;
            const result = await database_1.db.raw(query, [userId, targetId, targetType]);
            logger_1.logger.info('收藏删除成功', { userId, targetId, targetType });
            return result.rowCount > 0;
        }
        catch (error) {
            logger_1.logger.error('删除收藏失败', { error, userId, targetId, targetType });
            throw error;
        }
    }
    static async exists(userId, targetId, targetType) {
        try {
            const query = `
        SELECT 1 FROM favorites 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;
            const result = await database_1.db.raw(query, [userId, targetId, targetType]);
            return result.rowCount > 0;
        }
        catch (error) {
            logger_1.logger.error('检查收藏状态失败', { error, userId, targetId, targetType });
            throw error;
        }
    }
    static async getUserFavorites(userId, options = {}) {
        try {
            const { page = 1, limit = 20, targetType } = options;
            const offset = (page - 1) * limit;
            let whereClause = 'WHERE f.user_id = $1';
            const params = [userId];
            if (targetType) {
                whereClause += ' AND f.target_type = $2';
                params.push(targetType);
            }
            const countQuery = `
        SELECT COUNT(*) as total
        FROM favorites f
        ${whereClause}
      `;
            const countResult = await database_1.db.raw(countQuery, params);
            const total = parseInt(countResult.rows[0].total);
            const dataQuery = `
        SELECT 
          f.*,
          u.username,
          u.avatar,
          a.description as annotation_description,
          a.latitude as annotation_latitude,
          a.longitude as annotation_longitude,
          a.address as annotation_address
        FROM favorites f
        LEFT JOIN users u ON f.user_id = u.id
        LEFT JOIN annotations a ON f.target_type = 'annotation' AND f.target_id = a.id
        ${whereClause}
        ORDER BY f.created_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;
            params.push(limit, offset);
            const result = await database_1.db.raw(dataQuery, params);
            const favorites = result.rows.map((row) => this.mapRowToFavorite(row));
            return { favorites, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户收藏列表失败', { error, userId, options });
            throw error;
        }
    }
    static async getTargetFavoriteCount(targetId, targetType) {
        try {
            const query = `
        SELECT COUNT(*) as count
        FROM favorites
        WHERE target_id = $1 AND target_type = $2
      `;
            const result = await database_1.db.raw(query, [targetId, targetType]);
            return parseInt(result.rows[0].count);
        }
        catch (error) {
            logger_1.logger.error('获取收藏统计失败', { error, targetId, targetType });
            throw error;
        }
    }
    static mapRowToFavorite(row) {
        const favorite = {
            id: row.id,
            userId: row.user_id,
            targetId: row.target_id,
            targetType: row.target_type,
            createdAt: new Date(row.created_at),
            updatedAt: new Date(row.updated_at),
        };
        if (row.username) {
            favorite.user = {
                id: row.user_id,
                username: row.username,
                avatar: row.avatar,
            };
        }
        if (row.target_type === 'annotation' && row.annotation_description) {
            favorite.annotation = {
                id: row.target_id,
                title: `标注 ${row.target_id.slice(-4)}`,
                description: row.annotation_description,
                location: row.annotation_address || '未知位置',
                latitude: parseFloat(row.annotation_latitude) || 0,
                longitude: parseFloat(row.annotation_longitude) || 0,
            };
        }
        return favorite;
    }
}
exports.FavoriteModel = FavoriteModel;
class InteractionModel {
    static async getInteractionStats(targetId, targetType, userId) {
        try {
            const likeCount = await LikeModel.getTargetLikeCount(targetId, targetType);
            const favoriteCount = await FavoriteModel.getTargetFavoriteCount(targetId, targetType);
            let isLiked = false;
            let isFavorited = false;
            if (userId) {
                isLiked = await LikeModel.exists(userId, targetId, targetType);
                isFavorited = await FavoriteModel.exists(userId, targetId, targetType);
            }
            return {
                targetId,
                targetType,
                likeCount,
                favoriteCount,
                isLiked,
                isFavorited,
            };
        }
        catch (error) {
            logger_1.logger.error('获取互动统计失败', { error, targetId, targetType, userId });
            throw error;
        }
    }
    static async getUserActivityStats(userId, timeRange = '7d') {
        try {
            let timeFilter = '';
            let days = 7;
            if (timeRange !== 'all') {
                days = timeRange === '1d' ? 1 : timeRange === '7d' ? 7 : 30;
                timeFilter = `AND created_at >= NOW() - INTERVAL '${days} days'`;
            }
            const likeQuery = `
        SELECT 
          COUNT(*) as total,
          target_type,
          DATE(created_at) as date
        FROM likes
        WHERE user_id = $1 ${timeFilter}
        GROUP BY target_type, DATE(created_at)
        ORDER BY date DESC
      `;
            const likeResult = await database_1.db.raw(likeQuery, [userId]);
            const favoriteQuery = `
        SELECT 
          COUNT(*) as total,
          target_type,
          DATE(created_at) as date
        FROM favorites
        WHERE user_id = $1 ${timeFilter}
        GROUP BY target_type, DATE(created_at)
        ORDER BY date DESC
      `;
            const favoriteResult = await database_1.db.raw(favoriteQuery, [userId]);
            const likesByType = {};
            const favoritesByType = {};
            const dailyData = {};
            let totalLikes = 0;
            let totalFavorites = 0;
            likeResult.rows.forEach((row) => {
                const count = parseInt(row.total);
                totalLikes += count;
                likesByType[row.target_type] = (likesByType[row.target_type] || 0) + count;
                const date = row.date.toISOString().split('T')[0];
                if (!dailyData[date]) {
                    dailyData[date] = { likes: 0, favorites: 0 };
                }
                dailyData[date].likes += count;
            });
            favoriteResult.rows.forEach((row) => {
                const count = parseInt(row.total);
                totalFavorites += count;
                favoritesByType[row.target_type] = (favoritesByType[row.target_type] || 0) + count;
                const date = row.date.toISOString().split('T')[0];
                if (!dailyData[date]) {
                    dailyData[date] = { likes: 0, favorites: 0 };
                }
                dailyData[date].favorites += count;
            });
            const dailyActivity = [];
            const now = new Date();
            for (let i = days - 1; i >= 0; i--) {
                const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
                const dateStr = date.toISOString().split('T')[0];
                const dayData = dailyData[dateStr] || { likes: 0, favorites: 0 };
                dailyActivity.push({
                    date: dateStr,
                    likes: dayData.likes,
                    favorites: dayData.favorites,
                    total: dayData.likes + dayData.favorites,
                });
            }
            return {
                timeRange,
                totalLikes,
                totalFavorites,
                totalActivity: totalLikes + totalFavorites,
                likesByType,
                favoritesByType,
                dailyActivity,
                averageDailyActivity: Math.round((totalLikes + totalFavorites) / days * 10) / 10,
            };
        }
        catch (error) {
            logger_1.logger.error('获取用户活动统计失败', { error, userId, timeRange });
            throw error;
        }
    }
}
exports.InteractionModel = InteractionModel;
//# sourceMappingURL=Interaction.js.map