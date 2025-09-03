"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnnotationModel = void 0;
const uuid_1 = require("uuid");
const database_1 = require("@/config/database");
const logger_1 = require("@/utils/logger");
const TABLE_NAME = 'annotations';
class AnnotationModel {
    static async create(annotationData) {
        try {
            const insertData = {
                user_id: annotationData.user_id,
                latitude: annotationData.latitude,
                longitude: annotationData.longitude,
                smell_intensity: annotationData.smell_intensity,
                description: annotationData.description,
                media_files: JSON.stringify(annotationData.media_files || []),
                payment_id: annotationData.payment_id,
                status: 'pending',
                view_count: 0,
                like_count: 0,
                comment_count: 0,
            };
            const dbConfig = database_1.db.client.config;
            if (dbConfig.client === 'sqlite3') {
                insertData.id = (0, uuid_1.v4)();
            }
            else if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
                const locationPoint = `POINT(${annotationData.longitude} ${annotationData.latitude})`;
                insertData.location_point = database_1.db.raw(`ST_GeomFromText('${locationPoint}', 4326)`);
            }
            let annotation;
            if (dbConfig.client === 'sqlite3') {
                await (0, database_1.db)(TABLE_NAME).insert(insertData);
                annotation = await (0, database_1.db)(TABLE_NAME)
                    .where({ id: insertData.id })
                    .first();
                if (!annotation) {
                    throw new Error('Failed to retrieve inserted annotation');
                }
            }
            else {
                const [insertedAnnotation] = await (0, database_1.db)(TABLE_NAME)
                    .insert(insertData)
                    .returning('*');
                annotation = insertedAnnotation;
            }
            annotation.media_files = JSON.parse(annotation.media_files || '[]');
            logger_1.logger.info('标注创建成功', {
                annotationId: annotation.id,
                userId: annotation.user_id,
                intensity: annotation.smell_intensity,
            });
            return annotation;
        }
        catch (error) {
            logger_1.logger.error('标注创建失败', error);
            throw error;
        }
    }
    static async findById(id) {
        try {
            const annotation = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .first();
            if (annotation) {
                annotation.media_files = JSON.parse(annotation.media_files || '[]');
            }
            return annotation || null;
        }
        catch (error) {
            logger_1.logger.error('查找标注失败', { annotationId: id, error });
            throw error;
        }
    }
    static async update(id, updateData) {
        try {
            const [annotation] = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                ...updateData,
                updated_at: new Date(),
            })
                .returning('*');
            if (annotation) {
                annotation.media_files = JSON.parse(annotation.media_files || '[]');
                logger_1.logger.info('标注更新成功', { annotationId: id });
            }
            return annotation || null;
        }
        catch (error) {
            logger_1.logger.error('标注更新失败', { annotationId: id, error });
            throw error;
        }
    }
    static async getList(options = {}) {
        try {
            const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc', filters = {}, } = options;
            let query = (0, database_1.db)(TABLE_NAME)
                .select('annotations.*', 'users.username', 'users.display_name', 'users.avatar_url')
                .leftJoin('users', 'annotations.user_id', 'users.id');
            if (filters.status) {
                query = query.where('annotations.status', filters.status);
            }
            else {
                query = query.where('annotations.status', 'approved');
            }
            if (filters.userId) {
                query = query.where('annotations.user_id', filters.userId);
            }
            if (filters.intensityMin) {
                query = query.where('smell_intensity', '>=', filters.intensityMin);
            }
            if (filters.intensityMax) {
                query = query.where('smell_intensity', '<=', filters.intensityMax);
            }
            if (filters.country) {
                query = query.where('country', filters.country);
            }
            if (filters.region) {
                query = query.where('region', filters.region);
            }
            if (filters.city) {
                query = query.where('city', filters.city);
            }
            if (filters.startDate) {
                query = query.where('annotations.created_at', '>=', filters.startDate);
            }
            if (filters.endDate) {
                query = query.where('annotations.created_at', '<=', filters.endDate);
            }
            if (filters.latitude && filters.longitude && filters.radius) {
                const dbConfig = database_1.db.client.config;
                if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
                    query = query.whereRaw('ST_DWithin(location_point, ST_GeomFromText(?, 4326), ?)', [`POINT(${filters.longitude} ${filters.latitude})`, filters.radius]);
                }
                else {
                    const latDelta = filters.radius / 111000;
                    const lonDelta = filters.radius / (111000 * Math.cos(filters.latitude * Math.PI / 180));
                    query = query
                        .whereBetween('latitude', [filters.latitude - latDelta, filters.latitude + latDelta])
                        .whereBetween('longitude', [filters.longitude - lonDelta, filters.longitude + lonDelta]);
                }
            }
            const countResult = await query.clone().count('annotations.id as count');
            const total = parseInt(countResult[0]['count'], 10);
            const annotations = await query
                .orderBy(`annotations.${sortBy}`, sortOrder)
                .limit(limit)
                .offset((page - 1) * limit);
            annotations.forEach(annotation => {
                annotation.media_files = JSON.parse(annotation.media_files || '[]');
            });
            return { annotations, total };
        }
        catch (error) {
            logger_1.logger.error('获取标注列表失败', error);
            throw error;
        }
    }
    static async getMapData(bounds, options = {}) {
        try {
            const { zoom = 10, intensityMin, intensityMax } = options;
            let query = (0, database_1.db)(TABLE_NAME)
                .select('id', 'latitude', 'longitude', 'smell_intensity', 'description', 'created_at')
                .where('status', 'approved')
                .whereBetween('latitude', [bounds.south, bounds.north])
                .whereBetween('longitude', [bounds.west, bounds.east]);
            if (intensityMin) {
                query = query.where('smell_intensity', '>=', intensityMin);
            }
            if (intensityMax) {
                query = query.where('smell_intensity', '<=', intensityMax);
            }
            const limit = Math.min(1000, Math.max(100, zoom * 50));
            const annotations = await query
                .orderBy('smell_intensity', 'desc')
                .limit(limit);
            return annotations;
        }
        catch (error) {
            logger_1.logger.error('获取地图数据失败', error);
            throw error;
        }
    }
    static async getNearby(latitude, longitude, radius = 1000, limit = 10) {
        try {
            const dbConfig = database_1.db.client.config;
            if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
                const annotations = await (0, database_1.db)(TABLE_NAME)
                    .select('annotations.*', database_1.db.raw('ST_Distance(location_point, ST_GeomFromText(?, 4326)) as distance', [`POINT(${longitude} ${latitude})`]))
                    .where('status', 'approved')
                    .whereRaw('ST_DWithin(location_point, ST_GeomFromText(?, 4326), ?)', [`POINT(${longitude} ${latitude})`, radius])
                    .orderBy('distance')
                    .limit(limit);
                annotations.forEach(annotation => {
                    annotation.media_files = JSON.parse(annotation.media_files || '[]');
                });
                return annotations;
            }
            else {
                const latDelta = radius / 111000;
                const lonDelta = radius / (111000 * Math.cos(latitude * Math.PI / 180));
                const annotations = await (0, database_1.db)(TABLE_NAME)
                    .select('*')
                    .where('status', 'approved')
                    .whereBetween('latitude', [latitude - latDelta, latitude + latDelta])
                    .whereBetween('longitude', [longitude - lonDelta, longitude + lonDelta])
                    .limit(limit * 2);
                const nearbyAnnotations = annotations
                    .map(annotation => {
                    const R = 6371000;
                    const dLat = (annotation.latitude - latitude) * Math.PI / 180;
                    const dLon = (annotation.longitude - longitude) * Math.PI / 180;
                    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                        Math.cos(latitude * Math.PI / 180) * Math.cos(annotation.latitude * Math.PI / 180) *
                            Math.sin(dLon / 2) * Math.sin(dLon / 2);
                    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
                    const distance = R * c;
                    return {
                        ...annotation,
                        distance,
                        media_files: JSON.parse(annotation.media_files || '[]'),
                    };
                })
                    .filter(annotation => annotation.distance <= radius)
                    .sort((a, b) => a.distance - b.distance)
                    .slice(0, limit);
                return nearbyAnnotations;
            }
        }
        catch (error) {
            logger_1.logger.error('获取附近标注失败', error);
            throw error;
        }
    }
    static async incrementViewCount(id) {
        try {
            await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .increment('view_count', 1);
        }
        catch (error) {
            logger_1.logger.error('增加浏览次数失败', { annotationId: id, error });
        }
    }
    static async incrementLikeCount(id) {
        try {
            await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .increment('like_count', 1);
        }
        catch (error) {
            logger_1.logger.error('增加点赞次数失败', { annotationId: id, error });
            throw error;
        }
    }
    static async decrementLikeCount(id) {
        try {
            await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .where('like_count', '>', 0)
                .decrement('like_count', 1);
        }
        catch (error) {
            logger_1.logger.error('减少点赞次数失败', { annotationId: id, error });
            throw error;
        }
    }
    static async updateCommentCount(id) {
        try {
            const countResult = await (0, database_1.db)('comments')
                .where({ annotation_id: id, status: 'active' })
                .count('* as count');
            const count = countResult[0]['count'];
            await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({ comment_count: parseInt(count, 10) });
        }
        catch (error) {
            logger_1.logger.error('更新评论数量失败', { annotationId: id, error });
        }
    }
    static async getStats(filters = {}) {
        try {
            let query = (0, database_1.db)(TABLE_NAME).where('status', 'approved');
            if (filters.userId) {
                query = query.where('user_id', filters.userId);
            }
            if (filters.startDate) {
                query = query.where('created_at', '>=', filters.startDate);
            }
            if (filters.endDate) {
                query = query.where('created_at', '<=', filters.endDate);
            }
            const [totalResult] = await query.clone()
                .count('* as total')
                .avg('smell_intensity as avg_intensity');
            const total = parseInt(totalResult['total'], 10);
            const avgIntensity = parseFloat(totalResult['avg_intensity']) || 0;
            const intensityResults = await query.clone()
                .select('smell_intensity')
                .count('* as count')
                .groupBy('smell_intensity')
                .orderBy('smell_intensity');
            const byIntensity = {};
            intensityResults.forEach((row) => {
                byIntensity[row['smell_intensity']] = parseInt(row['count'], 10);
            });
            const countryResults = await query.clone()
                .select('country')
                .count('* as count')
                .whereNotNull('country')
                .groupBy('country')
                .orderBy('count', 'desc')
                .limit(10);
            const byCountry = {};
            countryResults.forEach((row) => {
                byCountry[row['country']] = parseInt(row['count'], 10);
            });
            const monthResults = await query.clone()
                .select(database_1.db.raw('DATE_TRUNC(\'month\', created_at) as month'))
                .count('* as count')
                .groupBy(database_1.db.raw('DATE_TRUNC(\'month\', created_at)'))
                .orderBy('month', 'desc')
                .limit(12);
            const byMonth = {};
            monthResults.forEach((row) => {
                const month = new Date(row['month']).toISOString().substring(0, 7);
                byMonth[month] = parseInt(row['count'], 10);
            });
            return {
                total,
                byIntensity,
                byCountry,
                byMonth,
                avgIntensity: Math.round(avgIntensity * 100) / 100,
            };
        }
        catch (error) {
            logger_1.logger.error('获取标注统计失败', error);
            throw error;
        }
    }
    static async delete(id) {
        try {
            const result = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                status: 'rejected',
                updated_at: new Date(),
            });
            if (result > 0) {
                logger_1.logger.info('标注删除成功', { annotationId: id });
                return true;
            }
            return false;
        }
        catch (error) {
            logger_1.logger.error('标注删除失败', { annotationId: id, error });
            throw error;
        }
    }
    static async getUserAnnotations(userId, options = {}) {
        try {
            const { page = 1, limit = 20, status } = options;
            let query = (0, database_1.db)(TABLE_NAME)
                .where('user_id', userId);
            if (status) {
                query = query.where('status', status);
            }
            const countResult = await query.clone().count('* as count');
            const total = parseInt(countResult[0]['count'], 10);
            const annotations = await query
                .orderBy('created_at', 'desc')
                .limit(limit)
                .offset((page - 1) * limit);
            annotations.forEach(annotation => {
                annotation.media_files = JSON.parse(annotation.media_files || '[]');
            });
            return { annotations, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户标注失败', { userId, error });
            throw error;
        }
    }
    static async moderate(id, status, moderatorId, reason) {
        try {
            const [annotation] = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                status,
                moderation_reason: reason,
                moderated_by: moderatorId,
                moderated_at: new Date(),
                updated_at: new Date(),
            })
                .returning('*');
            if (annotation) {
                annotation.media_files = JSON.parse(annotation.media_files || '[]');
                logger_1.logger.info('标注审核完成', {
                    annotationId: id,
                    status,
                    moderatorId,
                });
            }
            return annotation || null;
        }
        catch (error) {
            logger_1.logger.error('标注审核失败', { annotationId: id, error });
            throw error;
        }
    }
}
exports.AnnotationModel = AnnotationModel;
exports.default = AnnotationModel;
//# sourceMappingURL=Annotation.js.map