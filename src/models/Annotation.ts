import { v4 as uuidv4 } from 'uuid';
import { db } from '@/config/database';
import { logger } from '@/utils/logger';

export interface Annotation {
  id: string;
  user_id: string;
  latitude: number;
  longitude: number;
  location_point: string; // PostGIS POINT
  smell_intensity: number; // 1-10
  description?: string;
  country?: string;
  region?: string;
  city?: string;
  address?: string;
  status: 'pending' | 'approved' | 'rejected';
  moderation_reason?: string;
  moderated_by?: string;
  moderated_at?: Date;
  payment_id?: string;
  media_files: string[]; // Array of media file IDs
  view_count: number;
  like_count: number;
  comment_count: number;
  created_at: Date;
  updated_at: Date;
}

export interface CreateAnnotationData {
  user_id: string;
  latitude: number;
  longitude: number;
  smell_intensity: number;
  description?: string;
  media_files?: string[];
  payment_id?: string;
}

export interface UpdateAnnotationData {
  smell_intensity?: number;
  description?: string;
  status?: 'pending' | 'approved' | 'rejected';
  moderation_reason?: string;
  moderated_by?: string;
  moderated_at?: Date;
}

export interface AnnotationFilters {
  latitude?: number;
  longitude?: number;
  radius?: number; // in meters
  intensityMin?: number;
  intensityMax?: number;
  country?: string;
  region?: string;
  city?: string;
  status?: string;
  userId?: string;
  startDate?: Date;
  endDate?: Date;
}

export interface AnnotationStats {
  total: number;
  byIntensity: Record<number, number>;
  byCountry: Record<string, number>;
  byMonth: Record<string, number>;
  avgIntensity: number;
}

const TABLE_NAME = 'annotations';

export class AnnotationModel {
  // Create a new annotation
  static async create(annotationData: CreateAnnotationData): Promise<Annotation> {
    try {
      const insertData: any = {
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

      // Check database type and handle accordingly
      const dbConfig = db.client.config;

      if (dbConfig.client === 'sqlite3') {
        // For SQLite, generate UUID in application
        insertData.id = uuidv4();
        // SQLite doesn't support PostGIS, so we don't include location_point
      } else if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
        // Use PostGIS for PostgreSQL
        const locationPoint = `POINT(${annotationData.longitude} ${annotationData.latitude})`;
        insertData.location_point = db.raw("ST_GeomFromText(?, 4326)", [locationPoint]);
      }
      let annotation;

      if (dbConfig.client === 'sqlite3') {
        // For SQLite, insert and then fetch the record using the generated UUID
        await db(TABLE_NAME).insert(insertData);

        // Fetch the inserted record using the UUID we generated
        annotation = await db(TABLE_NAME)
          .where({ id: insertData.id })
          .first();

        if (!annotation) {
          throw new Error('Failed to retrieve inserted annotation');
        }
      } else {
        // For PostgreSQL, use returning
        const [insertedAnnotation] = await db(TABLE_NAME)
          .insert(insertData)
          .returning('*');
        annotation = insertedAnnotation;
      }

      // Parse media_files back to array
      annotation.media_files = JSON.parse(annotation.media_files || '[]');

      logger.info('标注创建成功', {
        annotationId: annotation.id,
        userId: annotation.user_id,
        intensity: annotation.smell_intensity,
      });

      return annotation;
    } catch (error) {
      logger.error('标注创建失败', error);
      throw error;
    }
  }

  // Find annotation by ID
  static async findById(id: string): Promise<Annotation | null> {
    try {
      const annotation = await db(TABLE_NAME)
        .where({ id })
        .first();

      if (annotation) {
        annotation.media_files = JSON.parse(annotation.media_files || '[]');
      }

      return annotation || null;
    } catch (error) {
      logger.error('查找标注失败', { annotationId: id, error });
      throw error;
    }
  }

  // Update annotation
  static async update(id: string, updateData: UpdateAnnotationData): Promise<Annotation | null> {
    try {
      const [annotation] = await db(TABLE_NAME)
        .where({ id })
        .update({
          ...updateData,
          updated_at: new Date(),
        })
        .returning('*');

      if (annotation) {
        annotation.media_files = JSON.parse(annotation.media_files || '[]');
        logger.info('标注更新成功', { annotationId: id });
      }

      return annotation || null;
    } catch (error) {
      logger.error('标注更新失败', { annotationId: id, error });
      throw error;
    }
  }

  // Get annotations list with filters
  static async getList(options: {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
    filters?: AnnotationFilters;
  } = {}): Promise<{ annotations: Annotation[]; total: number }> {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'created_at',
        sortOrder = 'desc',
        filters = {},
      } = options;

      let query = db(TABLE_NAME)
        .select(
          'annotations.*',
          'users.username',
          'users.display_name',
          'users.avatar_url',
        )
        .leftJoin('users', 'annotations.user_id', 'users.id');

      // Apply filters
      if (filters.status) {
        query = query.where('annotations.status', filters.status);
      } else {
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

      // Geographic filter
      if (filters.latitude && filters.longitude && filters.radius) {
        const dbConfig = db.client.config;

        if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
          // Use PostGIS for PostgreSQL
          query = query.whereRaw(
            'ST_DWithin(location_point, ST_GeomFromText(?, 4326), ?)',
            [`POINT(? ?)`, filters.radius],
          );
        } else {
          // Use simple bounding box for SQLite
          const latDelta = filters.radius / 111000; // 1 degree latitude ≈ 111km
          const lonDelta = filters.radius / (111000 * Math.cos(filters.latitude * Math.PI / 180));

          query = query
            .whereBetween('latitude', [filters.latitude - latDelta, filters.latitude + latDelta])
            .whereBetween('longitude', [filters.longitude - lonDelta, filters.longitude + lonDelta]);
        }
      }

      // Get total count
      const countResult = await query.clone().count('annotations.id as count');
      const total = parseInt((countResult[0] as any)['count'] as string, 10);

      // Apply pagination and sorting
      const annotations = await query
        .orderBy(`annotations.${sortBy}`, sortOrder)
        .limit(limit)
        .offset((page - 1) * limit);

      // Parse media_files for each annotation
      annotations.forEach(annotation => {
        annotation.media_files = JSON.parse(annotation.media_files || '[]');
      });

      return { annotations, total };
    } catch (error) {
      logger.error('获取标注列表失败', error);
      throw error;
    }
  }

  // Get annotations for map display
  static async getMapData(bounds: {
    north: number;
    south: number;
    east: number;
    west: number;
  }, options: {
    zoom?: number;
    intensityMin?: number;
    intensityMax?: number;
  } = {}): Promise<Annotation[]> {
    try {
      const { zoom = 10, intensityMin, intensityMax } = options;

      let query = db(TABLE_NAME)
        .select(
          'id',
          'latitude',
          'longitude',
          'smell_intensity',
          'description',
          'created_at',
        )
        .where('status', 'approved')
        .whereBetween('latitude', [bounds.south, bounds.north])
        .whereBetween('longitude', [bounds.west, bounds.east]);

      if (intensityMin) {
        query = query.where('smell_intensity', '>=', intensityMin);
      }

      if (intensityMax) {
        query = query.where('smell_intensity', '<=', intensityMax);
      }

      // Limit results based on zoom level to prevent too many markers
      const limit = Math.min(1000, Math.max(100, zoom * 50));

      const annotations = await query
        .orderBy('smell_intensity', 'desc')
        .limit(limit);

      return annotations;
    } catch (error) {
      logger.error('获取地图数据失败', error);
      throw error;
    }
  }

  // Get nearby annotations
  static async getNearby(
    latitude: number,
    longitude: number,
    radius: number = 1000,
    limit: number = 10,
  ): Promise<Annotation[]> {
    try {
      const dbConfig = db.client.config;

      if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
        // Use PostGIS for PostgreSQL
        const annotations = await db(TABLE_NAME)
          .select(
            'annotations.*',
            db.raw('ST_Distance(location_point, ST_GeomFromText(?, 4326)) as distance',
              [`POINT(${longitude} ${latitude})`],
            ),
          )
          .where('status', 'approved')
          .whereRaw(
            'ST_DWithin(location_point, ST_GeomFromText(?, 4326), ?)',
            [`POINT(${longitude} ${latitude})`, radius],
          )
          .orderBy('distance')
          .limit(limit);

        // Parse media_files for each annotation
        annotations.forEach(annotation => {
          annotation.media_files = JSON.parse(annotation.media_files || '[]');
        });

        return annotations;
      } else {
        // Use simple distance calculation for SQLite
        // Calculate approximate bounding box (rough approximation)
        const latDelta = radius / 111000; // 1 degree latitude ≈ 111km
        const lonDelta = radius / (111000 * Math.cos(latitude * Math.PI / 180));

        const annotations = await db(TABLE_NAME)
          .select('*')
          .where('status', 'approved')
          .whereBetween('latitude', [latitude - latDelta, latitude + latDelta])
          .whereBetween('longitude', [longitude - lonDelta, longitude + lonDelta])
          .limit(limit * 2); // Get more to filter by actual distance

        // Calculate actual distance and filter
        const nearbyAnnotations = annotations
          .map(annotation => {
            // Haversine formula for distance calculation
            const R = 6371000; // Earth's radius in meters
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
    } catch (error) {
      logger.error('获取附近标注失败', error);
      throw error;
    }
  }

  // Increment view count
  static async incrementViewCount(id: string): Promise<void> {
    try {
      await db(TABLE_NAME)
        .where({ id })
        .increment('view_count', 1);
    } catch (error) {
      logger.error('增加浏览次数失败', { annotationId: id, error });
      // Don't throw error for this non-critical operation
    }
  }

  // Increment like count
  static async incrementLikeCount(id: string): Promise<void> {
    try {
      await db(TABLE_NAME)
        .where({ id })
        .increment('like_count', 1);
    } catch (error) {
      logger.error('增加点赞次数失败', { annotationId: id, error });
      throw error;
    }
  }

  // Decrement like count
  static async decrementLikeCount(id: string): Promise<void> {
    try {
      await db(TABLE_NAME)
        .where({ id })
        .where('like_count', '>', 0)
        .decrement('like_count', 1);
    } catch (error) {
      logger.error('减少点赞次数失败', { annotationId: id, error });
      throw error;
    }
  }

  // Update comment count
  static async updateCommentCount(id: string): Promise<void> {
    try {
      const countResult = await db('comments')
        .where({ annotation_id: id, status: 'active' })
        .count('* as count');

      const count = (countResult[0] as any)['count'] as string;

      await db(TABLE_NAME)
        .where({ id })
        .update({ comment_count: parseInt(count, 10) });
    } catch (error) {
      logger.error('更新评论数量失败', { annotationId: id, error });
      // Don't throw error for this non-critical operation
    }
  }

  // Get statistics
  static async getStats(filters: AnnotationFilters = {}): Promise<AnnotationStats> {
    try {
      let query = db(TABLE_NAME).where('status', 'approved');

      // Apply filters
      if (filters.userId) {
        query = query.where('user_id', filters.userId);
      }

      if (filters.startDate) {
        query = query.where('created_at', '>=', filters.startDate);
      }

      if (filters.endDate) {
        query = query.where('created_at', '<=', filters.endDate);
      }

      // Get total count and average intensity
      const [totalResult] = await query.clone()
        .count('* as total')
        .avg('smell_intensity as avg_intensity');

      const total = parseInt((totalResult as any)['total'] as string, 10);
      const avgIntensity = parseFloat((totalResult as any)['avg_intensity'] as string) || 0;

      // Get by intensity
      const intensityResults = await query.clone()
        .select('smell_intensity')
        .count('* as count')
        .groupBy('smell_intensity')
        .orderBy('smell_intensity');

      const byIntensity: Record<number, number> = {};
      intensityResults.forEach((row: any) => {
        byIntensity[row['smell_intensity']] = parseInt(row['count'] as string, 10);
      });

      // Get by country
      const countryResults = await query.clone()
        .select('country')
        .count('* as count')
        .whereNotNull('country')
        .groupBy('country')
        .orderBy('count', 'desc')
        .limit(10);

      const byCountry: Record<string, number> = {};
      countryResults.forEach((row: any) => {
        byCountry[row['country']] = parseInt(row['count'] as string, 10);
      });

      // Get by month
      const monthResults = await query.clone()
        .select(db.raw('DATE_TRUNC(\'month\', created_at) as month'))
        .count('* as count')
        .groupBy(db.raw('DATE_TRUNC(\'month\', created_at)'))
        .orderBy('month', 'desc')
        .limit(12);

      const byMonth: Record<string, number> = {};
      monthResults.forEach((row: any) => {
        const month = new Date(row['month']).toISOString().substring(0, 7); // YYYY-MM
        byMonth[month] = parseInt(row['count'] as string, 10);
      });

      return {
        total,
        byIntensity,
        byCountry,
        byMonth,
        avgIntensity: Math.round(avgIntensity * 100) / 100,
      };
    } catch (error) {
      logger.error('获取标注统计失败', error);
      throw error;
    }
  }

  // Delete annotation (soft delete by updating status)
  static async delete(id: string): Promise<boolean> {
    try {
      const result = await db(TABLE_NAME)
        .where({ id })
        .update({
          status: 'rejected',
          updated_at: new Date(),
        });

      if (result > 0) {
        logger.info('标注删除成功', { annotationId: id });
        return true;
      }

      return false;
    } catch (error) {
      logger.error('标注删除失败', { annotationId: id, error });
      throw error;
    }
  }

  // Get user's annotations
  static async getUserAnnotations(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      status?: string;
    } = {},
  ): Promise<{ annotations: Annotation[]; total: number }> {
    try {
      const { page = 1, limit = 20, status } = options;

      let query = db(TABLE_NAME)
        .where('user_id', userId);

      if (status) {
        query = query.where('status', status);
      }

      // Get total count
      const countResult = await query.clone().count('* as count');
      const total = parseInt((countResult[0] as any)['count'] as string, 10);

      // Get annotations
      const annotations = await query
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset((page - 1) * limit);

      // Parse media_files for each annotation
      annotations.forEach(annotation => {
        annotation.media_files = JSON.parse(annotation.media_files || '[]');
      });

      return { annotations, total };
    } catch (error) {
      logger.error('获取用户标注失败', { userId, error });
      throw error;
    }
  }

  // Moderate annotation (admin/moderator)
  static async moderate(
    id: string,
    status: 'approved' | 'rejected',
    moderatorId: string,
    reason?: string,
  ): Promise<Annotation | null> {
    try {
      const [annotation] = await db(TABLE_NAME)
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
        logger.info('标注审核完成', {
          annotationId: id,
          status,
          moderatorId,
        });
      }

      return annotation || null;
    } catch (error) {
      logger.error('标注审核失败', { annotationId: id, error });
      throw error;
    }
  }
}

export default AnnotationModel;
