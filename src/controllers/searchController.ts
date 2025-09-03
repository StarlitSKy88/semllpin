import { Request, Response } from 'express';
import { db } from '@/config/database';
import {
  createValidationError,
} from '@/middleware/errorHandler';
import { asyncHandler } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { cacheService } from '@/config/redis';

// Search annotations by location
export const searchAnnotationsByLocation = asyncHandler(async (
  req: Request,
  res: Response,
): Promise<void> => {
  const {
    lat,
    lng,
    latitude,
    longitude,
    radius = 5000,
    smellIntensity,
    category,
    keyword,
    sortBy = 'created_at',
    sortOrder = 'desc',
    page = 1,
    limit = 20,
  } = req.query as any;

  // Support both lat/lng and latitude/longitude parameter formats
  const finalLatitude = lat || latitude;
  const finalLongitude = lng || longitude;

  if (!finalLatitude || !finalLongitude) {
    throw createValidationError('location', '经纬度不能为空');
  }

  logger.info('开始地理位置搜索', { finalLatitude, finalLongitude, radius });

  try {
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const radiusInDegrees = parseInt(radius) / 111000; // Approximate conversion

    // Build base query (simplified to avoid timeout)
    let query = db('annotations')
      .select('annotations.*')
      .whereIn('annotations.status', ['approved', 'pending']);

    // Location filter
    if (finalLatitude && finalLongitude) {
      query = query.whereRaw('ABS(annotations.latitude - ?) < ? AND ABS(annotations.longitude - ?) < ?', [
        parseFloat(finalLatitude), radiusInDegrees,
        parseFloat(finalLongitude), radiusInDegrees,
      ]);
    }

    // Smell intensity filter
    if (smellIntensity) {
      if (smellIntensity.min !== undefined) {
        query = query.where('annotations.smell_intensity', '>=', parseInt(smellIntensity.min));
      }
      if (smellIntensity.max !== undefined) {
        query = query.where('annotations.smell_intensity', '<=', parseInt(smellIntensity.max));
      }
    }

    // Category filter (removed as category field doesn't exist)
    // if (category) {
    //   query = query.where('annotations.category', category);
    // }

    // Keyword search
    if (keyword) {
      query = query.where(function () {
        this.where('annotations.description', 'like', `%${keyword}%`)
          .orWhere('annotations.address', 'like', `%${keyword}%`)
          .orWhere('annotations.city', 'like', `%${keyword}%`);
      });
    }

    // Sorting
    switch (sortBy) {
      case 'distance':
        // For SQLite, we'll use a simple approximation
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

    logger.info('执行查询前', { query: query.toSQL() });

    // Get total count for pagination
    const totalQuery = query.clone().clearSelect().clearOrder().count('* as count').first();

    logger.info('开始执行主查询');
    // Apply pagination
    const results = await query.limit(parseInt(limit)).offset(offset);

    logger.info('主查询完成，开始执行计数查询');
    const totalCount = await totalQuery;

    logger.info('查询完成', { resultsCount: results.length, totalCount });

    // Calculate approximate distance for each result
    const annotationsWithDistance = results.map(annotation => {
      const distance = Math.sqrt(
        Math.pow((annotation.latitude - parseFloat(finalLatitude)) * 111000, 2) +
        Math.pow((annotation.longitude - parseFloat(finalLongitude)) * 111000, 2),
      );

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

    // Cache results for 5 minutes
    const cacheKey = `search:location:${finalLatitude}:${finalLongitude}:${radius}:${JSON.stringify(req.query)}`;
    await cacheService.set(cacheKey, JSON.stringify(annotationsWithDistance), 300);

    logger.info('地理位置搜索成功', {
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
          total: parseInt(totalCount?.['count'] as string || '0'),
          totalPages: Math.ceil(parseInt(totalCount?.['count'] as string || '0') / parseInt(limit)),
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
  } catch (error) {
    logger.error('地理位置搜索失败', { error });
    throw error;
  }
});

// Search annotations by content
export const searchAnnotationsByContent = asyncHandler(async (
  req: Request,
  res: Response,
): Promise<void> => {
  const {
    keyword,
    category,
    smellIntensity,
    sortBy = 'relevance',
    sortOrder = 'desc',
    page = 1,
    limit = 20,
  } = req.query as any;

  if (!keyword) {
    throw createValidationError('keyword', '搜索关键词不能为空');
  }

  try {
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build base query with relevance scoring
    let query = db('annotations')
      .leftJoin('users', 'annotations.user_id', 'users.id')
      .leftJoin('media_files', 'annotations.id', 'media_files.annotation_id')
      .select(
        'annotations.*',
        'users.username',
        'users.display_name',
        'users.avatar_url',
        db.raw('COUNT(DISTINCT media_files.id) as media_count'),
        db.raw(`
          (
            CASE WHEN annotations.description LIKE '%${keyword}%' THEN 3 ELSE 0 END +
            CASE WHEN annotations.address LIKE '%${keyword}%' THEN 2 ELSE 0 END +
            CASE WHEN annotations.city LIKE '%${keyword}%' THEN 1 ELSE 0 END
          ) as relevance_score
        `),
      )
      .where('annotations.status', 'approved')
      .where(function () {
        this.where('annotations.description', 'like', `%${keyword}%`)
          .orWhere('annotations.address', 'like', `%${keyword}%`)
          .orWhere('annotations.city', 'like', `%${keyword}%`);
      })
      .groupBy('annotations.id', 'users.id');

    // Category filter (removed as category field doesn't exist)
    // if (category) {
    //   query = query.where('annotations.category', category);
    // }

    // Smell intensity filter
    if (smellIntensity) {
      if (smellIntensity.min !== undefined) {
        query = query.where('annotations.smell_intensity', '>=', parseInt(smellIntensity.min));
      }
      if (smellIntensity.max !== undefined) {
        query = query.where('annotations.smell_intensity', '<=', parseInt(smellIntensity.max));
      }
    }

    // Sorting
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

    // Get total count for pagination
    const totalQuery = query.clone().clearSelect().clearOrder().count('* as count').first();

    // Apply pagination
    const results = await query.limit(parseInt(limit)).offset(offset);
    const totalCount = await totalQuery;

    // Format results
    const annotationsWithRelevance = results.map(annotation => ({
      ...annotation,
      user: {
        username: annotation.username,
        display_name: annotation.display_name,
        avatar_url: annotation.avatar_url,
      },
    }));

    // Cache results for 5 minutes
    const cacheKey = `search:content:${keyword}:${JSON.stringify(req.query)}`;
    await cacheService.set(cacheKey, JSON.stringify(annotationsWithRelevance), 300);

    logger.info('内容搜索成功', { keyword, count: annotationsWithRelevance.length });

    res.json({
      success: true,
      message: '内容搜索成功',
      data: {
        annotations: annotationsWithRelevance,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: parseInt(totalCount?.['count'] as string || '0'),
          totalPages: Math.ceil(parseInt(totalCount?.['count'] as string || '0') / parseInt(limit)),
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
  } catch (error) {
    logger.error('内容搜索失败', { error });
    throw error;
  }
});

// Get popular search terms
export const getPopularSearchTerms = asyncHandler(async (
  _req: Request,
  res: Response,
): Promise<void> => {
  try {
    // Get popular categories
    const popularCategories = await db('annotations')
      .select('category')
      .count('* as count')
      .where('status', 'approved')
      .whereNotNull('category')
      .groupBy('category')
      .orderBy('count', 'desc')
      .limit(10);

    // Get popular locations
    const popularLocations = await db('annotations')
      .select('location_name')
      .count('* as count')
      .where('status', 'approved')
      .whereNotNull('location_name')
      .groupBy('location_name')
      .orderBy('count', 'desc')
      .limit(10);

    // Get smell intensity distribution
    const smellIntensityDistribution = await db('annotations')
      .select('smell_intensity')
      .count('* as count')
      .where('status', 'approved')
      .groupBy('smell_intensity')
      .orderBy('smell_intensity', 'asc');

    // Cache results for 1 hour
    const cacheKey = 'search:popular_terms';
    const results = {
      categories: popularCategories,
      locations: popularLocations,
      smellIntensityDistribution,
    };
    await cacheService.set(cacheKey, JSON.stringify(results), 3600);

    logger.info('热门搜索词获取成功');

    res.json({
      success: true,
      message: '热门搜索词获取成功',
      data: results,
    });
  } catch (error) {
    logger.error('热门搜索词获取失败', { error });
    throw error;
  }
});

// Advanced search with multiple filters
export const advancedSearch = asyncHandler(async (
  req: Request,
  res: Response,
): Promise<void> => {
  const {
    latitude,
    longitude,
    radius = 5000,
    keyword,
    category,
    smellIntensity,
    dateRange,
    hasMedia,
    sortBy = 'created_at',
    sortOrder = 'desc',
    page = 1,
    limit = 20,
  } = req.body;

  try {
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build base query
    let query = db('annotations')
      .leftJoin('users', 'annotations.user_id', 'users.id')
      .leftJoin('media_files', 'annotations.id', 'media_files.annotation_id')
      .select(
        'annotations.*',
        'users.username',
        'users.display_name',
        'users.avatar_url',
        db.raw('COUNT(DISTINCT media_files.id) as media_count'),
      )
      .where('annotations.status', 'approved')
      .groupBy('annotations.id', 'users.id');

    // Location filter
    if (latitude && longitude) {
      const radiusInDegrees = parseInt(radius) / 111000;
      query = query.whereRaw('ABS(annotations.latitude - ?) < ? AND ABS(annotations.longitude - ?) < ?', [
        parseFloat(latitude), radiusInDegrees,
        parseFloat(longitude), radiusInDegrees,
      ]);
    }

    // Keyword search
    if (keyword) {
      query = query.where(function () {
        this.where('annotations.title', 'like', `%${keyword}%`)
          .orWhere('annotations.description', 'like', `%${keyword}%`)
          .orWhere('annotations.location_name', 'like', `%${keyword}%`);
      });
    }

    // Category filter
    if (category) {
      query = query.where('annotations.category', category);
    }

    // Smell intensity filter
    if (smellIntensity) {
      if (smellIntensity.min !== undefined) {
        query = query.where('annotations.smell_intensity', '>=', parseInt(smellIntensity.min));
      }
      if (smellIntensity.max !== undefined) {
        query = query.where('annotations.smell_intensity', '<=', parseInt(smellIntensity.max));
      }
    }

    // Date range filter
    if (dateRange) {
      if (dateRange.start) {
        query = query.where('annotations.created_at', '>=', new Date(dateRange.start));
      }
      if (dateRange.end) {
        query = query.where('annotations.created_at', '<=', new Date(dateRange.end));
      }
    }

    // Media filter
    if (hasMedia !== undefined) {
      if (hasMedia) {
        query = query.having(db.raw('COUNT(DISTINCT media_files.id)'), '>', 0);
      } else {
        query = query.having(db.raw('COUNT(DISTINCT media_files.id)'), '=', 0);
      }
    }

    // Sorting
    switch (sortBy) {
      case 'distance':
        if (latitude && longitude) {
          query = query.orderByRaw(`
            (ABS(annotations.latitude - ${parseFloat(latitude)}) + ABS(annotations.longitude - ${parseFloat(longitude)})) ${sortOrder.toUpperCase()}
          `);
        } else {
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

    // Get total count for pagination
    const totalQuery = query.clone().clearSelect().clearOrder().count('* as count').first();

    // Apply pagination
    const results = await query.limit(parseInt(limit)).offset(offset);
    const totalCount = await totalQuery;

    // Calculate distance if location provided
    const annotationsWithExtras = results.map(annotation => {
      const result: any = {
        ...annotation,
        user: {
          username: annotation.username,
          display_name: annotation.display_name,
          avatar_url: annotation.avatar_url,
        },
      };

      if (latitude && longitude) {
        const distance = Math.sqrt(
          Math.pow((annotation.latitude - parseFloat(latitude)) * 111000, 2) +
          Math.pow((annotation.longitude - parseFloat(longitude)) * 111000, 2),
        );
        result.distance = Math.round(distance);
      }

      return result;
    });

    logger.info('高级搜索成功', {
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
          total: parseInt(totalCount?.['count'] as string || '0'),
          totalPages: Math.ceil(parseInt(totalCount?.['count'] as string || '0') / parseInt(limit)),
        },
        filters: req.body,
      },
    });
  } catch (error) {
    logger.error('高级搜索失败', { error });
    throw error;
  }
});

export default {
  searchAnnotationsByLocation,
  searchAnnotationsByContent,
  getPopularSearchTerms,
  advancedSearch,
};
