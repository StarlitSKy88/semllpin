import { Request, Response } from 'express';
import { SocialRecommendationModel } from '../models/SocialRecommendation';
import { logger } from '../utils/logger';

interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

/**
 * 社交推荐控制器
 * 处理用户推荐和内容推荐
 */
export class RecommendationController {
  // 推荐用户关注
  static async recommendUsers(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const {
        limit = 10,
        exclude_following = 'true',
        include_location = 'false',
        latitude,
        longitude,
        radius = 50
      } = req.query;

      const options: any = {
        limit: Number(limit),
        excludeFollowing: exclude_following === 'true',
        includeLocationBased: include_location === 'true',
        radius: Number(radius)
      };
      
      if (latitude) {
        options.userLat = parseFloat(latitude as string);
      }
      if (longitude) {
        options.userLon = parseFloat(longitude as string);
      }

      const recommendations = await SocialRecommendationModel.recommendUsers(userId, options);

      return res.json({
        success: true,
        data: {
          recommendations,
          count: recommendations.length,
          options: {
            includeLocation: options.includeLocationBased,
            excludeFollowing: options.excludeFollowing,
            radius: options.radius
          }
        }
      });
    } catch (error) {
      logger.error('获取用户推荐失败', error);
      return res.status(500).json({ 
        error: '获取用户推荐失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 推荐内容
  static async recommendContent(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const {
        limit = 20,
        content_type = 'all',
        include_location = 'false',
        latitude,
        longitude,
        radius = 20
      } = req.query;

      const contentType = content_type as 'annotation' | 'comment' | 'all';
      const options: any = {
        limit: Number(limit),
        contentType,
        includeLocationBased: include_location === 'true',
        radius: Number(radius)
      };
      
      if (latitude) {
        options.userLat = parseFloat(latitude as string);
      }
      if (longitude) {
        options.userLon = parseFloat(longitude as string);
      }

      const recommendations = await SocialRecommendationModel.recommendContent(userId, options);

      return res.json({
        success: true,
        data: {
          recommendations,
          count: recommendations.length,
          options: {
            contentType: options.contentType,
            includeLocation: options.includeLocationBased,
            radius: options.radius
          }
        }
      });
    } catch (error) {
      logger.error('获取内容推荐失败', error);
      return res.status(500).json({ 
        error: '获取内容推荐失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 根据兴趣推荐用户
  static async recommendUsersByInterests(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const { limit = 10 } = req.query;

      const recommendations = await SocialRecommendationModel.recommendUsers(userId, {
        limit: Number(limit),
        excludeFollowing: true,
        includeLocationBased: false
      });

      // 过滤只返回基于兴趣的推荐
      const interestBasedRecs = recommendations.filter(rec => 
        rec.recommendation_reason.some(reason => reason.includes('兴趣') || reason.includes('偏好'))
      );

      return res.json({
        success: true,
        data: {
          recommendations: interestBasedRecs,
          count: interestBasedRecs.length,
          type: 'interest_based'
        }
      });
    } catch (error) {
      logger.error('获取兴趣推荐失败', error);
      return res.status(500).json({ 
        error: '获取兴趣推荐失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 根据地理位置推荐用户
  static async recommendUsersByLocation(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const { latitude, longitude, radius = 50, limit = 10 } = req.query;

      if (!latitude || !longitude) {
        return res.status(400).json({ error: '需要提供地理位置信息' });
      }

      const recommendations = await SocialRecommendationModel.recommendUsers(userId, {
        limit: Number(limit),
        excludeFollowing: true,
        includeLocationBased: true,
        userLat: parseFloat(latitude as string),
        userLon: parseFloat(longitude as string),
        radius: Number(radius)
      });

      // 过滤只返回基于位置的推荐
      const locationBasedRecs = recommendations.filter(rec =>
        rec.recommendation_reason.some(reason => reason.includes('附近') || reason.includes('km'))
      );

      return res.json({
        success: true,
        data: {
          recommendations: locationBasedRecs,
          count: locationBasedRecs.length,
          type: 'location_based',
          location: {
            latitude: parseFloat(latitude as string),
            longitude: parseFloat(longitude as string),
            radius: Number(radius)
          }
        }
      });
    } catch (error) {
      logger.error('获取地理位置推荐失败', error);
      return res.status(500).json({ 
        error: '获取地理位置推荐失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取热门内容推荐
  static async getTrendingContent(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const {
        limit = 20,
        content_type = 'annotation'
      } = req.query;

      const contentType = content_type as 'annotation' | 'comment' | 'all';

      const recommendations = await SocialRecommendationModel.recommendContent(userId, {
        limit: Number(limit),
        contentType,
        includeLocationBased: false
      });

      // 过滤只返回热门内容
      const trendingContent = recommendations.filter(rec =>
        rec.recommendation_reason.some(reason => reason.includes('热门'))
      );

      return res.json({
        success: true,
        data: {
          recommendations: trendingContent,
          count: trendingContent.length,
          type: 'trending',
          contentType
        }
      });
    } catch (error) {
      logger.error('获取热门内容推荐失败', error);
      return res.status(500).json({ 
        error: '获取热门内容推荐失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取关注用户的内容推荐
  static async getFollowingContent(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const {
        limit = 20,
        content_type = 'all'
      } = req.query;

      const contentType = content_type as 'annotation' | 'comment' | 'all';

      const recommendations = await SocialRecommendationModel.recommendContent(userId, {
        limit: Number(limit),
        contentType,
        includeLocationBased: false
      });

      // 过滤只返回来自关注用户的内容
      const followingContent = recommendations.filter(rec =>
        rec.recommendation_reason.some(reason => reason.includes('关注'))
      );

      return res.json({
        success: true,
        data: {
          recommendations: followingContent,
          count: followingContent.length,
          type: 'following',
          contentType
        }
      });
    } catch (error) {
      logger.error('获取关注内容推荐失败', error);
      return res.status(500).json({ 
        error: '获取关注内容推荐失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取附近的内容推荐
  static async getNearbyContent(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const { latitude, longitude, radius = 20, limit = 20 } = req.query;

      if (!latitude || !longitude) {
        return res.status(400).json({ error: '需要提供地理位置信息' });
      }

      const recommendations = await SocialRecommendationModel.recommendContent(userId, {
        limit: Number(limit),
        contentType: 'annotation', // 只有标注有地理位置
        includeLocationBased: true,
        userLat: parseFloat(latitude as string),
        userLon: parseFloat(longitude as string),
        radius: Number(radius)
      });

      // 过滤只返回基于位置的内容
      const nearbyContent = recommendations.filter(rec =>
        rec.recommendation_reason.some(reason => reason.includes('附近') || reason.includes('km'))
      );

      return res.json({
        success: true,
        data: {
          recommendations: nearbyContent,
          count: nearbyContent.length,
          type: 'nearby',
          location: {
            latitude: parseFloat(latitude as string),
            longitude: parseFloat(longitude as string),
            radius: Number(radius)
          }
        }
      });
    } catch (error) {
      logger.error('获取附近内容推荐失败', error);
      return res.status(500).json({ 
        error: '获取附近内容推荐失败',
        message: '服务器内部错误' 
      });
    }
  }
}

export default RecommendationController;