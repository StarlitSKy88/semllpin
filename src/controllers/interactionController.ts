import { Request, Response } from 'express';
import {
  LikeModel,
  FavoriteModel,
  InteractionModel,
  LikeType,
  FavoriteType,
  Like,
  Favorite,
  InteractionStats,
} from '../models/Interaction';

// 扩展Request接口以包含用户信息

// 重新导出类型
export { LikeType, FavoriteType, Like, Favorite, InteractionStats };

// 点赞
export const likeAnnotation = async (req: Request, res: Response): Promise<void> => {
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

    // 检查是否已经点赞
    const existingLike = await LikeModel.exists(userId, targetId, targetType as LikeType);
    if (existingLike) {
      res.status(400).json({
        success: false,
        message: '已经点赞过了',
      });
      return;
    }

    // 创建点赞记录
    const newLike = await LikeModel.create({
      userId,
      targetId,
      targetType: targetType as LikeType,
    });

    res.json({
      code: 200,
      message: '点赞成功',
      data: newLike,
    });
  } catch (error) {
    console.error('点赞失败:', error);
    res.status(500).json({
      code: 500,
      message: '点赞失败',
      data: null,
    });
  }
};

// 取消点赞
export const unlikeAnnotation = async (req: Request, res: Response): Promise<void> => {
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

    // 删除点赞记录
    const deleted = await LikeModel.delete(userId, targetId, targetType as LikeType);
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
  } catch (error) {
    console.error('取消点赞失败:', error);
    res.status(500).json({
      code: 500,
      message: '取消点赞失败',
      data: null,
    });
  }
};

// 收藏
export const favoriteAnnotation = async (req: Request, res: Response): Promise<void> => {
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

    // 检查是否已经收藏
    const existingFavorite = await FavoriteModel.exists(userId, targetId, targetType as FavoriteType);
    if (existingFavorite) {
      res.status(400).json({
        code: 400,
        message: '已经收藏过了',
        data: null,
      });
      return;
    }

    // 创建收藏记录
    const newFavorite = await FavoriteModel.create({
      userId,
      targetId,
      targetType: targetType as FavoriteType,
    });

    res.json({
      code: 200,
      message: '收藏成功',
      data: newFavorite,
    });
  } catch (error) {
    console.error('收藏失败:', error);
    res.status(500).json({
      code: 500,
      message: '收藏失败',
      data: null,
    });
  }
};

// 取消收藏
export const unfavoriteAnnotation = async (req: Request, res: Response): Promise<void> => {
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

    // 删除收藏记录
    const deleted = await FavoriteModel.delete(userId, targetId, targetType as FavoriteType);
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
  } catch (error) {
    console.error('取消收藏失败:', error);
    res.status(500).json({
      code: 500,
      message: '取消收藏失败',
      data: null,
    });
  }
};

// 获取互动统计
export const getInteractionStats = async (req: Request, res: Response): Promise<void> => {
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

    const stats = await InteractionModel.getInteractionStats(
      targetId as string,
      targetType as string,
      userId,
    );

    res.json({
      code: 200,
      message: '获取统计成功',
      data: stats,
    });
  } catch (error) {
    console.error('获取互动统计失败:', error);
    res.status(500).json({
      code: 500,
      message: '获取统计失败',
      data: null,
    });
  }
};

// 获取用户点赞历史
export const getUserLikes = async (req: Request, res: Response): Promise<void> => {
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

    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);

    const result = await LikeModel.getUserLikes(userId, {
      page: pageNum,
      limit: limitNum,
      targetType: type as any,
    });

    res.json({
      code: 200,
      message: '获取点赞历史成功',
      data: result,
    });
  } catch (error) {
    console.error('获取用户点赞历史失败:', error);
    res.status(500).json({
      code: 500,
      message: '获取点赞历史失败',
      data: null,
    });
  }
};

// 获取用户收藏列表
export const getUserFavorites = async (req: Request, res: Response): Promise<void> => {
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

    const result = await FavoriteModel.getUserFavorites(userId, {
      page: parseInt(page as string) || 1,
      limit: parseInt(limit as string) || 20,
      targetType: type as any,
    });

    res.json({
      code: 200,
      message: '获取收藏列表成功',
      data: result,
    });
  } catch (error) {
    console.error('获取用户收藏列表失败:', error);
    res.status(500).json({
      code: 500,
      message: '获取收藏列表失败',
      data: null,
    });
  }
};

// 获取用户活跃度统计
export const getUserActivityStats = async (req: Request, res: Response): Promise<void> => {
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

    const stats = await InteractionModel.getUserActivityStats(userId, timeRange as string || '7d');

    res.json({
      code: 200,
      message: '获取活跃度统计成功',
      data: stats,
    });
  } catch (error) {
    console.error('获取用户活跃度统计失败:', error);
    res.status(500).json({
      code: 500,
      message: '获取活跃度统计失败',
      data: null,
    });
  }
};

// 获取热门内容
export const getPopularContent = async (req: Request, res: Response): Promise<void> => {
  try {
    const { type, timeRange = '7d', limit = 10 } = req.query;

    const limitNum = parseInt(limit as string);
    const content = await LikeModel.getPopularContent({ targetType: type as any, timeRange: timeRange as string, limit: limitNum });

    res.json({
      code: 200,
      message: '获取热门内容成功',
      data: {
        content,
        timeRange,
        total: content.length,
      },
    });
  } catch (error) {
    console.error('获取热门内容失败:', error);
    res.status(500).json({
      code: 500,
      message: '获取热门内容失败',
      data: null,
    });
  }
};
