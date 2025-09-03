import { Router } from 'express';
import {
  followUser,
  unfollowUser,
  getUserFollowing,
  getUserFollowers,
  checkFollowStatus,
  getMutualFollows,
} from '../controllers/followController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

/**
 * 用户关注系统路由
 */

// 关注用户
router.post('/:userId/follow', authMiddleware, followUser);

// 取消关注用户
router.delete('/:userId/follow', authMiddleware, unfollowUser);

// 获取用户的关注列表
router.get('/:userId/following', getUserFollowing);

// 获取用户的粉丝列表
router.get('/:userId/followers', getUserFollowers);

// 检查关注状态
router.get('/:userId/follow-status', authMiddleware, checkFollowStatus);

// 获取互相关注的用户列表
router.get('/:userId/mutual-follows', authMiddleware, getMutualFollows);

export default router;
