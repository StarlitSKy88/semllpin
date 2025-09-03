import { Router } from 'express';
import { FeedController } from '../controllers/feedController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 所有动态流功能都需要认证
router.use(authMiddleware);

// 获取用户的关注动态流
router.get('/feed', FeedController.getUserFeed);

// 获取用户的活动历史
router.get('/users/:userId/activity', FeedController.getUserActivity);

// 管理员功能：清理过期动态
router.post('/feed/cleanup', FeedController.cleanOldFeeds);

// 删除用户的所有动态
router.delete('/users/:userId/feeds', FeedController.deleteUserFeeds);

export default router;