import { Router } from 'express';
import { ProfileController } from '../controllers/profileController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 获取用户资料（公开，可以不登录访问）
router.get('/users/:userId/profile', ProfileController.getUserProfile);

// 获取用户的标注历史（公开，可以不登录访问）
router.get('/users/:userId/annotations', ProfileController.getUserAnnotations);

// 获取用户成就（公开，可以不登录访问）
router.get('/users/:userId/achievements', ProfileController.getUserAchievements);

// 获取用户活动时间线（可能需要权限）
router.get('/users/:userId/timeline', ProfileController.getUserActivityTimeline);

// 需要认证的路由
router.use(authMiddleware);

// 更新用户资料
router.put('/users/:userId/profile', ProfileController.updateUserProfile);

// 获取/更新隐私设置
router.get('/privacy-settings', ProfileController.getUserPrivacySettings);
router.put('/privacy-settings', ProfileController.updatePrivacySettings);

export default router;