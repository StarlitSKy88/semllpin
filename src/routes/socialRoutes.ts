import { Router } from 'express';
import {
  followUser,
  unfollowUser,
  getFollowing,
  getFollowers,
  likeAnnotation,
  unlikeAnnotation,
  favoriteAnnotation,
  unfavoriteAnnotation,
  getUserFavorites,
  getUserNotifications,
  markNotificationAsRead,
  markAllNotificationsAsRead,
} from '../controllers/socialController';
import {
  getUserNotificationSettings,
  updateUserNotificationSettings,
  testNotification,
  getNotificationStats,
  deleteNotifications,
} from '../controllers/notificationController';
import {
  createShareRecord,
  getAnnotationShareStats,
  getUserShareHistory,
  getPopularShares,
  generateShareLink,
} from '../controllers/shareController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 公开的分享路由（不需要认证）
router.get('/annotations/:annotationId/shares/stats', getAnnotationShareStats);
router.get('/shares/popular', getPopularShares);
router.get('/annotations/:annotationId/share-link', generateShareLink);

// 所有其他社交功能都需要认证
router.use(authMiddleware);

// 用户关注相关路由
router.post('/follow/:userId', followUser);
router.delete('/follow/:userId', unfollowUser);
router.get('/following/:userId', getFollowing);
router.get('/followers/:userId', getFollowers);

// 标注点赞相关路由
router.post('/annotations/:annotationId/like', likeAnnotation);
router.delete('/annotations/:annotationId/like', unlikeAnnotation);

// 标注收藏相关路由
router.post('/annotations/:annotationId/favorite', favoriteAnnotation);
router.delete('/annotations/:annotationId/favorite', unfavoriteAnnotation);
router.get('/favorites', getUserFavorites);

// 通知相关路由
router.get('/notifications', getUserNotifications);
router.patch('/notifications/:notificationId/read', markNotificationAsRead);
router.patch('/notifications/read-all', markAllNotificationsAsRead);
router.delete('/notifications', deleteNotifications);

// 通知设置相关路由
router.get('/notifications/settings', getUserNotificationSettings);
router.patch('/notifications/settings', updateUserNotificationSettings);
router.get('/notifications/stats', getNotificationStats);
router.post('/notifications/test', testNotification);

// 需要认证的分享路由
router.post('/annotations/:annotationId/share', createShareRecord);
router.get('/shares/history', getUserShareHistory);

export default router;
