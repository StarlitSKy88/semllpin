import { Router } from 'express';
import { RecommendationController } from '../controllers/recommendationController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 所有推荐功能都需要认证
router.use(authMiddleware);

// 综合推荐
router.get('/users', RecommendationController.recommendUsers);
router.get('/content', RecommendationController.recommendContent);

// 基于兴趣的推荐
router.get('/users/by-interests', RecommendationController.recommendUsersByInterests);

// 基于地理位置的推荐
router.get('/users/nearby', RecommendationController.recommendUsersByLocation);
router.get('/content/nearby', RecommendationController.getNearbyContent);

// 热门内容推荐
router.get('/content/trending', RecommendationController.getTrendingContent);

// 关注用户的内容推荐
router.get('/content/following', RecommendationController.getFollowingContent);

export default router;