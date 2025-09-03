import { Router } from 'express';
import { generateShareLink, createShareRecord, getAnnotationShareStats, getUserShareHistory, getPopularShares } from '../controllers/shareController';
import authMiddleware from '../middleware/auth';

const router = Router();

// ==================== 分享链接相关路由 ====================

// 创建分享记录
router.post('/annotations/:annotationId/share', authMiddleware, createShareRecord);

// 生成分享链接
router.post('/share/generate', authMiddleware, generateShareLink);

// 获取分享统计
router.get('/annotations/:annotationId/share/stats', getAnnotationShareStats);

// 获取用户分享历史
router.get('/users/shares', authMiddleware, getUserShareHistory);

// 获取热门分享内容
router.get('/shares/popular', getPopularShares);

export default router;
