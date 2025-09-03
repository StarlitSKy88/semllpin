import { Router } from 'express';
import { ModerationController } from '../controllers/moderationController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 所有审核功能都需要认证
router.use(authMiddleware);

// 用户举报功能
router.post('/reports', ModerationController.reportContent);
router.get('/reports/my', ModerationController.getUserReports);

// 管理员/版主功能
router.get('/queue', ModerationController.getModerationQueue);
router.post('/reports/:reportId/moderate', ModerationController.moderateContent);

export default router;