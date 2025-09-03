import { Router } from 'express';
import monitorController from '../controllers/monitorController';

const router = Router();

// 监控相关路由
router.get('/stats', monitorController.getStats.bind(monitorController));
router.get('/health', monitorController.getHealth.bind(monitorController));
router.get('/performance', monitorController.getPerformance.bind(monitorController));
router.get('/overview', monitorController.getOverviewStats.bind(monitorController));

// 新增监控接口
router.get('/system', monitorController.getSystemMetrics.bind(monitorController));
router.get('/prometheus', monitorController.getPrometheusMetrics.bind(monitorController));
router.get('/performance-detailed', monitorController.getPerformanceMetrics.bind(monitorController));
router.get('/business', monitorController.getBusinessMetrics.bind(monitorController));
router.get('/errors', monitorController.getErrorMetrics.bind(monitorController));

export default router;
