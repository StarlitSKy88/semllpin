import { Router } from 'express';
import walletController from '../controllers/walletController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 所有钱包路由都需要认证
router.use(authMiddleware);

// 获取钱包信息
router.get('/', walletController.getWallet);

// 获取交易历史
router.get('/transactions', walletController.getTransactionHistory);

// 获取交易统计
router.get('/transactions/summary', walletController.getTransactionSummary);

// 导出交易记录
router.get('/transactions/export', walletController.exportTransactions);

// 创建充值会话
router.post('/topup', walletController.createTopUpSession);

// 处理充值成功回调
router.post('/topup/:sessionId/success', walletController.handleTopUpSuccess);

// 获取LBS奖励记录
router.get('/rewards', walletController.getLBSRewards);

export default router;
