"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const walletController_1 = __importDefault(require("../controllers/walletController"));
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.use(auth_1.authMiddleware);
router.get('/', walletController_1.default.getWallet);
router.get('/transactions', walletController_1.default.getTransactionHistory);
router.get('/transactions/summary', walletController_1.default.getTransactionSummary);
router.get('/transactions/export', walletController_1.default.exportTransactions);
router.post('/topup', walletController_1.default.createTopUpSession);
router.post('/topup/:sessionId/success', walletController_1.default.handleTopUpSuccess);
router.get('/rewards', walletController_1.default.getLBSRewards);
exports.default = router;
//# sourceMappingURL=walletRoutes.js.map