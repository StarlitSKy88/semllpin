"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const monitorController_1 = __importDefault(require("../controllers/monitorController"));
const router = (0, express_1.Router)();
router.get('/stats', monitorController_1.default.getStats.bind(monitorController_1.default));
router.get('/health', monitorController_1.default.getHealth.bind(monitorController_1.default));
router.get('/performance', monitorController_1.default.getPerformance.bind(monitorController_1.default));
router.get('/overview', monitorController_1.default.getOverviewStats.bind(monitorController_1.default));
router.get('/system', monitorController_1.default.getSystemMetrics.bind(monitorController_1.default));
router.get('/prometheus', monitorController_1.default.getPrometheusMetrics.bind(monitorController_1.default));
router.get('/performance-detailed', monitorController_1.default.getPerformanceMetrics.bind(monitorController_1.default));
router.get('/business', monitorController_1.default.getBusinessMetrics.bind(monitorController_1.default));
router.get('/errors', monitorController_1.default.getErrorMetrics.bind(monitorController_1.default));
exports.default = router;
//# sourceMappingURL=monitorRoutes.js.map