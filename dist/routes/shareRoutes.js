"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const shareController_1 = require("../controllers/shareController");
const auth_1 = __importDefault(require("../middleware/auth"));
const router = (0, express_1.Router)();
router.post('/annotations/:annotationId/share', auth_1.default, shareController_1.createShareRecord);
router.post('/share/generate', auth_1.default, shareController_1.generateShareLink);
router.get('/annotations/:annotationId/share/stats', shareController_1.getAnnotationShareStats);
router.get('/users/shares', auth_1.default, shareController_1.getUserShareHistory);
router.get('/shares/popular', shareController_1.getPopularShares);
exports.default = router;
//# sourceMappingURL=shareRoutes.js.map