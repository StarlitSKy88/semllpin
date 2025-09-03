"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const userController_1 = __importDefault(require("@/controllers/userController"));
const auth_1 = require("@/middleware/auth");
const validation_1 = require("@/middleware/validation");
const auth_2 = require("@/middleware/auth");
const router = (0, express_1.Router)();
router.post('/register', (0, validation_1.validateRequest)(validation_1.userSchemas.register), (0, auth_2.rateLimitByUser)(5, 15 * 60 * 1000), userController_1.default.register);
router.post('/login', (0, validation_1.validateRequest)(validation_1.userSchemas.login), (0, auth_2.rateLimitByUser)(10, 15 * 60 * 1000), userController_1.default.login);
router.post('/refresh-token', (0, auth_2.rateLimitByUser)(20, 60 * 1000), userController_1.default.refreshToken);
router.post('/forgot-password', (0, validation_1.validateRequest)(validation_1.userSchemas.forgotPassword), (0, auth_2.rateLimitByUser)(3, 60 * 60 * 1000), userController_1.default.forgotPassword);
router.post('/reset-password', (0, validation_1.validateRequest)(validation_1.userSchemas.resetPassword), (0, auth_2.rateLimitByUser)(5, 60 * 60 * 1000), userController_1.default.resetPassword);
router.get('/:id', auth_1.optionalAuthMiddleware, userController_1.default.getUserById);
router.use(auth_1.authMiddleware);
router.post('/logout', userController_1.default.logout);
router.get('/profile/me', userController_1.default.getProfile);
router.put('/profile', (0, validation_1.validateRequest)(validation_1.userSchemas.updateProfile), userController_1.default.updateProfile);
router.put('/password', (0, validation_1.validateRequest)(validation_1.userSchemas.changePassword), (0, auth_2.rateLimitByUser)(5, 60 * 60 * 1000), userController_1.default.changePassword);
router.get('/', auth_1.requireAdmin, userController_1.default.getUsersList);
router.put('/:id', auth_1.requireAdmin, (0, validation_1.validateRequest)(validation_1.adminSchemas.updateUser), userController_1.default.updateUser);
router.delete('/:id', auth_1.requireAdmin, userController_1.default.deleteUser);
exports.default = router;
//# sourceMappingURL=userRoutes.js.map