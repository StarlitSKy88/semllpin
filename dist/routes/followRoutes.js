"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const followController_1 = require("../controllers/followController");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.post('/:userId/follow', auth_1.authMiddleware, followController_1.followUser);
router.delete('/:userId/follow', auth_1.authMiddleware, followController_1.unfollowUser);
router.get('/:userId/following', followController_1.getUserFollowing);
router.get('/:userId/followers', followController_1.getUserFollowers);
router.get('/:userId/follow-status', auth_1.authMiddleware, followController_1.checkFollowStatus);
router.get('/:userId/mutual-follows', auth_1.authMiddleware, followController_1.getMutualFollows);
exports.default = router;
//# sourceMappingURL=followRoutes.js.map