"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const commentController_1 = require("../controllers/commentController");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.get('/annotations/:annotationId/comments', commentController_1.getAnnotationComments);
router.get('/comments/:commentId/replies', commentController_1.getCommentReplies);
router.use(auth_1.authMiddleware);
router.post('/annotations/:annotationId/comments', commentController_1.createComment);
router.put('/comments/:commentId', commentController_1.updateComment);
router.delete('/comments/:commentId', commentController_1.deleteComment);
router.post('/comments/:commentId/like', commentController_1.likeComment);
router.delete('/comments/:commentId/like', commentController_1.unlikeComment);
exports.default = router;
//# sourceMappingURL=commentRoutes.js.map