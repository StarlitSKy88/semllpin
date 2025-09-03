import { Router } from 'express';
import {
  createComment,
  getAnnotationComments,
  getCommentReplies,
  updateComment,
  deleteComment,
  likeComment,
  unlikeComment,
} from '../controllers/commentController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 获取标注的评论列表（公开接口）
router.get('/annotations/:annotationId/comments', getAnnotationComments);

// 获取评论的回复列表（公开接口）
router.get('/comments/:commentId/replies', getCommentReplies);

// 需要认证的路由
router.use(authMiddleware);

// 创建评论
router.post('/annotations/:annotationId/comments', createComment);

// 更新评论
router.put('/comments/:commentId', updateComment);

// 删除评论
router.delete('/comments/:commentId', deleteComment);

// 点赞评论
router.post('/comments/:commentId/like', likeComment);

// 取消点赞评论
router.delete('/comments/:commentId/like', unlikeComment);

export default router;
