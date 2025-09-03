"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.unlikeComment = exports.likeComment = exports.deleteComment = exports.updateComment = exports.getCommentReplies = exports.getAnnotationComments = exports.createComment = void 0;
const uuid_1 = require("uuid");
const database_1 = __importDefault(require("../config/database"));
const createComment = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const { content, parentId } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        if (!content || content.trim().length === 0) {
            return res.status(400).json({ error: '评论内容不能为空' });
        }
        if (content.length > 500) {
            return res.status(400).json({ error: '评论内容不能超过500字符' });
        }
        const annotation = await (0, database_1.default)('annotations').where('id', annotationId).first();
        if (!annotation) {
            return res.status(404).json({ error: '标注不存在' });
        }
        if (parentId) {
            const parentComment = await (0, database_1.default)('comments').where('id', parentId).first();
            if (!parentComment) {
                return res.status(404).json({ error: '父评论不存在' });
            }
            if (parentComment.annotation_id !== annotationId) {
                return res.status(400).json({ error: '父评论不属于该标注' });
            }
        }
        const commentId = (0, uuid_1.v4)();
        await (0, database_1.default)('comments').insert({
            id: commentId,
            annotation_id: annotationId,
            user_id: userId,
            parent_id: parentId || null,
            content: content.trim(),
            likes_count: 0,
            created_at: new Date(),
            updated_at: new Date(),
        });
        const comment = await (0, database_1.default)('comments')
            .join('users', 'comments.user_id', 'users.id')
            .where('comments.id', commentId)
            .select('comments.*', 'users.username', 'users.avatar_url')
            .first();
        if (annotation.user_id !== userId && annotationId) {
            const userInfo = await (0, database_1.default)('users').where('id', userId).first();
            await createNotification({
                user_id: annotation.user_id,
                from_user_id: userId,
                type: 'comment',
                title: '新评论',
                content: `${userInfo.username} 评论了你的标注`,
                related_id: annotationId,
                related_type: 'annotation',
            });
        }
        if (parentId && commentId) {
            const parentComment = await (0, database_1.default)('comments').where('id', parentId).first();
            if (parentComment && parentComment.user_id !== userId) {
                const userInfo = await (0, database_1.default)('users').where('id', userId).first();
                await createNotification({
                    user_id: parentComment.user_id,
                    from_user_id: userId,
                    type: 'reply',
                    title: '新回复',
                    content: `${userInfo.username} 回复了你的评论`,
                    related_id: commentId,
                    related_type: 'comment',
                });
            }
        }
        return res.status(201).json({
            message: '评论创建成功',
            comment: {
                id: comment.id,
                content: comment.content,
                likes_count: comment.likes_count,
                created_at: comment.created_at,
                updated_at: comment.updated_at,
                parent_id: comment.parent_id,
                user: {
                    id: comment.user_id,
                    username: comment.username,
                    avatar_url: comment.avatar_url,
                },
            },
        });
    }
    catch (error) {
        console.error('创建评论失败:', error);
        return res.status(500).json({ error: '创建评论失败' });
    }
};
exports.createComment = createComment;
const getAnnotationComments = async (req, res) => {
    try {
        const { annotationId } = req.params;
        const { page = 1, limit = 20, sort = 'newest' } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const annotation = await (0, database_1.default)('annotations').where('id', annotationId).first();
        if (!annotation) {
            return res.status(404).json({ error: '标注不存在' });
        }
        let orderBy = ['comments.created_at', 'desc'];
        if (sort === 'oldest') {
            orderBy = ['comments.created_at', 'asc'];
        }
        else if (sort === 'likes') {
            orderBy = ['comments.likes_count', 'desc'];
        }
        const comments = await (0, database_1.default)('comments')
            .join('users', 'comments.user_id', 'users.id')
            .where('comments.annotation_id', annotationId)
            .whereNull('comments.parent_id')
            .select('comments.*', 'users.username', 'users.avatar_url')
            .orderBy(orderBy[0], orderBy[1])
            .limit(Number(limit))
            .offset(offset);
        const commentsWithReplies = await Promise.all(comments.map(async (comment) => {
            const replies = await (0, database_1.default)('comments')
                .join('users', 'comments.user_id', 'users.id')
                .where('comments.parent_id', comment.id)
                .select('comments.*', 'users.username', 'users.avatar_url')
                .orderBy('comments.created_at', 'asc')
                .limit(5);
            const replyCount = await (0, database_1.default)('comments')
                .where('parent_id', comment.id)
                .count('* as count')
                .first();
            return {
                id: comment.id,
                content: comment.content,
                likes_count: comment.likes_count,
                created_at: comment.created_at,
                updated_at: comment.updated_at,
                user: {
                    id: comment.user_id,
                    username: comment.username,
                    avatar_url: comment.avatar_url,
                },
                replies: replies.map(reply => ({
                    id: reply.id,
                    content: reply.content,
                    likes_count: reply.likes_count,
                    created_at: reply.created_at,
                    user: {
                        id: reply.user_id,
                        username: reply.username,
                        avatar_url: reply.avatar_url,
                    },
                })),
                reply_count: Number(replyCount?.['count']) || 0,
            };
        }));
        const total = await (0, database_1.default)('comments')
            .where('annotation_id', annotationId)
            .whereNull('parent_id')
            .count('* as count')
            .first();
        return res.json({
            comments: commentsWithReplies,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取评论列表失败:', error);
        return res.status(500).json({ error: '获取评论列表失败' });
    }
};
exports.getAnnotationComments = getAnnotationComments;
const getCommentReplies = async (req, res) => {
    try {
        const { commentId } = req.params;
        const { page = 1, limit = 10 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const parentComment = await (0, database_1.default)('comments').where('id', commentId).first();
        if (!parentComment) {
            return res.status(404).json({ error: '评论不存在' });
        }
        const replies = await (0, database_1.default)('comments')
            .join('users', 'comments.user_id', 'users.id')
            .where('comments.parent_id', commentId)
            .select('comments.*', 'users.username', 'users.avatar_url')
            .orderBy('comments.created_at', 'asc')
            .limit(Number(limit))
            .offset(offset);
        const total = await (0, database_1.default)('comments')
            .where('parent_id', commentId)
            .count('* as count')
            .first();
        return res.json({
            replies: replies.map(reply => ({
                id: reply.id,
                content: reply.content,
                likes_count: reply.likes_count,
                created_at: reply.created_at,
                user: {
                    id: reply.user_id,
                    username: reply.username,
                    avatar_url: reply.avatar_url,
                },
            })),
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: Number(total?.['count']) || 0,
                totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
            },
        });
    }
    catch (error) {
        console.error('获取回复列表失败:', error);
        return res.status(500).json({ error: '获取回复列表失败' });
    }
};
exports.getCommentReplies = getCommentReplies;
const updateComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const { content } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        if (!content || content.trim().length === 0) {
            return res.status(400).json({ error: '评论内容不能为空' });
        }
        if (content.length > 500) {
            return res.status(400).json({ error: '评论内容不能超过500字符' });
        }
        const comment = await (0, database_1.default)('comments').where('id', commentId).first();
        if (!comment) {
            return res.status(404).json({ error: '评论不存在' });
        }
        if (comment.user_id !== userId && req.user?.role !== 'admin') {
            return res.status(403).json({ error: '只能编辑自己的评论' });
        }
        await (0, database_1.default)('comments')
            .where('id', commentId)
            .update({
            content: content.trim(),
            updated_at: new Date(),
        });
        const updatedComment = await (0, database_1.default)('comments')
            .join('users', 'comments.user_id', 'users.id')
            .where('comments.id', commentId)
            .select('comments.*', 'users.username', 'users.avatar_url')
            .first();
        return res.json({
            message: '评论更新成功',
            comment: {
                id: updatedComment.id,
                content: updatedComment.content,
                likes_count: updatedComment.likes_count,
                created_at: updatedComment.created_at,
                updated_at: updatedComment.updated_at,
                user: {
                    id: updatedComment.user_id,
                    username: updatedComment.username,
                    avatar_url: updatedComment.avatar_url,
                },
            },
        });
    }
    catch (error) {
        console.error('更新评论失败:', error);
        return res.status(500).json({ error: '更新评论失败' });
    }
};
exports.updateComment = updateComment;
const deleteComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const comment = await (0, database_1.default)('comments').where('id', commentId).first();
        if (!comment) {
            return res.status(404).json({ error: '评论不存在' });
        }
        if (comment.user_id !== userId && req.user?.role !== 'admin') {
            return res.status(403).json({ error: '只能删除自己的评论' });
        }
        await database_1.default.transaction(async (trx) => {
            await trx('comments').where('parent_id', commentId).del();
            await trx('comments').where('id', commentId).del();
        });
        return res.json({ message: '评论删除成功' });
    }
    catch (error) {
        console.error('删除评论失败:', error);
        return res.status(500).json({ error: '删除评论失败' });
    }
};
exports.deleteComment = deleteComment;
const likeComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const comment = await (0, database_1.default)('comments').where('id', commentId).first();
        if (!comment) {
            return res.status(404).json({ error: '评论不存在' });
        }
        const existingLike = await (0, database_1.default)('comment_likes')
            .where({ comment_id: commentId, user_id: userId })
            .first();
        if (existingLike) {
            return res.status(400).json({ error: '已经点赞过该评论' });
        }
        const likeId = (0, uuid_1.v4)();
        await (0, database_1.default)('comment_likes').insert({
            id: likeId,
            comment_id: commentId,
            user_id: userId,
            created_at: new Date(),
        });
        await (0, database_1.default)('comments')
            .where('id', commentId)
            .increment('likes_count', 1);
        if (comment.user_id !== userId && commentId) {
            const userInfo = await (0, database_1.default)('users').where('id', userId).first();
            await createNotification({
                user_id: comment.user_id,
                from_user_id: userId,
                type: 'comment_like',
                title: '评论获得点赞',
                content: `${userInfo.username} 点赞了你的评论`,
                related_id: commentId,
                related_type: 'comment',
            });
        }
        return res.json({ message: '点赞成功', likeId });
    }
    catch (error) {
        console.error('点赞评论失败:', error);
        return res.status(500).json({ error: '点赞失败' });
    }
};
exports.likeComment = likeComment;
const unlikeComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const deleted = await (0, database_1.default)('comment_likes')
            .where({ comment_id: commentId, user_id: userId })
            .del();
        if (deleted === 0) {
            return res.status(404).json({ error: '未找到点赞记录' });
        }
        await (0, database_1.default)('comments')
            .where('id', commentId)
            .decrement('likes_count', 1);
        return res.json({ message: '取消点赞成功' });
    }
    catch (error) {
        console.error('取消点赞失败:', error);
        return res.status(500).json({ error: '取消点赞失败' });
    }
};
exports.unlikeComment = unlikeComment;
const createNotification = async (notificationData) => {
    try {
        const notificationId = (0, uuid_1.v4)();
        await (0, database_1.default)('notifications').insert({
            id: notificationId,
            ...notificationData,
            is_read: false,
            created_at: new Date(),
        });
        return notificationId;
    }
    catch (error) {
        console.error('创建通知失败:', error);
        return undefined;
    }
};
//# sourceMappingURL=commentController.js.map