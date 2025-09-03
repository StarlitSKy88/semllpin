"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteNotifications = exports.getNotificationStats = exports.testNotification = exports.updateUserNotificationSettings = exports.getUserNotificationSettings = void 0;
const uuid_1 = require("uuid");
const database_1 = __importDefault(require("../config/database"));
const getUserNotificationSettings = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const user = await (0, database_1.default)('users')
            .select('email_notifications', 'push_notifications', 'follow_notifications', 'comment_notifications', 'like_notifications', 'share_notifications', 'system_notifications')
            .where('id', userId)
            .first();
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        const settings = {
            email_notifications: user.email_notifications ?? true,
            push_notifications: user.push_notifications ?? true,
            follow_notifications: user.follow_notifications ?? true,
            comment_notifications: user.comment_notifications ?? true,
            like_notifications: user.like_notifications ?? true,
            share_notifications: user.share_notifications ?? true,
            system_notifications: user.system_notifications ?? true,
        };
        return res.json({
            success: true,
            data: settings,
        });
    }
    catch (error) {
        console.error('获取通知设置失败:', error);
        return res.status(500).json({ error: '服务器内部错误' });
    }
};
exports.getUserNotificationSettings = getUserNotificationSettings;
const updateUserNotificationSettings = async (req, res) => {
    try {
        const userId = req.user?.id;
        const settings = req.body;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const allowedFields = [
            'email_notifications',
            'push_notifications',
            'follow_notifications',
            'comment_notifications',
            'like_notifications',
            'share_notifications',
            'system_notifications',
        ];
        const updateData = {};
        for (const field of allowedFields) {
            if (field in settings && typeof settings[field] === 'boolean') {
                updateData[field] = settings[field];
            }
        }
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: '没有有效的设置字段' });
        }
        await (0, database_1.default)('users')
            .where('id', userId)
            .update({
            ...updateData,
            updated_at: new Date(),
        });
        const updatedUser = await (0, database_1.default)('users')
            .select('email_notifications', 'push_notifications', 'follow_notifications', 'comment_notifications', 'like_notifications', 'share_notifications', 'system_notifications')
            .where('id', userId)
            .first();
        const updatedSettings = {
            email_notifications: updatedUser.email_notifications ?? true,
            push_notifications: updatedUser.push_notifications ?? true,
            follow_notifications: updatedUser.follow_notifications ?? true,
            comment_notifications: updatedUser.comment_notifications ?? true,
            like_notifications: updatedUser.like_notifications ?? true,
            share_notifications: updatedUser.share_notifications ?? true,
            system_notifications: updatedUser.system_notifications ?? true,
        };
        return res.json({
            success: true,
            message: '通知设置更新成功',
            data: updatedSettings,
        });
    }
    catch (error) {
        console.error('更新通知设置失败:', error);
        return res.status(500).json({ error: '服务器内部错误' });
    }
};
exports.updateUserNotificationSettings = updateUserNotificationSettings;
const testNotification = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { type = 'system' } = req.body;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const notificationId = (0, uuid_1.v4)();
        await (0, database_1.default)('notifications').insert({
            id: notificationId,
            user_id: userId,
            type,
            title: '测试通知',
            content: '这是一条测试通知，用于验证通知系统是否正常工作。',
            related_id: userId,
            related_type: 'user',
            is_read: false,
            created_at: new Date(),
        });
        return res.json({
            success: true,
            message: '测试通知发送成功',
            data: {
                notificationId,
            },
        });
    }
    catch (error) {
        console.error('发送测试通知失败:', error);
        return res.status(500).json({ error: '服务器内部错误' });
    }
};
exports.testNotification = testNotification;
const getNotificationStats = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const stats = await (0, database_1.default)('notifications')
            .select(database_1.default.raw('COUNT(*) as total'), database_1.default.raw('COUNT(CASE WHEN is_read = false THEN 1 END) as unread'), database_1.default.raw('COUNT(CASE WHEN type = "follow" THEN 1 END) as follow_count'), database_1.default.raw('COUNT(CASE WHEN type = "comment" THEN 1 END) as comment_count'), database_1.default.raw('COUNT(CASE WHEN type = "like" THEN 1 END) as like_count'), database_1.default.raw('COUNT(CASE WHEN type = "share" THEN 1 END) as share_count'), database_1.default.raw('COUNT(CASE WHEN type = "system" THEN 1 END) as system_count'))
            .where('user_id', userId)
            .first();
        const recentStats = await (0, database_1.default)('notifications')
            .select(database_1.default.raw('DATE(created_at) as date'), database_1.default.raw('COUNT(*) as count'))
            .where('user_id', userId)
            .where('created_at', '>=', database_1.default.raw('DATE_SUB(NOW(), INTERVAL 7 DAY)'))
            .groupBy(database_1.default.raw('DATE(created_at)'))
            .orderBy('date', 'desc');
        return res.json({
            success: true,
            data: {
                total: parseInt(stats['total']) || 0,
                unread: parseInt(stats['unread']) || 0,
                byType: {
                    follow: parseInt(stats['follow_count']) || 0,
                    comment: parseInt(stats['comment_count']) || 0,
                    like: parseInt(stats['like_count']) || 0,
                    share: parseInt(stats['share_count']) || 0,
                    system: parseInt(stats['system_count']) || 0,
                },
                recent: recentStats.map((item) => ({
                    date: item['date'],
                    count: parseInt(item['count']) || 0,
                })),
            },
        });
    }
    catch (error) {
        console.error('获取通知统计失败:', error);
        return res.status(500).json({ error: '服务器内部错误' });
    }
};
exports.getNotificationStats = getNotificationStats;
const deleteNotifications = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { notificationIds, deleteAll = false } = req.body;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        let deletedCount = 0;
        if (deleteAll) {
            deletedCount = await (0, database_1.default)('notifications')
                .where('user_id', userId)
                .del();
        }
        else if (notificationIds && Array.isArray(notificationIds)) {
            deletedCount = await (0, database_1.default)('notifications')
                .where('user_id', userId)
                .whereIn('id', notificationIds)
                .del();
        }
        else {
            return res.status(400).json({ error: '请提供要删除的通知ID或设置deleteAll为true' });
        }
        return res.json({
            success: true,
            message: `成功删除 ${deletedCount} 条通知`,
            data: {
                deletedCount,
            },
        });
    }
    catch (error) {
        console.error('删除通知失败:', error);
        return res.status(500).json({ error: '服务器内部错误' });
    }
};
exports.deleteNotifications = deleteNotifications;
//# sourceMappingURL=notificationController.js.map