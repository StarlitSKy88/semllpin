import { NotificationService } from '../notificationService';
import { jest } from '@jest/globals';

// Mock dependencies
jest.mock('../../config/database');
jest.mock('../../config/redis');
jest.mock('node-cron');

describe('NotificationService', () => {
  let notificationService: NotificationService;
  
  beforeEach(() => {
    notificationService = new NotificationService();
    jest.clearAllMocks();
  });

  describe('sendRewardNotification', () => {
    it('should send reward notification successfully', async () => {
      const notificationData = {
        userId: 'user123',
        rewardAmount: 25.5,
        annotationTitle: 'Funny smell here!',
        location: 'Central Park, NYC'
      };

      // Mock database operations
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ push_token: 'token123', preferences: { rewards: true } }] }) // User preferences
        .mockResolvedValueOnce({ rows: [{ id: 'notif123' }] }); // Insert notification
      
      (notificationService as any).db = { query: mockQuery };

      // Mock push notification service
      const mockSendPush = jest.fn().mockResolvedValue({ success: true }) as jest.MockedFunction<any>;
      (notificationService as any).sendPushNotification = mockSendPush;

      const result = await notificationService.sendRewardNotification(notificationData);

      expect(result.success).toBe(true);
      expect(mockSendPush).toHaveBeenCalledWith(
        'token123',
        expect.objectContaining({
          title: expect.stringContaining('奖励'),
          body: expect.stringContaining('25.5')
        })
      );
    });

    it('should skip notification if user disabled rewards', async () => {
      const notificationData = {
        userId: 'user123',
        rewardAmount: 25.5,
        annotationTitle: 'Funny smell here!',
        location: 'Central Park, NYC'
      };

      // Mock user with disabled reward notifications
      const mockQuery = jest.fn().mockResolvedValue({ 
        rows: [{ push_token: 'token123', preferences: { rewards: false } }] 
      });
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.sendRewardNotification(notificationData);

      expect(result.success).toBe(true);
      expect(result.skipped).toBe(true);
      expect(result.reason).toContain('User disabled reward notifications');
    });

    it('should handle missing push token gracefully', async () => {
      const notificationData = {
        userId: 'user123',
        rewardAmount: 25.5,
        annotationTitle: 'Funny smell here!',
        location: 'Central Park, NYC'
      };

      // Mock user without push token
      const mockQuery = jest.fn().mockResolvedValue({ 
        rows: [{ push_token: null, preferences: { rewards: true } }] 
      });
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.sendRewardNotification(notificationData);

      expect(result.success).toBe(false);
      expect(result.error).toContain('No push token');
    });
  });

  describe('sendNearbyAnnotationAlert', () => {
    it('should send nearby annotation alert', async () => {
      const alertData = {
        userId: 'user123',
        annotationId: 'ann123',
        annotationTitle: 'Stinky spot ahead!',
        distance: 50, // 50 meters
        estimatedReward: 15.0
      };

      // Mock user preferences
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ push_token: 'token123', preferences: { nearby_alerts: true } }] })
        .mockResolvedValueOnce({ rows: [{ id: 'notif123' }] });
      
      (notificationService as any).db = { query: mockQuery };

      const mockSendPush = jest.fn().mockResolvedValue({ success: true }) as jest.MockedFunction<any>;
      (notificationService as any).sendPushNotification = mockSendPush;

      const result = await notificationService.sendNearbyAnnotationAlert(alertData);

      expect(result.success).toBe(true);
      expect(mockSendPush).toHaveBeenCalledWith(
        'token123',
        expect.objectContaining({
          title: expect.stringContaining('附近发现'),
          body: expect.stringContaining('50米')
        })
      );
    });

    it('should not send alert if user is too far', async () => {
      const alertData = {
        userId: 'user123',
        annotationId: 'ann123',
        annotationTitle: 'Stinky spot ahead!',
        distance: 1500, // 1.5km - too far
        estimatedReward: 15.0
      };

      const result = await notificationService.sendNearbyAnnotationAlert(alertData);

      expect(result.success).toBe(false);
      expect(result.reason).toContain('Distance too far');
    });
  });

  describe('sendSystemNotification', () => {
    it('should send system notification to specific user', async () => {
      const systemNotification = {
        userId: 'user123',
        title: '系统维护通知',
        message: '系统将于今晚进行维护，预计2小时',
        type: 'maintenance',
        priority: 'high'
      };

      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ push_token: 'token123' }] })
        .mockResolvedValueOnce({ rows: [{ id: 'notif123' }] });
      
      (notificationService as any).db = { query: mockQuery };

      const mockSendPush = jest.fn().mockResolvedValue({ success: true }) as jest.MockedFunction<any>;
      (notificationService as any).sendPushNotification = mockSendPush;

      const result = await notificationService.sendSystemNotification(systemNotification);

      expect(result.success).toBe(true);
      expect(mockSendPush).toHaveBeenCalledWith(
        'token123',
        expect.objectContaining({
          title: '系统维护通知',
          body: '系统将于今晚进行维护，预计2小时'
        })
      );
    });

    it('should broadcast system notification to all users', async () => {
      const broadcastNotification = {
        title: '新功能上线',
        message: '我们推出了新的奖励机制！',
        type: 'feature_update',
        priority: 'medium'
      };

      // Mock multiple users with push tokens
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ 
          rows: [
            { user_id: 'user1', push_token: 'token1' },
            { user_id: 'user2', push_token: 'token2' },
            { user_id: 'user3', push_token: 'token3' }
          ] 
        })
        .mockResolvedValue({ rows: [{ id: 'notif123' }] });
      
      (notificationService as any).db = { query: mockQuery };

      const mockSendPush = jest.fn().mockResolvedValue({ success: true }) as jest.MockedFunction<any>;
      (notificationService as any).sendPushNotification = mockSendPush;

      const result = await notificationService.broadcastSystemNotification(broadcastNotification);

      expect(result.success).toBe(true);
      expect(result.sentCount).toBe(3);
      expect(mockSendPush).toHaveBeenCalledTimes(3);
    });
  });

  describe('scheduleDelayedNotification', () => {
    it('should schedule delayed notification', async () => {
      const delayedNotification = {
        userId: 'user123',
        title: '别忘了领取奖励！',
        message: '您有未领取的奖励，快来看看吧！',
        scheduledFor: new Date(Date.now() + 60 * 60 * 1000), // 1 hour later
        type: 'reminder'
      };

      const mockQuery = jest.fn().mockResolvedValue({
        rows: [{ id: 'scheduled123', ...delayedNotification }]
      });
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.scheduleDelayedNotification(delayedNotification);

      expect(result.success).toBe(true);
      expect(result.scheduledId).toBe('scheduled123');
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO scheduled_notifications'),
        expect.arrayContaining([
          delayedNotification.userId,
          delayedNotification.title,
          delayedNotification.message,
          delayedNotification.scheduledFor,
          delayedNotification.type
        ])
      );
    });

    it('should reject past scheduled time', async () => {
      const invalidNotification = {
        userId: 'user123',
        title: 'Test',
        message: 'Test message',
        scheduledFor: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
        type: 'reminder'
      };

      const result = await notificationService.scheduleDelayedNotification(invalidNotification);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Cannot schedule notification in the past');
    });
  });

  describe('processScheduledNotifications', () => {
    it('should process due scheduled notifications', async () => {
      const now = new Date();
      
      // Mock scheduled notifications that are due
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ 
          rows: [
            {
              id: 'scheduled1',
              user_id: 'user1',
              title: 'Reminder 1',
              message: 'Message 1',
              scheduled_for: new Date(now.getTime() - 5 * 60 * 1000) // 5 minutes ago
            },
            {
              id: 'scheduled2',
              user_id: 'user2',
              title: 'Reminder 2',
              message: 'Message 2',
              scheduled_for: new Date(now.getTime() - 2 * 60 * 1000) // 2 minutes ago
            }
          ] 
        })
        .mockResolvedValueOnce({ rows: [{ push_token: 'token1' }] }) // User 1
        .mockResolvedValueOnce({ rows: [{ push_token: 'token2' }] }) // User 2
        .mockResolvedValue({ rows: [] }); // Update queries
      
      (notificationService as any).db = { query: mockQuery };

      const mockSendPush = jest.fn().mockResolvedValue({ success: true }) as jest.MockedFunction<any>;
      (notificationService as any).sendPushNotification = mockSendPush;

      const result = await notificationService.processScheduledNotifications();

      expect(result.processedCount).toBe(2);
      expect(mockSendPush).toHaveBeenCalledTimes(2);
    });
  });

  describe('updateNotificationPreferences', () => {
    it('should update user notification preferences', async () => {
      const userId = 'user123';
      const preferences = {
        rewards: true,
        nearby_alerts: false,
        system_notifications: true,
        marketing: false
      };

      const mockQuery = jest.fn().mockResolvedValue({
        rows: [{ user_id: userId, preferences }]
      });
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.updateNotificationPreferences(
        userId,
        preferences
      );

      expect(result.success).toBe(true);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE user_notification_preferences'),
        expect.arrayContaining([JSON.stringify(preferences), userId])
      );
    });

    it('should validate preference structure', async () => {
      const userId = 'user123';
      const invalidPreferences = {
        invalid_key: true
      };

      const result = await notificationService.updateNotificationPreferences(
        userId,
        invalidPreferences
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid preference keys');
    });
  });

  describe('getNotificationHistory', () => {
    it('should retrieve user notification history', async () => {
      const userId = 'user123';
      const limit = 20;
      const offset = 0;

      const mockQuery = jest.fn().mockResolvedValue({
        rows: [
          {
            id: 'notif1',
            title: 'Reward Notification',
            message: 'You earned 25.5 yuan!',
            type: 'reward',
            sent_at: new Date(),
            read_at: null
          },
          {
            id: 'notif2',
            title: 'System Update',
            message: 'New features available',
            type: 'system',
            sent_at: new Date(Date.now() - 60 * 60 * 1000),
            read_at: new Date(Date.now() - 30 * 60 * 1000)
          }
        ]
      });
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.getNotificationHistory(
        userId,
        limit,
        offset
      );

      expect(result.notifications).toHaveLength(2);
      expect(result.notifications[0]).toHaveProperty('id', 'notif1');
      expect(result.notifications[0]).toHaveProperty('read_at', null);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM notifications'),
        [userId, limit, offset]
      );
    });
  });

  describe('markNotificationAsRead', () => {
    it('should mark notification as read', async () => {
      const notificationId = 'notif123';
      const userId = 'user123';

      const mockQuery = jest.fn().mockResolvedValue({
        rows: [{ id: notificationId, read_at: new Date() }]
      }) as jest.MockedFunction<any>;
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.markNotificationAsRead(
        notificationId,
        userId
      );

      expect(result.success).toBe(true);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE notifications SET read_at'),
        expect.arrayContaining([notificationId, userId])
      );
    });

    it('should handle non-existent notification', async () => {
      const notificationId = 'nonexistent';
      const userId = 'user123';

      const mockQuery = jest.fn().mockResolvedValue({ rows: [] }) as jest.MockedFunction<any>;
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.markNotificationAsRead(
        notificationId,
        userId
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Notification not found');
    });
  });

  describe('getUnreadCount', () => {
    it('should return unread notification count', async () => {
      const userId = 'user123';

      const mockQuery = jest.fn().mockResolvedValue({
        rows: [{ count: '5' }]
      }) as jest.MockedFunction<any>;
      (notificationService as any).db = { query: mockQuery };

      const count = await notificationService.getUnreadCount(userId);

      expect(count).toBe(5);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('SELECT COUNT(*) FROM notifications'),
        [userId]
      );
    });
  });

  describe('cleanupOldNotifications', () => {
    it('should cleanup old notifications', async () => {
      const daysToKeep = 30;

      const mockQuery = jest.fn().mockResolvedValue({
        rows: [{ deleted_count: '150' }]
      }) as jest.MockedFunction<any>;
      (notificationService as any).db = { query: mockQuery };

      const result = await notificationService.cleanupOldNotifications(daysToKeep);

      expect(result.deletedCount).toBe(150);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM notifications'),
        expect.arrayContaining([daysToKeep])
      );
    });
  });
});