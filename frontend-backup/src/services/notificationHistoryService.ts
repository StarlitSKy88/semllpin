import { message } from 'antd';
import api from '../utils/api';

// 通知历史项接口
export interface NotificationHistoryItem {
  id: string;
  type: string;
  title: string;
  message: string;
  data?: Record<string, unknown>;
  timestamp: Date;
  read: boolean;
  priority: 'low' | 'medium' | 'high';
  source: 'websocket' | 'push' | 'email' | 'system';
  category?: string;
  actions?: Array<{
    label: string;
    action: string;
    data?: Record<string, unknown>;
  }>;
}

// 通知过滤器
export interface NotificationFilter {
  type?: string[];
  category?: string[];
  priority?: ('low' | 'medium' | 'high')[];
  source?: ('websocket' | 'push' | 'email' | 'system')[];
  read?: boolean;
  dateRange?: {
    start: Date;
    end: Date;
  };
  keyword?: string;
}

// 通知统计信息
export interface NotificationStats {
  total: number;
  unread: number;
  byType: Record<string, number>;
  byCategory: Record<string, number>;
  byPriority: Record<string, number>;
  bySource: Record<string, number>;
  todayCount: number;
  weekCount: number;
  monthCount: number;
}

// 通知历史管理服务
class NotificationHistoryService {
  private notifications: NotificationHistoryItem[] = [];
  private maxLocalStorage = 1000; // 本地存储最大数量
  private maxMemory = 500; // 内存中保持的最大数量
  private syncInterval: number | null = null;
  private lastSyncTime: Date | null = null;

  constructor() {
    this.loadFromLocalStorage();
    this.startAutoSync();
  }

  // 添加通知到历史
  addNotification(notification: Omit<NotificationHistoryItem, 'id' | 'timestamp'>): string {
    const historyItem: NotificationHistoryItem = {
      ...notification,
      id: this.generateId(),
      timestamp: new Date()
    };

    // 添加到内存
    this.notifications.unshift(historyItem);
    
    // 限制内存中的数量
    if (this.notifications.length > this.maxMemory) {
      this.notifications = this.notifications.slice(0, this.maxMemory);
    }

    // 保存到本地存储
    this.saveToLocalStorage();

    // 异步同步到服务器
    this.syncToServer([historyItem]);

    return historyItem.id;
  }

  // 批量添加通知
  addNotifications(notifications: Array<Omit<NotificationHistoryItem, 'id' | 'timestamp'>>): string[] {
    const historyItems = notifications.map(notification => ({
      ...notification,
      id: this.generateId(),
      timestamp: new Date()
    }));

    // 添加到内存
    this.notifications.unshift(...historyItems);
    
    // 限制内存中的数量
    if (this.notifications.length > this.maxMemory) {
      this.notifications = this.notifications.slice(0, this.maxMemory);
    }

    // 保存到本地存储
    this.saveToLocalStorage();

    // 异步同步到服务器
    this.syncToServer(historyItems);

    return historyItems.map(item => item.id);
  }

  // 获取通知历史
  getNotifications(
    filter?: NotificationFilter,
    pagination?: {
      page: number;
      pageSize: number;
    }
  ): {
    notifications: NotificationHistoryItem[];
    total: number;
    hasMore: boolean;
  } {
    let filteredNotifications = this.notifications;

    // 应用过滤器
    if (filter) {
      filteredNotifications = this.applyFilter(filteredNotifications, filter);
    }

    // 应用分页
    const total = filteredNotifications.length;
    let notifications = filteredNotifications;
    let hasMore = false;

    if (pagination) {
      const { page, pageSize } = pagination;
      const startIndex = (page - 1) * pageSize;
      const endIndex = startIndex + pageSize;
      notifications = filteredNotifications.slice(startIndex, endIndex);
      hasMore = endIndex < total;
    }

    return {
      notifications,
      total,
      hasMore
    };
  }

  // 应用过滤器
  private applyFilter(
    notifications: NotificationHistoryItem[],
    filter: NotificationFilter
  ): NotificationHistoryItem[] {
    return notifications.filter(notification => {
      // 类型过滤
      if (filter.type && !filter.type.includes(notification.type)) {
        return false;
      }

      // 分类过滤
      if (filter.category && notification.category && !filter.category.includes(notification.category)) {
        return false;
      }

      // 优先级过滤
      if (filter.priority && !filter.priority.includes(notification.priority)) {
        return false;
      }

      // 来源过滤
      if (filter.source && !filter.source.includes(notification.source)) {
        return false;
      }

      // 已读状态过滤
      if (filter.read !== undefined && notification.read !== filter.read) {
        return false;
      }

      // 日期范围过滤
      if (filter.dateRange) {
        const notificationTime = notification.timestamp.getTime();
        const startTime = filter.dateRange.start.getTime();
        const endTime = filter.dateRange.end.getTime();
        if (notificationTime < startTime || notificationTime > endTime) {
          return false;
        }
      }

      // 关键词过滤
      if (filter.keyword) {
        const keyword = filter.keyword.toLowerCase();
        const searchText = `${notification.title} ${notification.message}`.toLowerCase();
        if (!searchText.includes(keyword)) {
          return false;
        }
      }

      return true;
    });
  }

  // 标记通知为已读
  markAsRead(notificationIds: string[]): void {
    let updated = false;
    
    this.notifications.forEach(notification => {
      if (notificationIds.includes(notification.id) && !notification.read) {
        notification.read = true;
        updated = true;
      }
    });

    if (updated) {
      this.saveToLocalStorage();
      // 异步同步到服务器
      this.syncReadStatusToServer(notificationIds);
    }
  }

  // 标记所有通知为已读
  markAllAsRead(): void {
    const unreadIds: string[] = [];
    
    this.notifications.forEach(notification => {
      if (!notification.read) {
        notification.read = true;
        unreadIds.push(notification.id);
      }
    });

    if (unreadIds.length > 0) {
      this.saveToLocalStorage();
      this.syncReadStatusToServer(unreadIds);
    }
  }

  // 删除通知
  deleteNotifications(notificationIds: string[]): void {
    this.notifications = this.notifications.filter(
      notification => !notificationIds.includes(notification.id)
    );
    
    this.saveToLocalStorage();
    // 异步同步到服务器
    this.syncDeleteToServer(notificationIds);
  }

  // 清空历史记录
  clearHistory(olderThan?: Date): void {
    if (olderThan) {
      this.notifications = this.notifications.filter(
        notification => notification.timestamp > olderThan
      );
    } else {
      this.notifications = [];
    }
    
    this.saveToLocalStorage();
    // 同步到服务器
    this.syncClearToServer(olderThan);
  }

  // 获取统计信息
  getStats(): NotificationStats {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const stats: NotificationStats = {
      total: this.notifications.length,
      unread: this.notifications.filter(n => !n.read).length,
      byType: {},
      byCategory: {},
      byPriority: {},
      bySource: {},
      todayCount: this.notifications.filter(n => n.timestamp >= today).length,
      weekCount: this.notifications.filter(n => n.timestamp >= weekAgo).length,
      monthCount: this.notifications.filter(n => n.timestamp >= monthAgo).length
    };

    // 统计各维度数据
    this.notifications.forEach(notification => {
      // 按类型统计
      stats.byType[notification.type] = (stats.byType[notification.type] || 0) + 1;
      
      // 按分类统计
      if (notification.category) {
        stats.byCategory[notification.category] = (stats.byCategory[notification.category] || 0) + 1;
      }
      
      // 按优先级统计
      stats.byPriority[notification.priority] = (stats.byPriority[notification.priority] || 0) + 1;
      
      // 按来源统计
      stats.bySource[notification.source] = (stats.bySource[notification.source] || 0) + 1;
    });

    return stats;
  }

  // 搜索通知
  searchNotifications(
    keyword: string,
    options?: {
      limit?: number;
      includeRead?: boolean;
    }
  ): NotificationHistoryItem[] {
    const { limit = 50, includeRead = true } = options || {};
    const searchTerm = keyword.toLowerCase();

    return this.notifications
      .filter(notification => {
        if (!includeRead && notification.read) {
          return false;
        }
        
        const searchText = `${notification.title} ${notification.message}`.toLowerCase();
        return searchText.includes(searchTerm);
      })
      .slice(0, limit);
  }

  // 获取未读通知数量
  getUnreadCount(): number {
    return this.notifications.filter(notification => !notification.read).length;
  }

  // 获取最新通知
  getLatestNotifications(count: number = 10): NotificationHistoryItem[] {
    return this.notifications.slice(0, count);
  }

  // 生成唯一ID
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // 保存到本地存储
  private saveToLocalStorage(): void {
    try {
      const dataToSave = this.notifications.slice(0, this.maxLocalStorage);
      localStorage.setItem('notificationHistory', JSON.stringify({
        notifications: dataToSave,
        lastUpdated: new Date().toISOString()
      }));
    } catch (error) {
      console.warn('保存通知历史到本地存储失败:', error);
    }
  }

  // 从本地存储加载
  private loadFromLocalStorage(): void {
    try {
      const saved = localStorage.getItem('notificationHistory');
      if (saved) {
        const data = JSON.parse(saved);
        if (data && Array.isArray(data.notifications)) {
          this.notifications = data.notifications.map((item: unknown) => {
            if (typeof item === 'object' && item !== null) {
              const notification = item as Record<string, unknown>;
              return {
                ...notification,
                timestamp: new Date(notification.timestamp as string)
              } as NotificationHistoryItem;
            }
            return item as NotificationHistoryItem;
          });
        }
      }
    } catch (error) {
      console.warn('从本地存储加载通知历史失败:', error);
      this.notifications = [];
    }
  }

  // 开始自动同步
  private startAutoSync(): void {
    // 每5分钟同步一次
    this.syncInterval = window.setInterval(() => {
      this.syncFromServer();
    }, 5 * 60 * 1000);

    // 立即执行一次同步
    this.syncFromServer();
  }

  // 同步到服务器
  private async syncToServer(notifications: NotificationHistoryItem[]): Promise<void> {
    try {
      await api.post('/api/notifications/history/sync', {
        notifications: notifications.map(n => ({
          ...n,
          timestamp: n.timestamp.toISOString()
        }))
      });
    } catch (error) {
      console.warn('同步通知历史到服务器失败:', error);
    }
  }

  // 从服务器同步
  private async syncFromServer(): Promise<void> {
    try {
      const lastSync = this.lastSyncTime || new Date(Date.now() - 24 * 60 * 60 * 1000);
      const response = await api.get('/api/notifications/history', {
        params: {
          since: lastSync.toISOString(),
          limit: 100
        }
      });

      if (response.data.notifications) {
        const serverNotifications = response.data.notifications.map((item: unknown) => {
          if (typeof item === 'object' && item !== null) {
            const notification = item as Record<string, unknown>;
            return {
              ...notification,
              timestamp: new Date(notification.timestamp as string)
            } as NotificationHistoryItem;
          }
          return item as NotificationHistoryItem;
        });

        // 合并服务器数据
        this.mergeServerNotifications(serverNotifications);
        this.lastSyncTime = new Date();
      }
    } catch (error) {
      console.warn('从服务器同步通知历史失败:', error);
    }
  }

  // 合并服务器通知
  private mergeServerNotifications(serverNotifications: NotificationHistoryItem[]): void {
    const existingIds = new Set(this.notifications.map(n => n.id));
    
    const newNotifications = serverNotifications.filter(n => !existingIds.has(n.id));
    
    if (newNotifications.length > 0) {
      this.notifications = [...newNotifications, ...this.notifications]
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(0, this.maxMemory);
      
      this.saveToLocalStorage();
    }
  }

  // 同步已读状态到服务器
  private async syncReadStatusToServer(notificationIds: string[]): Promise<void> {
    try {
      await api.post('/api/notifications/mark-read', {
        notificationIds
      });
    } catch (error) {
      console.warn('同步已读状态到服务器失败:', error);
    }
  }

  // 同步删除到服务器
  private async syncDeleteToServer(notificationIds: string[]): Promise<void> {
    try {
      await api.delete('/api/notifications/history', {
        data: { notificationIds }
      });
    } catch (error) {
      console.warn('同步删除到服务器失败:', error);
    }
  }

  // 同步清空到服务器
  private async syncClearToServer(olderThan?: Date): Promise<void> {
    try {
      await api.delete('/api/notifications/history/clear', {
        data: { olderThan: olderThan?.toISOString() }
      });
    } catch (error) {
      console.warn('同步清空到服务器失败:', error);
    }
  }

  // 导出历史记录
  exportHistory(format: 'json' | 'csv' = 'json'): string {
    if (format === 'json') {
      return JSON.stringify(this.notifications, null, 2);
    } else {
      // CSV格式
      const headers = ['ID', 'Type', 'Title', 'Message', 'Priority', 'Source', 'Read', 'Timestamp'];
      const rows = this.notifications.map(n => [
        n.id,
        n.type,
        n.title,
        n.message,
        n.priority,
        n.source,
        n.read ? 'Yes' : 'No',
        n.timestamp.toISOString()
      ]);
      
      return [headers, ...rows]
        .map(row => row.map(cell => `"${cell}"`).join(','))
        .join('\n');
    }
  }

  // 导入历史记录
  importHistory(data: string, format: 'json' | 'csv' = 'json'): number {
    try {
      let importedNotifications: NotificationHistoryItem[] = [];
      
      if (format === 'json') {
        const parsed = JSON.parse(data);
        importedNotifications = Array.isArray(parsed) ? parsed : [parsed];
      } else {
        // CSV格式解析
        const lines = data.split('\n');
        const headers = lines[0].split(',').map(h => h.replace(/"/g, ''));
        
        for (let i = 1; i < lines.length; i++) {
          const values = lines[i].split(',').map(v => v.replace(/"/g, ''));
          if (values.length >= headers.length) {
            importedNotifications.push({
              id: values[0],
              type: values[1],
              title: values[2],
              message: values[3],
              priority: values[4] as 'low' | 'medium' | 'high',
              source: values[5] as 'websocket' | 'push' | 'email' | 'system',
              read: values[6] === 'Yes',
              timestamp: new Date(values[7])
            });
          }
        }
      }
      
      // 合并导入的通知
      this.mergeServerNotifications(importedNotifications);
      
      message.success(`成功导入 ${importedNotifications.length} 条通知记录`);
      return importedNotifications.length;
    } catch (error) {
      console.error('导入历史记录失败:', error);
      message.error('导入历史记录失败');
      return 0;
    }
  }

  // 清理资源
  cleanup(): void {
    if (this.syncInterval) {
      window.clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }
}

// 导出单例实例
export const notificationHistoryService = new NotificationHistoryService();
export default notificationHistoryService;