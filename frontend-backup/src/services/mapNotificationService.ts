import { message, notification } from 'antd';
// import { sendRealtimeNotification } from './websocketService';
// import React from 'react';

// 地图通知类型
export interface MapNotification {
  id: string;
  type: 'new_annotation' | 'nearby_activity' | 'location_alert' | 'trending_spot';
  title: string;
  message: string;
  location: {
    latitude: number;
    longitude: number;
    address?: string;
  };
  data?: Record<string, unknown>;
  timestamp: Date;
  userId?: string;
  priority: 'low' | 'medium' | 'high';
}

// 地理位置通知服务
class MapNotificationService {
  private watchId: number | null = null;
  // private lastKnownPosition: GeolocationPosition | null = null;
  private notificationQueue: MapNotification[] = [];
  private isProcessing = false;

  // 初始化地理位置监听
  async initializeLocationTracking(): Promise<boolean> {
    if (!navigator.geolocation) {
      message.warning('您的浏览器不支持地理位置功能');
      return false;
    }

    try {
      // 请求位置权限
      const permission = await navigator.permissions.query({ name: 'geolocation' });
      
      if (permission.state === 'denied') {
        message.error('地理位置权限被拒绝，无法提供位置相关通知');
        return false;
      }

      // 开始监听位置变化
      this.watchId = navigator.geolocation.watchPosition(
        this.handlePositionUpdate.bind(this),
        this.handlePositionError.bind(this),
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 60000 // 1分钟缓存
        }
      );

      message.success('地理位置跟踪已启用');
      return true;
    } catch (error) {
      console.error('初始化地理位置跟踪失败:', error);
      return false;
    }
  }

  // 停止地理位置监听
  stopLocationTracking(): void {
    if (this.watchId !== null) {
      navigator.geolocation.clearWatch(this.watchId);
      this.watchId = null;
      message.info('地理位置跟踪已停止');
    }
  }

  // 处理位置更新
  private handlePositionUpdate(position: GeolocationPosition): void {
    // this.lastKnownPosition = position;
    
    // 检查附近活动
    this.checkNearbyActivity(position.coords.latitude, position.coords.longitude);
  }

  // 处理位置错误
  private handlePositionError(error: GeolocationPositionError): void {
    switch (error.code) {
      case error.PERMISSION_DENIED:
        message.error('地理位置权限被拒绝');
        break;
      case error.POSITION_UNAVAILABLE:
        message.warning('无法获取地理位置信息');
        break;
      case error.TIMEOUT:
        message.warning('获取地理位置超时');
        break;
      default:
        message.error('获取地理位置时发生未知错误');
        break;
    }
  }

  // 检查附近活动
  private async checkNearbyActivity(latitude: number, longitude: number): Promise<void> {
    try {
      // 这里应该调用后端API检查附近的新标注或活动
      // const response = await api.get(`/api/annotations/nearby?lat=${latitude}&lng=${longitude}&radius=1000`);
      
      // 模拟附近活动检查
      const mockNearbyActivities = [
        {
          id: 'nearby_1',
          type: 'new_annotation' as const,
          title: '附近新标注',
          message: '距离您500米处有新的恶搞标注',
          location: { latitude: latitude + 0.001, longitude: longitude + 0.001 },
          priority: 'medium' as const
        }
      ];

      // 处理附近活动通知
      mockNearbyActivities.forEach(activity => {
        this.addNotification({
          ...activity,
          timestamp: new Date()
        });
      });
    } catch (error) {
      console.error('检查附近活动失败:', error);
    }
  }

  // 添加地图通知
  addNotification(mapNotification: MapNotification): void {
    this.notificationQueue.push(mapNotification);
    this.processNotificationQueue();
  }

  // 处理通知队列
  private async processNotificationQueue(): Promise<void> {
    if (this.isProcessing || this.notificationQueue.length === 0) {
      return;
    }

    this.isProcessing = true;

    while (this.notificationQueue.length > 0) {
      const mapNotification = this.notificationQueue.shift()!;
      await this.showNotification(mapNotification);
      
      // 发送到WebSocket
      if (mapNotification.userId) {
        try {
          // TODO: 实现WebSocket通知
          // await sendRealtimeNotification(mapNotification.userId, {
          //   type: 'map_notification',
          //   title: mapNotification.title,
          //   message: mapNotification.message,
          //   data: {
          //     location: mapNotification.location,
          //     mapNotificationType: mapNotification.type,
          //     priority: mapNotification.priority
          //   }
          // });
        } catch (error) {
          console.error('发送实时地图通知失败:', error);
        }
      }

      // 避免通知过于频繁
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    this.isProcessing = false;
  }

  // 显示通知
  private async showNotification(mapNotification: MapNotification): Promise<void> {
    const { title, message: msg, location, priority } = mapNotification;

    // 选择图标颜色
    // let iconColor;
    // switch (type) {
    //   case 'new_annotation':
    //     iconColor = '#1890ff';
    //     break;
    //   case 'nearby_activity':
    //     iconColor = '#52c41a';
    //     break;
    //   case 'trending_spot':
    //     iconColor = '#ff4d4f';
    //     break;
    //   default:
    //     iconColor = '#1890ff';
    // }

    // 显示应用内通知
    const descriptionText = location.address 
      ? `${msg}\n📍 ${location.address}`
      : msg;

    notification.open({
      message: title,
      description: descriptionText,
      placement: 'topRight',
      duration: priority === 'high' ? 0 : priority === 'medium' ? 6 : 4,
      onClick: () => {
        // 点击通知时跳转到地图位置
        this.navigateToLocation(location.latitude, location.longitude);
      }
    });

    // 显示桌面通知（如果权限允许）
    if ('Notification' in window && Notification.permission === 'granted') {
      const desktopNotification = new Notification(title, {
        body: msg,
        icon: '/favicon.ico',
        tag: `map-${mapNotification.id}`,
        requireInteraction: priority === 'high'
      });

      desktopNotification.onclick = () => {
        window.focus();
        this.navigateToLocation(location.latitude, location.longitude);
        desktopNotification.close();
      };
    }
  }

  // 导航到指定位置
  private navigateToLocation(latitude: number, longitude: number): void {
    // 触发地图跳转事件
    const event = new CustomEvent('mapNavigate', {
      detail: { latitude, longitude }
    });
    window.dispatchEvent(event);
  }

  // 创建新标注通知
  createNewAnnotationNotification(
    annotationId: string,
    location: { latitude: number; longitude: number; address?: string },
    userId?: string
  ): MapNotification {
    return {
      id: `annotation_${annotationId}`,
      type: 'new_annotation',
      title: '新的恶搞标注',
      message: '附近有新的搞笑标注等你发现！',
      location,
      timestamp: new Date(),
      userId,
      priority: 'medium'
    };
  }

  // 创建附近活动通知
  createNearbyActivityNotification(
    activityType: string,
    location: { latitude: number; longitude: number; address?: string },
    userId?: string
  ): MapNotification {
    return {
      id: `activity_${Date.now()}`,
      type: 'nearby_activity',
      title: '附近活动',
      message: `附近有${activityType}活动`,
      location,
      timestamp: new Date(),
      userId,
      priority: 'low'
    };
  }

  // 创建热门地点通知
  createTrendingSpotNotification(
    spotName: string,
    location: { latitude: number; longitude: number; address?: string },
    userId?: string
  ): MapNotification {
    return {
      id: `trending_${Date.now()}`,
      type: 'trending_spot',
      title: '热门地点',
      message: `${spotName} 正在热门中！`,
      location,
      timestamp: new Date(),
      userId,
      priority: 'high'
    };
  }

  // 获取当前位置
  getCurrentPosition(): Promise<GeolocationPosition> {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('浏览器不支持地理位置'));
        return;
      }

      navigator.geolocation.getCurrentPosition(
        resolve,
        reject,
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 60000
        }
      );
    });
  }

  // 计算两点间距离（米）
  calculateDistance(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number
  ): number {
    const R = 6371e3; // 地球半径（米）
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lon2 - lon1) * Math.PI / 180;

    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  // 清理资源
  cleanup(): void {
    this.stopLocationTracking();
    this.notificationQueue = [];
    this.isProcessing = false;
  }
}

// 导出单例实例
export const mapNotificationService = new MapNotificationService();
export default mapNotificationService;