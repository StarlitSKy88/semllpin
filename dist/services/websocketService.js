"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class WebSocketService {
    constructor() {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.isConnecting = false;
        this.handlers = new Map();
        this.heartbeatInterval = null;
        this.connectionPromise = null;
    }
    async connect(token) {
        if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
            return this.connectionPromise || Promise.resolve();
        }
        this.isConnecting = true;
        this.connectionPromise = new Promise((resolve, reject) => {
            try {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const host = window.location.host;
                const wsUrl = `${protocol}//${host}/ws?token=${encodeURIComponent(token)}`;
                this.ws = new WebSocket(wsUrl);
                this.ws.onopen = () => {
                    console.log('WebSocket连接已建立');
                    this.isConnecting = false;
                    this.reconnectAttempts = 0;
                    this.startHeartbeat();
                    this.emit('connection_established', { timestamp: new Date().toISOString() });
                    resolve();
                };
                this.ws.onmessage = (event) => {
                    try {
                        const notification = JSON.parse(event.data);
                        this.handleNotification(notification);
                    }
                    catch (error) {
                        console.error('解析WebSocket消息失败:', error);
                    }
                };
                this.ws.onclose = (event) => {
                    console.log('WebSocket连接关闭:', event.code, event.reason);
                    this.isConnecting = false;
                    this.stopHeartbeat();
                    this.emit('connection_closed', { code: event.code, reason: event.reason });
                    if (this.reconnectAttempts < this.maxReconnectAttempts) {
                        this.scheduleReconnect(token);
                    }
                };
                this.ws.onerror = (error) => {
                    console.error('WebSocket连接错误:', error);
                    this.isConnecting = false;
                    this.emit('connection_error', { error });
                    reject(error);
                };
            }
            catch (error) {
                this.isConnecting = false;
                reject(error);
            }
        });
        return this.connectionPromise;
    }
    disconnect() {
        if (this.ws) {
            this.stopHeartbeat();
            this.ws.close(1000, '用户主动断开连接');
            this.ws = null;
        }
        this.reconnectAttempts = this.maxReconnectAttempts;
    }
    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        }
        else {
            console.warn('WebSocket未连接，无法发送消息');
        }
    }
    subscribeNotifications(notifications = ['all']) {
        this.send({
            type: 'subscribe_notifications',
            notifications,
        });
    }
    markNotificationRead(notificationId) {
        this.send({
            type: 'mark_notification_read',
            notificationId,
        });
    }
    requestLocationUpdate() {
        this.send({
            type: 'request_location_update',
        });
    }
    getOnlineStatus() {
        this.send({
            type: 'get_online_status',
        });
    }
    on(event, handler) {
        if (!this.handlers.has(event)) {
            this.handlers.set(event, []);
        }
        this.handlers.get(event).push(handler);
    }
    off(event, handler) {
        const handlers = this.handlers.get(event);
        if (handlers) {
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }
    emit(event, data) {
        const handlers = this.handlers.get(event);
        if (handlers) {
            handlers.forEach(handler => {
                try {
                    handler(data);
                }
                catch (error) {
                    console.error(`事件处理器执行失败 [${event}]:`, error);
                }
            });
        }
    }
    handleNotification(notification) {
        console.log('收到通知:', notification);
        switch (notification.type) {
            case 'reward_earned':
                this.handleRewardNotification(notification.data);
                break;
            case 'geofence_entered':
                this.handleGeofenceNotification(notification.data);
                break;
            case 'achievement_unlocked':
                this.handleAchievementNotification(notification.data);
                break;
            case 'connection_established':
                this.emit('connected', notification.data);
                break;
            case 'pong':
                break;
            case 'system_message':
                this.emit('system_message', notification.data);
                break;
            case 'server_status':
                this.emit('server_status', notification.data);
                break;
            default:
                this.emit(notification.type, notification.data);
        }
    }
    handleRewardNotification(data) {
        this.emit('reward_earned', data);
        this.showBrowserNotification('🎉 获得奖励！', `在${data.geofenceName}获得${data.amount}积分`, '/icons/reward-icon.png');
    }
    handleGeofenceNotification(data) {
        this.emit('geofence_entered', data);
        this.showBrowserNotification('📍 发现新地点！', `进入${data.name}，可获得${data.potentialReward}积分`, '/icons/location-icon.png');
    }
    handleAchievementNotification(data) {
        this.emit('achievement_unlocked', data);
        this.showBrowserNotification('🏆 成就解锁！', `解锁成就：${data.name}`, '/icons/achievement-icon.png');
    }
    async showBrowserNotification(title, body, icon) {
        if ('Notification' in window) {
            if (Notification.permission === 'granted') {
                const options = { body };
                if (icon) {
                    options.icon = icon;
                }
                new Notification(title, options);
            }
            else if (Notification.permission !== 'denied') {
                const permission = await Notification.requestPermission();
                if (permission === 'granted') {
                    const options = { body };
                    if (icon) {
                        options.icon = icon;
                    }
                    new Notification(title, options);
                }
            }
        }
    }
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            this.send({ type: 'ping' });
        }, 30000);
    }
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }
    scheduleReconnect(token) {
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        console.log(`${delay}ms后尝试第${this.reconnectAttempts}次重连...`);
        setTimeout(() => {
            this.connect(token).catch(error => {
                console.error('重连失败:', error);
            });
        }, delay);
    }
    get isConnected() {
        return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
    }
    get connectionState() {
        if (!this.ws) {
            return 'disconnected';
        }
        switch (this.ws.readyState) {
            case WebSocket.CONNECTING:
                return 'connecting';
            case WebSocket.OPEN:
                return 'connected';
            case WebSocket.CLOSING:
                return 'closing';
            case WebSocket.CLOSED:
                return 'closed';
            default:
                return 'unknown';
        }
    }
}
const websocketService = new WebSocketService();
exports.default = websocketService;
//# sourceMappingURL=websocketService.js.map