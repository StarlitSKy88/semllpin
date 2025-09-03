/**
 * WebSocket路由处理器
 * 处理实时通知的WebSocket连接
 */

const WebSocket = require('ws');
const url = require('url');
const jwt = require('jsonwebtoken');
const notificationService = require('../services/notificationService');

/**
 * 创建WebSocket服务器
 * @param {Object} server - HTTP服务器实例
 * @returns {WebSocket.Server} WebSocket服务器
 */
function createWebSocketServer(server) {
  const wss = new WebSocket.Server({
    server,
    path: '/ws',
    verifyClient: (info) => {
      // 验证WebSocket连接
      try {
        const query = url.parse(info.req.url, true).query;
        const token = query.token;
        
        if (!token) {
          console.log('WebSocket连接被拒绝：缺少token');
          return false;
        }
        
        // 验证JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        info.req.userId = decoded.userId;
        
        return true;
      } catch (error) {
        console.log('WebSocket连接被拒绝：token无效', error.message);
        return false;
      }
    }
  });

  wss.on('connection', (ws, req) => {
    const userId = req.userId;
    console.log(`用户 ${userId} 建立WebSocket连接`);
    
    // 注册连接到通知服务
    notificationService.registerConnection(userId, ws);
    
    // 处理客户端消息
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        handleClientMessage(userId, data, ws);
      } catch (error) {
        console.error('解析WebSocket消息失败:', error);
        ws.send(JSON.stringify({
          type: 'error',
          message: '消息格式错误'
        }));
      }
    });
    
    // 处理连接错误
    ws.on('error', (error) => {
      console.error(`用户 ${userId} WebSocket连接错误:`, error);
    });
    
    // 处理连接关闭
    ws.on('close', (code, reason) => {
      console.log(`用户 ${userId} WebSocket连接关闭:`, code, reason.toString());
    });
    
    // 发送心跳包
    const heartbeat = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.ping();
      } else {
        clearInterval(heartbeat);
      }
    }, 30000); // 每30秒发送一次心跳
    
    // 处理心跳响应
    ws.on('pong', () => {
      // 客户端响应心跳，连接正常
    });
  });

  // 监听服务器关闭
  wss.on('close', () => {
    console.log('WebSocket服务器关闭');
  });

  console.log('WebSocket服务器已启动，路径: /ws');
  return wss;
}

/**
 * 处理客户端消息
 * @param {string} userId - 用户ID
 * @param {Object} data - 消息数据
 * @param {WebSocket} ws - WebSocket连接
 */
function handleClientMessage(userId, data, ws) {
  switch (data.type) {
    case 'ping':
      // 响应ping消息
      ws.send(JSON.stringify({
        type: 'pong',
        timestamp: new Date().toISOString()
      }));
      break;
      
    case 'subscribe_notifications':
      // 订阅特定类型的通知
      ws.send(JSON.stringify({
        type: 'subscription_confirmed',
        subscriptions: data.notifications || ['all'],
        timestamp: new Date().toISOString()
      }));
      break;
      
    case 'mark_notification_read':
      // 标记通知为已读
      handleMarkNotificationRead(userId, data.notificationId);
      break;
      
    case 'get_online_status':
      // 获取在线状态
      ws.send(JSON.stringify({
        type: 'online_status',
        data: {
          isOnline: true,
          onlineUsers: notificationService.getOnlineUserCount(),
          timestamp: new Date().toISOString()
        }
      }));
      break;
      
    case 'request_location_update':
      // 请求位置更新（用于实时追踪）
      ws.send(JSON.stringify({
        type: 'location_update_requested',
        timestamp: new Date().toISOString()
      }));
      break;
      
    default:
      console.log(`未知的WebSocket消息类型: ${data.type}`);
      ws.send(JSON.stringify({
        type: 'error',
        message: `未知的消息类型: ${data.type}`
      }));
  }
}

/**
 * 处理标记通知为已读
 * @param {string} userId - 用户ID
 * @param {string} notificationId - 通知ID
 */
async function handleMarkNotificationRead(userId, notificationId) {
  try {
    // TODO: 实现通知已读状态的数据库更新
    console.log(`用户 ${userId} 标记通知 ${notificationId} 为已读`);
  } catch (error) {
    console.error('标记通知已读失败:', error);
  }
}

/**
 * 中间件：验证WebSocket升级请求
 */
function authenticateWebSocket(req, res, next) {
  // 这个中间件在HTTP升级到WebSocket之前执行
  // 实际的认证在verifyClient中处理
  next();
}

/**
 * 广播系统消息
 * @param {string} message - 消息内容
 * @param {string} type - 消息类型
 */
function broadcastSystemMessage(message, type = 'system') {
  notificationService.broadcast({
    type: 'system_message',
    data: {
      message,
      messageType: type,
      timestamp: new Date().toISOString()
    }
  });
}

/**
 * 发送服务器状态更新
 * @param {string} status - 服务器状态
 */
function broadcastServerStatus(status) {
  notificationService.broadcast({
    type: 'server_status',
    data: {
      status,
      timestamp: new Date().toISOString()
    }
  });
}

module.exports = {
  createWebSocketServer,
  authenticateWebSocket,
  broadcastSystemMessage,
  broadcastServerStatus
};