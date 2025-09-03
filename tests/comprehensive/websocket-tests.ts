/**
 * WebSocket连接和实时通知全面测试套件
 * 
 * 测试WebSocket连接、实时消息传递、连接管理等
 */

import { Server } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import { io as Client, Socket as ClientSocket } from 'socket.io-client';
import { faker } from '@faker-js/faker/locale/zh_CN';
import jwt from 'jsonwebtoken';

// 测试WebSocket服务器设置
class TestWebSocketServer {
  private httpServer: Server;
  private io: SocketIOServer;
  private port: number;
  
  constructor() {
    this.httpServer = createServer();
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      },
      transports: ['websocket', 'polling']
    });
    this.port = 0; // 让系统分配端口
    this.setupSocketHandlers();
  }

  private setupSocketHandlers() {
    this.io.use((socket, next) => {
      // JWT认证中间件
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication token required'));
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'test-secret') as any;
        socket.userId = decoded.userId;
        socket.userEmail = decoded.email;
        next();
      } catch (err) {
        next(new Error('Invalid authentication token'));
      }
    });

    this.io.on('connection', (socket) => {
      console.log(`用户 ${socket.userId} 已连接WebSocket`);

      // 加入用户专用房间
      socket.join(`user:${socket.userId}`);

      // 处理位置更新
      socket.on('location:update', (data) => {
        // 验证位置数据
        if (!data.latitude || !data.longitude) {
          socket.emit('error', { message: 'Invalid location data' });
          return;
        }

        // 广播位置更新给附近用户
        socket.broadcast.emit('location:nearby_user', {
          userId: socket.userId,
          latitude: data.latitude,
          longitude: data.longitude,
          timestamp: new Date()
        });

        socket.emit('location:update_confirmed', {
          success: true,
          timestamp: new Date()
        });
      });

      // 处理标注相关事件
      socket.on('annotation:create', (data) => {
        // 模拟标注创建逻辑
        const annotationId = faker.string.uuid();
        
        // 向创建者确认
        socket.emit('annotation:created', {
          success: true,
          annotationId,
          data
        });

        // 通知附近用户
        socket.broadcast.emit('annotation:new_nearby', {
          annotationId,
          creatorId: socket.userId,
          latitude: data.latitude,
          longitude: data.longitude,
          smellType: data.smellType,
          intensity: data.intensity
        });
      });

      socket.on('annotation:like', (data) => {
        const { annotationId } = data;
        
        // 向点赞者确认
        socket.emit('annotation:liked', {
          success: true,
          annotationId
        });

        // 通知标注作者
        if (data.authorId && data.authorId !== socket.userId) {
          this.io.to(`user:${data.authorId}`).emit('notification:like_received', {
            type: 'like',
            annotationId,
            likerId: socket.userId,
            message: '有人点赞了你的标注'
          });
        }
      });

      // 处理奖励相关事件
      socket.on('reward:discover', (data) => {
        const { annotationId, distance } = data;
        const rewardAmount = Math.max(1, 10 - distance / 100); // 距离越近奖励越高

        socket.emit('reward:earned', {
          success: true,
          annotationId,
          amount: rewardAmount,
          distance
        });

        // 通知标注作者有人发现了他们的标注
        if (data.authorId && data.authorId !== socket.userId) {
          this.io.to(`user:${data.authorId}`).emit('notification:annotation_discovered', {
            type: 'discovery',
            annotationId,
            discoverId: socket.userId,
            rewardAmount,
            message: '有人发现了你的标注'
          });
        }
      });

      // 处理聊天消息
      socket.on('chat:send', (data) => {
        const { message, roomId } = data;
        
        // 验证消息内容
        if (!message || message.trim().length === 0) {
          socket.emit('error', { message: 'Message cannot be empty' });
          return;
        }

        if (message.length > 500) {
          socket.emit('error', { message: 'Message too long' });
          return;
        }

        const messageData = {
          id: faker.string.uuid(),
          userId: socket.userId,
          userEmail: socket.userEmail,
          message: message.trim(),
          timestamp: new Date(),
          roomId
        };

        // 发送给房间内所有用户
        this.io.to(roomId).emit('chat:message', messageData);
      });

      // 处理房间加入/离开
      socket.on('room:join', (data) => {
        const { roomId } = data;
        socket.join(roomId);
        socket.to(roomId).emit('room:user_joined', {
          userId: socket.userId,
          userEmail: socket.userEmail
        });
        socket.emit('room:joined', { roomId });
      });

      socket.on('room:leave', (data) => {
        const { roomId } = data;
        socket.leave(roomId);
        socket.to(roomId).emit('room:user_left', {
          userId: socket.userId,
          userEmail: socket.userEmail
        });
        socket.emit('room:left', { roomId });
      });

      // 处理系统通知
      socket.on('system:status', () => {
        socket.emit('system:info', {
          connectedUsers: this.io.engine.clientsCount,
          serverTime: new Date(),
          uptime: process.uptime()
        });
      });

      // 处理断开连接
      socket.on('disconnect', (reason) => {
        console.log(`用户 ${socket.userId} 断开连接: ${reason}`);
        
        // 通知相关房间用户已离线
        socket.broadcast.emit('user:offline', {
          userId: socket.userId,
          timestamp: new Date()
        });
      });

      // 处理错误
      socket.on('error', (error) => {
        console.error(`WebSocket错误 (用户 ${socket.userId}):`, error);
        socket.emit('error', { message: 'An error occurred' });
      });
    });
  }

  public async start(): Promise<number> {
    return new Promise((resolve) => {
      this.httpServer.listen(0, () => {
        this.port = (this.httpServer.address() as any).port;
        resolve(this.port);
      });
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.io.close(() => {
        this.httpServer.close(() => {
          resolve();
        });
      });
    });
  }

  public getIO(): SocketIOServer {
    return this.io;
  }
}

describe('6. WebSocket连接测试', () => {
  let testServer: TestWebSocketServer;
  let serverPort: number;
  let testUser: any;
  let authToken: string;

  beforeAll(async () => {
    // 启动测试WebSocket服务器
    testServer = new TestWebSocketServer();
    serverPort = await testServer.start();

    // 创建测试用户
    testUser = {
      id: faker.string.uuid(),
      email: faker.internet.email(),
      username: faker.internet.username()
    };

    // 生成认证令牌
    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    // 停止测试服务器
    if (testServer) {
      await testServer.stop();
    }
  });

  describe('WebSocket连接管理', () => {
    it('应该成功建立WebSocket连接', (done) => {
      const client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      client.on('connect', () => {
        expect(client.connected).toBe(true);
        expect(client.id).toBeTruthy();
        
        client.disconnect();
        done();
      });

      client.on('connect_error', (error) => {
        done(error);
      });
    });

    it('应该拒绝无效的认证令牌', (done) => {
      const client = Client(`http://localhost:${serverPort}`, {
        auth: { token: 'invalid-token' },
        transports: ['websocket']
      });

      client.on('connect', () => {
        done(new Error('应该拒绝无效令牌的连接'));
      });

      client.on('connect_error', (error) => {
        expect(error.message).toContain('Invalid authentication token');
        done();
      });
    });

    it('应该要求认证令牌', (done) => {
      const client = Client(`http://localhost:${serverPort}`, {
        transports: ['websocket']
        // 不提供认证令牌
      });

      client.on('connect', () => {
        done(new Error('应该要求认证令牌'));
      });

      client.on('connect_error', (error) => {
        expect(error.message).toContain('Authentication token required');
        done();
      });
    });

    it('应该支持多个并发连接', async () => {
      const connectionCount = 5;
      const clients: ClientSocket[] = [];

      try {
        // 创建多个客户端连接
        const connectionPromises = Array.from({ length: connectionCount }, () => {
          return new Promise<ClientSocket>((resolve, reject) => {
            const client = Client(`http://localhost:${serverPort}`, {
              auth: { token: authToken },
              transports: ['websocket']
            });

            client.on('connect', () => resolve(client));
            client.on('connect_error', reject);
          });
        });

        const connectedClients = await Promise.all(connectionPromises);
        clients.push(...connectedClients);

        // 验证所有连接都成功
        expect(connectedClients).toHaveLength(connectionCount);
        connectedClients.forEach(client => {
          expect(client.connected).toBe(true);
        });

      } finally {
        // 断开所有连接
        clients.forEach(client => client.disconnect());
      }
    });

    it('应该正确处理连接断开', (done) => {
      const client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      let connected = false;

      client.on('connect', () => {
        connected = true;
        client.disconnect();
      });

      client.on('disconnect', (reason) => {
        expect(connected).toBe(true);
        expect(reason).toBeTruthy();
        done();
      });

      client.on('connect_error', done);
    });

    it('应该支持自动重连', (done) => {
      const client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket'],
        autoConnect: false
      });

      let connectCount = 0;

      client.on('connect', () => {
        connectCount++;
        
        if (connectCount === 1) {
          // 第一次连接，模拟网络中断
          client.disconnect();
          setTimeout(() => {
            client.connect(); // 手动重连
          }, 100);
        } else if (connectCount === 2) {
          // 第二次连接成功，测试完成
          expect(connectCount).toBe(2);
          client.disconnect();
          done();
        }
      });

      client.connect();
    }, 10000);
  });

  describe('实时位置更新', () => {
    let client: ClientSocket;

    beforeEach((done) => {
      client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      client.on('connect', () => done());
      client.on('connect_error', done);
    });

    afterEach(() => {
      if (client) {
        client.disconnect();
      }
    });

    it('应该成功发送位置更新', (done) => {
      const locationData = {
        latitude: 31.2304,
        longitude: 121.4737,
        accuracy: 10,
        timestamp: Date.now()
      };

      client.on('location:update_confirmed', (response) => {
        expect(response.success).toBe(true);
        expect(response.timestamp).toBeTruthy();
        done();
      });

      client.emit('location:update', locationData);
    });

    it('应该拒绝无效的位置数据', (done) => {
      const invalidLocationData = {
        latitude: null,
        longitude: 121.4737
      };

      client.on('error', (error) => {
        expect(error.message).toContain('Invalid location data');
        done();
      });

      client.emit('location:update', invalidLocationData);
    });

    it('应该向附近用户广播位置更新', (done) => {
      // 创建第二个客户端作为接收者
      const receiver = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      receiver.on('connect', () => {
        receiver.on('location:nearby_user', (data) => {
          expect(data.userId).toBe(testUser.id);
          expect(data.latitude).toBe(31.2304);
          expect(data.longitude).toBe(121.4737);
          expect(data.timestamp).toBeTruthy();
          
          receiver.disconnect();
          done();
        });

        // 发送者发送位置更新
        client.emit('location:update', {
          latitude: 31.2304,
          longitude: 121.4737,
          accuracy: 10
        });
      });
    });

    it('应该处理高频位置更新', (done) => {
      let confirmationCount = 0;
      const updateCount = 10;

      client.on('location:update_confirmed', () => {
        confirmationCount++;
        if (confirmationCount === updateCount) {
          expect(confirmationCount).toBe(updateCount);
          done();
        }
      });

      // 快速发送多个位置更新
      for (let i = 0; i < updateCount; i++) {
        client.emit('location:update', {
          latitude: 31.2304 + i * 0.001,
          longitude: 121.4737 + i * 0.001,
          accuracy: 10,
          timestamp: Date.now() + i
        });
      }
    }, 5000);
  });

  describe('标注相关实时通知', () => {
    let client: ClientSocket;

    beforeEach((done) => {
      client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      client.on('connect', () => done());
      client.on('connect_error', done);
    });

    afterEach(() => {
      if (client) {
        client.disconnect();
      }
    });

    it('应该通知标注创建成功', (done) => {
      const annotationData = {
        latitude: 31.2304,
        longitude: 121.4737,
        smellType: 'industrial',
        intensity: 4,
        description: '测试标注'
      };

      client.on('annotation:created', (response) => {
        expect(response.success).toBe(true);
        expect(response.annotationId).toBeTruthy();
        expect(response.data).toEqual(annotationData);
        done();
      });

      client.emit('annotation:create', annotationData);
    });

    it('应该向附近用户广播新标注', (done) => {
      // 创建接收者客户端
      const receiver = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      receiver.on('connect', () => {
        receiver.on('annotation:new_nearby', (data) => {
          expect(data.creatorId).toBe(testUser.id);
          expect(data.smellType).toBe('industrial');
          expect(data.intensity).toBe(4);
          expect(data.annotationId).toBeTruthy();
          
          receiver.disconnect();
          done();
        });

        // 发送者创建标注
        client.emit('annotation:create', {
          latitude: 31.2304,
          longitude: 121.4737,
          smellType: 'industrial',
          intensity: 4,
          description: '测试广播标注'
        });
      });
    });

    it('应该处理点赞通知', (done) => {
      const annotationId = faker.string.uuid();
      const authorId = faker.string.uuid();

      // 创建标注作者客户端
      const authorToken = jwt.sign(
        { userId: authorId, email: 'author@example.com' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      const authorClient = Client(`http://localhost:${serverPort}`, {
        auth: { token: authorToken },
        transports: ['websocket']
      });

      authorClient.on('connect', () => {
        authorClient.on('notification:like_received', (notification) => {
          expect(notification.type).toBe('like');
          expect(notification.annotationId).toBe(annotationId);
          expect(notification.likerId).toBe(testUser.id);
          expect(notification.message).toContain('点赞');
          
          authorClient.disconnect();
          done();
        });

        // 点赞者发送点赞事件
        client.emit('annotation:like', {
          annotationId,
          authorId
        });
      });
    });

    it('应该确认点赞操作', (done) => {
      const annotationId = faker.string.uuid();

      client.on('annotation:liked', (response) => {
        expect(response.success).toBe(true);
        expect(response.annotationId).toBe(annotationId);
        done();
      });

      client.emit('annotation:like', { annotationId });
    });
  });

  describe('奖励系统实时通知', () => {
    let client: ClientSocket;

    beforeEach((done) => {
      client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      client.on('connect', () => done());
      client.on('connect_error', done);
    });

    afterEach(() => {
      if (client) {
        client.disconnect();
      }
    });

    it('应该通知奖励获得', (done) => {
      const discoverData = {
        annotationId: faker.string.uuid(),
        distance: 50 // 50米距离
      };

      client.on('reward:earned', (response) => {
        expect(response.success).toBe(true);
        expect(response.annotationId).toBe(discoverData.annotationId);
        expect(response.amount).toBeGreaterThan(0);
        expect(response.distance).toBe(discoverData.distance);
        done();
      });

      client.emit('reward:discover', discoverData);
    });

    it('应该根据距离计算奖励金额', (done) => {
      const testCases = [
        { distance: 10, expectedMinAmount: 9 },
        { distance: 100, expectedMinAmount: 8 },
        { distance: 500, expectedMinAmount: 5 }
      ];

      let completedTests = 0;

      testCases.forEach((testCase, index) => {
        client.emit('reward:discover', {
          annotationId: `test-${index}`,
          distance: testCase.distance
        });
      });

      client.on('reward:earned', (response) => {
        const testCase = testCases.find(tc => 
          response.annotationId.includes(testCases.indexOf(tc).toString())
        );
        
        if (testCase) {
          expect(response.amount).toBeGreaterThanOrEqual(testCase.expectedMinAmount);
          completedTests++;
          
          if (completedTests === testCases.length) {
            done();
          }
        }
      });
    });

    it('应该通知标注作者有人发现了标注', (done) => {
      const annotationId = faker.string.uuid();
      const authorId = faker.string.uuid();

      // 创建标注作者客户端
      const authorToken = jwt.sign(
        { userId: authorId, email: 'author@example.com' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      const authorClient = Client(`http://localhost:${serverPort}`, {
        auth: { token: authorToken },
        transports: ['websocket']
      });

      authorClient.on('connect', () => {
        authorClient.on('notification:annotation_discovered', (notification) => {
          expect(notification.type).toBe('discovery');
          expect(notification.annotationId).toBe(annotationId);
          expect(notification.discoverId).toBe(testUser.id);
          expect(notification.rewardAmount).toBeGreaterThan(0);
          expect(notification.message).toContain('发现');
          
          authorClient.disconnect();
          done();
        });

        // 发现者发送发现事件
        client.emit('reward:discover', {
          annotationId,
          authorId,
          distance: 25
        });
      });
    });
  });

  describe('实时聊天功能', () => {
    let client: ClientSocket;
    const roomId = 'test-room-' + Date.now();

    beforeEach((done) => {
      client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      client.on('connect', () => {
        // 加入测试房间
        client.emit('room:join', { roomId });
        client.on('room:joined', () => done());
      });
      client.on('connect_error', done);
    });

    afterEach(() => {
      if (client) {
        client.disconnect();
      }
    });

    it('应该成功发送聊天消息', (done) => {
      const message = 'Hello, World!';

      client.on('chat:message', (messageData) => {
        expect(messageData.userId).toBe(testUser.id);
        expect(messageData.message).toBe(message);
        expect(messageData.roomId).toBe(roomId);
        expect(messageData.timestamp).toBeTruthy();
        expect(messageData.id).toBeTruthy();
        done();
      });

      client.emit('chat:send', { message, roomId });
    });

    it('应该拒绝空消息', (done) => {
      client.on('error', (error) => {
        expect(error.message).toContain('Message cannot be empty');
        done();
      });

      client.emit('chat:send', { message: '', roomId });
    });

    it('应该拒绝过长消息', (done) => {
      const longMessage = 'a'.repeat(501); // 超过500字符限制

      client.on('error', (error) => {
        expect(error.message).toContain('Message too long');
        done();
      });

      client.emit('chat:send', { message: longMessage, roomId });
    });

    it('应该向房间内所有用户广播消息', (done) => {
      // 创建第二个客户端
      const receiver = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      receiver.on('connect', () => {
        // 加入同一个房间
        receiver.emit('room:join', { roomId });
        
        receiver.on('room:joined', () => {
          receiver.on('chat:message', (messageData) => {
            expect(messageData.userId).toBe(testUser.id);
            expect(messageData.message).toBe('Room broadcast test');
            expect(messageData.roomId).toBe(roomId);
            
            receiver.disconnect();
            done();
          });

          // 发送者发送消息
          client.emit('chat:send', { 
            message: 'Room broadcast test', 
            roomId 
          });
        });
      });
    });

    it('应该处理房间加入和离开', (done) => {
      const newRoomId = 'new-room-' + Date.now();
      
      // 创建观察者客户端
      const observer = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      observer.on('connect', () => {
        // 观察者加入房间
        observer.emit('room:join', { roomId: newRoomId });
        
        observer.on('room:joined', () => {
          let joinEventReceived = false;
          let leaveEventReceived = false;

          observer.on('room:user_joined', (data) => {
            expect(data.userId).toBe(testUser.id);
            joinEventReceived = true;
            
            // 用户离开房间
            client.emit('room:leave', { roomId: newRoomId });
          });

          observer.on('room:user_left', (data) => {
            expect(data.userId).toBe(testUser.id);
            leaveEventReceived = true;
            
            if (joinEventReceived && leaveEventReceived) {
              observer.disconnect();
              done();
            }
          });

          // 用户加入房间
          client.emit('room:join', { roomId: newRoomId });
        });
      });
    });
  });

  describe('系统状态和监控', () => {
    let client: ClientSocket;

    beforeEach((done) => {
      client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      client.on('connect', () => done());
      client.on('connect_error', done);
    });

    afterEach(() => {
      if (client) {
        client.disconnect();
      }
    });

    it('应该返回系统状态信息', (done) => {
      client.on('system:info', (info) => {
        expect(info.connectedUsers).toBeGreaterThan(0);
        expect(info.serverTime).toBeTruthy();
        expect(info.uptime).toBeGreaterThan(0);
        done();
      });

      client.emit('system:status');
    });

    it('应该正确计算连接用户数', (done) => {
      // 创建多个客户端连接
      const additionalClients: ClientSocket[] = [];
      const clientCount = 3;

      Promise.all(
        Array.from({ length: clientCount }, () => {
          return new Promise<ClientSocket>((resolve, reject) => {
            const newClient = Client(`http://localhost:${serverPort}`, {
              auth: { token: authToken },
              transports: ['websocket']
            });

            newClient.on('connect', () => resolve(newClient));
            newClient.on('connect_error', reject);
          });
        })
      ).then((clients) => {
        additionalClients.push(...clients);

        // 查询系统状态
        client.on('system:info', (info) => {
          // 应该包含原始客户端 + 新增客户端
          expect(info.connectedUsers).toBeGreaterThanOrEqual(clientCount + 1);
          
          // 断开额外的客户端
          additionalClients.forEach(c => c.disconnect());
          done();
        });

        client.emit('system:status');
      }).catch(done);
    });

    it('应该处理WebSocket错误', (done) => {
      client.on('error', (error) => {
        expect(error.message).toBeTruthy();
        done();
      });

      // 触发一个错误事件
      client.emit('error', new Error('Test error'));
    });

    it('应该记录用户离线状态', (done) => {
      // 创建观察者客户端
      const observer = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      observer.on('connect', () => {
        observer.on('user:offline', (data) => {
          expect(data.userId).toBe(testUser.id);
          expect(data.timestamp).toBeTruthy();
          
          observer.disconnect();
          done();
        });

        // 断开主客户端
        client.disconnect();
      });
    });
  });

  describe('WebSocket性能测试', () => {
    it('应该处理大量并发消息', async () => {
      const messageCount = 100;
      const clients: ClientSocket[] = [];

      try {
        // 创建多个客户端
        const clientPromises = Array.from({ length: 5 }, () => {
          return new Promise<ClientSocket>((resolve, reject) => {
            const client = Client(`http://localhost:${serverPort}`, {
              auth: { token: authToken },
              transports: ['websocket']
            });

            client.on('connect', () => resolve(client));
            client.on('connect_error', reject);
          });
        });

        const connectedClients = await Promise.all(clientPromises);
        clients.push(...connectedClients);

        const startTime = Date.now();
        let receivedMessages = 0;
        const totalExpectedMessages = messageCount * clients.length;

        // 设置消息接收监听
        clients.forEach(client => {
          client.on('location:update_confirmed', () => {
            receivedMessages++;
          });
        });

        // 同时发送大量位置更新消息
        clients.forEach(client => {
          for (let i = 0; i < messageCount; i++) {
            client.emit('location:update', {
              latitude: 31.2304 + Math.random() * 0.01,
              longitude: 121.4737 + Math.random() * 0.01,
              accuracy: 10
            });
          }
        });

        // 等待所有消息处理完成
        await new Promise<void>((resolve) => {
          const checkInterval = setInterval(() => {
            if (receivedMessages >= totalExpectedMessages) {
              clearInterval(checkInterval);
              resolve();
            }
          }, 100);
          
          // 超时保护
          setTimeout(() => {
            clearInterval(checkInterval);
            resolve();
          }, 10000);
        });

        const endTime = Date.now();
        const duration = endTime - startTime;

        expect(receivedMessages).toBeGreaterThan(totalExpectedMessages * 0.9); // 允许少量丢失
        expect(duration).toBeLessThan(10000); // 应在10秒内完成

      } finally {
        // 清理所有客户端连接
        clients.forEach(client => client.disconnect());
      }
    }, 15000);

    it('应该维持连接稳定性', (done) => {
      const client = Client(`http://localhost:${serverPort}`, {
        auth: { token: authToken },
        transports: ['websocket']
      });

      let messageCount = 0;
      const targetMessages = 50;
      let disconnected = false;

      client.on('connect', () => {
        // 定期发送心跳消息
        const heartbeatInterval = setInterval(() => {
          if (!disconnected) {
            client.emit('system:status');
          } else {
            clearInterval(heartbeatInterval);
          }
        }, 100);
      });

      client.on('system:info', () => {
        messageCount++;
        if (messageCount >= targetMessages) {
          disconnected = true;
          client.disconnect();
          
          // 验证连接保持稳定
          expect(messageCount).toBe(targetMessages);
          done();
        }
      });

      client.on('connect_error', done);
      client.on('disconnect', () => {
        if (messageCount < targetMessages) {
          done(new Error(`连接过早断开，只收到 ${messageCount}/${targetMessages} 条消息`));
        }
      });
    }, 10000);

    it('应该处理内存使用效率', async () => {
      const initialMemory = process.memoryUsage();
      const clients: ClientSocket[] = [];
      const messageCount = 1000;

      try {
        // 创建多个客户端并发送大量消息
        for (let i = 0; i < 10; i++) {
          const client = await new Promise<ClientSocket>((resolve, reject) => {
            const c = Client(`http://localhost:${serverPort}`, {
              auth: { token: authToken },
              transports: ['websocket']
            });

            c.on('connect', () => resolve(c));
            c.on('connect_error', reject);
          });

          clients.push(client);

          // 每个客户端发送消息
          for (let j = 0; j < messageCount; j++) {
            client.emit('location:update', {
              latitude: 31.2304 + Math.random(),
              longitude: 121.4737 + Math.random(),
              accuracy: 10
            });
          }
        }

        // 等待消息处理
        await new Promise(resolve => setTimeout(resolve, 2000));

        const finalMemory = process.memoryUsage();
        const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

        // 内存增长应该在合理范围内（例如少于100MB）
        expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);

      } finally {
        // 清理所有连接
        clients.forEach(client => client.disconnect());
        
        // 强制垃圾回收（如果可用）
        if (global.gc) {
          global.gc();
        }
      }
    }, 15000);
  });
});