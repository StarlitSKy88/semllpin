"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const socket_io_1 = require("socket.io");
const http_1 = require("http");
const socket_io_client_1 = require("socket.io-client");
const zh_CN_1 = require("@faker-js/faker/locale/zh_CN");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
class TestWebSocketServer {
    constructor() {
        this.httpServer = (0, http_1.createServer)();
        this.io = new socket_io_1.Server(this.httpServer, {
            cors: {
                origin: "*",
                methods: ["GET", "POST"]
            },
            transports: ['websocket', 'polling']
        });
        this.port = 0;
        this.setupSocketHandlers();
    }
    setupSocketHandlers() {
        this.io.use((socket, next) => {
            const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
            if (!token) {
                return next(new Error('Authentication token required'));
            }
            try {
                const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET || 'test-secret');
                socket.userId = decoded.userId;
                socket.userEmail = decoded.email;
                next();
            }
            catch (err) {
                next(new Error('Invalid authentication token'));
            }
        });
        this.io.on('connection', (socket) => {
            console.log(`用户 ${socket.userId} 已连接WebSocket`);
            socket.join(`user:${socket.userId}`);
            socket.on('location:update', (data) => {
                if (!data.latitude || !data.longitude) {
                    socket.emit('error', { message: 'Invalid location data' });
                    return;
                }
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
            socket.on('annotation:create', (data) => {
                const annotationId = zh_CN_1.faker.string.uuid();
                socket.emit('annotation:created', {
                    success: true,
                    annotationId,
                    data
                });
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
                socket.emit('annotation:liked', {
                    success: true,
                    annotationId
                });
                if (data.authorId && data.authorId !== socket.userId) {
                    this.io.to(`user:${data.authorId}`).emit('notification:like_received', {
                        type: 'like',
                        annotationId,
                        likerId: socket.userId,
                        message: '有人点赞了你的标注'
                    });
                }
            });
            socket.on('reward:discover', (data) => {
                const { annotationId, distance } = data;
                const rewardAmount = Math.max(1, 10 - distance / 100);
                socket.emit('reward:earned', {
                    success: true,
                    annotationId,
                    amount: rewardAmount,
                    distance
                });
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
            socket.on('chat:send', (data) => {
                const { message, roomId } = data;
                if (!message || message.trim().length === 0) {
                    socket.emit('error', { message: 'Message cannot be empty' });
                    return;
                }
                if (message.length > 500) {
                    socket.emit('error', { message: 'Message too long' });
                    return;
                }
                const messageData = {
                    id: zh_CN_1.faker.string.uuid(),
                    userId: socket.userId,
                    userEmail: socket.userEmail,
                    message: message.trim(),
                    timestamp: new Date(),
                    roomId
                };
                this.io.to(roomId).emit('chat:message', messageData);
            });
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
            socket.on('system:status', () => {
                socket.emit('system:info', {
                    connectedUsers: this.io.engine.clientsCount,
                    serverTime: new Date(),
                    uptime: process.uptime()
                });
            });
            socket.on('disconnect', (reason) => {
                console.log(`用户 ${socket.userId} 断开连接: ${reason}`);
                socket.broadcast.emit('user:offline', {
                    userId: socket.userId,
                    timestamp: new Date()
                });
            });
            socket.on('error', (error) => {
                console.error(`WebSocket错误 (用户 ${socket.userId}):`, error);
                socket.emit('error', { message: 'An error occurred' });
            });
        });
    }
    async start() {
        return new Promise((resolve) => {
            this.httpServer.listen(0, () => {
                this.port = this.httpServer.address().port;
                resolve(this.port);
            });
        });
    }
    async stop() {
        return new Promise((resolve) => {
            this.io.close(() => {
                this.httpServer.close(() => {
                    resolve();
                });
            });
        });
    }
    getIO() {
        return this.io;
    }
}
describe('6. WebSocket连接测试', () => {
    let testServer;
    let serverPort;
    let testUser;
    let authToken;
    beforeAll(async () => {
        testServer = new TestWebSocketServer();
        serverPort = await testServer.start();
        testUser = {
            id: zh_CN_1.faker.string.uuid(),
            email: zh_CN_1.faker.internet.email(),
            username: zh_CN_1.faker.internet.username()
        };
        authToken = jsonwebtoken_1.default.sign({ userId: testUser.id, email: testUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
    });
    afterAll(async () => {
        if (testServer) {
            await testServer.stop();
        }
    });
    describe('WebSocket连接管理', () => {
        it('应该成功建立WebSocket连接', (done) => {
            const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                transports: ['websocket']
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
            const clients = [];
            try {
                const connectionPromises = Array.from({ length: connectionCount }, () => {
                    return new Promise((resolve, reject) => {
                        const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                            auth: { token: authToken },
                            transports: ['websocket']
                        });
                        client.on('connect', () => resolve(client));
                        client.on('connect_error', reject);
                    });
                });
                const connectedClients = await Promise.all(connectionPromises);
                clients.push(...connectedClients);
                expect(connectedClients).toHaveLength(connectionCount);
                connectedClients.forEach(client => {
                    expect(client.connected).toBe(true);
                });
            }
            finally {
                clients.forEach(client => client.disconnect());
            }
        });
        it('应该正确处理连接断开', (done) => {
            const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                auth: { token: authToken },
                transports: ['websocket'],
                autoConnect: false
            });
            let connectCount = 0;
            client.on('connect', () => {
                connectCount++;
                if (connectCount === 1) {
                    client.disconnect();
                    setTimeout(() => {
                        client.connect();
                    }, 100);
                }
                else if (connectCount === 2) {
                    expect(connectCount).toBe(2);
                    client.disconnect();
                    done();
                }
            });
            client.connect();
        }, 10000);
    });
    describe('实时位置更新', () => {
        let client;
        beforeEach((done) => {
            client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const receiver = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
        let client;
        beforeEach((done) => {
            client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const receiver = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const annotationId = zh_CN_1.faker.string.uuid();
            const authorId = zh_CN_1.faker.string.uuid();
            const authorToken = jsonwebtoken_1.default.sign({ userId: authorId, email: 'author@example.com' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
            const authorClient = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
                client.emit('annotation:like', {
                    annotationId,
                    authorId
                });
            });
        });
        it('应该确认点赞操作', (done) => {
            const annotationId = zh_CN_1.faker.string.uuid();
            client.on('annotation:liked', (response) => {
                expect(response.success).toBe(true);
                expect(response.annotationId).toBe(annotationId);
                done();
            });
            client.emit('annotation:like', { annotationId });
        });
    });
    describe('奖励系统实时通知', () => {
        let client;
        beforeEach((done) => {
            client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
                annotationId: zh_CN_1.faker.string.uuid(),
                distance: 50
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
                const testCase = testCases.find(tc => response.annotationId.includes(testCases.indexOf(tc).toString()));
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
            const annotationId = zh_CN_1.faker.string.uuid();
            const authorId = zh_CN_1.faker.string.uuid();
            const authorToken = jsonwebtoken_1.default.sign({ userId: authorId, email: 'author@example.com' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
            const authorClient = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
                client.emit('reward:discover', {
                    annotationId,
                    authorId,
                    distance: 25
                });
            });
        });
    });
    describe('实时聊天功能', () => {
        let client;
        const roomId = 'test-room-' + Date.now();
        beforeEach((done) => {
            client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                auth: { token: authToken },
                transports: ['websocket']
            });
            client.on('connect', () => {
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
            const longMessage = 'a'.repeat(501);
            client.on('error', (error) => {
                expect(error.message).toContain('Message too long');
                done();
            });
            client.emit('chat:send', { message: longMessage, roomId });
        });
        it('应该向房间内所有用户广播消息', (done) => {
            const receiver = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                auth: { token: authToken },
                transports: ['websocket']
            });
            receiver.on('connect', () => {
                receiver.emit('room:join', { roomId });
                receiver.on('room:joined', () => {
                    receiver.on('chat:message', (messageData) => {
                        expect(messageData.userId).toBe(testUser.id);
                        expect(messageData.message).toBe('Room broadcast test');
                        expect(messageData.roomId).toBe(roomId);
                        receiver.disconnect();
                        done();
                    });
                    client.emit('chat:send', {
                        message: 'Room broadcast test',
                        roomId
                    });
                });
            });
        });
        it('应该处理房间加入和离开', (done) => {
            const newRoomId = 'new-room-' + Date.now();
            const observer = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                auth: { token: authToken },
                transports: ['websocket']
            });
            observer.on('connect', () => {
                observer.emit('room:join', { roomId: newRoomId });
                observer.on('room:joined', () => {
                    let joinEventReceived = false;
                    let leaveEventReceived = false;
                    observer.on('room:user_joined', (data) => {
                        expect(data.userId).toBe(testUser.id);
                        joinEventReceived = true;
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
                    client.emit('room:join', { roomId: newRoomId });
                });
            });
        });
    });
    describe('系统状态和监控', () => {
        let client;
        beforeEach((done) => {
            client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
            const additionalClients = [];
            const clientCount = 3;
            Promise.all(Array.from({ length: clientCount }, () => {
                return new Promise((resolve, reject) => {
                    const newClient = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                        auth: { token: authToken },
                        transports: ['websocket']
                    });
                    newClient.on('connect', () => resolve(newClient));
                    newClient.on('connect_error', reject);
                });
            })).then((clients) => {
                additionalClients.push(...clients);
                client.on('system:info', (info) => {
                    expect(info.connectedUsers).toBeGreaterThanOrEqual(clientCount + 1);
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
            client.emit('error', new Error('Test error'));
        });
        it('应该记录用户离线状态', (done) => {
            const observer = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
                client.disconnect();
            });
        });
    });
    describe('WebSocket性能测试', () => {
        it('应该处理大量并发消息', async () => {
            const messageCount = 100;
            const clients = [];
            try {
                const clientPromises = Array.from({ length: 5 }, () => {
                    return new Promise((resolve, reject) => {
                        const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
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
                clients.forEach(client => {
                    client.on('location:update_confirmed', () => {
                        receivedMessages++;
                    });
                });
                clients.forEach(client => {
                    for (let i = 0; i < messageCount; i++) {
                        client.emit('location:update', {
                            latitude: 31.2304 + Math.random() * 0.01,
                            longitude: 121.4737 + Math.random() * 0.01,
                            accuracy: 10
                        });
                    }
                });
                await new Promise((resolve) => {
                    const checkInterval = setInterval(() => {
                        if (receivedMessages >= totalExpectedMessages) {
                            clearInterval(checkInterval);
                            resolve();
                        }
                    }, 100);
                    setTimeout(() => {
                        clearInterval(checkInterval);
                        resolve();
                    }, 10000);
                });
                const endTime = Date.now();
                const duration = endTime - startTime;
                expect(receivedMessages).toBeGreaterThan(totalExpectedMessages * 0.9);
                expect(duration).toBeLessThan(10000);
            }
            finally {
                clients.forEach(client => client.disconnect());
            }
        }, 15000);
        it('应该维持连接稳定性', (done) => {
            const client = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                auth: { token: authToken },
                transports: ['websocket']
            });
            let messageCount = 0;
            const targetMessages = 50;
            let disconnected = false;
            client.on('connect', () => {
                const heartbeatInterval = setInterval(() => {
                    if (!disconnected) {
                        client.emit('system:status');
                    }
                    else {
                        clearInterval(heartbeatInterval);
                    }
                }, 100);
            });
            client.on('system:info', () => {
                messageCount++;
                if (messageCount >= targetMessages) {
                    disconnected = true;
                    client.disconnect();
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
            const clients = [];
            const messageCount = 1000;
            try {
                for (let i = 0; i < 10; i++) {
                    const client = await new Promise((resolve, reject) => {
                        const c = (0, socket_io_client_1.io)(`http://localhost:${serverPort}`, {
                            auth: { token: authToken },
                            transports: ['websocket']
                        });
                        c.on('connect', () => resolve(c));
                        c.on('connect_error', reject);
                    });
                    clients.push(client);
                    for (let j = 0; j < messageCount; j++) {
                        client.emit('location:update', {
                            latitude: 31.2304 + Math.random(),
                            longitude: 121.4737 + Math.random(),
                            accuracy: 10
                        });
                    }
                }
                await new Promise(resolve => setTimeout(resolve, 2000));
                const finalMemory = process.memoryUsage();
                const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
                expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
            }
            finally {
                clients.forEach(client => client.disconnect());
                if (global.gc) {
                    global.gc();
                }
            }
        }, 15000);
    });
});
//# sourceMappingURL=websocket-tests.js.map