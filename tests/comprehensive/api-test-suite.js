"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const ioredis_1 = __importDefault(require("ioredis"));
const testServer_1 = require("../setup/testServer");
const testDatabase_1 = require("../setup/testDatabase");
const test_metrics_1 = require("../utils/test-metrics");
const test_data_factory_1 = require("../factories/test-data-factory");
describe('SmellPin API 综合测试套件', () => {
    let server;
    let app;
    let testDb;
    let testRedis;
    let testMetrics;
    let testDataFactory;
    let testUser;
    let adminUser;
    let authToken;
    let adminToken;
    beforeAll(async () => {
        const testServer = await (0, testServer_1.createTestServer)();
        server = testServer.server;
        app = testServer.app;
        testDb = await (0, testDatabase_1.setupTestDatabase)();
        testRedis = new ioredis_1.default({
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379'),
            db: 15,
        });
        testMetrics = new test_metrics_1.TestMetrics();
        testDataFactory = new test_data_factory_1.TestDataFactory();
        testUser = testDataFactory.createUser();
        adminUser = testDataFactory.createUser({ role: 'admin' });
        authToken = jsonwebtoken_1.default.sign({ userId: testUser.id, email: testUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
        adminToken = jsonwebtoken_1.default.sign({ userId: adminUser.id, email: adminUser.email, role: 'admin' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
    });
    afterAll(async () => {
        await testRedis.flushdb();
        await testRedis.quit();
        await (0, testDatabase_1.cleanupTestDatabase)(testDb);
        await (0, testServer_1.closeTestServer)(server);
        await testMetrics.generateReport();
    });
    describe('1. 用户认证API测试', () => {
        const authEndpoint = '/api/v1/users';
        describe('用户注册', () => {
            it('应该成功注册新用户', async () => {
                const startTime = Date.now();
                const userData = testDataFactory.createUserRegistrationData();
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(userData)
                    .expect(201);
                const responseTime = Date.now() - startTime;
                testMetrics.recordApiCall('POST /register', responseTime, response.status);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('token');
                expect(response.body.data.user).toHaveProperty('id');
                expect(response.body.data.user).not.toHaveProperty('password');
                expect(response.body.data.user.email).toBe(userData.email);
                const user = await testDb.query('SELECT * FROM users WHERE email = $1', [userData.email]);
                expect(user.rows).toHaveLength(1);
                expect(user.rows[0].email).toBe(userData.email);
            });
            it('应该拒绝重复的邮箱注册', async () => {
                const userData = testDataFactory.createUserRegistrationData();
                await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(userData);
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(userData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('EMAIL_ALREADY_EXISTS');
            });
            it('应该验证邮箱格式', async () => {
                const userData = testDataFactory.createUserRegistrationData({
                    email: 'invalid-email'
                });
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(userData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('VALIDATION_ERROR');
            });
            it('应该验证密码强度', async () => {
                const userData = testDataFactory.createUserRegistrationData({
                    password: '123'
                });
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(userData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('VALIDATION_ERROR');
            });
            it('应该触发速率限制', async () => {
                const ip = '192.168.1.100';
                const promises = Array.from({ length: 6 }, () => (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .set('X-Forwarded-For', ip)
                    .send(testDataFactory.createUserRegistrationData()));
                const responses = await Promise.all(promises);
                const lastResponse = responses[responses.length - 1];
                expect(lastResponse.status).toBe(429);
                expect(lastResponse.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
            });
        });
        describe('用户登录', () => {
            let registeredUser;
            beforeEach(async () => {
                registeredUser = testDataFactory.createUserRegistrationData();
                await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(registeredUser);
            });
            it('应该成功登录有效用户', async () => {
                const startTime = Date.now();
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/login`)
                    .send({
                    email: registeredUser.email,
                    password: registeredUser.password
                })
                    .expect(200);
                const responseTime = Date.now() - startTime;
                testMetrics.recordApiCall('POST /login', responseTime, response.status);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('token');
                expect(response.body.data).toHaveProperty('refreshToken');
                expect(response.body.data.user).toHaveProperty('id');
                expect(response.body.data.user).not.toHaveProperty('password');
                const decoded = jsonwebtoken_1.default.verify(response.body.data.token, process.env.JWT_SECRET || 'test-secret');
                expect(decoded).toHaveProperty('userId');
                expect(decoded.email).toBe(registeredUser.email);
            });
            it('应该拒绝错误的密码', async () => {
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/login`)
                    .send({
                    email: registeredUser.email,
                    password: 'wrong-password'
                })
                    .expect(401);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
            });
            it('应该拒绝不存在的用户', async () => {
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/login`)
                    .send({
                    email: 'nonexistent@example.com',
                    password: 'password123'
                })
                    .expect(401);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
            });
            it('应该记录登录尝试', async () => {
                await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/login`)
                    .send({
                    email: registeredUser.email,
                    password: 'wrong-password'
                });
                const attempts = await testDb.query('SELECT * FROM login_attempts WHERE email = $1', [registeredUser.email]);
                expect(attempts.rows.length).toBeGreaterThan(0);
            });
        });
        describe('JWT令牌验证', () => {
            it('应该验证有效的JWT令牌', async () => {
                const response = await (0, supertest_1.default)(app)
                    .get(`${authEndpoint}/profile/me`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('id');
            });
            it('应该拒绝无效的JWT令牌', async () => {
                const response = await (0, supertest_1.default)(app)
                    .get(`${authEndpoint}/profile/me`)
                    .set('Authorization', 'Bearer invalid-token')
                    .expect(401);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('INVALID_TOKEN');
            });
            it('应该拒绝过期的JWT令牌', async () => {
                const expiredToken = jsonwebtoken_1.default.sign({ userId: testUser.id, email: testUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '-1h' });
                const response = await (0, supertest_1.default)(app)
                    .get(`${authEndpoint}/profile/me`)
                    .set('Authorization', `Bearer ${expiredToken}`)
                    .expect(401);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('TOKEN_EXPIRED');
            });
            it('应该支持令牌刷新', async () => {
                const refreshToken = jsonwebtoken_1.default.sign({ userId: testUser.id, type: 'refresh' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '7d' });
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/refresh-token`)
                    .send({ refreshToken })
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('token');
                expect(response.body.data).toHaveProperty('refreshToken');
            });
        });
        describe('密码重置', () => {
            let registeredUser;
            beforeEach(async () => {
                registeredUser = testDataFactory.createUserRegistrationData();
                await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/register`)
                    .send(registeredUser);
            });
            it('应该发送密码重置邮件', async () => {
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/forgot-password`)
                    .send({ email: registeredUser.email })
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.message).toContain('重置链接已发送');
                const resetToken = await testRedis.get(`password_reset:${registeredUser.email}`);
                expect(resetToken).toBeTruthy();
            });
            it('应该成功重置密码', async () => {
                await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/forgot-password`)
                    .send({ email: registeredUser.email });
                const resetToken = await testRedis.get(`password_reset:${registeredUser.email}`);
                const newPassword = 'NewPassword123!';
                const response = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/reset-password`)
                    .send({
                    token: resetToken,
                    password: newPassword
                })
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                const loginResponse = await (0, supertest_1.default)(app)
                    .post(`${authEndpoint}/login`)
                    .send({
                    email: registeredUser.email,
                    password: newPassword
                })
                    .expect(200);
                expect(loginResponse.body).toHaveProperty('success', true);
            });
        });
    });
    describe('2. LBS相关API测试', () => {
        const lbsEndpoint = '/api/v1/lbs';
        describe('位置上报', () => {
            it('应该成功上报位置', async () => {
                const locationData = testDataFactory.createLocationData();
                const startTime = Date.now();
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/location`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(locationData)
                    .expect(200);
                const responseTime = Date.now() - startTime;
                testMetrics.recordApiCall('POST /lbs/location', responseTime, response.status);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('locationId');
                const storedLocation = await testDb.query('SELECT * FROM user_locations WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1', [testUser.id]);
                expect(storedLocation.rows).toHaveLength(1);
                expect(parseFloat(storedLocation.rows[0].latitude)).toBeCloseTo(locationData.latitude, 6);
                expect(parseFloat(storedLocation.rows[0].longitude)).toBeCloseTo(locationData.longitude, 6);
            });
            it('应该验证GPS坐标有效性', async () => {
                const invalidLocationData = {
                    latitude: 200,
                    longitude: -200,
                    accuracy: 10,
                    timestamp: Date.now()
                };
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/location`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(invalidLocationData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('INVALID_COORDINATES');
            });
            it('应该检测GPS欺骗', async () => {
                const suspiciousData = testDataFactory.createSuspiciousLocationData();
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/location`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(suspiciousData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('SUSPICIOUS_LOCATION_DATA');
            });
            it('应该处理高频位置更新', async () => {
                const locations = Array.from({ length: 10 }, () => testDataFactory.createLocationData());
                const promises = locations.map(location => (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/location`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(location));
                const responses = await Promise.all(promises);
                responses.forEach(response => {
                    expect(response.status).toBe(200);
                    expect(response.body).toHaveProperty('success', true);
                });
            });
        });
        describe('地理围栏检测', () => {
            let testAnnotation;
            beforeEach(async () => {
                testAnnotation = testDataFactory.createAnnotationData();
                const annotation = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, testAnnotation.latitude, testAnnotation.longitude, testAnnotation.smellType, testAnnotation.intensity, testAnnotation.description]);
                testAnnotation.id = annotation.rows[0].id;
            });
            it('应该检测用户进入地理围栏', async () => {
                const nearbyLocation = {
                    latitude: testAnnotation.latitude + 0.001,
                    longitude: testAnnotation.longitude + 0.001,
                    accuracy: 10,
                    timestamp: Date.now()
                };
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/geofence/check`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(nearbyLocation)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data.geofences).toHaveLength(1);
                expect(response.body.data.geofences[0]).toHaveProperty('annotationId', testAnnotation.id);
                expect(response.body.data.geofences[0]).toHaveProperty('distance');
                expect(response.body.data.geofences[0].distance).toBeLessThan(200);
            });
            it('应该计算准确的距离', async () => {
                const knownDistance = 500;
                const locationWithKnownDistance = testDataFactory.createLocationAtDistance(testAnnotation.latitude, testAnnotation.longitude, knownDistance);
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/geofence/check`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(locationWithKnownDistance)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                if (response.body.data.geofences.length > 0) {
                    const calculatedDistance = response.body.data.geofences[0].distance;
                    expect(calculatedDistance).toBeCloseTo(knownDistance, 50);
                }
            });
            it('应该支持多个地理围栏检测', async () => {
                const annotations = await Promise.all(Array.from({ length: 3 }, async () => {
                    const data = testDataFactory.createAnnotationData({
                        latitude: testAnnotation.latitude + Math.random() * 0.01,
                        longitude: testAnnotation.longitude + Math.random() * 0.01
                    });
                    const result = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, data.latitude, data.longitude, data.smellType, data.intensity, data.description]);
                    return { ...data, id: result.rows[0].id };
                }));
                const centerLocation = {
                    latitude: testAnnotation.latitude,
                    longitude: testAnnotation.longitude,
                    accuracy: 10,
                    timestamp: Date.now()
                };
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/geofence/check`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(centerLocation)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data.geofences.length).toBeGreaterThan(1);
            });
        });
        describe('奖励计算', () => {
            let testAnnotation;
            beforeEach(async () => {
                testAnnotation = testDataFactory.createAnnotationData();
                const annotation = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description, reward_amount) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id', [testUser.id, testAnnotation.latitude, testAnnotation.longitude, testAnnotation.smellType, testAnnotation.intensity, testAnnotation.description, 10.00]);
                testAnnotation.id = annotation.rows[0].id;
            });
            it('应该成功发现并获得奖励', async () => {
                const discoveryData = {
                    annotationId: testAnnotation.id,
                    location: {
                        latitude: testAnnotation.latitude + 0.0001,
                        longitude: testAnnotation.longitude + 0.0001,
                        accuracy: 5,
                        timestamp: Date.now()
                    }
                };
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/rewards/discover`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(discoveryData)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('rewardAmount');
                expect(response.body.data.rewardAmount).toBeGreaterThan(0);
                const reward = await testDb.query('SELECT * FROM user_rewards WHERE user_id = $1 AND annotation_id = $2', [testUser.id, testAnnotation.id]);
                expect(reward.rows).toHaveLength(1);
                expect(parseFloat(reward.rows[0].amount)).toBeGreaterThan(0);
            });
            it('应该防止重复获得奖励', async () => {
                const discoveryData = {
                    annotationId: testAnnotation.id,
                    location: {
                        latitude: testAnnotation.latitude + 0.0001,
                        longitude: testAnnotation.longitude + 0.0001,
                        accuracy: 5,
                        timestamp: Date.now()
                    }
                };
                await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/rewards/discover`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(discoveryData)
                    .expect(200);
                const response = await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/rewards/discover`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(discoveryData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('ALREADY_DISCOVERED');
            });
            it('应该根据距离调整奖励金额', async () => {
                const distances = [10, 50, 100, 200];
                const rewards = [];
                for (const distance of distances) {
                    const location = testDataFactory.createLocationAtDistance(testAnnotation.latitude, testAnnotation.longitude, distance);
                    const discoveryData = {
                        annotationId: testAnnotation.id,
                        location: { ...location, accuracy: 5, timestamp: Date.now() }
                    };
                    const tempUser = testDataFactory.createUser();
                    const tempToken = jsonwebtoken_1.default.sign({ userId: tempUser.id, email: tempUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
                    const response = await (0, supertest_1.default)(app)
                        .post(`${lbsEndpoint}/rewards/discover`)
                        .set('Authorization', `Bearer ${tempToken}`)
                        .send(discoveryData);
                    if (response.status === 200) {
                        rewards.push({
                            distance,
                            amount: response.body.data.rewardAmount
                        });
                    }
                }
                for (let i = 1; i < rewards.length; i++) {
                    if (rewards[i].distance > rewards[i - 1].distance) {
                        expect(rewards[i].amount).toBeLessThanOrEqual(rewards[i - 1].amount);
                    }
                }
            });
            it('应该记录奖励统计信息', async () => {
                const discoveryData = {
                    annotationId: testAnnotation.id,
                    location: {
                        latitude: testAnnotation.latitude + 0.0001,
                        longitude: testAnnotation.longitude + 0.0001,
                        accuracy: 5,
                        timestamp: Date.now()
                    }
                };
                await (0, supertest_1.default)(app)
                    .post(`${lbsEndpoint}/rewards/discover`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(discoveryData);
                const response = await (0, supertest_1.default)(app)
                    .get(`${lbsEndpoint}/rewards/stats`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('totalRewards');
                expect(response.body.data).toHaveProperty('discoveredCount');
                expect(response.body.data.discoveredCount).toBeGreaterThan(0);
            });
        });
    });
    describe('3. 气味标记API测试', () => {
        const annotationEndpoint = '/api/v1/annotations';
        describe('创建标注', () => {
            it('应该成功创建气味标注', async () => {
                const annotationData = testDataFactory.createAnnotationData();
                const startTime = Date.now();
                const response = await (0, supertest_1.default)(app)
                    .post(annotationEndpoint)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(annotationData)
                    .expect(201);
                const responseTime = Date.now() - startTime;
                testMetrics.recordApiCall('POST /annotations', responseTime, response.status);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('id');
                expect(response.body.data.smellType).toBe(annotationData.smellType);
                expect(response.body.data.intensity).toBe(annotationData.intensity);
                const annotation = await testDb.query('SELECT * FROM annotations WHERE id = $1', [response.body.data.id]);
                expect(annotation.rows).toHaveLength(1);
                expect(annotation.rows[0].smell_type).toBe(annotationData.smellType);
            });
            it('应该验证标注数据完整性', async () => {
                const incompleteData = {
                    latitude: 31.2304,
                    longitude: 121.4737
                };
                const response = await (0, supertest_1.default)(app)
                    .post(annotationEndpoint)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(incompleteData)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('VALIDATION_ERROR');
            });
            it('应该限制用户每小时标注数量', async () => {
                const promises = Array.from({ length: 11 }, () => {
                    const annotationData = testDataFactory.createAnnotationData();
                    return (0, supertest_1.default)(app)
                        .post(annotationEndpoint)
                        .set('Authorization', `Bearer ${authToken}`)
                        .send(annotationData);
                });
                const responses = await Promise.all(promises);
                const lastResponse = responses[responses.length - 1];
                expect(lastResponse.status).toBe(429);
                expect(lastResponse.body.error.code).toBe('ANNOTATION_RATE_LIMIT_EXCEEDED');
            });
            it('应该支持图片上传', async () => {
                const annotationData = testDataFactory.createAnnotationData();
                const response = await (0, supertest_1.default)(app)
                    .post(annotationEndpoint)
                    .set('Authorization', `Bearer ${authToken}`)
                    .field('data', JSON.stringify(annotationData))
                    .attach('images', Buffer.from('fake-image-data'), 'test-image.jpg')
                    .expect(201);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('images');
                expect(response.body.data.images).toHaveLength(1);
            });
            it('应该自动检测垃圾内容', async () => {
                const spamAnnotation = testDataFactory.createAnnotationData({
                    description: '垃圾广告内容 联系QQ123456 免费获得金币'
                });
                const response = await (0, supertest_1.default)(app)
                    .post(annotationEndpoint)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(spamAnnotation)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('CONTENT_FILTERED');
            });
        });
        describe('查询标注', () => {
            let testAnnotations;
            beforeEach(async () => {
                testAnnotations = [];
                for (let i = 0; i < 5; i++) {
                    const data = testDataFactory.createAnnotationData();
                    const result = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, data.latitude, data.longitude, data.smellType, data.intensity, data.description]);
                    testAnnotations.push({ ...data, id: result.rows[0].id });
                }
            });
            it('应该获取标注列表', async () => {
                const response = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/list`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('annotations');
                expect(Array.isArray(response.body.data.annotations)).toBe(true);
                expect(response.body.data.annotations.length).toBeGreaterThan(0);
            });
            it('应该支持分页查询', async () => {
                const page1 = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/list?page=1&limit=3`)
                    .expect(200);
                const page2 = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/list?page=2&limit=3`)
                    .expect(200);
                expect(page1.body.data.annotations).toHaveLength(3);
                expect(page1.body.data.pagination.page).toBe(1);
                expect(page1.body.data.pagination.totalPages).toBeGreaterThanOrEqual(1);
                const page1Ids = page1.body.data.annotations.map((a) => a.id);
                const page2Ids = page2.body.data.annotations.map((a) => a.id);
                expect(page1Ids.some((id) => page2Ids.includes(id))).toBe(false);
            });
            it('应该支持按位置范围查询', async () => {
                const bounds = {
                    northEast: { lat: 31.3, lng: 121.5 },
                    southWest: { lat: 31.2, lng: 121.4 }
                };
                const response = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/map`)
                    .query({
                    neLat: bounds.northEast.lat,
                    neLng: bounds.northEast.lng,
                    swLat: bounds.southWest.lat,
                    swLng: bounds.southWest.lng
                })
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('annotations');
                response.body.data.annotations.forEach((annotation) => {
                    expect(annotation.latitude).toBeLessThanOrEqual(bounds.northEast.lat);
                    expect(annotation.latitude).toBeGreaterThanOrEqual(bounds.southWest.lat);
                    expect(annotation.longitude).toBeLessThanOrEqual(bounds.northEast.lng);
                    expect(annotation.longitude).toBeGreaterThanOrEqual(bounds.southWest.lng);
                });
            });
            it('应该支持按距离查询附近标注', async () => {
                const centerPoint = {
                    latitude: 31.2304,
                    longitude: 121.4737,
                    radius: 1000
                };
                const response = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/nearby`)
                    .query(centerPoint)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('annotations');
                response.body.data.annotations.forEach((annotation) => {
                    expect(annotation).toHaveProperty('distance');
                    expect(annotation.distance).toBeLessThanOrEqual(centerPoint.radius);
                });
            });
            it('应该支持过滤条件', async () => {
                const filters = {
                    smellType: 'industrial',
                    minIntensity: 3,
                    maxIntensity: 5
                };
                const response = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/list`)
                    .query(filters)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                response.body.data.annotations.forEach((annotation) => {
                    if (filters.smellType) {
                        expect(annotation.smellType).toBe(filters.smellType);
                    }
                    if (filters.minIntensity) {
                        expect(annotation.intensity).toBeGreaterThanOrEqual(filters.minIntensity);
                    }
                    if (filters.maxIntensity) {
                        expect(annotation.intensity).toBeLessThanOrEqual(filters.maxIntensity);
                    }
                });
            });
            it('应该返回标注统计信息', async () => {
                const response = await (0, supertest_1.default)(app)
                    .get(`${annotationEndpoint}/stats`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data).toHaveProperty('totalAnnotations');
                expect(response.body.data).toHaveProperty('annotationsByType');
                expect(response.body.data).toHaveProperty('averageIntensity');
                expect(response.body.data.totalAnnotations).toBeGreaterThan(0);
            });
        });
        describe('更新标注', () => {
            let testAnnotation;
            beforeEach(async () => {
                const data = testDataFactory.createAnnotationData();
                const result = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, data.latitude, data.longitude, data.smellType, data.intensity, data.description]);
                testAnnotation = { ...data, id: result.rows[0].id };
            });
            it('应该允许标注作者更新标注', async () => {
                const updateData = {
                    description: '更新后的描述',
                    intensity: 4
                };
                const response = await (0, supertest_1.default)(app)
                    .put(`${annotationEndpoint}/${testAnnotation.id}`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(updateData)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data.description).toBe(updateData.description);
                expect(response.body.data.intensity).toBe(updateData.intensity);
                const updated = await testDb.query('SELECT * FROM annotations WHERE id = $1', [testAnnotation.id]);
                expect(updated.rows[0].description).toBe(updateData.description);
                expect(updated.rows[0].intensity).toBe(updateData.intensity);
            });
            it('应该拒绝非作者的更新请求', async () => {
                const otherUser = testDataFactory.createUser();
                const otherToken = jsonwebtoken_1.default.sign({ userId: otherUser.id, email: otherUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
                const updateData = {
                    description: '恶意更新'
                };
                const response = await (0, supertest_1.default)(app)
                    .put(`${annotationEndpoint}/${testAnnotation.id}`)
                    .set('Authorization', `Bearer ${otherToken}`)
                    .send(updateData)
                    .expect(403);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
            });
            it('应该记录更新历史', async () => {
                const updateData = {
                    description: '更新后的描述'
                };
                await (0, supertest_1.default)(app)
                    .put(`${annotationEndpoint}/${testAnnotation.id}`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(updateData);
                const history = await testDb.query('SELECT * FROM annotation_history WHERE annotation_id = $1', [testAnnotation.id]);
                expect(history.rows.length).toBeGreaterThan(0);
                expect(history.rows[0].action).toBe('update');
            });
        });
        describe('删除标注', () => {
            let testAnnotation;
            beforeEach(async () => {
                const data = testDataFactory.createAnnotationData();
                const result = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, data.latitude, data.longitude, data.smellType, data.intensity, data.description]);
                testAnnotation = { ...data, id: result.rows[0].id };
            });
            it('应该允许标注作者删除标注', async () => {
                const response = await (0, supertest_1.default)(app)
                    .delete(`${annotationEndpoint}/${testAnnotation.id}`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                const deleted = await testDb.query('SELECT * FROM annotations WHERE id = $1', [testAnnotation.id]);
                expect(deleted.rows[0].deleted_at).toBeTruthy();
            });
            it('应该允许管理员删除任何标注', async () => {
                const response = await (0, supertest_1.default)(app)
                    .delete(`${annotationEndpoint}/${testAnnotation.id}`)
                    .set('Authorization', `Bearer ${adminToken}`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
            });
            it('应该拒绝非作者的删除请求', async () => {
                const otherUser = testDataFactory.createUser();
                const otherToken = jsonwebtoken_1.default.sign({ userId: otherUser.id, email: otherUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
                const response = await (0, supertest_1.default)(app)
                    .delete(`${annotationEndpoint}/${testAnnotation.id}`)
                    .set('Authorization', `Bearer ${otherToken}`)
                    .expect(403);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
            });
        });
        describe('标注互动', () => {
            let testAnnotation;
            beforeEach(async () => {
                const data = testDataFactory.createAnnotationData();
                const result = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, data.latitude, data.longitude, data.smellType, data.intensity, data.description]);
                testAnnotation = { ...data, id: result.rows[0].id };
            });
            it('应该支持点赞标注', async () => {
                const response = await (0, supertest_1.default)(app)
                    .post(`${annotationEndpoint}/${testAnnotation.id}/like`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                expect(response.body.data.likeCount).toBeGreaterThan(0);
                const like = await testDb.query('SELECT * FROM annotation_likes WHERE annotation_id = $1 AND user_id = $2', [testAnnotation.id, testUser.id]);
                expect(like.rows).toHaveLength(1);
            });
            it('应该支持取消点赞', async () => {
                await (0, supertest_1.default)(app)
                    .post(`${annotationEndpoint}/${testAnnotation.id}/like`)
                    .set('Authorization', `Bearer ${authToken}`);
                const response = await (0, supertest_1.default)(app)
                    .delete(`${annotationEndpoint}/${testAnnotation.id}/like`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .expect(200);
                expect(response.body).toHaveProperty('success', true);
                const like = await testDb.query('SELECT * FROM annotation_likes WHERE annotation_id = $1 AND user_id = $2', [testAnnotation.id, testUser.id]);
                expect(like.rows).toHaveLength(0);
            });
            it('应该防止重复点赞', async () => {
                await (0, supertest_1.default)(app)
                    .post(`${annotationEndpoint}/${testAnnotation.id}/like`)
                    .set('Authorization', `Bearer ${authToken}`);
                const response = await (0, supertest_1.default)(app)
                    .post(`${annotationEndpoint}/${testAnnotation.id}/like`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .expect(400);
                expect(response.body).toHaveProperty('success', false);
                expect(response.body.error.code).toBe('ALREADY_LIKED');
            });
            it('应该限制点赞频率', async () => {
                const annotations = await Promise.all(Array.from({ length: 101 }, async () => {
                    const data = testDataFactory.createAnnotationData();
                    const result = await testDb.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [testUser.id, data.latitude, data.longitude, data.smellType, data.intensity, data.description]);
                    return result.rows[0].id;
                }));
                const promises = annotations.map(id => (0, supertest_1.default)(app)
                    .post(`${annotationEndpoint}/${id}/like`)
                    .set('Authorization', `Bearer ${authToken}`));
                const responses = await Promise.all(promises);
                const lastResponse = responses[responses.length - 1];
                expect(lastResponse.status).toBe(429);
                expect(lastResponse.body.error.code).toBe('LIKE_RATE_LIMIT_EXCEEDED');
            });
        });
    });
});
//# sourceMappingURL=api-test-suite.js.map