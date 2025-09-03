"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const pg_1 = require("pg");
const zh_CN_1 = require("@faker-js/faker/locale/zh_CN");
describe('5. 数据库操作测试', () => {
    let db;
    beforeAll(async () => {
        db = new pg_1.Client({
            host: process.env.TEST_DB_HOST || 'localhost',
            port: parseInt(process.env.TEST_DB_PORT || '5432'),
            database: process.env.TEST_DB_NAME || 'smellpin_test',
            user: process.env.TEST_DB_USER || 'test_user',
            password: process.env.TEST_DB_PASSWORD || 'test_password'
        });
        await db.connect();
    });
    afterAll(async () => {
        await db.end();
    });
    describe('用户表操作', () => {
        describe('创建用户', () => {
            it('应该成功创建用户', async () => {
                const userData = {
                    email: zh_CN_1.faker.internet.email(),
                    username: zh_CN_1.faker.internet.username(),
                    password_hash: zh_CN_1.faker.internet.password(),
                    role: 'user'
                };
                const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [userData.email, userData.username, userData.password_hash, userData.role]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].email).toBe(userData.email);
                expect(result.rows[0].username).toBe(userData.username);
                expect(result.rows[0].role).toBe(userData.role);
                expect(result.rows[0].id).toBeTruthy();
                expect(result.rows[0].created_at).toBeTruthy();
                expect(result.rows[0].updated_at).toBeTruthy();
            });
            it('应该强制邮箱唯一性约束', async () => {
                const email = zh_CN_1.faker.internet.email();
                await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [email, zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
                await expect(db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [email, zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user'])).rejects.toThrow(/duplicate key value violates unique constraint/);
            });
            it('应该强制用户名唯一性约束', async () => {
                const username = zh_CN_1.faker.internet.username();
                await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [zh_CN_1.faker.internet.email(), username, zh_CN_1.faker.internet.password(), 'user']);
                await expect(db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [zh_CN_1.faker.internet.email(), username, zh_CN_1.faker.internet.password(), 'user'])).rejects.toThrow(/duplicate key value violates unique constraint/);
            });
            it('应该验证邮箱格式', async () => {
                const invalidEmails = ['invalid-email', 'test@', '@domain.com', 'test@domain'];
                for (const email of invalidEmails) {
                    await expect(db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [email, zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user'])).rejects.toThrow();
                }
            });
            it('应该验证角色枚举值', async () => {
                const invalidRole = 'invalid_role';
                await expect(db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), invalidRole])).rejects.toThrow(/invalid input value for enum/);
            });
            it('应该自动设置时间戳', async () => {
                const userData = {
                    email: zh_CN_1.faker.internet.email(),
                    username: zh_CN_1.faker.internet.username(),
                    password_hash: zh_CN_1.faker.internet.password(),
                    role: 'user'
                };
                const beforeInsert = new Date();
                const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [userData.email, userData.username, userData.password_hash, userData.role]);
                const afterInsert = new Date();
                const user = result.rows[0];
                const createdAt = new Date(user.created_at);
                const updatedAt = new Date(user.updated_at);
                expect(createdAt.getTime()).toBeGreaterThanOrEqual(beforeInsert.getTime());
                expect(createdAt.getTime()).toBeLessThanOrEqual(afterInsert.getTime());
                expect(updatedAt.getTime()).toBeGreaterThanOrEqual(beforeInsert.getTime());
                expect(updatedAt.getTime()).toBeLessThanOrEqual(afterInsert.getTime());
                expect(Math.abs(createdAt.getTime() - updatedAt.getTime())).toBeLessThan(1000);
            });
        });
        describe('查询用户', () => {
            let testUsers;
            beforeEach(async () => {
                testUsers = [];
                for (let i = 0; i < 5; i++) {
                    const userData = {
                        email: zh_CN_1.faker.internet.email(),
                        username: zh_CN_1.faker.internet.username(),
                        password_hash: zh_CN_1.faker.internet.password(),
                        role: i === 0 ? 'admin' : 'user'
                    };
                    const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [userData.email, userData.username, userData.password_hash, userData.role]);
                    testUsers.push(result.rows[0]);
                }
            });
            afterEach(async () => {
                if (testUsers.length > 0) {
                    const userIds = testUsers.map(user => user.id);
                    await db.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
                }
            });
            it('应该按ID查询用户', async () => {
                const targetUser = testUsers[0];
                const result = await db.query('SELECT * FROM users WHERE id = $1', [targetUser.id]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].id).toBe(targetUser.id);
                expect(result.rows[0].email).toBe(targetUser.email);
            });
            it('应该按邮箱查询用户', async () => {
                const targetUser = testUsers[1];
                const result = await db.query('SELECT * FROM users WHERE email = $1', [targetUser.email]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].id).toBe(targetUser.id);
                expect(result.rows[0].email).toBe(targetUser.email);
            });
            it('应该按用户名查询用户', async () => {
                const targetUser = testUsers[2];
                const result = await db.query('SELECT * FROM users WHERE username = $1', [targetUser.username]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].id).toBe(targetUser.id);
                expect(result.rows[0].username).toBe(targetUser.username);
            });
            it('应该支持模糊查询用户名', async () => {
                const targetUser = testUsers[0];
                const partialUsername = targetUser.username.substring(0, 3);
                const result = await db.query('SELECT * FROM users WHERE username ILIKE $1', [`%${partialUsername}%`]);
                expect(result.rows.length).toBeGreaterThan(0);
                expect(result.rows.some((user) => user.id === targetUser.id)).toBe(true);
            });
            it('应该按角色过滤用户', async () => {
                const adminUsers = await db.query('SELECT * FROM users WHERE role = $1', ['admin']);
                const regularUsers = await db.query('SELECT * FROM users WHERE role = $1', ['user']);
                expect(adminUsers.rows.length).toBe(1);
                expect(regularUsers.rows.length).toBe(4);
                expect(adminUsers.rows[0].role).toBe('admin');
                regularUsers.rows.forEach((user) => {
                    expect(user.role).toBe('user');
                });
            });
            it('应该支持分页查询', async () => {
                const limit = 2;
                const offset = 1;
                const result = await db.query('SELECT * FROM users ORDER BY created_at LIMIT $1 OFFSET $2', [limit, offset]);
                expect(result.rows).toHaveLength(limit);
                const firstUserId = testUsers[0].id;
                expect(result.rows.some((user) => user.id === firstUserId)).toBe(false);
            });
            it('应该支持按创建时间排序', async () => {
                const ascResult = await db.query('SELECT * FROM users ORDER BY created_at ASC');
                const descResult = await db.query('SELECT * FROM users ORDER BY created_at DESC');
                expect(ascResult.rows).toHaveLength(testUsers.length);
                expect(descResult.rows).toHaveLength(testUsers.length);
                for (let i = 1; i < ascResult.rows.length; i++) {
                    const prev = new Date(ascResult.rows[i - 1].created_at);
                    const curr = new Date(ascResult.rows[i].created_at);
                    expect(curr.getTime()).toBeGreaterThanOrEqual(prev.getTime());
                }
                for (let i = 1; i < descResult.rows.length; i++) {
                    const prev = new Date(descResult.rows[i - 1].created_at);
                    const curr = new Date(descResult.rows[i].created_at);
                    expect(curr.getTime()).toBeLessThanOrEqual(prev.getTime());
                }
            });
        });
        describe('更新用户', () => {
            let testUser;
            beforeEach(async () => {
                const userData = {
                    email: zh_CN_1.faker.internet.email(),
                    username: zh_CN_1.faker.internet.username(),
                    password_hash: zh_CN_1.faker.internet.password(),
                    role: 'user'
                };
                const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [userData.email, userData.username, userData.password_hash, userData.role]);
                testUser = result.rows[0];
            });
            afterEach(async () => {
                if (testUser) {
                    await db.query('DELETE FROM users WHERE id = $1', [testUser.id]);
                }
            });
            it('应该成功更新用户信息', async () => {
                const updateData = {
                    username: zh_CN_1.faker.internet.username(),
                    email: zh_CN_1.faker.internet.email()
                };
                const result = await db.query('UPDATE users SET username = $1, email = $2, updated_at = NOW() WHERE id = $3 RETURNING *', [updateData.username, updateData.email, testUser.id]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].username).toBe(updateData.username);
                expect(result.rows[0].email).toBe(updateData.email);
                expect(result.rows[0].id).toBe(testUser.id);
                const updatedAt = new Date(result.rows[0].updated_at);
                const originalUpdatedAt = new Date(testUser.updated_at);
                expect(updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt.getTime());
            });
            it('应该支持部分更新', async () => {
                const newUsername = zh_CN_1.faker.internet.username();
                const result = await db.query('UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2 RETURNING *', [newUsername, testUser.id]);
                expect(result.rows[0].username).toBe(newUsername);
                expect(result.rows[0].email).toBe(testUser.email);
                expect(result.rows[0].password_hash).toBe(testUser.password_hash);
            });
            it('应该在更新时验证唯一性约束', async () => {
                const otherUser = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
                await expect(db.query('UPDATE users SET email = $1 WHERE id = $2', [otherUser.rows[0].email, testUser.id])).rejects.toThrow(/duplicate key value violates unique constraint/);
                await db.query('DELETE FROM users WHERE id = $1', [otherUser.rows[0].id]);
            });
            it('应该支持条件更新', async () => {
                const newUsername = zh_CN_1.faker.internet.username();
                const originalEmail = testUser.email;
                const result = await db.query('UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2 AND email = $3 RETURNING *', [newUsername, testUser.id, originalEmail]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].username).toBe(newUsername);
                const result2 = await db.query('UPDATE users SET username = $1 WHERE id = $2 AND email = $3 RETURNING *', [zh_CN_1.faker.internet.username(), testUser.id, 'wrong@email.com']);
                expect(result2.rows).toHaveLength(0);
            });
        });
        describe('删除用户', () => {
            let testUser;
            beforeEach(async () => {
                const userData = {
                    email: zh_CN_1.faker.internet.email(),
                    username: zh_CN_1.faker.internet.username(),
                    password_hash: zh_CN_1.faker.internet.password(),
                    role: 'user'
                };
                const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [userData.email, userData.username, userData.password_hash, userData.role]);
                testUser = result.rows[0];
            });
            it('应该成功删除用户', async () => {
                const result = await db.query('DELETE FROM users WHERE id = $1 RETURNING *', [testUser.id]);
                expect(result.rows).toHaveLength(1);
                expect(result.rows[0].id).toBe(testUser.id);
                const checkResult = await db.query('SELECT * FROM users WHERE id = $1', [testUser.id]);
                expect(checkResult.rows).toHaveLength(0);
                testUser = null;
            });
            it('应该支持批量删除', async () => {
                const users = [];
                for (let i = 0; i < 3; i++) {
                    const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
                    users.push(result.rows[0]);
                }
                const userIds = users.map(user => user.id);
                const result = await db.query('DELETE FROM users WHERE id = ANY($1) RETURNING *', [userIds]);
                expect(result.rows).toHaveLength(3);
                const checkResult = await db.query('SELECT * FROM users WHERE id = ANY($1)', [userIds]);
                expect(checkResult.rows).toHaveLength(0);
            });
            it('应该支持条件删除', async () => {
                const email = testUser.email;
                const result = await db.query('DELETE FROM users WHERE id = $1 AND email = $2 RETURNING *', [testUser.id, email]);
                expect(result.rows).toHaveLength(1);
                testUser = null;
            });
            afterEach(async () => {
                if (testUser) {
                    await db.query('DELETE FROM users WHERE id = $1', [testUser.id]);
                }
            });
        });
    });
    describe('标注表操作', () => {
        let testUser;
        beforeAll(async () => {
            const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
            testUser = result.rows[0];
        });
        afterAll(async () => {
            await db.query('DELETE FROM users WHERE id = $1', [testUser.id]);
        });
        describe('创建标注', () => {
            it('应该成功创建标注', async () => {
                const annotationData = {
                    user_id: testUser.id,
                    latitude: 31.2304,
                    longitude: 121.4737,
                    smell_type: 'industrial',
                    intensity: 4,
                    description: zh_CN_1.faker.lorem.sentences(2)
                };
                const result = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [annotationData.user_id, annotationData.latitude, annotationData.longitude, annotationData.smell_type, annotationData.intensity, annotationData.description]);
                expect(result.rows).toHaveLength(1);
                const annotation = result.rows[0];
                expect(annotation.user_id).toBe(annotationData.user_id);
                expect(parseFloat(annotation.latitude)).toBeCloseTo(annotationData.latitude, 6);
                expect(parseFloat(annotation.longitude)).toBeCloseTo(annotationData.longitude, 6);
                expect(annotation.smell_type).toBe(annotationData.smell_type);
                expect(annotation.intensity).toBe(annotationData.intensity);
                expect(annotation.description).toBe(annotationData.description);
                expect(annotation.id).toBeTruthy();
                expect(annotation.created_at).toBeTruthy();
                await db.query('DELETE FROM annotations WHERE id = $1', [annotation.id]);
            });
            it('应该验证GPS坐标范围', async () => {
                const invalidCoordinates = [
                    { latitude: 91, longitude: 121.4737 },
                    { latitude: -91, longitude: 121.4737 },
                    { latitude: 31.2304, longitude: 181 },
                    { latitude: 31.2304, longitude: -181 }
                ];
                for (const coords of invalidCoordinates) {
                    await expect(db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6)', [testUser.id, coords.latitude, coords.longitude, 'industrial', 3, '测试无效坐标'])).rejects.toThrow();
                }
            });
            it('应该验证气味类型枚举值', async () => {
                await expect(db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6)', [testUser.id, 31.2304, 121.4737, 'invalid_smell_type', 3, '测试无效气味类型'])).rejects.toThrow(/invalid input value for enum/);
            });
            it('应该验证强度范围', async () => {
                const invalidIntensities = [0, 6, -1, 10];
                for (const intensity of invalidIntensities) {
                    await expect(db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6)', [testUser.id, 31.2304, 121.4737, 'industrial', intensity, '测试无效强度'])).rejects.toThrow();
                }
            });
            it('应该验证外键约束', async () => {
                const nonExistentUserId = '00000000-0000-0000-0000-000000000000';
                await expect(db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6)', [nonExistentUserId, 31.2304, 121.4737, 'industrial', 3, '测试外键约束'])).rejects.toThrow(/violates foreign key constraint/);
            });
            it('应该支持可选字段', async () => {
                const result = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity) VALUES ($1, $2, $3, $4, $5) RETURNING *', [testUser.id, 31.2304, 121.4737, 'industrial', 3]);
                expect(result.rows).toHaveLength(1);
                const annotation = result.rows[0];
                expect(annotation.description).toBeNull();
                expect(annotation.images).toBeNull();
                expect(annotation.verified).toBe(false);
                expect(annotation.like_count).toBe(0);
                await db.query('DELETE FROM annotations WHERE id = $1', [annotation.id]);
            });
        });
        describe('地理空间查询', () => {
            let testAnnotations;
            beforeEach(async () => {
                const locations = [
                    { lat: 31.2304, lng: 121.4737, description: '上海市中心' },
                    { lat: 31.2400, lng: 121.4800, description: '上海东北1km' },
                    { lat: 31.2200, lng: 121.4600, description: '上海西南1km' },
                    { lat: 39.9042, lng: 116.4074, description: '北京天安门' },
                    { lat: 22.3193, lng: 114.1694, description: '香港中环' }
                ];
                testAnnotations = [];
                for (const location of locations) {
                    const result = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [testUser.id, location.lat, location.lng, 'industrial', 3, location.description]);
                    testAnnotations.push(result.rows[0]);
                }
            });
            afterEach(async () => {
                const annotationIds = testAnnotations.map(a => a.id);
                if (annotationIds.length > 0) {
                    await db.query('DELETE FROM annotations WHERE id = ANY($1)', [annotationIds]);
                }
            });
            it('应该支持距离计算查询', async () => {
                const centerPoint = { lat: 31.2304, lng: 121.4737 };
                const radiusKm = 2;
                const result = await db.query(`
          SELECT *, 
            ST_Distance(
              ST_GeogFromText('POINT(' || longitude || ' ' || latitude || ')'),
              ST_GeogFromText('POINT($2 $1)')
            ) as distance
          FROM annotations 
          WHERE ST_DWithin(
            ST_GeogFromText('POINT(' || longitude || ' ' || latitude || ')'),
            ST_GeogFromText('POINT($2 $1)'),
            $3
          )
          ORDER BY distance
        `, [centerPoint.lat, centerPoint.lng, radiusKm * 1000]);
                expect(result.rows.length).toBeGreaterThan(0);
                expect(result.rows.length).toBeLessThanOrEqual(3);
                result.rows.forEach((annotation) => {
                    expect(parseFloat(annotation.distance)).toBeLessThanOrEqual(radiusKm * 1000);
                });
                for (let i = 1; i < result.rows.length; i++) {
                    const prevDistance = parseFloat(result.rows[i - 1].distance);
                    const currDistance = parseFloat(result.rows[i].distance);
                    expect(currDistance).toBeGreaterThanOrEqual(prevDistance);
                }
            });
            it('应该支持矩形边界查询', async () => {
                const bounds = {
                    north: 31.25,
                    south: 31.22,
                    east: 121.49,
                    west: 121.45
                };
                const result = await db.query(`
          SELECT * FROM annotations 
          WHERE latitude BETWEEN $1 AND $2 
          AND longitude BETWEEN $3 AND $4
        `, [bounds.south, bounds.north, bounds.west, bounds.east]);
                expect(result.rows.length).toBeGreaterThan(0);
                result.rows.forEach((annotation) => {
                    const lat = parseFloat(annotation.latitude);
                    const lng = parseFloat(annotation.longitude);
                    expect(lat).toBeGreaterThanOrEqual(bounds.south);
                    expect(lat).toBeLessThanOrEqual(bounds.north);
                    expect(lng).toBeGreaterThanOrEqual(bounds.west);
                    expect(lng).toBeLessThanOrEqual(bounds.east);
                });
            });
            it('应该支持多边形区域查询', async () => {
                const shanghaiPolygon = 'POLYGON((121.4 31.2, 121.5 31.2, 121.5 31.3, 121.4 31.3, 121.4 31.2))';
                const result = await db.query(`
          SELECT * FROM annotations 
          WHERE ST_Within(
            ST_GeogFromText('POINT(' || longitude || ' ' || latitude || ')'),
            ST_GeogFromText($1)
          )
        `, [shanghaiPolygon]);
                expect(result.rows.length).toBeGreaterThan(0);
                expect(result.rows.length).toBeLessThan(testAnnotations.length);
            });
            it('应该支持最近邻查询', async () => {
                const queryPoint = { lat: 31.2304, lng: 121.4737 };
                const limit = 3;
                const result = await db.query(`
          SELECT *, 
            ST_Distance(
              ST_GeogFromText('POINT(' || longitude || ' ' || latitude || ')'),
              ST_GeogFromText('POINT($2 $1)')
            ) as distance
          FROM annotations 
          ORDER BY distance
          LIMIT $3
        `, [queryPoint.lat, queryPoint.lng, limit]);
                expect(result.rows).toHaveLength(Math.min(limit, testAnnotations.length));
                for (let i = 1; i < result.rows.length; i++) {
                    const prevDistance = parseFloat(result.rows[i - 1].distance);
                    const currDistance = parseFloat(result.rows[i].distance);
                    expect(currDistance).toBeGreaterThanOrEqual(prevDistance);
                }
            });
            it('应该支持地理空间索引性能查询', async () => {
                const startTime = process.hrtime.bigint();
                await db.query(`
          SELECT COUNT(*) FROM annotations 
          WHERE ST_DWithin(
            ST_GeogFromText('POINT(' || longitude || ' ' || latitude || ')'),
            ST_GeogFromText('POINT(121.4737 31.2304)'),
            5000
          )
        `);
                const endTime = process.hrtime.bigint();
                const executionTime = Number(endTime - startTime) / 1000000;
                expect(executionTime).toBeLessThan(100);
            });
        });
    });
    describe('事务处理', () => {
        let testUser;
        beforeAll(async () => {
            const result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
            testUser = result.rows[0];
        });
        afterAll(async () => {
            await db.query('DELETE FROM users WHERE id = $1', [testUser.id]);
        });
        it('应该成功提交事务', async () => {
            await db.query('BEGIN');
            try {
                const annotationResult = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [testUser.id, 31.2304, 121.4737, 'industrial', 3, '事务测试标注']);
                const annotationId = annotationResult.rows[0].id;
                const paymentResult = await db.query('INSERT INTO payments (user_id, annotation_id, amount, status) VALUES ($1, $2, $3, $4) RETURNING *', [testUser.id, annotationId, '10.00', 'pending']);
                await db.query('COMMIT');
                const annotationCheck = await db.query('SELECT * FROM annotations WHERE id = $1', [annotationId]);
                const paymentCheck = await db.query('SELECT * FROM payments WHERE id = $1', [paymentResult.rows[0].id]);
                expect(annotationCheck.rows).toHaveLength(1);
                expect(paymentCheck.rows).toHaveLength(1);
                await db.query('DELETE FROM payments WHERE id = $1', [paymentResult.rows[0].id]);
                await db.query('DELETE FROM annotations WHERE id = $1', [annotationId]);
            }
            catch (error) {
                await db.query('ROLLBACK');
                throw error;
            }
        });
        it('应该正确回滚事务', async () => {
            await db.query('BEGIN');
            let annotationId;
            let paymentId;
            try {
                const annotationResult = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [testUser.id, 31.2304, 121.4737, 'industrial', 3, '回滚测试标注']);
                annotationId = annotationResult.rows[0].id;
                await db.query('INSERT INTO payments (user_id, annotation_id, amount, status) VALUES ($1, $2, $3, $4) RETURNING *', ['invalid-user-id', annotationId, '10.00', 'invalid_status']);
                await db.query('COMMIT');
            }
            catch (error) {
                await db.query('ROLLBACK');
                const annotationCheck = await db.query('SELECT * FROM annotations WHERE id = $1', [annotationId]);
                expect(annotationCheck.rows).toHaveLength(0);
                return;
            }
            throw new Error('事务应该已回滚但没有发生');
        });
        it('应该支持保存点', async () => {
            await db.query('BEGIN');
            try {
                const annotation1Result = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [testUser.id, 31.2304, 121.4737, 'industrial', 3, '保存点测试标注1']);
                const annotation1Id = annotation1Result.rows[0].id;
                await db.query('SAVEPOINT sp1');
                const annotation2Result = await db.query('INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [testUser.id, 31.2400, 121.4800, 'domestic', 2, '保存点测试标注2']);
                const annotation2Id = annotation2Result.rows[0].id;
                await db.query('ROLLBACK TO sp1');
                await db.query('COMMIT');
                const annotation1Check = await db.query('SELECT * FROM annotations WHERE id = $1', [annotation1Id]);
                const annotation2Check = await db.query('SELECT * FROM annotations WHERE id = $1', [annotation2Id]);
                expect(annotation1Check.rows).toHaveLength(1);
                expect(annotation2Check.rows).toHaveLength(0);
                await db.query('DELETE FROM annotations WHERE id = $1', [annotation1Id]);
            }
            catch (error) {
                await db.query('ROLLBACK');
                throw error;
            }
        });
        it('应该处理死锁', async () => {
            const db2 = new pg_1.Client({
                host: process.env.TEST_DB_HOST || 'localhost',
                port: parseInt(process.env.TEST_DB_PORT || '5432'),
                database: process.env.TEST_DB_NAME || 'smellpin_test',
                user: process.env.TEST_DB_USER || 'test_user',
                password: process.env.TEST_DB_PASSWORD || 'test_password'
            });
            await db2.connect();
            try {
                const user1Result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
                const user1Id = user1Result.rows[0].id;
                const user2Result = await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user']);
                const user2Id = user2Result.rows[0].id;
                const transaction1 = async () => {
                    await db.query('BEGIN');
                    await db.query('UPDATE users SET username = $1 WHERE id = $2', ['updated1', user1Id]);
                    await new Promise(resolve => setTimeout(resolve, 100));
                    await db.query('UPDATE users SET username = $1 WHERE id = $2', ['updated1_2', user2Id]);
                    await db.query('COMMIT');
                };
                const transaction2 = async () => {
                    await db2.query('BEGIN');
                    await db2.query('UPDATE users SET username = $1 WHERE id = $2', ['updated2', user2Id]);
                    await new Promise(resolve => setTimeout(resolve, 100));
                    await db2.query('UPDATE users SET username = $1 WHERE id = $2', ['updated2_1', user1Id]);
                    await db2.query('COMMIT');
                };
                const results = await Promise.allSettled([transaction1(), transaction2()]);
                const successful = results.filter(result => result.status === 'fulfilled');
                const failed = results.filter(result => result.status === 'rejected');
                expect(successful.length).toBeGreaterThan(0);
                expect(failed.length).toBeGreaterThan(0);
                failed.forEach(failure => {
                    if (failure.status === 'rejected') {
                        expect(failure.reason.message).toMatch(/deadlock detected/i);
                    }
                });
                await db.query('DELETE FROM users WHERE id IN ($1, $2)', [user1Id, user2Id]);
            }
            finally {
                await db2.end();
            }
        }, 10000);
        it('应该支持只读事务', async () => {
            await db.query('BEGIN READ ONLY');
            try {
                const result = await db.query('SELECT COUNT(*) FROM users');
                expect(result.rows).toHaveLength(1);
                await expect(db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user'])).rejects.toThrow(/cannot execute.*in a read-only transaction/i);
                await db.query('COMMIT');
            }
            catch (error) {
                await db.query('ROLLBACK');
                throw error;
            }
        });
    });
    describe('性能测试', () => {
        it('应该在合理时间内完成批量插入', async () => {
            const batchSize = 1000;
            const testUserId = testUser?.id || (await db.query('INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *', [zh_CN_1.faker.internet.email(), zh_CN_1.faker.internet.username(), zh_CN_1.faker.internet.password(), 'user'])).rows[0].id;
            const startTime = process.hrtime.bigint();
            const values = Array.from({ length: batchSize }, (_, i) => `('${testUserId}', ${31.2304 + i * 0.001}, ${121.4737 + i * 0.001}, 'industrial', 3, '批量测试标注${i}')`).join(',');
            await db.query(`
        INSERT INTO annotations (user_id, latitude, longitude, smell_type, intensity, description) 
        VALUES ${values}
      `);
            const endTime = process.hrtime.bigint();
            const executionTime = Number(endTime - startTime) / 1000000;
            expect(executionTime).toBeLessThan(5000);
            await db.query('DELETE FROM annotations WHERE description LIKE $1', ['批量测试标注%']);
        }, 10000);
        it('应该高效执行复杂查询', async () => {
            const startTime = process.hrtime.bigint();
            await db.query(`
        SELECT 
          u.username,
          COUNT(a.id) as annotation_count,
          AVG(a.intensity) as avg_intensity,
          ST_Distance(
            ST_GeogFromText('POINT(' || a.longitude || ' ' || a.latitude || ')'),
            ST_GeogFromText('POINT(121.4737 31.2304)')
          ) as avg_distance_from_center
        FROM users u
        LEFT JOIN annotations a ON u.id = a.user_id
        WHERE a.created_at >= NOW() - INTERVAL '30 days'
        GROUP BY u.id, u.username
        HAVING COUNT(a.id) > 0
        ORDER BY annotation_count DESC
        LIMIT 10
      `);
            const endTime = process.hrtime.bigint();
            const executionTime = Number(endTime - startTime) / 1000000;
            expect(executionTime).toBeLessThan(1000);
        });
        it('应该高效处理并发查询', async () => {
            const concurrentQueries = 10;
            const startTime = process.hrtime.bigint();
            const promises = Array.from({ length: concurrentQueries }, () => db.query('SELECT COUNT(*) FROM annotations WHERE created_at >= NOW() - INTERVAL \'7 days\''));
            await Promise.all(promises);
            const endTime = process.hrtime.bigint();
            const executionTime = Number(endTime - startTime) / 1000000;
            expect(executionTime).toBeLessThan(2000);
        });
        it('应该验证索引使用情况', async () => {
            const explainResult = await db.query(`
        EXPLAIN (ANALYZE, BUFFERS) 
        SELECT * FROM annotations 
        WHERE user_id = $1 
        ORDER BY created_at DESC 
        LIMIT 10
      `, [testUser?.id || '00000000-0000-0000-0000-000000000000']);
            const queryPlan = explainResult.rows.map(row => row['QUERY PLAN']).join('\n');
            expect(queryPlan).toMatch(/Index Scan|Bitmap Heap Scan/i);
            expect(queryPlan).not.toMatch(/Seq Scan on annotations/i);
        });
        it('应该监控连接池使用情况', async () => {
            const connectionResult = await db.query(`
        SELECT 
          count(*) as total_connections,
          count(*) FILTER (WHERE state = 'active') as active_connections,
          count(*) FILTER (WHERE state = 'idle') as idle_connections
        FROM pg_stat_activity 
        WHERE datname = current_database()
      `);
            const stats = connectionResult.rows[0];
            expect(parseInt(stats.total_connections)).toBeGreaterThan(0);
            expect(parseInt(stats.active_connections)).toBeGreaterThan(0);
            expect(parseInt(stats.idle_connections)).toBeGreaterThanOrEqual(0);
            expect(parseInt(stats.total_connections)).toBeLessThan(100);
        });
    });
});
//# sourceMappingURL=database-tests.js.map