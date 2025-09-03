"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const zh_CN_1 = require("@faker-js/faker/locale/zh_CN");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const stripe_1 = __importDefault(require("stripe"));
jest.mock('stripe');
const MockedStripe = stripe_1.default;
describe('4. 支付API测试', () => {
    const paymentEndpoint = '/api/v1/payments';
    let mockStripe;
    beforeEach(() => {
        MockedStripe.mockClear();
        mockStripe = new MockedStripe('test_key');
    });
    describe('创建支付意图', () => {
        it('应该成功创建支付意图', async () => {
            const paymentData = {
                amount: 10.00,
                currency: 'cny',
                annotationId: zh_CN_1.faker.string.uuid(),
                description: '创建气味标注'
            };
            const mockPaymentIntent = {
                id: 'pi_test_123456',
                client_secret: 'pi_test_123456_secret_test',
                amount: 1000,
                currency: 'cny',
                status: 'requires_payment_method'
            };
            mockStripe.paymentIntents.create.mockResolvedValue(mockPaymentIntent);
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(paymentData)
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data).toHaveProperty('clientSecret');
            expect(response.body.data).toHaveProperty('paymentIntentId');
            expect(response.body.data.paymentIntentId).toBe(mockPaymentIntent.id);
            expect(mockStripe.paymentIntents.create).toHaveBeenCalledWith({
                amount: 1000,
                currency: 'cny',
                metadata: expect.objectContaining({
                    userId: testUser.id,
                    annotationId: paymentData.annotationId
                })
            });
            const payment = await testDb.query('SELECT * FROM payments WHERE stripe_payment_intent_id = $1', [mockPaymentIntent.id]);
            expect(payment.rows).toHaveLength(1);
            expect(payment.rows[0].amount).toBe(paymentData.amount.toString());
            expect(payment.rows[0].status).toBe('pending');
        });
        it('应该验证支付金额限制', async () => {
            const invalidPaymentData = {
                amount: 0.01,
                currency: 'cny',
                annotationId: zh_CN_1.faker.string.uuid(),
                description: '测试最小金额限制'
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(invalidPaymentData)
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('INVALID_AMOUNT');
        });
        it('应该处理Stripe API错误', async () => {
            const paymentData = {
                amount: 10.00,
                currency: 'cny',
                annotationId: zh_CN_1.faker.string.uuid(),
                description: '测试Stripe错误处理'
            };
            mockStripe.paymentIntents.create.mockRejectedValue(new Error('Your card was declined.'));
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(paymentData)
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('PAYMENT_PROCESSING_ERROR');
        });
        it('应该验证标注存在性', async () => {
            const paymentData = {
                amount: 10.00,
                currency: 'cny',
                annotationId: 'non-existent-annotation-id',
                description: '测试标注验证'
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(paymentData)
                .expect(404);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('ANNOTATION_NOT_FOUND');
        });
        it('应该防止重复支付', async () => {
            const annotationId = zh_CN_1.faker.string.uuid();
            await testDb.query('INSERT INTO annotations (id, user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6, $7)', [annotationId, testUser.id, 31.2304, 121.4737, 'industrial', 3, '测试标注']);
            const paymentData = {
                amount: 10.00,
                currency: 'cny',
                annotationId,
                description: '创建气味标注'
            };
            mockStripe.paymentIntents.create.mockResolvedValue({
                id: 'pi_test_123456',
                client_secret: 'pi_test_123456_secret_test',
                amount: 1000,
                currency: 'cny',
                status: 'requires_payment_method'
            });
            await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(paymentData)
                .expect(200);
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(paymentData)
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('PAYMENT_ALREADY_EXISTS');
        });
    });
    describe('支付确认', () => {
        let paymentIntentId;
        let annotationId;
        beforeEach(async () => {
            annotationId = zh_CN_1.faker.string.uuid();
            await testDb.query('INSERT INTO annotations (id, user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6, $7)', [annotationId, testUser.id, 31.2304, 121.4737, 'industrial', 3, '测试标注']);
            paymentIntentId = 'pi_test_123456';
            await testDb.query('INSERT INTO payments (user_id, annotation_id, stripe_payment_intent_id, amount, status) VALUES ($1, $2, $3, $4, $5)', [testUser.id, annotationId, paymentIntentId, '10.00', 'pending']);
        });
        it('应该成功确认支付', async () => {
            mockStripe.paymentIntents.confirm.mockResolvedValue({
                id: paymentIntentId,
                status: 'succeeded',
                amount: 1000,
                currency: 'cny'
            });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/confirm`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                paymentMethodId: 'pm_test_card_visa'
            })
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data.status).toBe('succeeded');
            const payment = await testDb.query('SELECT * FROM payments WHERE stripe_payment_intent_id = $1', [paymentIntentId]);
            expect(payment.rows[0].status).toBe('completed');
            const annotation = await testDb.query('SELECT * FROM annotations WHERE id = $1', [annotationId]);
            expect(annotation.rows[0].payment_status).toBe('paid');
        });
        it('应该处理支付失败', async () => {
            mockStripe.paymentIntents.confirm.mockResolvedValue({
                id: paymentIntentId,
                status: 'payment_failed',
                last_payment_error: {
                    message: 'Your card was declined.'
                }
            });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/confirm`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                paymentMethodId: 'pm_test_card_declined'
            })
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('PAYMENT_FAILED');
            const payment = await testDb.query('SELECT * FROM payments WHERE stripe_payment_intent_id = $1', [paymentIntentId]);
            expect(payment.rows[0].status).toBe('failed');
        });
        it('应该验证支付所有权', async () => {
            const otherUser = testDataFactory.createUser();
            const otherToken = jsonwebtoken_1.default.sign({ userId: otherUser.id, email: otherUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/confirm`)
                .set('Authorization', `Bearer ${otherToken}`)
                .send({
                paymentIntentId,
                paymentMethodId: 'pm_test_card_visa'
            })
                .expect(403);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('PAYMENT_NOT_OWNED');
        });
        it('应该处理重复确认请求', async () => {
            await testDb.query('UPDATE payments SET status = $1 WHERE stripe_payment_intent_id = $2', ['completed', paymentIntentId]);
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/confirm`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                paymentMethodId: 'pm_test_card_visa'
            })
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('PAYMENT_ALREADY_COMPLETED');
        });
        it('应该支持3D Secure认证', async () => {
            mockStripe.paymentIntents.confirm.mockResolvedValue({
                id: paymentIntentId,
                status: 'requires_action',
                next_action: {
                    type: 'use_stripe_sdk',
                    use_stripe_sdk: {
                        type: 'three_d_secure_redirect',
                        stripe_js: 'https://js.stripe.com/v3/m-outer-123.html'
                    }
                }
            });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/confirm`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                paymentMethodId: 'pm_card_threeDSecure2Required'
            })
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data.status).toBe('requires_action');
            expect(response.body.data).toHaveProperty('nextAction');
            expect(response.body.data.nextAction.type).toBe('use_stripe_sdk');
        });
    });
    describe('Webhook处理', () => {
        it('应该处理支付成功webhook', async () => {
            const paymentIntentId = 'pi_test_webhook_123';
            const annotationId = zh_CN_1.faker.string.uuid();
            await testDb.query('INSERT INTO annotations (id, user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6, $7)', [annotationId, testUser.id, 31.2304, 121.4737, 'industrial', 3, '测试标注']);
            await testDb.query('INSERT INTO payments (user_id, annotation_id, stripe_payment_intent_id, amount, status) VALUES ($1, $2, $3, $4, $5)', [testUser.id, annotationId, paymentIntentId, '10.00', 'pending']);
            const webhookPayload = {
                id: 'evt_test_webhook',
                object: 'event',
                type: 'payment_intent.succeeded',
                data: {
                    object: {
                        id: paymentIntentId,
                        object: 'payment_intent',
                        status: 'succeeded',
                        amount: 1000,
                        currency: 'cny'
                    }
                }
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/webhook`)
                .send(webhookPayload)
                .set('stripe-signature', 'test-signature')
                .expect(200);
            expect(response.body).toHaveProperty('received', true);
            const payment = await testDb.query('SELECT * FROM payments WHERE stripe_payment_intent_id = $1', [paymentIntentId]);
            expect(payment.rows[0].status).toBe('completed');
        });
        it('应该处理支付失败webhook', async () => {
            const paymentIntentId = 'pi_test_webhook_failed';
            const annotationId = zh_CN_1.faker.string.uuid();
            await testDb.query('INSERT INTO payments (user_id, annotation_id, stripe_payment_intent_id, amount, status) VALUES ($1, $2, $3, $4, $5)', [testUser.id, annotationId, paymentIntentId, '10.00', 'pending']);
            const webhookPayload = {
                id: 'evt_test_webhook_failed',
                object: 'event',
                type: 'payment_intent.payment_failed',
                data: {
                    object: {
                        id: paymentIntentId,
                        object: 'payment_intent',
                        status: 'payment_failed',
                        last_payment_error: {
                            message: 'Your card was declined.'
                        }
                    }
                }
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/webhook`)
                .send(webhookPayload)
                .set('stripe-signature', 'test-signature')
                .expect(200);
            expect(response.body).toHaveProperty('received', true);
            const payment = await testDb.query('SELECT * FROM payments WHERE stripe_payment_intent_id = $1', [paymentIntentId]);
            expect(payment.rows[0].status).toBe('failed');
        });
        it('应该验证webhook签名', async () => {
            const webhookPayload = {
                id: 'evt_test_webhook',
                object: 'event',
                type: 'payment_intent.succeeded',
                data: {}
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/webhook`)
                .send(webhookPayload)
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('INVALID_WEBHOOK_SIGNATURE');
        });
        it('应该忽略未知的webhook事件', async () => {
            const webhookPayload = {
                id: 'evt_test_webhook',
                object: 'event',
                type: 'unknown_event_type',
                data: {}
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/webhook`)
                .send(webhookPayload)
                .set('stripe-signature', 'test-signature')
                .expect(200);
            expect(response.body).toHaveProperty('received', true);
        });
        it('应该处理重复的webhook事件', async () => {
            const eventId = 'evt_test_duplicate';
            const webhookPayload = {
                id: eventId,
                object: 'event',
                type: 'payment_intent.succeeded',
                data: {
                    object: {
                        id: 'pi_test_duplicate',
                        object: 'payment_intent',
                        status: 'succeeded'
                    }
                }
            };
            await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/webhook`)
                .send(webhookPayload)
                .set('stripe-signature', 'test-signature')
                .expect(200);
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/webhook`)
                .send(webhookPayload)
                .set('stripe-signature', 'test-signature')
                .expect(200);
            expect(response.body).toHaveProperty('received', true);
            const events = await testDb.query('SELECT * FROM webhook_events WHERE stripe_event_id = $1', [eventId]);
            expect(events.rows).toHaveLength(1);
        });
    });
    describe('退款处理', () => {
        let paymentIntentId;
        let annotationId;
        beforeEach(async () => {
            annotationId = zh_CN_1.faker.string.uuid();
            paymentIntentId = 'pi_test_refund';
            await testDb.query('INSERT INTO annotations (id, user_id, latitude, longitude, smell_type, intensity, description, payment_status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)', [annotationId, testUser.id, 31.2304, 121.4737, 'industrial', 3, '测试标注', 'paid']);
            await testDb.query('INSERT INTO payments (user_id, annotation_id, stripe_payment_intent_id, amount, status) VALUES ($1, $2, $3, $4, $5)', [testUser.id, annotationId, paymentIntentId, '10.00', 'completed']);
        });
        it('应该成功处理退款申请', async () => {
            mockStripe.refunds.create.mockResolvedValue({
                id: 're_test_123456',
                amount: 1000,
                currency: 'cny',
                payment_intent: paymentIntentId,
                status: 'succeeded'
            });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/refund`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                reason: 'requested_by_customer',
                description: '用户申请退款'
            })
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data).toHaveProperty('refundId');
            const refund = await testDb.query('SELECT * FROM refunds WHERE payment_intent_id = $1', [paymentIntentId]);
            expect(refund.rows).toHaveLength(1);
            expect(refund.rows[0].amount).toBe('10.00');
            expect(refund.rows[0].status).toBe('succeeded');
        });
        it('应该只允许管理员或标注作者申请退款', async () => {
            const otherUser = testDataFactory.createUser();
            const otherToken = jsonwebtoken_1.default.sign({ userId: otherUser.id, email: otherUser.email }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/refund`)
                .set('Authorization', `Bearer ${otherToken}`)
                .send({
                paymentIntentId,
                reason: 'requested_by_customer'
            })
                .expect(403);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('REFUND_NOT_AUTHORIZED');
        });
        it('应该支持部分退款', async () => {
            const partialAmount = 5.00;
            mockStripe.refunds.create.mockResolvedValue({
                id: 're_test_partial',
                amount: 500,
                currency: 'cny',
                payment_intent: paymentIntentId,
                status: 'succeeded'
            });
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/refund`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                amount: partialAmount,
                reason: 'requested_by_customer'
            })
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            const refund = await testDb.query('SELECT * FROM refunds WHERE payment_intent_id = $1', [paymentIntentId]);
            expect(refund.rows[0].amount).toBe(partialAmount.toString());
        });
        it('应该防止退款金额超过原始支付金额', async () => {
            const excessiveAmount = 20.00;
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/refund`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                amount: excessiveAmount,
                reason: 'requested_by_customer'
            })
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('REFUND_AMOUNT_EXCEEDS_PAYMENT');
        });
        it('应该处理退款失败', async () => {
            mockStripe.refunds.create.mockRejectedValue(new Error('Charge has already been refunded.'));
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/refund`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                reason: 'requested_by_customer'
            })
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('REFUND_PROCESSING_ERROR');
        });
    });
    describe('支付历史', () => {
        beforeEach(async () => {
            const payments = [
                { id: 'pi_test_1', amount: '10.00', status: 'completed' },
                { id: 'pi_test_2', amount: '15.00', status: 'failed' },
                { id: 'pi_test_3', amount: '20.00', status: 'pending' }
            ];
            for (const payment of payments) {
                await testDb.query('INSERT INTO payments (user_id, stripe_payment_intent_id, amount, status, created_at) VALUES ($1, $2, $3, $4, $5)', [testUser.id, payment.id, payment.amount, payment.status, new Date()]);
            }
        });
        it('应该获取用户支付历史', async () => {
            const response = await (0, supertest_1.default)(app)
                .get(`${paymentEndpoint}/history`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data).toHaveProperty('payments');
            expect(Array.isArray(response.body.data.payments)).toBe(true);
            expect(response.body.data.payments.length).toBe(3);
            response.body.data.payments.forEach((payment) => {
                expect(payment).toHaveProperty('id');
                expect(payment).toHaveProperty('amount');
                expect(payment).toHaveProperty('status');
                expect(payment).toHaveProperty('createdAt');
                expect(payment).not.toHaveProperty('stripePaymentIntentId');
            });
        });
        it('应该支持按状态过滤支付历史', async () => {
            const response = await (0, supertest_1.default)(app)
                .get(`${paymentEndpoint}/history?status=completed`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data.payments).toHaveLength(1);
            expect(response.body.data.payments[0].status).toBe('completed');
        });
        it('应该支持分页查询支付历史', async () => {
            const page1 = await (0, supertest_1.default)(app)
                .get(`${paymentEndpoint}/history?page=1&limit=2`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            expect(page1.body.data.payments).toHaveLength(2);
            expect(page1.body.data.pagination.page).toBe(1);
            expect(page1.body.data.pagination.totalCount).toBe(3);
            const page2 = await (0, supertest_1.default)(app)
                .get(`${paymentEndpoint}/history?page=2&limit=2`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            expect(page2.body.data.payments).toHaveLength(1);
            expect(page2.body.data.pagination.page).toBe(2);
        });
        it('应该支持按日期范围过滤', async () => {
            const startDate = new Date();
            startDate.setDate(startDate.getDate() - 7);
            const endDate = new Date();
            const response = await (0, supertest_1.default)(app)
                .get(`${paymentEndpoint}/history`)
                .query({
                startDate: startDate.toISOString(),
                endDate: endDate.toISOString()
            })
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data.payments.length).toBeGreaterThan(0);
        });
        it('应该计算支付统计信息', async () => {
            const response = await (0, supertest_1.default)(app)
                .get(`${paymentEndpoint}/stats`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body.data).toHaveProperty('totalAmount');
            expect(response.body.data).toHaveProperty('completedCount');
            expect(response.body.data).toHaveProperty('failedCount');
            expect(response.body.data).toHaveProperty('pendingCount');
            expect(response.body.data.totalAmount).toBe('10.00');
            expect(response.body.data.completedCount).toBe(1);
            expect(response.body.data.failedCount).toBe(1);
            expect(response.body.data.pendingCount).toBe(1);
        });
    });
    describe('支付安全性', () => {
        it('应该防止金额篡改', async () => {
            const annotationId = zh_CN_1.faker.string.uuid();
            await testDb.query('INSERT INTO annotations (id, user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6, $7)', [annotationId, testUser.id, 31.2304, 121.4737, 'industrial', 3, '测试标注']);
            const tammperedData = {
                amount: 0.01,
                currency: 'cny',
                annotationId,
                description: '尝试金额篡改'
            };
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(tammperedData)
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error.code).toBe('INVALID_AMOUNT');
        });
        it('应该验证支付方法合法性', async () => {
            const paymentIntentId = 'pi_test_security';
            await testDb.query('INSERT INTO payments (user_id, stripe_payment_intent_id, amount, status) VALUES ($1, $2, $3, $4)', [testUser.id, paymentIntentId, '10.00', 'pending']);
            const response = await (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/confirm`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                paymentIntentId,
                paymentMethodId: 'invalid_pm_id'
            })
                .expect(400);
            expect(response.body).toHaveProperty('success', false);
        });
        it('应该限制支付频率', async () => {
            const promises = Array.from({ length: 10 }, (_, i) => {
                const annotationId = zh_CN_1.faker.string.uuid();
                return (0, supertest_1.default)(app)
                    .post(`${paymentEndpoint}/create-intent`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send({
                    amount: 10.00,
                    currency: 'cny',
                    annotationId,
                    description: `测试支付频率限制 ${i + 1}`
                });
            });
            const responses = await Promise.all(promises);
            const rateLimitedResponses = responses.filter(res => res.status === 429);
            expect(rateLimitedResponses.length).toBeGreaterThan(0);
        });
        it('应该记录可疑支付活动', async () => {
            const suspiciousPayments = Array.from({ length: 5 }, () => ({
                amount: 0.05,
                currency: 'cny',
                annotationId: zh_CN_1.faker.string.uuid(),
                description: '可疑小额支付'
            }));
            for (const payment of suspiciousPayments) {
                await (0, supertest_1.default)(app)
                    .post(`${paymentEndpoint}/create-intent`)
                    .set('Authorization', `Bearer ${authToken}`)
                    .send(payment);
            }
            const riskLogs = await testDb.query('SELECT * FROM security_logs WHERE user_id = $1 AND event_type = $2', [testUser.id, 'suspicious_payment_pattern']);
            expect(riskLogs.rows.length).toBeGreaterThan(0);
        });
        it('应该处理并发支付请求', async () => {
            const annotationId = zh_CN_1.faker.string.uuid();
            await testDb.query('INSERT INTO annotations (id, user_id, latitude, longitude, smell_type, intensity, description) VALUES ($1, $2, $3, $4, $5, $6, $7)', [annotationId, testUser.id, 31.2304, 121.4737, 'industrial', 3, '测试标注']);
            const paymentData = {
                amount: 10.00,
                currency: 'cny',
                annotationId,
                description: '并发支付测试'
            };
            const promises = Array.from({ length: 3 }, () => (0, supertest_1.default)(app)
                .post(`${paymentEndpoint}/create-intent`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(paymentData));
            const responses = await Promise.all(promises);
            const successfulResponses = responses.filter(res => res.status === 200);
            const failedResponses = responses.filter(res => res.status === 400);
            expect(successfulResponses).toHaveLength(1);
            expect(failedResponses).toHaveLength(2);
            failedResponses.forEach(response => {
                expect(response.body.error.code).toBe('PAYMENT_ALREADY_EXISTS');
            });
        });
    });
});
//# sourceMappingURL=payment-api-tests.js.map