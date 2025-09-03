"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaymentService = void 0;
const Payment_1 = require("@/models/Payment");
class PaymentService {
    static async create(paymentData) {
        return await Payment_1.PaymentModel.create(paymentData);
    }
    static async findById(id) {
        return await Payment_1.PaymentModel.findById(id);
    }
    static async findByPayPalOrderId(orderId) {
        return await Payment_1.PaymentModel.findByPayPalOrderId(orderId);
    }
    static async updateStatus(id, status, metadata) {
        return await Payment_1.PaymentModel.updateStatus(id, { status, metadata });
    }
    static async getUserPayments(userId, options = {}) {
        return await Payment_1.PaymentModel.getUserPayments(userId, options);
    }
    static async getPaymentStats(options = {}) {
        return await Payment_1.PaymentModel.getPaymentStats(options);
    }
    static async processRefund(paymentId, refundAmount, reason) {
        return await Payment_1.PaymentModel.processRefund(paymentId, refundAmount, reason);
    }
    static async checkDuplicatePayment(userId, annotationId, amount, timeWindow = 300000) {
        const payment = await Payment_1.PaymentModel.checkDuplicatePayment(userId, annotationId, amount, timeWindow);
        return !!payment;
    }
    static async getPaymentMethodStats(options = {}) {
        return await Payment_1.PaymentModel.getPaymentMethodStats(options);
    }
}
exports.PaymentService = PaymentService;
exports.default = PaymentService;
//# sourceMappingURL=paymentService.js.map