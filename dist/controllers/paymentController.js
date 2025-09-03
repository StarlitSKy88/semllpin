"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleWebhook = exports.refundPayment = exports.getPaymentDetails = exports.confirmPayment = exports.createPaymentSession = exports.paymentController = exports.PaymentController = void 0;
const paypalPaymentController_1 = require("./paypalPaymentController");
class PaymentController {
    async createPaymentIntent(req, res) {
        return paypalPaymentController_1.paypalPaymentController.createPayment(req, res);
    }
    async createCheckoutSession(req, res) {
        return paypalPaymentController_1.paypalPaymentController.createPayment(req, res);
    }
    async confirmPayment(req, res) {
        return paypalPaymentController_1.paypalPaymentController.capturePayment(req, res);
    }
    async getPaymentDetails(req, res) {
        return paypalPaymentController_1.paypalPaymentController.getPaymentDetails(req, res);
    }
    async refundPayment(req, res) {
        return paypalPaymentController_1.paypalPaymentController.refundPayment(req, res);
    }
    async handleWebhook(req, res) {
        return paypalPaymentController_1.paypalPaymentController.handleWebhook(req, res);
    }
}
exports.PaymentController = PaymentController;
exports.paymentController = new PaymentController();
exports.createPaymentSession = exports.paymentController.createPaymentIntent.bind(exports.paymentController);
exports.confirmPayment = exports.paymentController.confirmPayment.bind(exports.paymentController);
exports.getPaymentDetails = exports.paymentController.getPaymentDetails.bind(exports.paymentController);
exports.refundPayment = exports.paymentController.refundPayment.bind(exports.paymentController);
exports.handleWebhook = exports.paymentController.handleWebhook.bind(exports.paymentController);
exports.default = exports.paymentController;
//# sourceMappingURL=paymentController.js.map