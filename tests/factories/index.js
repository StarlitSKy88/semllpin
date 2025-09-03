"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createTestPayment = exports.PaymentFactory = exports.createTestLocation = exports.LocationFactory = exports.createTestMedia = exports.MediaFactory = exports.createMultipleTestAnnotations = exports.createTestAnnotation = exports.AnnotationFactory = exports.createMultipleTestUsers = exports.createTestUser = exports.UserFactory = void 0;
exports.configureFactories = configureFactories;
exports.getFactoryConfig = getFactoryConfig;
exports.resetFactories = resetFactories;
exports.cleanupTestData = cleanupTestData;
var userFactory_1 = require("./userFactory");
Object.defineProperty(exports, "UserFactory", { enumerable: true, get: function () { return userFactory_1.UserFactory; } });
Object.defineProperty(exports, "createTestUser", { enumerable: true, get: function () { return userFactory_1.createTestUser; } });
Object.defineProperty(exports, "createMultipleTestUsers", { enumerable: true, get: function () { return userFactory_1.createMultipleTestUsers; } });
var annotationFactory_1 = require("./annotationFactory");
Object.defineProperty(exports, "AnnotationFactory", { enumerable: true, get: function () { return annotationFactory_1.AnnotationFactory; } });
Object.defineProperty(exports, "createTestAnnotation", { enumerable: true, get: function () { return annotationFactory_1.createTestAnnotation; } });
Object.defineProperty(exports, "createMultipleTestAnnotations", { enumerable: true, get: function () { return annotationFactory_1.createMultipleTestAnnotations; } });
var mediaFactory_1 = require("./mediaFactory");
Object.defineProperty(exports, "MediaFactory", { enumerable: true, get: function () { return mediaFactory_1.MediaFactory; } });
Object.defineProperty(exports, "createTestMedia", { enumerable: true, get: function () { return mediaFactory_1.createTestMedia; } });
var locationFactory_1 = require("./locationFactory");
Object.defineProperty(exports, "LocationFactory", { enumerable: true, get: function () { return locationFactory_1.LocationFactory; } });
Object.defineProperty(exports, "createTestLocation", { enumerable: true, get: function () { return locationFactory_1.createTestLocation; } });
var paymentFactory_1 = require("./paymentFactory");
Object.defineProperty(exports, "PaymentFactory", { enumerable: true, get: function () { return paymentFactory_1.PaymentFactory; } });
Object.defineProperty(exports, "createTestPayment", { enumerable: true, get: function () { return paymentFactory_1.createTestPayment; } });
const defaultConfig = {
    seed: 12345,
    locale: 'zh-CN',
    timezone: 'Asia/Shanghai',
};
let factoryConfig = { ...defaultConfig };
function configureFactories(config) {
    factoryConfig = { ...factoryConfig, ...config };
}
function getFactoryConfig() {
    return factoryConfig;
}
function resetFactories() {
    factoryConfig = { ...defaultConfig };
}
async function cleanupTestData() {
    console.log('🧹 Cleaning up test data...');
}
//# sourceMappingURL=index.js.map