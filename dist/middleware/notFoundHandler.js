"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.notFoundHandler = void 0;
const errorHandler_1 = require("./errorHandler");
const notFoundHandler = (req, _res, next) => {
    const error = new errorHandler_1.AppError(`路由 ${req.originalUrl} 不存在`, 404, 'ROUTE_NOT_FOUND');
    next(error);
};
exports.notFoundHandler = notFoundHandler;
exports.default = exports.notFoundHandler;
//# sourceMappingURL=notFoundHandler.js.map