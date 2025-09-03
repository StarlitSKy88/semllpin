"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.adminSchemas = exports.mediaSchemas = exports.uploadSchemas = exports.paymentSchemas = exports.commentSchemas = exports.annotationSchemas = exports.userSchemas = exports.commonSchemas = exports.validateRequest = void 0;
const joi_1 = __importDefault(require("joi"));
const errorHandler_1 = require("./errorHandler");
const validateRequest = (schema) => {
    return (req, _res, next) => {
        const errors = [];
        if (schema.body) {
            const { error } = schema.body.validate(req.body);
            if (error) {
                errors.push(`Body: ${error.details.map(d => d.message).join(', ')}`);
            }
        }
        if (schema.query) {
            const { error } = schema.query.validate(req.query);
            if (error) {
                errors.push(`Query: ${error.details.map(d => d.message).join(', ')}`);
            }
        }
        if (schema.params) {
            const { error } = schema.params.validate(req.params);
            if (error) {
                errors.push(`Params: ${error.details.map(d => d.message).join(', ')}`);
            }
        }
        if (errors.length > 0) {
            throw new errorHandler_1.AppError(`数据验证失败: ${errors.join('; ')}`, 400, 'VALIDATION_ERROR');
        }
        next();
    };
};
exports.validateRequest = validateRequest;
exports.commonSchemas = {
    uuid: joi_1.default.string().uuid().required(),
    pagination: joi_1.default.object({
        page: joi_1.default.number().integer().min(1).default(1),
        limit: joi_1.default.number().integer().min(1).max(100).default(20),
    }),
    sorting: joi_1.default.object({
        sortBy: joi_1.default.string().default('created_at'),
        sortOrder: joi_1.default.string().valid('asc', 'desc').default('desc'),
    }),
    search: joi_1.default.object({
        q: joi_1.default.string().min(1).max(100),
    }),
    coordinates: joi_1.default.object({
        latitude: joi_1.default.number().min(-90).max(90).required(),
        longitude: joi_1.default.number().min(-180).max(180).required(),
    }),
    bounds: joi_1.default.object({
        north: joi_1.default.number().min(-90).max(90).required(),
        south: joi_1.default.number().min(-90).max(90).required(),
        east: joi_1.default.number().min(-180).max(180).required(),
        west: joi_1.default.number().min(-180).max(180).required(),
    }).custom((value, helpers) => {
        if (value.north <= value.south) {
            return helpers.error('bounds.invalid', { message: 'North must be greater than south' });
        }
        if (value.east <= value.west) {
            return helpers.error('bounds.invalid', { message: 'East must be greater than west' });
        }
        return value;
    }),
    email: joi_1.default.string().email().required(),
    password: joi_1.default.string()
        .min(8)
        .max(128)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 'password')
        .required()
        .messages({
        'string.pattern.name': '密码必须包含至少一个大写字母、一个小写字母、一个数字和一个特殊字符',
    }),
    username: joi_1.default.string()
        .alphanum()
        .min(3)
        .max(30)
        .required(),
};
exports.userSchemas = {
    register: {
        body: joi_1.default.object({
            email: exports.commonSchemas.email,
            password: exports.commonSchemas.password,
            username: exports.commonSchemas.username,
            displayName: joi_1.default.string().min(1).max(100),
        }),
    },
    login: {
        body: joi_1.default.object({
            email: exports.commonSchemas.email,
            password: joi_1.default.string().required(),
        }),
    },
    updateProfile: {
        body: joi_1.default.object({
            displayName: joi_1.default.string().min(1).max(100),
            bio: joi_1.default.string().max(500),
        }),
    },
    changePassword: {
        body: joi_1.default.object({
            currentPassword: joi_1.default.string().required(),
            newPassword: exports.commonSchemas.password,
        }),
    },
    forgotPassword: {
        body: joi_1.default.object({
            email: exports.commonSchemas.email,
        }),
    },
    resetPassword: {
        body: joi_1.default.object({
            token: joi_1.default.string().required(),
            password: exports.commonSchemas.password,
        }),
    },
};
exports.annotationSchemas = {
    create: {
        body: joi_1.default.object({
            latitude: joi_1.default.number().min(-90).max(90).required(),
            longitude: joi_1.default.number().min(-180).max(180).required(),
            smellIntensity: joi_1.default.number().integer().min(1).max(10).required(),
            description: joi_1.default.string().max(500),
            mediaFiles: joi_1.default.array().items(joi_1.default.string().uuid()).max(5),
        }),
    },
    update: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
        body: joi_1.default.object({
            smellIntensity: joi_1.default.number().integer().min(1).max(10),
            description: joi_1.default.string().max(500),
        }),
    },
    getById: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
    },
    getList: {
        query: joi_1.default.object({
            page: joi_1.default.number().integer().min(1).default(1),
            limit: joi_1.default.number().integer().min(1).max(100).default(20),
            sortBy: joi_1.default.string().default('created_at'),
            sortOrder: joi_1.default.string().valid('asc', 'desc').default('desc'),
            latitude: joi_1.default.number().min(-90).max(90),
            longitude: joi_1.default.number().min(-180).max(180),
            radius: joi_1.default.number().min(1).max(50000).default(1000),
            intensityMin: joi_1.default.number().integer().min(1).max(10),
            intensityMax: joi_1.default.number().integer().min(1).max(10),
            smell_type: joi_1.default.string().valid('funny', 'industrial', 'food', 'chemical', 'natural', 'other'),
            country: joi_1.default.string().length(2),
            region: joi_1.default.string().max(100),
            city: joi_1.default.string().max(100),
            startDate: joi_1.default.date().iso(),
            endDate: joi_1.default.date().iso().min(joi_1.default.ref('startDate')),
        }),
    },
    getMapData: {
        query: joi_1.default.object({
            north: joi_1.default.number().min(-90).max(90).required(),
            south: joi_1.default.number().min(-90).max(90).required(),
            east: joi_1.default.number().min(-180).max(180).required(),
            west: joi_1.default.number().min(-180).max(180).required(),
            zoom: joi_1.default.number().integer().min(1).max(20).default(10),
            intensityMin: joi_1.default.number().integer().min(1).max(10),
            intensityMax: joi_1.default.number().integer().min(1).max(10),
        }),
    },
};
exports.commentSchemas = {
    create: {
        body: joi_1.default.object({
            annotationId: exports.commonSchemas.uuid,
            content: joi_1.default.string().min(1).max(1000).required(),
            parentId: exports.commonSchemas.uuid.optional(),
        }),
    },
    update: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
        body: joi_1.default.object({
            content: joi_1.default.string().min(1).max(1000).required(),
        }),
    },
    getById: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
    },
    getByAnnotation: {
        params: joi_1.default.object({
            annotationId: exports.commonSchemas.uuid,
        }),
        query: exports.commonSchemas.pagination,
    },
};
exports.paymentSchemas = {
    create: {
        body: joi_1.default.object({
            amount: joi_1.default.number().positive().precision(2).required(),
            currency: joi_1.default.string().length(3).uppercase().default('USD'),
            paymentMethod: joi_1.default.string().valid('stripe', 'paypal', 'alipay', 'wechat').required(),
            annotationId: exports.commonSchemas.uuid.optional(),
            description: joi_1.default.string().max(200),
        }),
    },
    confirm: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
        body: joi_1.default.object({
            paymentIntentId: joi_1.default.string().required(),
        }),
    },
    webhook: {
        body: joi_1.default.object({
            type: joi_1.default.string().required(),
            data: joi_1.default.object().required(),
        }),
    },
};
exports.uploadSchemas = {
    single: {
        query: joi_1.default.object({
            type: joi_1.default.string().valid('image', 'video', 'audio').required(),
        }),
    },
    multiple: {
        query: joi_1.default.object({
            type: joi_1.default.string().valid('image', 'video', 'audio').required(),
            maxFiles: joi_1.default.number().integer().min(1).max(10).default(5),
        }),
    },
};
exports.mediaSchemas = {
    getList: {
        query: joi_1.default.object({
            page: joi_1.default.number().integer().min(1).default(1),
            limit: joi_1.default.number().integer().min(1).max(100).default(20),
            fileType: joi_1.default.string().valid('image', 'video', 'audio'),
            sortBy: joi_1.default.string().default('created_at'),
            sortOrder: joi_1.default.string().valid('asc', 'desc').default('desc'),
        }),
    },
    getById: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
    },
    delete: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
    },
};
exports.adminSchemas = {
    updateUser: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
        body: joi_1.default.object({
            status: joi_1.default.string().valid('active', 'suspended', 'deleted'),
            role: joi_1.default.string().valid('user', 'moderator', 'admin'),
        }),
    },
    moderateAnnotation: {
        params: joi_1.default.object({
            id: exports.commonSchemas.uuid,
        }),
        body: joi_1.default.object({
            status: joi_1.default.string().valid('pending', 'approved', 'rejected').required(),
            reason: joi_1.default.string().max(200),
        }),
    },
    getStats: {
        query: joi_1.default.object({
            startDate: joi_1.default.date().iso(),
            endDate: joi_1.default.date().iso().min(joi_1.default.ref('startDate')),
            groupBy: joi_1.default.string().valid('day', 'week', 'month').default('day'),
        }),
    },
};
exports.default = exports.validateRequest;
//# sourceMappingURL=validation.js.map