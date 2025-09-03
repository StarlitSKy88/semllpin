import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { AppError } from './errorHandler';

// Validation middleware factory
export const validateRequest = (schema: {
  body?: Joi.ObjectSchema;
  query?: Joi.ObjectSchema;
  params?: Joi.ObjectSchema;
}) => {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const errors: string[] = [];

    // Validate body
    if (schema.body) {
      const { error } = schema.body.validate(req.body);
      if (error) {
        errors.push(`Body: ${error.details.map(d => d.message).join(', ')}`);
      }
    }

    // Validate query
    if (schema.query) {
      const { error } = schema.query.validate(req.query);
      if (error) {
        errors.push(`Query: ${error.details.map(d => d.message).join(', ')}`);
      }
    }

    // Validate params
    if (schema.params) {
      const { error } = schema.params.validate(req.params);
      if (error) {
        errors.push(`Params: ${error.details.map(d => d.message).join(', ')}`);
      }
    }

    if (errors.length > 0) {
      throw new AppError(
        `数据验证失败: ${errors.join('; ')}`,
        400,
        'VALIDATION_ERROR',
      );
    }

    next();
  };
};

// Common validation schemas
export const commonSchemas = {
  // UUID validation
  uuid: Joi.string().uuid().required(),

  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
  }),

  // Sorting
  sorting: Joi.object({
    sortBy: Joi.string().default('created_at'),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  }),

  // Search
  search: Joi.object({
    q: Joi.string().min(1).max(100),
  }),

  // Geographic coordinates
  coordinates: Joi.object({
    latitude: Joi.number().min(-90).max(90).required(),
    longitude: Joi.number().min(-180).max(180).required(),
  }),

  // Geographic bounds
  bounds: Joi.object({
    north: Joi.number().min(-90).max(90).required(),
    south: Joi.number().min(-90).max(90).required(),
    east: Joi.number().min(-180).max(180).required(),
    west: Joi.number().min(-180).max(180).required(),
  }).custom((value, helpers) => {
    if (value.north <= value.south) {
      return helpers.error('bounds.invalid', { message: 'North must be greater than south' });
    }
    if (value.east <= value.west) {
      return helpers.error('bounds.invalid', { message: 'East must be greater than west' });
    }
    return value;
  }),

  // Email validation
  email: Joi.string().email().required(),

  // Password validation - simplified for MVP
  password: Joi.string()
    .min(6)
    .max(128)
    .required()
    .messages({
      'string.min': '密码至少需要6个字符',
      'string.max': '密码不能超过128个字符',
      'any.required': '密码不能为空',
    }),

  // Username validation
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),
};

// User validation schemas
export const userSchemas = {
  register: {
    body: Joi.object({
      email: commonSchemas.email,
      password: commonSchemas.password,
      username: commonSchemas.username,
      displayName: Joi.string().min(1).max(100),
    }),
  },

  login: {
    body: Joi.object({
      email: commonSchemas.email,
      password: Joi.string().required(),
    }),
  },

  updateProfile: {
    body: Joi.object({
      displayName: Joi.string().min(1).max(100),
      bio: Joi.string().max(500),
    }),
  },

  changePassword: {
    body: Joi.object({
      currentPassword: Joi.string().required(),
      newPassword: commonSchemas.password,
    }),
  },

  forgotPassword: {
    body: Joi.object({
      email: commonSchemas.email,
    }),
  },

  resetPassword: {
    body: Joi.object({
      token: Joi.string().required(),
      password: commonSchemas.password,
    }),
  },
};

// Annotation validation schemas
export const annotationSchemas = {
  create: {
    body: Joi.object({
      latitude: Joi.number().min(-90).max(90).required(),
      longitude: Joi.number().min(-180).max(180).required(),
      smellIntensity: Joi.number().integer().min(1).max(10).required(),
      description: Joi.string().max(500),
      mediaFiles: Joi.array().items(Joi.string().uuid()).max(5),
    }),
  },

  update: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
    body: Joi.object({
      smellIntensity: Joi.number().integer().min(1).max(10),
      description: Joi.string().max(500),
    }),
  },

  getById: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
  },

  getList: {
    query: Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20),
      sortBy: Joi.string().default('created_at'),
      sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
      latitude: Joi.number().min(-90).max(90),
      longitude: Joi.number().min(-180).max(180),
      radius: Joi.number().min(1).max(50000).default(1000), // meters
      intensityMin: Joi.number().integer().min(1).max(10),
      intensityMax: Joi.number().integer().min(1).max(10),
      smell_type: Joi.string().valid('funny', 'industrial', 'food', 'chemical', 'natural', 'other'),
      country: Joi.string().length(2), // ISO country code
      region: Joi.string().max(100),
      city: Joi.string().max(100),
      startDate: Joi.date().iso(),
      endDate: Joi.date().iso().min(Joi.ref('startDate')),
    }),
  },

  getMapData: {
    query: Joi.object({
      north: Joi.number().min(-90).max(90).required(),
      south: Joi.number().min(-90).max(90).required(),
      east: Joi.number().min(-180).max(180).required(),
      west: Joi.number().min(-180).max(180).required(),
      zoom: Joi.number().integer().min(1).max(20).default(10),
      intensityMin: Joi.number().integer().min(1).max(10),
      intensityMax: Joi.number().integer().min(1).max(10),
    }),
  },
};

// Comment validation schemas
export const commentSchemas = {
  create: {
    body: Joi.object({
      annotationId: commonSchemas.uuid,
      content: Joi.string().min(1).max(1000).required(),
      parentId: commonSchemas.uuid.optional(),
    }),
  },

  update: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
    body: Joi.object({
      content: Joi.string().min(1).max(1000).required(),
    }),
  },

  getById: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
  },

  getByAnnotation: {
    params: Joi.object({
      annotationId: commonSchemas.uuid,
    }),
    query: commonSchemas.pagination,
  },
};

// Payment validation schemas
export const paymentSchemas = {
  create: {
    body: Joi.object({
      amount: Joi.number().positive().precision(2).required(),
      currency: Joi.string().length(3).uppercase().default('USD'),
      paymentMethod: Joi.string().valid('stripe', 'paypal', 'alipay', 'wechat').required(),
      annotationId: commonSchemas.uuid.optional(),
      description: Joi.string().max(200),
    }),
  },

  confirm: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
    body: Joi.object({
      paymentIntentId: Joi.string().required(),
    }),
  },

  webhook: {
    body: Joi.object({
      type: Joi.string().required(),
      data: Joi.object().required(),
    }),
  },
};

// File upload validation
export const uploadSchemas = {
  single: {
    query: Joi.object({
      type: Joi.string().valid('image', 'video', 'audio').required(),
    }),
  },

  multiple: {
    query: Joi.object({
      type: Joi.string().valid('image', 'video', 'audio').required(),
      maxFiles: Joi.number().integer().min(1).max(10).default(5),
    }),
  },
};

// Admin validation schemas
export const mediaSchemas = {
  getList: {
    query: Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20),
      fileType: Joi.string().valid('image', 'video', 'audio'),
      sortBy: Joi.string().default('created_at'),
      sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
    }),
  },

  getById: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
  },

  delete: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
  },
};

export const adminSchemas = {
  updateUser: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
    body: Joi.object({
      status: Joi.string().valid('active', 'suspended', 'deleted'),
      role: Joi.string().valid('user', 'moderator', 'admin'),
    }),
  },

  moderateAnnotation: {
    params: Joi.object({
      id: commonSchemas.uuid,
    }),
    body: Joi.object({
      status: Joi.string().valid('pending', 'approved', 'rejected').required(),
      reason: Joi.string().max(200),
    }),
  },

  getStats: {
    query: Joi.object({
      startDate: Joi.date().iso(),
      endDate: Joi.date().iso().min(Joi.ref('startDate')),
      groupBy: Joi.string().valid('day', 'week', 'month').default('day'),
    }),
  },
};

export default validateRequest;
