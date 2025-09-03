import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
export declare const validateRequest: (schema: {
    body?: Joi.ObjectSchema;
    query?: Joi.ObjectSchema;
    params?: Joi.ObjectSchema;
}) => (req: Request, _res: Response, next: NextFunction) => void;
export declare const commonSchemas: {
    uuid: Joi.StringSchema<string>;
    pagination: Joi.ObjectSchema<any>;
    sorting: Joi.ObjectSchema<any>;
    search: Joi.ObjectSchema<any>;
    coordinates: Joi.ObjectSchema<any>;
    bounds: Joi.ObjectSchema<any>;
    email: Joi.StringSchema<string>;
    password: Joi.StringSchema<string>;
    username: Joi.StringSchema<string>;
};
export declare const userSchemas: {
    register: {
        body: Joi.ObjectSchema<any>;
    };
    login: {
        body: Joi.ObjectSchema<any>;
    };
    updateProfile: {
        body: Joi.ObjectSchema<any>;
    };
    changePassword: {
        body: Joi.ObjectSchema<any>;
    };
    forgotPassword: {
        body: Joi.ObjectSchema<any>;
    };
    resetPassword: {
        body: Joi.ObjectSchema<any>;
    };
};
export declare const annotationSchemas: {
    create: {
        body: Joi.ObjectSchema<any>;
    };
    update: {
        params: Joi.ObjectSchema<any>;
        body: Joi.ObjectSchema<any>;
    };
    getById: {
        params: Joi.ObjectSchema<any>;
    };
    getList: {
        query: Joi.ObjectSchema<any>;
    };
    getMapData: {
        query: Joi.ObjectSchema<any>;
    };
};
export declare const commentSchemas: {
    create: {
        body: Joi.ObjectSchema<any>;
    };
    update: {
        params: Joi.ObjectSchema<any>;
        body: Joi.ObjectSchema<any>;
    };
    getById: {
        params: Joi.ObjectSchema<any>;
    };
    getByAnnotation: {
        params: Joi.ObjectSchema<any>;
        query: Joi.ObjectSchema<any>;
    };
};
export declare const paymentSchemas: {
    create: {
        body: Joi.ObjectSchema<any>;
    };
    confirm: {
        params: Joi.ObjectSchema<any>;
        body: Joi.ObjectSchema<any>;
    };
    webhook: {
        body: Joi.ObjectSchema<any>;
    };
};
export declare const uploadSchemas: {
    single: {
        query: Joi.ObjectSchema<any>;
    };
    multiple: {
        query: Joi.ObjectSchema<any>;
    };
};
export declare const mediaSchemas: {
    getList: {
        query: Joi.ObjectSchema<any>;
    };
    getById: {
        params: Joi.ObjectSchema<any>;
    };
    delete: {
        params: Joi.ObjectSchema<any>;
    };
};
export declare const adminSchemas: {
    updateUser: {
        params: Joi.ObjectSchema<any>;
        body: Joi.ObjectSchema<any>;
    };
    moderateAnnotation: {
        params: Joi.ObjectSchema<any>;
        body: Joi.ObjectSchema<any>;
    };
    getStats: {
        query: Joi.ObjectSchema<any>;
    };
};
export default validateRequest;
//# sourceMappingURL=validation.d.ts.map