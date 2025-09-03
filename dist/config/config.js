"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
exports.config = {
    NODE_ENV: process.env['NODE_ENV'] || 'development',
    PORT: parseInt(process.env['PORT'] || '3002', 10),
    DATABASE_URL: process.env['DATABASE_URL'] || 'postgresql://localhost:5432/smellpin',
    REDIS_URL: process.env['REDIS_URL'] || 'redis://localhost:6379',
    cache: {
        ttl: parseInt(process.env['CACHE_TTL'] || '3600', 10),
        max: parseInt(process.env['CACHE_MAX'] || '1000', 10),
    },
    JWT_SECRET: process.env['JWT_SECRET'] || 'your-secret-key',
    JWT_EXPIRES_IN: process.env['JWT_EXPIRES_IN'] || '7d',
    JWT_REFRESH_SECRET: process.env['JWT_REFRESH_SECRET'] || 'your-refresh-secret',
    JWT_REFRESH_EXPIRES_IN: process.env['JWT_REFRESH_EXPIRES_IN'] || '30d',
    API_VERSION: process.env['API_VERSION'] || 'v1',
    LOG_LEVEL: process.env['LOG_LEVEL'] || 'info',
    HEALTH_CHECK_TIMEOUT: parseInt(process.env['HEALTH_CHECK_TIMEOUT'] || '5000', 10),
    APP_NAME: process.env['APP_NAME'] || 'SmellPin API',
    APP_VERSION: process.env['APP_VERSION'] || '1.0.0',
    nodeEnv: process.env['NODE_ENV'] || 'development',
    port: parseInt(process.env['PORT'] || '3002', 10),
    apiVersion: process.env['API_VERSION'] || 'v1',
    jwt: {
        secret: process.env['JWT_SECRET'] || 'your-secret-key',
        expiresIn: process.env['JWT_EXPIRES_IN'] || '7d',
        refreshSecret: process.env['JWT_REFRESH_SECRET'] || 'your-refresh-secret',
        refreshExpiresIn: process.env['JWT_REFRESH_EXPIRES_IN'] || '30d',
    },
    cors: {
        origin: process.env['CORS_ORIGIN'] || 'http://localhost:5174',
        credentials: process.env['CORS_CREDENTIALS'] === 'true' || true,
    },
    rateLimit: {
        windowMs: parseInt(process.env['RATE_LIMIT_WINDOW_MS'] || '900000', 10),
        maxRequests: parseInt(process.env['RATE_LIMIT_MAX_REQUESTS'] || '100', 10),
    },
    database: {
        host: process.env['DB_HOST'] || 'localhost',
        port: parseInt(process.env['DB_PORT'] || '5432', 10),
        username: process.env['DB_USERNAME'] || 'postgres',
        password: process.env['DB_PASSWORD'] || 'password',
        database: process.env['DB_NAME'] || 'smellpin',
        ssl: process.env['DB_SSL'] === 'true',
        logging: process.env['NODE_ENV'] === 'development',
        synchronize: process.env['NODE_ENV'] === 'development',
        entities: ['src/entities/**/*.ts'],
        migrations: ['src/migrations/**/*.ts'],
        subscribers: ['src/subscribers/**/*.ts'],
    },
    redis: {
        host: process.env['REDIS_HOST'] || 'localhost',
        port: parseInt(process.env['REDIS_PORT'] || '6379', 10),
        password: process.env['REDIS_PASSWORD'],
        db: parseInt(process.env['REDIS_DB'] || '0', 10),
    },
    payment: {
        stripe: {
            secretKey: process.env['STRIPE_SECRET_KEY'] || 'sk_test_...',
            publishableKey: process.env['STRIPE_PUBLISHABLE_KEY'] || 'pk_test_...',
            webhookSecret: process.env['STRIPE_WEBHOOK_SECRET'] || 'whsec_...',
        },
    },
    frontendUrl: process.env['FRONTEND_URL'] || 'http://localhost:3000',
};
exports.default = exports.config;
//# sourceMappingURL=config.js.map