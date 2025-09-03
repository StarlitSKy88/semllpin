export declare const config: {
    NODE_ENV: string;
    PORT: number;
    DATABASE_URL: string;
    REDIS_URL: string;
    cache: {
        ttl: number;
        max: number;
    };
    JWT_SECRET: string;
    JWT_EXPIRES_IN: string;
    JWT_REFRESH_SECRET: string;
    JWT_REFRESH_EXPIRES_IN: string;
    API_VERSION: string;
    LOG_LEVEL: string;
    HEALTH_CHECK_TIMEOUT: number;
    APP_NAME: string;
    APP_VERSION: string;
    nodeEnv: string;
    port: number;
    apiVersion: string;
    jwt: {
        secret: string;
        expiresIn: string;
        refreshSecret: string;
        refreshExpiresIn: string;
    };
    cors: {
        origin: string;
        credentials: true;
    };
    rateLimit: {
        windowMs: number;
        maxRequests: number;
    };
    database: {
        host: string;
        port: number;
        username: string;
        password: string;
        database: string;
        ssl: boolean;
        logging: boolean;
        synchronize: boolean;
        entities: string[];
        migrations: string[];
        subscribers: string[];
    };
    redis: {
        host: string;
        port: number;
        password: string | undefined;
        db: number;
    };
    payment: {
        stripe: {
            secretKey: string;
            publishableKey: string;
            webhookSecret: string;
        };
    };
    frontendUrl: string;
};
export default config;
//# sourceMappingURL=config.d.ts.map