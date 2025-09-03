import { Request, Response, NextFunction } from 'express';
import client from 'prom-client';
export declare const prometheusMiddleware: (req: Request, res: Response, next: NextFunction) => void;
export declare const metricsHandler: (_req: Request, res: Response) => Promise<void>;
export declare const metrics: {
    httpRequestsTotal: client.Counter<"route" | "method" | "status_code" | "user_agent">;
    httpRequestDuration: client.Histogram<"route" | "method" | "status_code">;
    activeUsers: client.Gauge<string>;
    databaseConnections: client.Gauge<"state">;
    redisConnections: client.Gauge<"state">;
    annotationsCreated: client.Counter<"country" | "intensity_level">;
    lbsRewards: client.Counter<"reward_type" | "location_type">;
    paymentSuccess: client.Counter<"status" | "payment_method">;
    websocketConnections: client.Gauge<string>;
    errorRate: client.Counter<"error_type" | "endpoint">;
    systemResources: client.Gauge<"resource_type">;
    register: client.Registry<"text/plain; version=0.0.4; charset=utf-8">;
};
export declare const recordBusinessMetrics: {
    annotationCreated: (country: string, intensityLevel: string) => void;
    lbsReward: (rewardType: string, locationType: string) => void;
    payment: (status: "success" | "failed", paymentMethod: string) => void;
    updateActiveUsers: (count: number) => void;
    updateWebSocketConnections: (count: number) => void;
    updateDatabaseConnections: (active: number, idle: number, waiting: number) => void;
    updateRedisConnections: (connected: number, disconnected: number) => void;
};
declare const _default: {
    prometheusMiddleware: (req: Request, res: Response, next: NextFunction) => void;
    metricsHandler: (_req: Request, res: Response) => Promise<void>;
    metrics: {
        httpRequestsTotal: client.Counter<"route" | "method" | "status_code" | "user_agent">;
        httpRequestDuration: client.Histogram<"route" | "method" | "status_code">;
        activeUsers: client.Gauge<string>;
        databaseConnections: client.Gauge<"state">;
        redisConnections: client.Gauge<"state">;
        annotationsCreated: client.Counter<"country" | "intensity_level">;
        lbsRewards: client.Counter<"reward_type" | "location_type">;
        paymentSuccess: client.Counter<"status" | "payment_method">;
        websocketConnections: client.Gauge<string>;
        errorRate: client.Counter<"error_type" | "endpoint">;
        systemResources: client.Gauge<"resource_type">;
        register: client.Registry<"text/plain; version=0.0.4; charset=utf-8">;
    };
    recordBusinessMetrics: {
        annotationCreated: (country: string, intensityLevel: string) => void;
        lbsReward: (rewardType: string, locationType: string) => void;
        payment: (status: "success" | "failed", paymentMethod: string) => void;
        updateActiveUsers: (count: number) => void;
        updateWebSocketConnections: (count: number) => void;
        updateDatabaseConnections: (active: number, idle: number, waiting: number) => void;
        updateRedisConnections: (connected: number, disconnected: number) => void;
    };
};
export default _default;
//# sourceMappingURL=prometheus.d.ts.map