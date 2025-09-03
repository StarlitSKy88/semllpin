import { Request, Response } from 'express';
declare class MonitorController {
    getWebSocketStats(_req: Request, res: Response): Promise<Response>;
    getNotificationStats(_req: Request, res: Response): Promise<void>;
    getSystemStats(_req: Request, res: Response): Promise<void>;
    getApiStats(_req: Request, res: Response): Promise<Response>;
    getUserActivityStats(_req: Request, res: Response): Promise<void>;
    getAlerts(_req: Request, res: Response): Promise<void>;
    getSystemMetrics(_req: Request, res: Response): Promise<void>;
    getPrometheusMetrics(_req: Request, res: Response): Promise<void>;
    getPerformanceMetrics(_req: Request, res: Response): Promise<void>;
    getBusinessMetrics(_req: Request, res: Response): Promise<void>;
    getErrorMetrics(_req: Request, res: Response): Promise<void>;
    getOverviewStats(_req: Request, res: Response): Promise<void>;
    private getCPUUsage;
    private getWebSocketStatsData;
    private getNotificationStatsData;
    private getSystemStatsData;
    private getApiStatsData;
    private getUserActivityStatsData;
    getStats(req: Request, res: Response): Promise<void>;
    getHealth(req: Request, res: Response): Promise<void>;
    getPerformance(req: Request, res: Response): Promise<void>;
    private getDiskUsage;
    private getNewUsersThisWeek;
    private getNewUsersThisMonth;
    private getTopActivities;
    private formatActivityName;
    private getSystemAlerts;
}
declare const _default: MonitorController;
export default _default;
//# sourceMappingURL=monitorController.d.ts.map