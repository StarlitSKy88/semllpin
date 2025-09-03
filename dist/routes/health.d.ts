declare const router: import("express-serve-static-core").Router;
declare const updateMetrics: {
    incrementRequests: () => number;
    incrementErrors: () => number;
    setActiveConnections: (count: number) => number;
};
export { router as healthRouter, updateMetrics };
//# sourceMappingURL=health.d.ts.map