"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.schedule = void 0;
const cron = {
    schedule: () => {
        let running = false;
        return {
            start: () => { running = true; },
            stop: () => { running = false; },
            getStatus: () => running,
            unref: () => { }
        };
    }
};
exports.default = cron;
exports.schedule = cron.schedule;
//# sourceMappingURL=node-cron.js.map