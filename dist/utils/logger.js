"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const config_1 = require("../config/config");
var LogLevel;
(function (LogLevel) {
    LogLevel[LogLevel["ERROR"] = 0] = "ERROR";
    LogLevel[LogLevel["WARN"] = 1] = "WARN";
    LogLevel[LogLevel["INFO"] = 2] = "INFO";
    LogLevel[LogLevel["DEBUG"] = 3] = "DEBUG";
})(LogLevel || (LogLevel = {}));
class Logger {
    constructor() {
        this.logLevel = this.getLogLevel(config_1.config.LOG_LEVEL);
    }
    getLogLevel(level) {
        switch (level.toLowerCase()) {
            case 'error':
                return LogLevel.ERROR;
            case 'warn':
                return LogLevel.WARN;
            case 'info':
                return LogLevel.INFO;
            case 'debug':
                return LogLevel.DEBUG;
            default:
                return LogLevel.INFO;
        }
    }
    formatMessage(level, message, meta) {
        const timestamp = new Date().toISOString();
        const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
        return `[${timestamp}] ${level.toUpperCase()}: ${message}${metaStr}`;
    }
    log(level, levelName, message, meta) {
        if (level <= this.logLevel) {
            const formattedMessage = this.formatMessage(levelName, message, meta);
            switch (level) {
                case LogLevel.ERROR:
                    console.error(formattedMessage);
                    break;
                case LogLevel.WARN:
                    console.warn(formattedMessage);
                    break;
                case LogLevel.INFO:
                    console.info(formattedMessage);
                    break;
                case LogLevel.DEBUG:
                    console.debug(formattedMessage);
                    break;
            }
        }
    }
    error(message, meta) {
        this.log(LogLevel.ERROR, 'error', message, meta);
    }
    warn(message, meta) {
        this.log(LogLevel.WARN, 'warn', message, meta);
    }
    info(message, meta) {
        this.log(LogLevel.INFO, 'info', message, meta);
    }
    debug(message, meta) {
        this.log(LogLevel.DEBUG, 'debug', message, meta);
    }
}
exports.logger = new Logger();
exports.default = exports.logger;
//# sourceMappingURL=logger.js.map