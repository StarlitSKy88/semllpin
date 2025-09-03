"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisMock = void 0;
class RedisMock {
    constructor() {
        this.store = new Map();
        this.connected = true;
    }
    async get(key) {
        const item = this.store.get(key);
        if (!item) {
            return null;
        }
        if (item.expires && Date.now() > item.expires) {
            this.store.delete(key);
            return null;
        }
        return item.value;
    }
    async set(key, value, ttl) {
        const item = { value };
        if (ttl) {
            item.expires = Date.now() + ttl * 1000;
        }
        this.store.set(key, item);
    }
    async del(key) {
        const existed = this.store.has(key);
        this.store.delete(key);
        return existed ? 1 : 0;
    }
    async exists(key) {
        const item = this.store.get(key);
        if (!item) {
            return 0;
        }
        if (item.expires && Date.now() > item.expires) {
            this.store.delete(key);
            return 0;
        }
        return 1;
    }
    async ping() {
        if (!this.connected) {
            throw new Error('Redis connection lost');
        }
        return 'PONG';
    }
    async info(section) {
        const mockInfo = {
            server: 'redis_version:6.2.0\nredis_mode:standalone',
            memory: 'used_memory:1048576\nused_memory_human:1.00M',
            stats: 'total_connections_received:100\ntotal_commands_processed:1000',
            replication: 'role:master\nconnected_slaves:0',
        };
        if (section && mockInfo[section]) {
            return mockInfo[section];
        }
        return Object.values(mockInfo).join('\n');
    }
    async quit() {
        this.connected = false;
        this.store.clear();
    }
    isConnected() {
        return this.connected;
    }
    getKeyCount() {
        return this.store.size;
    }
    cleanup() {
        const now = Date.now();
        for (const [key, item] of this.store.entries()) {
            if (item.expires && now > item.expires) {
                this.store.delete(key);
            }
        }
    }
    async incr(key) {
        const current = await this.get(key);
        const value = current ? parseInt(current, 10) : 0;
        const newValue = value + 1;
        await this.set(key, newValue.toString());
        return newValue;
    }
    async decr(key) {
        const current = await this.get(key);
        const value = current ? parseInt(current, 10) : 0;
        const newValue = value - 1;
        await this.set(key, newValue.toString());
        return newValue;
    }
    async expire(key, seconds) {
        const item = this.store.get(key);
        if (!item) {
            return 0;
        }
        item.expires = Date.now() + seconds * 1000;
        this.store.set(key, item);
        return 1;
    }
    async ttl(key) {
        const item = this.store.get(key);
        if (!item) {
            return -2;
        }
        if (!item.expires) {
            return -1;
        }
        const remaining = Math.ceil((item.expires - Date.now()) / 1000);
        return remaining > 0 ? remaining : -2;
    }
    async setex(key, seconds, value) {
        const expires = Date.now() + (seconds * 1000);
        this.store.set(key, { value, expires });
        return 'OK';
    }
}
exports.RedisMock = RedisMock;
const redisMock = new RedisMock();
setInterval(() => {
    redisMock.cleanup();
}, 60000);
exports.default = redisMock;
//# sourceMappingURL=redis-mock.js.map