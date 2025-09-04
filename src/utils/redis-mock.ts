/**
 * Redis Mock 工具类
 * 用于在开发和测试环境中模拟Redis功能
 */

export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttl?: number): Promise<void>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<number>;
  ping(): Promise<string>;
  info(section?: string): Promise<string>;
  quit(): Promise<void>;
  connect?(): Promise<void>;
  incr(key: string): Promise<number>;
  decr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  ttl(key: string): Promise<number>;
  setex(key: string, seconds: number, value: string): Promise<string>;
  mget(...keys: string[]): Promise<(string | null)[]>;
  keys(pattern: string): Promise<string[]>;
  sadd(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
  srem(key: string, ...members: string[]): Promise<number>;
  sismember(key: string, member: string): Promise<number>;
  flushall(): Promise<string>;
}

class RedisMock implements RedisClient {
  private store: Map<string, { value: string; expires?: number }> = new Map();
  private sets: Map<string, Set<string>> = new Map();
  private connected: boolean = true;

  async get(key: string): Promise<string | null> {
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

  async set(key: string, value: string, ttl?: number): Promise<void> {
    const item: { value: string; expires?: number } = { value };
    if (ttl) {
      item.expires = Date.now() + ttl * 1000;
    }
    this.store.set(key, item);
  }

  async del(...keys: string[]): Promise<number> {
    let count = 0;
    keys.forEach(key => {
      if (this.store.has(key)) {
        this.store.delete(key);
        count++;
      }
      if (this.sets.has(key)) {
        this.sets.delete(key);
        count++;
      }
    });
    return count;
  }

  async exists(key: string): Promise<number> {
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

  async ping(): Promise<string> {
    if (!this.connected) {
      throw new Error('Redis connection lost');
    }
    return 'PONG';
  }

  async info(section?: string): Promise<string> {
    const mockInfo = {
      server: 'redis_version:6.2.0\nredis_mode:standalone',
      memory: 'used_memory:1048576\nused_memory_human:1.00M',
      stats: 'total_connections_received:100\ntotal_commands_processed:1000',
      replication: 'role:master\nconnected_slaves:0',
    };

    if (section && mockInfo[section as keyof typeof mockInfo]) {
      return mockInfo[section as keyof typeof mockInfo];
    }

    return Object.values(mockInfo).join('\n');
  }

  async connect(): Promise<void> {
    this.connected = true;
  }

  async quit(): Promise<void> {
    this.connected = false;
    this.store.clear();
    this.sets.clear();
  }

  // 模拟连接状态
  isConnected(): boolean {
    return this.connected;
  }

  // 获取存储的键数量
  getKeyCount(): number {
    return this.store.size;
  }

  // 清理过期键
  cleanup(): void {
    const now = Date.now();
    for (const [key, item] of this.store.entries()) {
      if (item.expires && now > item.expires) {
        this.store.delete(key);
      }
    }
  }

  async incr(key: string): Promise<number> {
    const current = await this.get(key);
    const value = current ? parseInt(current, 10) : 0;
    const newValue = value + 1;
    await this.set(key, newValue.toString());
    return newValue;
  }

  async decr(key: string): Promise<number> {
    const current = await this.get(key);
    const value = current ? parseInt(current, 10) : 0;
    const newValue = value - 1;
    await this.set(key, newValue.toString());
    return newValue;
  }

  async expire(key: string, seconds: number): Promise<number> {
    const item = this.store.get(key);
    if (!item) {
      return 0;
    }
    item.expires = Date.now() + seconds * 1000;
    this.store.set(key, item);
    return 1;
  }

  async ttl(key: string): Promise<number> {
    const item = this.store.get(key);
    if (!item) {
      return -2;
    } // Key doesn't exist
    if (!item.expires) {
      return -1;
    } // Key exists but has no expiry

    const remaining = Math.ceil((item.expires - Date.now()) / 1000);
    return remaining > 0 ? remaining : -2;
  }

  async setex(key: string, seconds: number, value: string): Promise<string> {
    const expires = Date.now() + (seconds * 1000);
    this.store.set(key, { value, expires });
    return 'OK';
  }

  async mget(...keys: string[]): Promise<(string | null)[]> {
    return Promise.all(keys.map(key => this.get(key)));
  }

  async keys(pattern: string): Promise<string[]> {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    const allKeys = [...this.store.keys(), ...this.sets.keys()];
    return allKeys.filter(key => regex.test(key));
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    if (!this.sets.has(key)) {
      this.sets.set(key, new Set());
    }
    const set = this.sets.get(key)!;
    let added = 0;
    members.forEach(member => {
      if (!set.has(member)) {
        set.add(member);
        added++;
      }
    });
    return added;
  }

  async smembers(key: string): Promise<string[]> {
    const set = this.sets.get(key);
    return set ? Array.from(set) : [];
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    const set = this.sets.get(key);
    if (!set) return 0;
    
    let removed = 0;
    members.forEach(member => {
      if (set.has(member)) {
        set.delete(member);
        removed++;
      }
    });
    
    if (set.size === 0) {
      this.sets.delete(key);
    }
    return removed;
  }

  async sismember(key: string, member: string): Promise<number> {
    const set = this.sets.get(key);
    return set && set.has(member) ? 1 : 0;
  }

  async flushall(): Promise<string> {
    this.store.clear();
    this.sets.clear();
    return 'OK';
  }
}

// 导出单例实例
const redisMock = new RedisMock();

// 定期清理过期键（测试环境禁用）
const isTestEnv = (process.env['NODE_ENV'] === 'test') || (typeof process.env['JEST_WORKER_ID'] !== 'undefined');
if (!isTestEnv) {
  const interval = setInterval(() => {
    redisMock.cleanup();
  }, 60000); // 每分钟清理一次
  const maybeUnref = (interval as any).unref;
  if (typeof maybeUnref === 'function') {
    maybeUnref.call(interval);
  }
}

export default redisMock;
export { RedisMock };
