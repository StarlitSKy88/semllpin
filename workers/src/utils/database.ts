import { Pool, PoolClient } from 'pg';

export interface DatabaseClient {
  from: (table: string) => QueryBuilder;
  rpc: (fn: string, params?: any) => Promise<{ data: any; error: any }>;
  auth: AuthClient;
}

export interface QueryBuilder {
  select: (columns?: string) => SelectBuilder;
  insert: (data: any) => InsertBuilder;
  update: (data: any) => UpdateBuilder;
  delete: () => DeleteBuilder;
}

export interface SelectBuilder {
  eq: (column: string, value: any) => SelectBuilder;
  neq: (column: string, value: any) => SelectBuilder;
  gt: (column: string, value: any) => SelectBuilder;
  gte: (column: string, value: any) => SelectBuilder;
  lt: (column: string, value: any) => SelectBuilder;
  lte: (column: string, value: any) => SelectBuilder;
  like: (column: string, value: any) => SelectBuilder;
  ilike: (column: string, value: any) => SelectBuilder;
  in: (column: string, values: any[]) => SelectBuilder;
  is: (column: string, value: any) => SelectBuilder;
  limit: (count: number) => SelectBuilder;
  order: (column: string, options?: { ascending?: boolean }) => SelectBuilder;
  range: (from: number, to: number) => Promise<{ data: any[]; error: any }>;
  single: () => Promise<{ data: any; error: any }>;
  then: (resolve: any) => Promise<{ data: any[]; error: any }>;
}

export interface InsertBuilder {
  select: (columns?: string) => Promise<{ data: any; error: any }>;
  then: (resolve: any) => Promise<{ data: any; error: any }>;
}

export interface UpdateBuilder {
  eq: (column: string, value: any) => Promise<{ data: any; error: any }>;
  then: (resolve: any) => Promise<{ data: any; error: any }>;
}

export interface DeleteBuilder {
  eq: (column: string, value: any) => Promise<{ data: any; error: any }>;
  then: (resolve: any) => Promise<{ data: any; error: any }>;
}

export interface AuthClient {
  getUser: () => Promise<{ data: { user: any }; error: any }>;
  signUp: (credentials: any) => Promise<{ data: any; error: any }>;
  signInWithPassword: (credentials: any) => Promise<{ data: any; error: any }>;
  signOut: () => Promise<{ error: any }>;
  resetPasswordForEmail: (email: string, options?: any) => Promise<{ error: any }>;
  updateUser: (data: any) => Promise<{ error: any }>;
}

class PostgreSQLQueryBuilder implements QueryBuilder {
  private pool: Pool;
  private tableName: string;
  private selectColumns: string = '*';
  private whereConditions: string[] = [];
  private whereValues: any[] = [];
  private orderByClause: string = '';
  private limitClause: string = '';
  private offsetClause: string = '';
  private paramCounter: number = 1;

  constructor(pool: Pool, tableName: string) {
    this.pool = pool;
    this.tableName = tableName;
  }

  select(columns?: string): SelectBuilder {
    this.selectColumns = columns || '*';
    return this as any;
  }

  insert(data: any): InsertBuilder {
    const columns = Object.keys(data).join(', ');
    const placeholders = Object.keys(data).map((_, i) => `$${i + 1}`).join(', ');
    const values = Object.values(data);
    
    const query = `INSERT INTO ${this.tableName} (${columns}) VALUES (${placeholders}) RETURNING *`;
    
    return {
      select: async (returnColumns?: string) => {
        try {
          const result = await this.pool.query(query, values);
          return { data: result.rows[0], error: null };
        } catch (error) {
          return { data: null, error };
        }
      },
      then: async (resolve: any) => {
        try {
          const result = await this.pool.query(query, values);
          return resolve({ data: result.rows[0], error: null });
        } catch (error) {
          return resolve({ data: null, error });
        }
      }
    };
  }

  update(data: any): UpdateBuilder {
    const setClause = Object.keys(data).map((key, i) => `${key} = $${i + 1}`).join(', ');
    const values = Object.values(data);
    
    return {
      eq: async (column: string, value: any) => {
        const query = `UPDATE ${this.tableName} SET ${setClause} WHERE ${column} = $${values.length + 1} RETURNING *`;
        try {
          const result = await this.pool.query(query, [...values, value]);
          return { data: result.rows[0], error: null };
        } catch (error) {
          return { data: null, error };
        }
      },
      then: async (resolve: any) => {
        const query = `UPDATE ${this.tableName} SET ${setClause} RETURNING *`;
        try {
          const result = await this.pool.query(query, values);
          return resolve({ data: result.rows, error: null });
        } catch (error) {
          return resolve({ data: null, error });
        }
      }
    };
  }

  delete(): DeleteBuilder {
    return {
      eq: async (column: string, value: any) => {
        const query = `DELETE FROM ${this.tableName} WHERE ${column} = $1 RETURNING *`;
        try {
          const result = await this.pool.query(query, [value]);
          return { data: result.rows, error: null };
        } catch (error) {
          return { data: null, error };
        }
      },
      then: async (resolve: any) => {
        const query = `DELETE FROM ${this.tableName} RETURNING *`;
        try {
          const result = await this.pool.query(query);
          return resolve({ data: result.rows, error: null });
        } catch (error) {
          return resolve({ data: null, error });
        }
      }
    };
  }

  eq(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} = $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  neq(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} != $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  gt(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} > $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  gte(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} >= $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  lt(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} < $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  lte(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} <= $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  like(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} LIKE $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  ilike(column: string, value: any): SelectBuilder {
    this.whereConditions.push(`${column} ILIKE $${this.paramCounter}`);
    this.whereValues.push(value);
    this.paramCounter++;
    return this as any;
  }

  in(column: string, values: any[]): SelectBuilder {
    const placeholders = values.map((_, i) => `$${this.paramCounter + i}`).join(', ');
    this.whereConditions.push(`${column} IN (${placeholders})`);
    this.whereValues.push(...values);
    this.paramCounter += values.length;
    return this as any;
  }

  is(column: string, value: any): SelectBuilder {
    if (value === null) {
      this.whereConditions.push(`${column} IS NULL`);
    } else {
      this.whereConditions.push(`${column} IS $${this.paramCounter}`);
      this.whereValues.push(value);
      this.paramCounter++;
    }
    return this as any;
  }

  limit(count: number): SelectBuilder {
    this.limitClause = `LIMIT ${count}`;
    return this as any;
  }

  order(column: string, options?: { ascending?: boolean }): SelectBuilder {
    const direction = options?.ascending === false ? 'DESC' : 'ASC';
    this.orderByClause = `ORDER BY ${column} ${direction}`;
    return this as any;
  }

  async range(from: number, to: number): Promise<{ data: any[]; error: any }> {
    this.offsetClause = `OFFSET ${from}`;
    this.limitClause = `LIMIT ${to - from + 1}`;
    return this.executeSelect();
  }

  async single(): Promise<{ data: any; error: any }> {
    this.limitClause = 'LIMIT 1';
    const result = await this.executeSelect();
    return {
      data: result.data?.[0] || null,
      error: result.error
    };
  }

  async then(resolve: any): Promise<{ data: any[]; error: any }> {
    const result = await this.executeSelect();
    return resolve(result);
  }

  private async executeSelect(): Promise<{ data: any[]; error: any }> {
    let query = `SELECT ${this.selectColumns} FROM ${this.tableName}`;
    
    if (this.whereConditions.length > 0) {
      query += ` WHERE ${this.whereConditions.join(' AND ')}`;
    }
    
    if (this.orderByClause) {
      query += ` ${this.orderByClause}`;
    }
    
    if (this.limitClause) {
      query += ` ${this.limitClause}`;
    }
    
    if (this.offsetClause) {
      query += ` ${this.offsetClause}`;
    }

    try {
      const result = await this.pool.query(query, this.whereValues);
      return { data: result.rows, error: null };
    } catch (error) {
      return { data: [], error };
    }
  }
}

class PostgreSQLClient implements DatabaseClient {
  private pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  from(table: string): QueryBuilder {
    return new PostgreSQLQueryBuilder(this.pool, table);
  }

  async rpc(fn: string, params?: any): Promise<{ data: any; error: any }> {
    try {
      const paramNames = params ? Object.keys(params) : [];
      const paramValues = params ? Object.values(params) : [];
      const paramPlaceholders = paramValues.map((_, i) => `$${i + 1}`).join(', ');
      
      const query = `SELECT ${fn}(${paramPlaceholders}) as result`;
      const result = await this.pool.query(query, paramValues);
      
      return { data: result.rows[0]?.result, error: null };
    } catch (error) {
      return { data: null, error };
    }
  }

  auth: AuthClient = {
    getUser: async () => ({ data: { user: null }, error: null }),
    signUp: async () => ({ data: null, error: null }),
    signInWithPassword: async () => ({ data: null, error: null }),
    signOut: async () => ({ error: null }),
    resetPasswordForEmail: async () => ({ error: null }),
    updateUser: async () => ({ error: null })
  };
}

/**
 * Create a database client using PostgreSQL
 */
export function createDatabaseClient(env: any): DatabaseClient {
  if (!env.DATABASE_URL) {
    throw new Error('DATABASE_URL environment variable is required');
  }

  console.log('Using PostgreSQL connection:', env.DATABASE_URL.replace(/:\/\/[^@]+@/, '://***:***@'));
  
  const pool = new Pool({
    connectionString: env.DATABASE_URL,
    ssl: env.DATABASE_URL.includes('neon.tech') ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  return new PostgreSQLClient(pool);
}

/**
 * Get database configuration info for debugging
 */
export function getDatabaseInfo(env: any): { type: string; url?: string } {
  if (env.DATABASE_URL) {
    return {
      type: 'PostgreSQL',
      url: env.DATABASE_URL.replace(/:\/\/[^@]+@/, '://***:***@')
    };
  }
  
  return { type: 'None' };
}