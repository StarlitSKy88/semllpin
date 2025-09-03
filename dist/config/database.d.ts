import { Knex } from 'knex';
export declare const db: Knex<any, unknown[]>;
export declare const connectDatabase: () => Promise<void>;
export declare const disconnectDatabase: () => Promise<void>;
export declare const checkDatabaseHealth: () => Promise<boolean>;
export declare const withTransaction: <T>(callback: (trx: Knex.Transaction) => Promise<T>) => Promise<T>;
export declare const buildPaginationQuery: (query: Knex.QueryBuilder, page?: number, limit?: number) => Knex.QueryBuilder;
export declare const buildSearchQuery: (query: Knex.QueryBuilder, searchTerm: string, searchColumns: string[]) => Knex.QueryBuilder;
export declare const buildSortQuery: (query: Knex.QueryBuilder, sortBy?: string, sortOrder?: "asc" | "desc") => Knex.QueryBuilder;
export declare const buildLocationQuery: (query: Knex.QueryBuilder, latitude: number, longitude: number, radiusInMeters?: number) => Knex.QueryBuilder;
export declare const buildBoundsQuery: (query: Knex.QueryBuilder, bounds: {
    north: number;
    south: number;
    east: number;
    west: number;
}) => Knex.QueryBuilder;
export declare const monitorQuery: <T>(queryName: string, queryFn: () => Promise<T>) => Promise<T>;
export default db;
//# sourceMappingURL=database.d.ts.map