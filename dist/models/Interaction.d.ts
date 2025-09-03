export declare enum LikeType {
    ANNOTATION = "annotation",
    COMMENT = "comment",
    USER = "user"
}
export declare enum FavoriteType {
    ANNOTATION = "annotation",
    USER = "user"
}
export interface Like {
    id: string;
    userId: string;
    targetId: string;
    targetType: LikeType;
    createdAt: Date;
    updatedAt: Date;
    user?: {
        id: string;
        username: string;
        avatar?: string;
    };
}
export interface Favorite {
    id: string;
    userId: string;
    targetId: string;
    targetType: FavoriteType;
    createdAt: Date;
    updatedAt: Date;
    annotation?: {
        id: string;
        title: string;
        description: string;
        imageUrl?: string;
        location: string;
        latitude: number;
        longitude: number;
    };
    user?: {
        id: string;
        username: string;
        avatar?: string;
    };
}
export interface InteractionStats {
    targetId: string;
    targetType: string;
    likeCount: number;
    favoriteCount: number;
    isLiked: boolean;
    isFavorited: boolean;
}
export interface CreateLikeData {
    userId: string;
    targetId: string;
    targetType: LikeType;
}
export interface CreateFavoriteData {
    userId: string;
    targetId: string;
    targetType: FavoriteType;
}
export interface UserActivityStats {
    timeRange: string;
    totalLikes: number;
    totalFavorites: number;
    totalActivity: number;
    likesByType: Record<string, number>;
    favoritesByType: Record<string, number>;
    dailyActivity: Array<{
        date: string;
        likes: number;
        favorites: number;
        total: number;
    }>;
    averageDailyActivity: number;
}
export interface PopularContent {
    targetId: string;
    targetType: string;
    likeCount: number;
    recentLikes: Like[];
}
export declare class LikeModel {
    static create(data: CreateLikeData): Promise<Like>;
    static delete(userId: string, targetId: string, targetType: LikeType): Promise<boolean>;
    static exists(userId: string, targetId: string, targetType: LikeType): Promise<boolean>;
    static getUserLikes(userId: string, options?: {
        page?: number;
        limit?: number;
        targetType?: LikeType;
    }): Promise<{
        likes: Like[];
        total: number;
    }>;
    static getTargetLikeCount(targetId: string, targetType: LikeType): Promise<number>;
    static getPopularContent(options?: {
        targetType?: LikeType;
        limit?: number;
        timeRange?: string;
    }): Promise<PopularContent[]>;
    private static mapRowToLike;
}
export declare class FavoriteModel {
    static create(data: CreateFavoriteData): Promise<Favorite>;
    static delete(userId: string, targetId: string, targetType: FavoriteType): Promise<boolean>;
    static exists(userId: string, targetId: string, targetType: FavoriteType): Promise<boolean>;
    static getUserFavorites(userId: string, options?: {
        page?: number;
        limit?: number;
        targetType?: FavoriteType;
    }): Promise<{
        favorites: Favorite[];
        total: number;
    }>;
    static getTargetFavoriteCount(targetId: string, targetType: FavoriteType): Promise<number>;
    private static mapRowToFavorite;
}
export declare class InteractionModel {
    static getInteractionStats(targetId: string, targetType: string, userId?: string): Promise<InteractionStats>;
    static getUserActivityStats(userId: string, timeRange?: string): Promise<UserActivityStats>;
}
//# sourceMappingURL=Interaction.d.ts.map