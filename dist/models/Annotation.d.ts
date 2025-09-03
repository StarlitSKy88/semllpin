export interface Annotation {
    id: string;
    user_id: string;
    latitude: number;
    longitude: number;
    location_point: string;
    smell_intensity: number;
    description?: string;
    country?: string;
    region?: string;
    city?: string;
    address?: string;
    status: 'pending' | 'approved' | 'rejected';
    moderation_reason?: string;
    moderated_by?: string;
    moderated_at?: Date;
    payment_id?: string;
    media_files: string[];
    view_count: number;
    like_count: number;
    comment_count: number;
    created_at: Date;
    updated_at: Date;
}
export interface CreateAnnotationData {
    user_id: string;
    latitude: number;
    longitude: number;
    smell_intensity: number;
    description?: string;
    media_files?: string[];
    payment_id?: string;
}
export interface UpdateAnnotationData {
    smell_intensity?: number;
    description?: string;
    status?: 'pending' | 'approved' | 'rejected';
    moderation_reason?: string;
    moderated_by?: string;
    moderated_at?: Date;
}
export interface AnnotationFilters {
    latitude?: number;
    longitude?: number;
    radius?: number;
    intensityMin?: number;
    intensityMax?: number;
    country?: string;
    region?: string;
    city?: string;
    status?: string;
    userId?: string;
    startDate?: Date;
    endDate?: Date;
}
export interface AnnotationStats {
    total: number;
    byIntensity: Record<number, number>;
    byCountry: Record<string, number>;
    byMonth: Record<string, number>;
    avgIntensity: number;
}
export declare class AnnotationModel {
    static create(annotationData: CreateAnnotationData): Promise<Annotation>;
    static findById(id: string): Promise<Annotation | null>;
    static update(id: string, updateData: UpdateAnnotationData): Promise<Annotation | null>;
    static getList(options?: {
        page?: number;
        limit?: number;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
        filters?: AnnotationFilters;
    }): Promise<{
        annotations: Annotation[];
        total: number;
    }>;
    static getMapData(bounds: {
        north: number;
        south: number;
        east: number;
        west: number;
    }, options?: {
        zoom?: number;
        intensityMin?: number;
        intensityMax?: number;
    }): Promise<Annotation[]>;
    static getNearby(latitude: number, longitude: number, radius?: number, limit?: number): Promise<Annotation[]>;
    static incrementViewCount(id: string): Promise<void>;
    static incrementLikeCount(id: string): Promise<void>;
    static decrementLikeCount(id: string): Promise<void>;
    static updateCommentCount(id: string): Promise<void>;
    static getStats(filters?: AnnotationFilters): Promise<AnnotationStats>;
    static delete(id: string): Promise<boolean>;
    static getUserAnnotations(userId: string, options?: {
        page?: number;
        limit?: number;
        status?: string;
    }): Promise<{
        annotations: Annotation[];
        total: number;
    }>;
    static moderate(id: string, status: 'approved' | 'rejected', moderatorId: string, reason?: string): Promise<Annotation | null>;
}
export default AnnotationModel;
//# sourceMappingURL=Annotation.d.ts.map