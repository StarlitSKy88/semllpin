import { type ClassValue } from 'clsx';
export declare function cn(...inputs: ClassValue[]): string;
export declare function formatDistance(distance: number): string;
export declare function formatTime(seconds: number): string;
export declare function formatReward(amount: number): string;
export declare function calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number;
export declare function calculateBearing(lat1: number, lon1: number, lat2: number, lon2: number): number;
export declare function debounce<T extends (...args: any[]) => any>(func: T, wait: number): (...args: Parameters<T>) => void;
export declare function throttle<T extends (...args: any[]) => any>(func: T, limit: number): (...args: Parameters<T>) => void;
//# sourceMappingURL=utils.d.ts.map