interface Location {
    latitude: number;
    longitude: number;
    accuracy: number;
    altitude: number | undefined;
    heading: number | undefined;
    speed: number | undefined;
    timestamp: number;
}
interface Geofence {
    id: string;
    name: string;
    description?: string;
    latitude: number;
    longitude: number;
    radius: number;
    rewardType: 'discovery' | 'checkin' | 'stay' | 'social';
    baseReward: number;
    isActive: boolean;
    createdBy: string;
    createdAt: string;
    distance?: number;
}
interface RewardRecord {
    id: string;
    userId: string;
    geofenceId: string;
    geofenceName: string;
    rewardType: 'discovery' | 'checkin' | 'stay' | 'social';
    baseReward: number;
    timeDecay: number;
    firstDiscoveryBonus: number;
    extraReward: number;
    finalPoints: number;
    latitude: number;
    longitude: number;
    timestamp: string;
    metadata?: any;
}
interface LocationReportResponse {
    success: boolean;
    rewards?: RewardRecord[];
    geofences?: Geofence[];
    message?: string;
}
interface LBSSettings {
    trackingEnabled: boolean;
    highAccuracy: boolean;
    updateInterval: number;
    backgroundTracking: boolean;
    autoReportLocation: boolean;
    notificationsEnabled: boolean;
}
interface LBSState {
    isTracking: boolean;
    isOnline: boolean;
    lastReportTime: number | null;
    currentLocation: Location | null;
    locationHistory: Location[];
    nearbyGeofences: Geofence[];
    enteredGeofences: string[];
    recentRewards: RewardRecord[];
    totalRewards: number;
    todayRewards: number;
    settings: LBSSettings;
    isLoading: boolean;
    error: string | null;
    hasLocationPermission: boolean;
    hasNotificationPermission: boolean;
}
interface LBSActions {
    startTracking: () => Promise<void>;
    stopTracking: () => void;
    setTracking: (tracking: boolean) => void;
    updateLocation: (location: Location) => void;
    reportLocation: (location: Location) => Promise<LocationReportResponse>;
    clearLocationHistory: () => void;
    fetchNearbyGeofences: (location: Location, radius?: number) => Promise<void>;
    checkGeofenceEntry: (location: Location) => void;
    addReward: (reward: RewardRecord) => void;
    fetchRewardHistory: (limit?: number, offset?: number) => Promise<void>;
    claimReward: (rewardId: string) => Promise<void>;
    updateSettings: (settings: Partial<LBSSettings>) => void;
    requestLocationPermission: () => Promise<boolean>;
    requestNotificationPermission: () => Promise<boolean>;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
    setOnlineStatus: (online: boolean) => void;
    reset: () => void;
}
type LBSStore = LBSState & LBSActions;
export declare const useLBSStore: import("zustand").UseBoundStore<Omit<import("zustand").StoreApi<LBSStore>, "setState" | "persist"> & {
    setState(partial: LBSStore | Partial<LBSStore> | ((state: LBSStore) => LBSStore | Partial<LBSStore>), replace?: false | undefined): unknown;
    setState(state: LBSStore | ((state: LBSStore) => LBSStore), replace: true): unknown;
    persist: {
        setOptions: (options: Partial<import("zustand/middleware").PersistOptions<LBSStore, {
            settings: LBSSettings;
            totalRewards: number;
            hasLocationPermission: boolean;
            hasNotificationPermission: boolean;
        }, unknown>>) => void;
        clearStorage: () => void;
        rehydrate: () => Promise<void> | void;
        hasHydrated: () => boolean;
        onHydrate: (fn: (state: LBSStore) => void) => () => void;
        onFinishHydration: (fn: (state: LBSStore) => void) => () => void;
        getOptions: () => Partial<import("zustand/middleware").PersistOptions<LBSStore, {
            settings: LBSSettings;
            totalRewards: number;
            hasLocationPermission: boolean;
            hasNotificationPermission: boolean;
        }, unknown>>;
    };
}>;
export default useLBSStore;
export type { Location, Geofence, RewardRecord, LBSSettings };
//# sourceMappingURL=lbsStore.d.ts.map