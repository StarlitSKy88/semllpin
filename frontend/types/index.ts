/**
 * SmellPin Application Type Definitions
 * Comprehensive type system for production-ready code
 */

// ==================== COMMON TYPES ====================

export type ID = string;
export type Timestamp = string; // ISO 8601 format
export type Currency = 'CNY' | 'USD' | 'EUR';
export type Status = 'active' | 'inactive' | 'pending' | 'suspended';

// ==================== GEOLOCATION TYPES ====================

export interface Coordinates {
  readonly latitude: number;
  readonly longitude: number;
  readonly accuracy?: number;
  readonly altitude?: number;
  readonly altitudeAccuracy?: number;
  readonly heading?: number;
  readonly speed?: number;
}

export interface GeofenceArea {
  readonly id: ID;
  readonly center: Coordinates;
  readonly radius: number; // in meters
  readonly name: string;
  readonly description?: string;
  readonly isActive: boolean;
  readonly createdAt: Timestamp;
  readonly updatedAt: Timestamp;
}

export interface LocationData {
  readonly coordinates: Coordinates;
  readonly timestamp: Timestamp;
  readonly address?: string;
  readonly city?: string;
  readonly country?: string;
  readonly isVerified: boolean;
}

// ==================== USER SYSTEM TYPES ====================

export interface User {
  readonly id: ID;
  readonly email: string;
  readonly username: string;
  readonly displayName: string;
  readonly avatar?: string;
  readonly bio?: string;
  readonly status: Status;
  readonly role: 'user' | 'moderator' | 'admin';
  readonly preferences: UserPreferences;
  readonly stats: UserStats;
  readonly createdAt: Timestamp;
  readonly updatedAt: Timestamp;
  readonly lastActiveAt: Timestamp;
}

export interface UserPreferences {
  readonly theme: 'light' | 'dark' | 'system';
  readonly language: 'zh-CN' | 'en-US';
  readonly notifications: NotificationSettings;
  readonly privacy: PrivacySettings;
  readonly lbsSettings: LBSSettings;
}

export interface NotificationSettings {
  readonly email: boolean;
  readonly push: boolean;
  readonly sms: boolean;
  readonly rewards: boolean;
  readonly annotations: boolean;
  readonly social: boolean;
}

export interface PrivacySettings {
  readonly profileVisibility: 'public' | 'friends' | 'private';
  readonly locationSharing: boolean;
  readonly activitySharing: boolean;
}

export interface LBSSettings {
  readonly autoCheckIn: boolean;
  readonly geofenceNotifications: boolean;
  readonly rewardNotifications: boolean;
  readonly accuracyThreshold: number; // in meters
}

export interface UserStats {
  readonly totalAnnotations: number;
  readonly totalRewards: number;
  readonly totalEarnings: number;
  readonly level: number;
  readonly experience: number;
  readonly checkinStreak: number;
  readonly friendsCount: number;
}

// ==================== ANNOTATION SYSTEM TYPES ====================

export interface Annotation {
  readonly id: ID;
  readonly creatorId: ID;
  readonly location: LocationData;
  readonly title: string;
  readonly description: string;
  readonly category: AnnotationCategory;
  readonly media: MediaItem[];
  readonly tags: string[];
  readonly visibility: 'public' | 'friends' | 'private';
  readonly isPaid: boolean;
  readonly price?: number;
  readonly currency: Currency;
  readonly interactions: AnnotationInteractions;
  readonly status: 'active' | 'reported' | 'hidden' | 'deleted';
  readonly expiresAt?: Timestamp;
  readonly createdAt: Timestamp;
  readonly updatedAt: Timestamp;
}

export type AnnotationCategory = 
  | 'funny'
  | 'weird' 
  | 'scary'
  | 'romantic'
  | 'historical'
  | 'food'
  | 'nature'
  | 'urban'
  | 'other';

export interface MediaItem {
  readonly id: ID;
  readonly type: 'image' | 'video' | 'audio';
  readonly url: string;
  readonly thumbnailUrl?: string;
  readonly caption?: string;
  readonly size: number; // in bytes
  readonly duration?: number; // for video/audio in seconds
  readonly metadata?: Record<string, unknown>;
}

export interface AnnotationInteractions {
  readonly likes: number;
  readonly dislikes: number;
  readonly comments: number;
  readonly shares: number;
  readonly views: number;
  readonly reports: number;
}

// ==================== LBS REWARD SYSTEM TYPES ====================

export interface Reward {
  readonly id: ID;
  readonly userId: ID;
  readonly annotationId?: ID;
  readonly type: RewardType;
  readonly amount: number;
  readonly currency: Currency;
  readonly location: LocationData;
  readonly reason: string;
  readonly metadata: RewardMetadata;
  readonly status: 'pending' | 'completed' | 'expired' | 'cancelled';
  readonly claimedAt?: Timestamp;
  readonly expiresAt?: Timestamp;
  readonly createdAt: Timestamp;
}

export type RewardType = 
  | 'checkin'
  | 'annotation_view'
  | 'annotation_like'
  | 'annotation_comment'
  | 'referral'
  | 'milestone'
  | 'daily_bonus'
  | 'location_discovery';

export interface RewardMetadata {
  readonly geofenceId?: ID;
  readonly distance?: number;
  readonly accuracy?: number;
  readonly verificationMethod: 'gps' | 'qr_code' | 'nfc' | 'manual';
  readonly fraudScore?: number;
  readonly bonusMultiplier?: number;
}

export interface RewardPool {
  readonly id: ID;
  readonly annotationId: ID;
  readonly totalAmount: number;
  readonly remainingAmount: number;
  readonly currency: Currency;
  readonly maxRewardPerUser: number;
  readonly minDistance: number; // minimum distance to claim in meters
  readonly maxDistance: number; // maximum distance to claim in meters
  readonly isActive: boolean;
  readonly expiresAt?: Timestamp;
  readonly createdAt: Timestamp;
}

// ==================== PAYMENT SYSTEM TYPES ====================

export interface Wallet {
  readonly id: ID;
  readonly userId: ID;
  readonly balance: number;
  readonly currency: Currency;
  readonly frozenBalance: number;
  readonly totalEarned: number;
  readonly totalSpent: number;
  readonly lastTransactionAt?: Timestamp;
  readonly createdAt: Timestamp;
  readonly updatedAt: Timestamp;
}

export interface Transaction {
  readonly id: ID;
  readonly walletId: ID;
  readonly type: TransactionType;
  readonly amount: number;
  readonly currency: Currency;
  readonly status: TransactionStatus;
  readonly description: string;
  readonly reference?: string; // External payment reference
  readonly metadata: TransactionMetadata;
  readonly createdAt: Timestamp;
  readonly completedAt?: Timestamp;
}

export type TransactionType = 
  | 'deposit'
  | 'withdrawal'
  | 'reward_earned'
  | 'annotation_payment'
  | 'refund'
  | 'fee'
  | 'bonus';

export type TransactionStatus = 
  | 'pending'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'refunded';

export interface TransactionMetadata {
  readonly paymentMethod?: 'alipay' | 'wechat' | 'bank_card' | 'paypal';
  readonly externalTransactionId?: string;
  readonly failureReason?: string;
  readonly processingFee?: number;
  readonly exchangeRate?: number;
  readonly relatedAnnotationId?: ID;
  readonly relatedRewardId?: ID;
}

// ==================== API RESPONSE TYPES ====================

export interface ApiResponse<T = unknown> {
  readonly success: boolean;
  readonly data?: T;
  readonly error?: ApiError;
  readonly metadata?: ResponseMetadata;
}

export interface ApiError {
  readonly code: string;
  readonly message: string;
  readonly details?: Record<string, unknown>;
  readonly timestamp: Timestamp;
  readonly requestId?: string;
}

export interface ResponseMetadata {
  readonly pagination?: PaginationInfo;
  readonly requestId: string;
  readonly timestamp: Timestamp;
  readonly version: string;
}

export interface PaginationInfo {
  readonly page: number;
  readonly limit: number;
  readonly total: number;
  readonly totalPages: number;
  readonly hasNext: boolean;
  readonly hasPrevious: boolean;
}

// ==================== FORM AND VALIDATION TYPES ====================

export interface CreateAnnotationForm {
  title: string;
  description: string;
  category: AnnotationCategory;
  tags: string[];
  visibility: 'public' | 'friends' | 'private';
  isPaid: boolean;
  price?: number;
  currency: Currency;
  media: File[];
  location: Coordinates;
}

export interface LoginForm {
  email: string;
  password: string;
  rememberMe: boolean;
}

export interface RegisterForm {
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
  displayName: string;
  agreeToTerms: boolean;
}

export interface ValidationError {
  readonly field: string;
  readonly message: string;
  readonly code: string;
}

// ==================== STATE MANAGEMENT TYPES ====================

export interface AppState {
  readonly user: UserState;
  readonly auth: AuthState;
  readonly location: LocationState;
  readonly annotations: AnnotationsState;
  readonly rewards: RewardsState;
  readonly ui: UIState;
}

export interface UserState {
  readonly currentUser: User | null;
  readonly profile: User | null;
  readonly stats: UserStats | null;
  readonly preferences: UserPreferences | null;
  readonly isLoading: boolean;
  readonly error: string | null;
}

export interface AuthState {
  readonly isAuthenticated: boolean;
  readonly token: string | null;
  readonly refreshToken: string | null;
  readonly expiresAt: number | null;
  readonly isLoading: boolean;
  readonly error: string | null;
}

export interface LocationState {
  readonly currentLocation: LocationData | null;
  readonly permissionStatus: 'granted' | 'denied' | 'prompt' | 'unknown';
  readonly isTracking: boolean;
  readonly nearbyGeofences: GeofenceArea[];
  readonly isLoading: boolean;
  readonly error: string | null;
}

export interface AnnotationsState {
  readonly annotations: Annotation[];
  readonly selectedAnnotation: Annotation | null;
  readonly nearbyAnnotations: Annotation[];
  readonly isLoading: boolean;
  readonly error: string | null;
  readonly pagination: PaginationInfo | null;
}

export interface RewardsState {
  readonly availableRewards: Reward[];
  readonly claimedRewards: Reward[];
  readonly totalEarnings: number;
  readonly pendingRewards: Reward[];
  readonly isLoading: boolean;
  readonly error: string | null;
}

export interface UIState {
  readonly theme: 'light' | 'dark' | 'system';
  readonly language: 'zh-CN' | 'en-US';
  readonly sidebar: {
    readonly isOpen: boolean;
    readonly activeSection: string | null;
  };
  readonly modals: {
    readonly [key: string]: boolean;
  };
  readonly toasts: Toast[];
  readonly isMapView: boolean;
  readonly mapCenter: Coordinates | null;
  readonly mapZoom: number;
}

export interface Toast {
  readonly id: ID;
  readonly type: 'success' | 'error' | 'warning' | 'info';
  readonly title: string;
  readonly message: string;
  readonly duration?: number;
  readonly action?: {
    readonly label: string;
    readonly onClick: () => void;
  };
  readonly createdAt: Timestamp;
}

// ==================== COMPONENT PROPS TYPES ====================

export interface BaseComponentProps {
  readonly className?: string;
  readonly children?: React.ReactNode;
  readonly testId?: string;
}

export interface AnnotationCardProps extends BaseComponentProps {
  readonly annotation: Annotation;
  readonly onLike?: (id: ID) => Promise<void>;
  readonly onComment?: (id: ID) => Promise<void>;
  readonly onShare?: (id: ID) => Promise<void>;
  readonly showActions?: boolean;
}

export interface MapComponentProps extends BaseComponentProps {
  readonly center?: Coordinates;
  readonly zoom?: number;
  readonly annotations?: Annotation[];
  readonly geofences?: GeofenceArea[];
  readonly onLocationSelect?: (coordinates: Coordinates) => void;
  readonly onAnnotationClick?: (annotation: Annotation) => void;
  readonly showUserLocation?: boolean;
  readonly interactive?: boolean;
}

// ==================== UTILITY TYPES ====================

export type DeepPartial<T> = {
  [P in keyof T]?: DeepPartial<T[P]>;
};

export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type NonEmptyArray<T> = [T, ...T[]];

export type ValueOf<T> = T[keyof T];

// ==================== API CLIENT TYPES ====================

export interface ApiClientConfig {
  readonly baseUrl: string;
  readonly timeout: number;
  readonly retries: number;
  readonly headers?: Record<string, string>;
}

export interface ApiClient {
  readonly get: <T>(url: string, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly post: <T>(url: string, data?: unknown, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly put: <T>(url: string, data?: unknown, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly delete: <T>(url: string, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly upload: <T>(url: string, file: File, config?: RequestConfig) => Promise<ApiResponse<T>>;
}

export interface RequestConfig {
  readonly headers?: Record<string, string>;
  readonly timeout?: number;
  readonly retries?: number;
  readonly onUploadProgress?: (progress: ProgressEvent) => void;
}

// ==================== HOOKS TYPES ====================

export interface UseLocationResult {
  readonly location: LocationData | null;
  readonly error: string | null;
  readonly isLoading: boolean;
  readonly requestPermission: () => Promise<void>;
  readonly startTracking: () => void;
  readonly stopTracking: () => void;
}

export interface UseAnnotationsResult {
  readonly annotations: Annotation[];
  readonly isLoading: boolean;
  readonly error: string | null;
  readonly refetch: () => Promise<void>;
  readonly loadMore: () => Promise<void>;
  readonly hasMore: boolean;
}

export interface UseRewardsResult {
  readonly rewards: Reward[];
  readonly totalEarnings: number;
  readonly pendingRewards: Reward[];
  readonly isLoading: boolean;
  readonly error: string | null;
  readonly claimReward: (rewardId: ID) => Promise<void>;
  readonly refetch: () => Promise<void>;
}

// ==================== EVENT TYPES ====================

export interface LocationUpdateEvent {
  readonly type: 'location_update';
  readonly data: LocationData;
}

export interface GeofenceEvent {
  readonly type: 'geofence_enter' | 'geofence_exit';
  readonly data: {
    readonly geofence: GeofenceArea;
    readonly location: LocationData;
  };
}

export interface RewardEvent {
  readonly type: 'reward_available' | 'reward_claimed' | 'reward_expired';
  readonly data: Reward;
}

export interface AnnotationEvent {
  readonly type: 'annotation_created' | 'annotation_updated' | 'annotation_deleted';
  readonly data: Annotation;
}

export type AppEvent = LocationUpdateEvent | GeofenceEvent | RewardEvent | AnnotationEvent;

// ==================== GEOCODING TYPES ====================

export interface GeocodingResult {
  readonly place_id: string;
  readonly display_name: string;
  readonly formatted_address_zh: string;
  readonly formatted_address_en: string;
  readonly coordinates: {
    readonly latitude: number;
    readonly longitude: number;
  };
  readonly address_components: {
    readonly house_number?: string;
    readonly road?: string;
    readonly neighbourhood?: string;
    readonly suburb?: string;
    readonly city?: string;
    readonly county?: string;
    readonly state?: string;
    readonly country?: string;
    readonly country_code?: string;
    readonly postcode?: string;
  };
  readonly bounds: {
    readonly northeast: { readonly lat: number; readonly lng: number };
    readonly southwest: { readonly lat: number; readonly lng: number };
  };
  readonly type: string;
  readonly category: string;
  readonly importance: number;
}

export interface ReverseGeocodingResult {
  readonly place_id: string;
  readonly display_name: string;
  readonly formatted_address_zh: string;
  readonly formatted_address_en: string;
  readonly coordinates: {
    readonly latitude: number;
    readonly longitude: number;
  };
  readonly address_components: {
    readonly house_number?: string;
    readonly road?: string;
    readonly neighbourhood?: string;
    readonly suburb?: string;
    readonly city?: string;
    readonly county?: string;
    readonly state?: string;
    readonly country?: string;
    readonly country_code?: string;
    readonly postcode?: string;
  };
  readonly bounds: {
    readonly northeast: { readonly lat: number; readonly lng: number };
    readonly southwest: { readonly lat: number; readonly lng: number };
  };
  readonly type?: string;
  readonly category?: string;
  readonly place_rank?: number;
  readonly importance?: number;
}

export type POIType = 
  | 'restaurant'
  | 'gas_station' 
  | 'atm'
  | 'hospital'
  | 'pharmacy'
  | 'school'
  | 'bank'
  | 'hotel'
  | 'shopping_mall'
  | 'park'
  | 'bus_station'
  | 'subway_station'
  | 'convenience_store';

export interface POISearchResult {
  readonly place_id: string;
  readonly name?: string;
  readonly display_name: string;
  readonly formatted_address: string;
  readonly coordinates: {
    readonly latitude: number;
    readonly longitude: number;
  };
  readonly distance_km?: number;
  readonly distance_text?: string;
  readonly type: string;
  readonly category: string;
  readonly importance: number;
  readonly address_components: {
    readonly road?: string;
    readonly suburb?: string;
    readonly city?: string;
    readonly country?: string;
  };
}

export interface IPLocationResult {
  readonly ip: string;
  readonly coordinates: {
    readonly latitude: number;
    readonly longitude: number;
  };
  readonly address: {
    readonly city: string;
    readonly region: string;
    readonly region_code: string;
    readonly country: string;
    readonly country_code: string;
    readonly postal_code: string;
  };
  readonly timezone: string;
  readonly isp: string;
}

export interface POITypeInfo {
  readonly type: POIType;
  readonly name: string;
  readonly name_en: string;
  readonly icon?: string;
}

export interface GeocodingOptions {
  readonly country?: string;
  readonly limit?: number;
  readonly useCache?: boolean;
}

export interface ReverseGeocodingOptions {
  readonly zoom?: number;
  readonly useCache?: boolean;
}

export interface POISearchOptions {
  readonly radius?: number;
  readonly limit?: number;
  readonly useCache?: boolean;
}

export interface BoundingBox {
  readonly northeast: { readonly lat: number; readonly lng: number };
  readonly southwest: { readonly lat: number; readonly lng: number };
}

// Geocoding state for store management
export interface GeocodingState {
  readonly searchResults: GeocodingResult[];
  readonly reverseResult: ReverseGeocodingResult | null;
  readonly nearbyPOIs: POISearchResult[];
  readonly currentLocation: IPLocationResult | null;
  readonly isSearching: boolean;
  readonly isLoadingLocation: boolean;
  readonly error: string | null;
  readonly lastSearchQuery: string | null;
  readonly searchHistory: string[];
}

// Geocoding hooks result types
export interface UseGeocodingResult {
  readonly searchResults: GeocodingResult[];
  readonly isSearching: boolean;
  readonly error: string | null;
  readonly search: (address: string, options?: GeocodingOptions) => Promise<GeocodingResult[]>;
  readonly clearResults: () => void;
}

export interface UseReverseGeocodingResult {
  readonly result: ReverseGeocodingResult | null;
  readonly isLoading: boolean;
  readonly error: string | null;
  readonly reverseGeocode: (lat: number, lng: number, options?: ReverseGeocodingOptions) => Promise<ReverseGeocodingResult | null>;
  readonly clearResult: () => void;
}

export interface UsePOISearchResult {
  readonly results: POISearchResult[];
  readonly isLoading: boolean;
  readonly error: string | null;
  readonly searchPOIs: (lat: number, lng: number, type: POIType, options?: POISearchOptions) => Promise<POISearchResult[]>;
  readonly clearResults: () => void;
}

export interface UseLocationByIPResult {
  readonly location: IPLocationResult | null;
  readonly isLoading: boolean;
  readonly error: string | null;
  readonly getLocationByIP: (ip?: string) => Promise<IPLocationResult>;
  readonly clearLocation: () => void;
}

// Geocoding events
export interface GeocodingEvent {
  readonly type: 'search_completed' | 'reverse_completed' | 'poi_search_completed' | 'location_detected';
  readonly data: GeocodingResult[] | ReverseGeocodingResult | POISearchResult[] | IPLocationResult;
}

// Extend the main AppEvent type
export type ExtendedAppEvent = AppEvent | GeocodingEvent;