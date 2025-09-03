/**
 * Store Type Definitions
 * Shared types for all Zustand stores
 */

import type {
  User,
  UserStats,
  UserPreferences,
  LocationData,
  Coordinates,
  GeofenceArea,
  Annotation,
  Reward,
  Toast,
  ApiError,
} from '@/types';

// ==================== AUTH STORE TYPES ====================

export interface AuthState {
  // Auth status
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // User data
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  expiresAt: number | null;

  // User preferences and stats
  preferences: UserPreferences | null;
  stats: UserStats | null;
}

export interface AuthActions {
  // Authentication methods
  login: (email: string, password: string) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<void>;
  
  // Profile management
  updateProfile: (data: Partial<User>) => Promise<void>;
  updatePreferences: (preferences: Partial<UserPreferences>) => Promise<void>;
  
  // Token management
  setToken: (token: string, refreshToken?: string, expiresAt?: number) => void;
  clearAuth: () => void;
  
  // Utilities
  setError: (error: string | null) => void;
  setLoading: (loading: boolean) => void;
}

export interface RegisterData {
  email: string;
  username: string;
  password: string;
  displayName: string;
  agreeToTerms: boolean;
}

export type AuthStore = AuthState & AuthActions;

// ==================== LOCATION STORE TYPES ====================

export interface LocationState {
  // Current location
  currentLocation: LocationData | null;
  previousLocation: LocationData | null;
  
  // Permission and tracking
  permissionStatus: PermissionStatus;
  isTracking: boolean;
  isLoading: boolean;
  error: string | null;
  
  // Geofencing
  geofences: GeofenceArea[];
  activeGeofences: GeofenceArea[];
  nearbyGeofences: GeofenceArea[];
  
  // Location history
  locationHistory: LocationData[];
  maxHistorySize: number;
}

export interface LocationActions {
  // Location tracking
  startTracking: () => Promise<void>;
  stopTracking: () => void;
  getCurrentLocation: () => Promise<LocationData | null>;
  updateLocation: (location: LocationData) => void;
  
  // Permission management
  requestPermission: () => Promise<PermissionStatus>;
  checkPermission: () => Promise<PermissionStatus>;
  
  // Geofence management
  loadGeofences: () => Promise<void>;
  checkGeofences: (location: LocationData) => GeofenceArea[];
  addGeofence: (geofence: GeofenceArea) => void;
  removeGeofence: (geofenceId: string) => void;
  
  // History management
  addToHistory: (location: LocationData) => void;
  clearHistory: () => void;
  
  // Utilities
  setError: (error: string | null) => void;
  setLoading: (loading: boolean) => void;
}

export type PermissionStatus = 'granted' | 'denied' | 'prompt' | 'unknown';

export type LocationStore = LocationState & LocationActions;

// ==================== ANNOTATION STORE TYPES ====================

export interface AnnotationState {
  // Annotations data
  annotations: Annotation[];
  nearbyAnnotations: Annotation[];
  selectedAnnotation: Annotation | null;
  
  // Loading and error states
  isLoading: boolean;
  isCreating: boolean;
  isUpdating: boolean;
  error: string | null;
  
  // Pagination and filtering
  page: number;
  hasMore: boolean;
  totalCount: number;
  filters: AnnotationFilters;
  sortBy: AnnotationSortBy;
  
  // Map view
  mapBounds: MapBounds | null;
  visibleAnnotations: Annotation[];
}

export interface AnnotationActions {
  // Data fetching
  loadAnnotations: (force?: boolean) => Promise<void>;
  loadNearbyAnnotations: (location: LocationData, radius?: number) => Promise<void>;
  loadMore: () => Promise<void>;
  refresh: () => Promise<void>;
  
  // CRUD operations
  createAnnotation: (data: CreateAnnotationData) => Promise<Annotation>;
  updateAnnotation: (id: string, data: Partial<Annotation>) => Promise<void>;
  deleteAnnotation: (id: string) => Promise<void>;
  
  // Interaction
  likeAnnotation: (id: string) => Promise<void>;
  commentOnAnnotation: (id: string, comment: string) => Promise<void>;
  shareAnnotation: (id: string) => Promise<void>;
  reportAnnotation: (id: string, reason: string) => Promise<void>;
  
  // Selection and filtering
  selectAnnotation: (annotation: Annotation | null) => void;
  setFilters: (filters: Partial<AnnotationFilters>) => void;
  setSortBy: (sortBy: AnnotationSortBy) => void;
  
  // Map management
  setMapBounds: (bounds: MapBounds) => void;
  updateVisibleAnnotations: () => void;
  
  // Utilities
  setError: (error: string | null) => void;
  setLoading: (loading: boolean) => void;
}

export interface CreateAnnotationData {
  title: string;
  description: string;
  category: string;
  location: Coordinates;
  tags: string[];
  visibility: 'public' | 'friends' | 'private';
  isPaid: boolean;
  price?: number;
  media?: File[];
}

export interface AnnotationFilters {
  category?: string;
  tags?: string[];
  visibility?: 'public' | 'friends' | 'private';
  isPaid?: boolean;
  priceRange?: [number, number];
  location?: Coordinates;
  radius?: number;
  dateRange?: [Date, Date];
}

export type AnnotationSortBy = 
  | 'created_at'
  | 'updated_at' 
  | 'likes'
  | 'comments'
  | 'distance'
  | 'price';

export interface MapBounds {
  north: number;
  south: number;
  east: number;
  west: number;
}

export type AnnotationStore = AnnotationState & AnnotationActions;

// ==================== REWARD STORE TYPES ====================

export interface RewardState {
  // Rewards data
  availableRewards: Reward[];
  claimedRewards: Reward[];
  pendingRewards: Reward[];
  
  // Statistics
  totalEarnings: number;
  todayEarnings: number;
  weeklyEarnings: number;
  monthlyEarnings: number;
  
  // Loading states
  isLoading: boolean;
  isClaiming: boolean;
  error: string | null;
  
  // Pagination
  page: number;
  hasMore: boolean;
  
  // Filters
  filters: RewardFilters;
}

export interface RewardActions {
  // Data fetching
  loadRewards: (force?: boolean) => Promise<void>;
  loadAvailableRewards: (location?: LocationData) => Promise<void>;
  loadClaimedRewards: () => Promise<void>;
  loadMore: () => Promise<void>;
  
  // Reward claiming
  claimReward: (rewardId: string) => Promise<void>;
  claimAllAvailable: () => Promise<void>;
  
  // Statistics
  updateEarnings: () => Promise<void>;
  getEarningsByPeriod: (period: 'day' | 'week' | 'month') => number;
  
  // Filtering
  setFilters: (filters: Partial<RewardFilters>) => void;
  
  // Utilities
  setError: (error: string | null) => void;
  setLoading: (loading: boolean) => void;
}

export interface RewardFilters {
  type?: string[];
  status?: 'pending' | 'completed' | 'expired';
  minAmount?: number;
  maxAmount?: number;
  dateRange?: [Date, Date];
}

export type RewardStore = RewardState & RewardActions;

// ==================== UI STORE TYPES ====================

export interface UIState {
  // Theme and appearance
  theme: 'light' | 'dark' | 'system';
  language: 'zh-CN' | 'en-US';
  
  // Navigation
  activeRoute: string;
  previousRoute: string | null;
  
  // Layout
  sidebar: SidebarState;
  header: HeaderState;
  
  // Modals and overlays
  modals: Record<string, boolean>;
  overlays: Record<string, boolean>;
  
  // Notifications
  toasts: Toast[];
  notifications: UINotification[];
  
  // Map view
  mapView: MapViewState;
  
  // Loading states
  globalLoading: boolean;
  loadingStates: Record<string, boolean>;
}

export interface UIActions {
  // Theme management
  setTheme: (theme: 'light' | 'dark' | 'system') => void;
  toggleTheme: () => void;
  setLanguage: (language: 'zh-CN' | 'en-US') => void;
  
  // Navigation
  setActiveRoute: (route: string) => void;
  goBack: () => void;
  
  // Layout management
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  setSidebarSection: (section: string | null) => void;
  setHeaderVisible: (visible: boolean) => void;
  
  // Modal management
  openModal: (modalId: string) => void;
  closeModal: (modalId: string) => void;
  toggleModal: (modalId: string) => void;
  closeAllModals: () => void;
  
  // Overlay management
  showOverlay: (overlayId: string) => void;
  hideOverlay: (overlayId: string) => void;
  
  // Toast notifications
  addToast: (toast: Omit<Toast, 'id' | 'createdAt'>) => void;
  removeToast: (toastId: string) => void;
  clearToasts: () => void;
  
  // Notifications
  addNotification: (notification: Omit<UINotification, 'id' | 'createdAt'>) => void;
  removeNotification: (notificationId: string) => void;
  clearNotifications: () => void;
  markAsRead: (notificationId: string) => void;
  
  // Map view
  setMapCenter: (center: Coordinates) => void;
  setMapZoom: (zoom: number) => void;
  setMapView: (view: 'map' | 'list') => void;
  
  // Loading states
  setGlobalLoading: (loading: boolean) => void;
  setLoadingState: (key: string, loading: boolean) => void;
  clearLoadingStates: () => void;
}

export interface SidebarState {
  isOpen: boolean;
  activeSection: string | null;
  isPinned: boolean;
}

export interface HeaderState {
  isVisible: boolean;
  title: string;
  showBackButton: boolean;
  actions: HeaderAction[];
}

export interface HeaderAction {
  id: string;
  label: string;
  icon?: string;
  onClick: () => void;
}

export interface UINotification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  isRead: boolean;
  createdAt: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export interface MapViewState {
  view: 'map' | 'list';
  center: Coordinates | null;
  zoom: number;
  showUserLocation: boolean;
  showGeofences: boolean;
  showRewards: boolean;
}

export type UIStore = UIState & UIActions;

// ==================== APP STORE TYPES ====================

export interface AppState {
  // App metadata
  version: string;
  buildNumber: string;
  environment: 'development' | 'staging' | 'production';
  
  // Connection status
  isOnline: boolean;
  lastSyncTime: Date | null;
  
  // Feature flags
  features: Record<string, boolean>;
  
  // Performance metrics
  metrics: PerformanceMetrics;
  
  // Settings
  settings: AppSettings;
}

export interface AppActions {
  // App lifecycle
  initialize: () => Promise<void>;
  reset: () => void;
  
  // Connection management
  setOnlineStatus: (online: boolean) => void;
  sync: () => Promise<void>;
  
  // Feature flags
  setFeature: (feature: string, enabled: boolean) => void;
  isFeatureEnabled: (feature: string) => boolean;
  
  // Settings
  updateSettings: (settings: Partial<AppSettings>) => void;
  
  // Performance
  recordMetric: (key: string, value: number) => void;
  clearMetrics: () => void;
}

export interface PerformanceMetrics {
  loadTime: number;
  apiResponseTimes: Record<string, number>;
  errorCount: number;
  memoryUsage: number;
}

export interface AppSettings {
  enableAnalytics: boolean;
  enableCrashReporting: boolean;
  enableNotifications: boolean;
  cacheSize: number;
  maxImageSize: number;
  locationUpdateInterval: number;
}

export type AppStore = AppState & AppActions;

// ==================== STORE PERSISTENCE TYPES ====================

export interface PersistConfig<T> {
  name: string;
  storage?: 'localStorage' | 'sessionStorage' | 'cookie';
  partialize?: (state: T) => Partial<T>;
  serialize?: {
    serialize: (state: any) => string;
    deserialize: (str: string) => any;
  };
  version?: number;
  migrate?: (persistedState: any, version: number) => any;
}

// ==================== STORE MIDDLEWARE TYPES ====================

export interface StoreMiddleware<T> {
  (config: (set: any, get: any, api: any) => T): (set: any, get: any, api: any) => T;
}

export interface DevtoolsConfig {
  name: string;
  enabled?: boolean;
  serialize?: boolean;
}

// ==================== STORE SUBSCRIPTION TYPES ====================

export interface StoreSubscription<T> {
  selector: (state: T) => any;
  listener: (state: any, previousState: any) => void;
  fireImmediately?: boolean;
  equalityFn?: (a: any, b: any) => boolean;
}