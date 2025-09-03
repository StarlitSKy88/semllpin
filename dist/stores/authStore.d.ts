interface User {
    id: string;
    email: string;
    username: string;
    avatar?: string;
    university?: string;
    graduation_year?: number;
    level: number;
    points: number;
    role: string;
    created_at: string;
    updated_at: string;
}
interface AuthState {
    user: User | null;
    token: string | null;
    isLoading: boolean;
    error: string | null;
    isAuthenticated: boolean;
}
interface AuthActions {
    login: (email: string, password: string) => Promise<void>;
    register: (email: string, password: string, username: string) => Promise<void>;
    logout: () => void;
    checkAuth: () => Promise<void>;
    updateProfile: (data: Partial<User>) => Promise<void>;
    refreshToken: () => Promise<void>;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
    clearError: () => void;
}
type AuthStore = AuthState & AuthActions;
export declare const useAuthStore: import("zustand").UseBoundStore<Omit<import("zustand").StoreApi<AuthStore>, "setState" | "persist"> & {
    setState(partial: AuthStore | Partial<AuthStore> | ((state: AuthStore) => AuthStore | Partial<AuthStore>), replace?: false | undefined): unknown;
    setState(state: AuthStore | ((state: AuthStore) => AuthStore), replace: true): unknown;
    persist: {
        setOptions: (options: Partial<import("zustand/middleware").PersistOptions<AuthStore, {
            token: string | null;
            user: User | null;
            isAuthenticated: boolean;
        }, unknown>>) => void;
        clearStorage: () => void;
        rehydrate: () => Promise<void> | void;
        hasHydrated: () => boolean;
        onHydrate: (fn: (state: AuthStore) => void) => () => void;
        onFinishHydration: (fn: (state: AuthStore) => void) => () => void;
        getOptions: () => Partial<import("zustand/middleware").PersistOptions<AuthStore, {
            token: string | null;
            user: User | null;
            isAuthenticated: boolean;
        }, unknown>>;
    };
}>;
export default useAuthStore;
//# sourceMappingURL=authStore.d.ts.map