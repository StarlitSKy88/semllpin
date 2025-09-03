/**
 * Authentication Store
 * Manages user authentication, profile, and session state
 */

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type { AuthStore, RegisterData } from './types';
import type { User, UserPreferences, UserStats } from '@/types';
import { apiClient } from '@/lib/api';

const useAuthStore = create<AuthStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // ==================== STATE ====================
        isAuthenticated: false,
        isLoading: false,
        error: null,
        user: null,
        token: null,
        refreshToken: null,
        expiresAt: null,
        preferences: null,
        stats: null,

        // ==================== AUTHENTICATION ACTIONS ====================
        login: async (email: string, password: string) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await apiClient.post<{
              user: User;
              token: string;
              refreshToken: string;
              expiresAt: number;
            }>('/auth/login', { email, password });

            if (response.success && response.data) {
              const { user, token, refreshToken, expiresAt } = response.data;

              set((state) => {
                state.isAuthenticated = true;
                state.user = user;
                state.token = token;
                state.refreshToken = refreshToken;
                state.expiresAt = expiresAt;
                state.isLoading = false;
                state.error = null;
              });

              // Load user preferences and stats
              get().loadUserData();
            } else {
              throw new Error(response.error?.message || 'Login failed');
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Login failed';
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        register: async (data: RegisterData) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await apiClient.post<{
              user: User;
              token: string;
              refreshToken: string;
              expiresAt: number;
            }>('/auth/register', data);

            if (response.success && response.data) {
              const { user, token, refreshToken, expiresAt } = response.data;

              set((state) => {
                state.isAuthenticated = true;
                state.user = user;
                state.token = token;
                state.refreshToken = refreshToken;
                state.expiresAt = expiresAt;
                state.isLoading = false;
                state.error = null;
              });

              // Load user preferences and stats
              get().loadUserData();
            } else {
              throw new Error(response.error?.message || 'Registration failed');
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Registration failed';
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        logout: async () => {
          set((state) => {
            state.isLoading = true;
          });

          try {
            // Call logout endpoint to invalidate server session
            await apiClient.post('/auth/logout');
          } catch (error) {
            // Continue with client-side logout even if server logout fails
            console.warn('Server logout failed:', error);
          }

          // Clear all auth state
          get().clearAuth();
        },

        refreshAuth: async () => {
          const { refreshToken, expiresAt } = get();
          
          if (!refreshToken) {
            throw new Error('No refresh token available');
          }

          // Check if token is close to expiring (within 5 minutes)
          const now = Date.now();
          const fiveMinutes = 5 * 60 * 1000;
          
          if (expiresAt && (expiresAt - now) > fiveMinutes) {
            return; // Token is still valid
          }

          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await apiClient.post<{
              token: string;
              refreshToken: string;
              expiresAt: number;
            }>('/auth/refresh', { refreshToken });

            if (response.success && response.data) {
              const { token, refreshToken: newRefreshToken, expiresAt: newExpiresAt } = response.data;

              set((state) => {
                state.token = token;
                state.refreshToken = newRefreshToken;
                state.expiresAt = newExpiresAt;
                state.isLoading = false;
                state.error = null;
              });
            } else {
              throw new Error(response.error?.message || 'Token refresh failed');
            }
          } catch (error) {
            // If refresh fails, logout the user
            console.error('Token refresh failed:', error);
            get().clearAuth();
            throw error;
          }
        },

        // ==================== PROFILE MANAGEMENT ====================
        updateProfile: async (data: Partial<User>) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await apiClient.put<User>('/user/profile', data);

            if (response.success && response.data) {
              set((state) => {
                state.user = response.data!;
                state.isLoading = false;
                state.error = null;
              });
            } else {
              throw new Error(response.error?.message || 'Profile update failed');
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Profile update failed';
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        updatePreferences: async (preferences: Partial<UserPreferences>) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await apiClient.put<UserPreferences>('/user/preferences', preferences);

            if (response.success && response.data) {
              set((state) => {
                state.preferences = response.data!;
                state.isLoading = false;
                state.error = null;
              });
            } else {
              throw new Error(response.error?.message || 'Preferences update failed');
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Preferences update failed';
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        // ==================== TOKEN MANAGEMENT ====================
        setToken: (token: string, refreshToken?: string, expiresAt?: number) => {
          set((state) => {
            state.token = token;
            if (refreshToken) state.refreshToken = refreshToken;
            if (expiresAt) state.expiresAt = expiresAt;
          });
        },

        clearAuth: () => {
          set((state) => {
            state.isAuthenticated = false;
            state.user = null;
            state.token = null;
            state.refreshToken = null;
            state.expiresAt = null;
            state.preferences = null;
            state.stats = null;
            state.isLoading = false;
            state.error = null;
          });
        },

        // ==================== UTILITY METHODS ====================
        setError: (error: string | null) => {
          set((state) => {
            state.error = error;
          });
        },

        setLoading: (loading: boolean) => {
          set((state) => {
            state.isLoading = loading;
          });
        },

        loadUserData: async () => {
          try {
            // Load preferences and stats in parallel
            const [preferencesResponse, statsResponse] = await Promise.all([
              apiClient.get<UserPreferences>('/user/preferences'),
              apiClient.get<UserStats>('/user/stats'),
            ]);

            set((state) => {
              if (preferencesResponse.success && preferencesResponse.data) {
                state.preferences = preferencesResponse.data;
              }
              if (statsResponse.success && statsResponse.data) {
                state.stats = statsResponse.data;
              }
            });
          } catch (error) {
            console.error('Failed to load user data:', error);
            // Don't throw here as this is not critical for authentication
          }
        },

        // ==================== TOKEN VALIDATION ====================
        isTokenValid: () => {
          const { token, expiresAt } = get();
          if (!token || !expiresAt) return false;
          
          // Add 1 minute buffer
          return Date.now() < (expiresAt - 60000);
        },

        // ==================== SESSION MANAGEMENT ====================
        checkSession: async () => {
          const { token, isTokenValid } = get();
          
          if (!token) {
            get().clearAuth();
            return false;
          }

          if (!isTokenValid()) {
            try {
              await get().refreshAuth();
              return true;
            } catch {
              get().clearAuth();
              return false;
            }
          }

          return true;
        },
      })),
      {
        name: 'smellpin-auth',
        partialize: (state) => ({
          token: state.token,
          refreshToken: state.refreshToken,
          expiresAt: state.expiresAt,
          user: state.user,
          preferences: state.preferences,
          stats: state.stats,
          isAuthenticated: state.isAuthenticated,
        }),
        version: 1,
        migrate: (persistedState: any, version: number) => {
          // Handle migration between versions
          if (version === 0) {
            // Migrate from version 0 to version 1
            return {
              ...persistedState,
              preferences: null,
              stats: null,
            };
          }
          return persistedState;
        },
      }
    ),
    {
      name: 'auth-store',
      serialize: { options: true },
    }
  )
);

export { useAuthStore };