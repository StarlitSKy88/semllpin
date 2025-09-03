/**
 * Location Store
 * Manages geolocation, tracking, and geofencing functionality
 */

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type { LocationStore, PermissionStatus } from './types';
import type { LocationData, Coordinates, GeofenceArea } from '@/types';
import { apiClient } from '@/lib/api';

// Geolocation options for high accuracy
const GEO_OPTIONS: PositionOptions = {
  enableHighAccuracy: true,
  timeout: 10000,
  maximumAge: 60000, // 1 minute
};

const useLocationStore = create<LocationStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // ==================== STATE ====================
        currentLocation: null,
        previousLocation: null,
        permissionStatus: 'unknown',
        isTracking: false,
        isLoading: false,
        error: null,
        geofences: [],
        activeGeofences: [],
        nearbyGeofences: [],
        locationHistory: [],
        maxHistorySize: 100,

        // ==================== LOCATION TRACKING ====================
        startTracking: async () => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            // Check permission first
            const permission = await get().checkPermission();
            
            if (permission !== 'granted') {
              throw new Error('Location permission not granted');
            }

            // Get initial location
            const location = await get().getCurrentLocation();
            
            if (location) {
              set((state) => {
                state.isTracking = true;
                state.isLoading = false;
              });

              // Start watching position
              const watchId = navigator.geolocation.watchPosition(
                (position) => {
                  const locationData: LocationData = {
                    coordinates: {
                      latitude: position.coords.latitude,
                      longitude: position.coords.longitude,
                      accuracy: position.coords.accuracy,
                      altitude: position.coords.altitude || undefined,
                      altitudeAccuracy: position.coords.altitudeAccuracy || undefined,
                      heading: position.coords.heading || undefined,
                      speed: position.coords.speed || undefined,
                    },
                    timestamp: new Date().toISOString(),
                    isVerified: true,
                  };

                  get().updateLocation(locationData);
                },
                (error) => {
                  console.error('Geolocation error:', error);
                  set((state) => {
                    state.error = error.message;
                  });
                },
                GEO_OPTIONS
              );

              // Store watch ID for cleanup
              (get() as any)._watchId = watchId;
            } else {
              throw new Error('Could not get current location');
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to start tracking';
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        stopTracking: () => {
          const watchId = (get() as any)._watchId;
          
          if (watchId) {
            navigator.geolocation.clearWatch(watchId);
            delete (get() as any)._watchId;
          }

          set((state) => {
            state.isTracking = false;
          });
        },

        getCurrentLocation: async (): Promise<LocationData | null> => {
          return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
              reject(new Error('Geolocation is not supported'));
              return;
            }

            navigator.geolocation.getCurrentPosition(
              async (position) => {
                try {
                  const coordinates: Coordinates = {
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude,
                    accuracy: position.coords.accuracy,
                    altitude: position.coords.altitude || undefined,
                    altitudeAccuracy: position.coords.altitudeAccuracy || undefined,
                    heading: position.coords.heading || undefined,
                    speed: position.coords.speed || undefined,
                  };

                  // Reverse geocode to get address
                  let address: string | undefined;
                  try {
                    const geocodeResponse = await apiClient.get<{
                      address: string;
                      city: string;
                      country: string;
                    }>(`/location/reverse-geocode?lat=${coordinates.latitude}&lng=${coordinates.longitude}`);
                    
                    if (geocodeResponse.success && geocodeResponse.data) {
                      address = geocodeResponse.data.address;
                    }
                  } catch (geocodeError) {
                    console.warn('Reverse geocoding failed:', geocodeError);
                  }

                  const locationData: LocationData = {
                    coordinates,
                    timestamp: new Date().toISOString(),
                    address,
                    isVerified: true,
                  };

                  resolve(locationData);
                } catch (error) {
                  reject(error);
                }
              },
              (error) => {
                reject(new Error(error.message));
              },
              GEO_OPTIONS
            );
          });
        },

        updateLocation: (location: LocationData) => {
          set((state) => {
            // Store previous location
            if (state.currentLocation) {
              state.previousLocation = state.currentLocation;
            }
            
            // Update current location
            state.currentLocation = location;
            
            // Add to history
            state.locationHistory.unshift(location);
            
            // Maintain history size
            if (state.locationHistory.length > state.maxHistorySize) {
              state.locationHistory = state.locationHistory.slice(0, state.maxHistorySize);
            }
          });

          // Check geofences
          const activeGeofences = get().checkGeofences(location);
          
          if (activeGeofences.length > 0) {
            set((state) => {
              state.activeGeofences = activeGeofences;
            });
            
            // Trigger geofence events
            activeGeofences.forEach(geofence => {
              // Emit geofence enter event
              window.dispatchEvent(new CustomEvent('geofence-enter', {
                detail: { geofence, location }
              }));
            });
          }
        },

        // ==================== PERMISSION MANAGEMENT ====================
        requestPermission: async (): Promise<PermissionStatus> => {
          if (!navigator.permissions || !navigator.permissions.query) {
            // Fallback for browsers without permissions API
            try {
              await get().getCurrentLocation();
              set((state) => {
                state.permissionStatus = 'granted';
              });
              return 'granted';
            } catch {
              set((state) => {
                state.permissionStatus = 'denied';
              });
              return 'denied';
            }
          }

          try {
            const permission = await navigator.permissions.query({ name: 'geolocation' as PermissionName });
            
            let status: PermissionStatus;
            switch (permission.state) {
              case 'granted':
                status = 'granted';
                break;
              case 'denied':
                status = 'denied';
                break;
              default:
                status = 'prompt';
                break;
            }

            set((state) => {
              state.permissionStatus = status;
            });

            // If permission is prompt, try to get location to trigger permission dialog
            if (status === 'prompt') {
              try {
                await get().getCurrentLocation();
                set((state) => {
                  state.permissionStatus = 'granted';
                });
                return 'granted';
              } catch {
                set((state) => {
                  state.permissionStatus = 'denied';
                });
                return 'denied';
              }
            }

            return status;
          } catch (error) {
            console.error('Permission check failed:', error);
            set((state) => {
              state.permissionStatus = 'unknown';
            });
            return 'unknown';
          }
        },

        checkPermission: async (): Promise<PermissionStatus> => {
          if (!navigator.permissions || !navigator.permissions.query) {
            return get().permissionStatus;
          }

          try {
            const permission = await navigator.permissions.query({ name: 'geolocation' as PermissionName });
            
            let status: PermissionStatus;
            switch (permission.state) {
              case 'granted':
                status = 'granted';
                break;
              case 'denied':
                status = 'denied';
                break;
              default:
                status = 'prompt';
                break;
            }

            set((state) => {
              state.permissionStatus = status;
            });

            return status;
          } catch (error) {
            console.error('Permission check failed:', error);
            return 'unknown';
          }
        },

        // ==================== GEOFENCE MANAGEMENT ====================
        loadGeofences: async () => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await apiClient.get<GeofenceArea[]>('/location/geofences');

            if (response.success && response.data) {
              set((state) => {
                state.geofences = response.data!;
                state.isLoading = false;
              });

              // Update nearby geofences if we have a current location
              const { currentLocation } = get();
              if (currentLocation) {
                get().updateNearbyGeofences(currentLocation);
              }
            } else {
              throw new Error(response.error?.message || 'Failed to load geofences');
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to load geofences';
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        checkGeofences: (location: LocationData): GeofenceArea[] => {
          const { geofences } = get();
          const activeGeofences: GeofenceArea[] = [];

          geofences.forEach(geofence => {
            if (!geofence.isActive) return;

            const distance = calculateDistance(
              location.coordinates.latitude,
              location.coordinates.longitude,
              geofence.center.latitude,
              geofence.center.longitude
            );

            if (distance <= geofence.radius) {
              activeGeofences.push(geofence);
            }
          });

          return activeGeofences;
        },

        addGeofence: (geofence: GeofenceArea) => {
          set((state) => {
            state.geofences.push(geofence);
          });
        },

        removeGeofence: (geofenceId: string) => {
          set((state) => {
            state.geofences = state.geofences.filter(g => g.id !== geofenceId);
            state.activeGeofences = state.activeGeofences.filter(g => g.id !== geofenceId);
            state.nearbyGeofences = state.nearbyGeofences.filter(g => g.id !== geofenceId);
          });
        },

        updateNearbyGeofences: (location: LocationData) => {
          const { geofences } = get();
          const nearbyGeofences: GeofenceArea[] = [];
          const NEARBY_RADIUS = 1000; // 1km

          geofences.forEach(geofence => {
            if (!geofence.isActive) return;

            const distance = calculateDistance(
              location.coordinates.latitude,
              location.coordinates.longitude,
              geofence.center.latitude,
              geofence.center.longitude
            );

            if (distance <= NEARBY_RADIUS) {
              nearbyGeofences.push(geofence);
            }
          });

          set((state) => {
            state.nearbyGeofences = nearbyGeofences;
          });
        },

        // ==================== HISTORY MANAGEMENT ====================
        addToHistory: (location: LocationData) => {
          set((state) => {
            state.locationHistory.unshift(location);
            
            if (state.locationHistory.length > state.maxHistorySize) {
              state.locationHistory = state.locationHistory.slice(0, state.maxHistorySize);
            }
          });
        },

        clearHistory: () => {
          set((state) => {
            state.locationHistory = [];
          });
        },

        // ==================== UTILITIES ====================
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

        // ==================== DISTANCE CALCULATION ====================
        getDistanceToLocation: (targetLocation: Coordinates): number | null => {
          const { currentLocation } = get();
          if (!currentLocation) return null;

          return calculateDistance(
            currentLocation.coordinates.latitude,
            currentLocation.coordinates.longitude,
            targetLocation.latitude,
            targetLocation.longitude
          );
        },
      })),
      {
        name: 'smellpin-location',
        partialize: (state) => ({
          permissionStatus: state.permissionStatus,
          geofences: state.geofences,
          locationHistory: state.locationHistory.slice(0, 10), // Only persist recent history
          maxHistorySize: state.maxHistorySize,
        }),
        version: 1,
      }
    ),
    {
      name: 'location-store',
      serialize: { options: true },
    }
  )
);

// ==================== UTILITY FUNCTIONS ====================

/**
 * Calculate distance between two coordinates using Haversine formula
 * Returns distance in meters
 */
function calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371000; // Earth's radius in meters
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

  return R * c;
}

export { useLocationStore };