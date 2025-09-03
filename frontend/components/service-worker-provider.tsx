'use client'

import { useEffect } from 'react'

export function ServiceWorkerProvider() {
  useEffect(() => {
    if (typeof window !== 'undefined' && 'serviceWorker' in navigator) {
      const registerSW = async () => {
        try {
          // Check if SW is already registered
          const existingRegistration = await navigator.serviceWorker.getRegistration()
          
          if (existingRegistration) {
            console.log('Service Worker already registered')
            
            // Check for updates
            existingRegistration.addEventListener('updatefound', () => {
              const newWorker = existingRegistration.installing
              if (newWorker) {
                newWorker.addEventListener('statechange', () => {
                  if (newWorker.state === 'installed') {
                    if (navigator.serviceWorker.controller) {
                      // New content available, notify user
                      console.log('New content available, reload to update')
                      if (confirm('New version available! Reload to update?')) {
                        window.location.reload()
                      }
                    } else {
                      console.log('Content cached for offline use')
                    }
                  }
                })
              }
            })
            return existingRegistration
          }

          // Register new SW
          const registration = await navigator.serviceWorker.register('/sw.js', {
            scope: '/',
          })

          console.log('Service Worker registered successfully')

          // Handle updates
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing
            if (newWorker) {
              newWorker.addEventListener('statechange', () => {
                if (newWorker.state === 'installed') {
                  if (navigator.serviceWorker.controller) {
                    console.log('New content available')
                  } else {
                    console.log('Content cached for offline use')
                  }
                }
              })
            }
          })

          // Listen for controlling SW changes
          navigator.serviceWorker.addEventListener('controllerchange', () => {
            console.log('Service Worker controller changed')
            window.location.reload()
          })

          return registration
        } catch (error) {
          console.error('Service Worker registration failed:', error)
        }
      }

      // Register SW after page load for better performance
      if (document.readyState === 'complete') {
        registerSW()
      } else {
        window.addEventListener('load', registerSW)
      }

      // Handle online/offline status
      const updateOnlineStatus = () => {
        const status = navigator.onLine ? 'online' : 'offline'
        console.log(`App is ${status}`)
        
        // Dispatch custom event for components to listen
        window.dispatchEvent(new CustomEvent('connectionchange', { 
          detail: { online: navigator.onLine } 
        }))
      }

      window.addEventListener('online', updateOnlineStatus)
      window.addEventListener('offline', updateOnlineStatus)

      // Check for PWA install prompt
      window.addEventListener('beforeinstallprompt', (e) => {
        console.log('PWA install prompt available')
        e.preventDefault()
        
        // Store for later use
        ;(window as any).deferredPrompt = e
        
        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('pwainstallprompt', { detail: e }))
      })

      // Background sync registration
      if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
        navigator.serviceWorker.ready.then((registration) => {
          // Register sync events for offline functionality
          try {
            registration.sync.register('background-sync-annotations')
            registration.sync.register('background-sync-location')
            console.log('Background sync registered')
          } catch (error) {
            console.log('Background sync registration failed:', error)
          }
        })
      }

      // Push notification setup
      if ('Notification' in window && 'serviceWorker' in navigator) {
        navigator.serviceWorker.ready.then(async (registration) => {
          try {
            // Check current permission
            let permission = Notification.permission
            
            if (permission === 'default') {
              // Don't automatically request permission
              console.log('Notification permission not granted yet')
              return
            }

            if (permission === 'granted') {
              // Check if already subscribed
              const existingSubscription = await registration.pushManager.getSubscription()
              
              if (!existingSubscription) {
                console.log('Push notifications available but not subscribed')
              }
            }
          } catch (error) {
            console.error('Push notification setup failed:', error)
          }
        })
      }

      return () => {
        window.removeEventListener('online', updateOnlineStatus)
        window.removeEventListener('offline', updateOnlineStatus)
      }
    }
  }, [])

  return null
}

// Hook for components to use SW features
export function useServiceWorker() {
  const requestNotificationPermission = async () => {
    if ('Notification' in window) {
      const permission = await Notification.requestPermission()
      return permission === 'granted'
    }
    return false
  }

  const subscribeToPushNotifications = async () => {
    if ('serviceWorker' in navigator && 'PushManager' in window) {
      try {
        const registration = await navigator.serviceWorker.ready
        
        const subscription = await registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY
        })
        
        // Send subscription to server
        await fetch('/api/v1/notifications/subscribe', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(subscription)
        })
        
        return subscription
      } catch (error) {
        console.error('Push subscription failed:', error)
        throw error
      }
    }
    throw new Error('Push notifications not supported')
  }

  const installPWA = async () => {
    const deferredPrompt = (window as any).deferredPrompt
    if (deferredPrompt) {
      deferredPrompt.prompt()
      const { outcome } = await deferredPrompt.userChoice
      console.log(`PWA install prompt outcome: ${outcome}`)
      ;(window as any).deferredPrompt = null
      return outcome === 'accepted'
    }
    return false
  }

  const shareContent = async (shareData: ShareData) => {
    if ('share' in navigator) {
      try {
        await navigator.share(shareData)
        return true
      } catch (error) {
        console.log('Web Share API failed:', error)
        return false
      }
    }
    return false
  }

  return {
    requestNotificationPermission,
    subscribeToPushNotifications,
    installPWA,
    shareContent,
    isOnline: typeof window !== 'undefined' ? navigator.onLine : true
  }
}