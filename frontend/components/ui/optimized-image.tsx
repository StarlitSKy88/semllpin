'use client'

import Image, { ImageProps } from 'next/image'
import { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'

interface OptimizedImageProps extends Omit<ImageProps, 'onLoad' | 'onError'> {
  fallback?: string
  skeleton?: boolean
  blur?: boolean
  lazy?: boolean
  priority?: boolean
  onLoad?: () => void
  onError?: () => void
}

export function OptimizedImage({
  src,
  alt,
  className,
  fallback = '/images/placeholder.jpg',
  skeleton = true,
  blur = true,
  lazy = true,
  priority = false,
  onLoad,
  onError,
  ...props
}: OptimizedImageProps) {
  const [imageState, setImageState] = useState<'loading' | 'loaded' | 'error'>('loading')
  const [imageSrc, setImageSrc] = useState(src)

  useEffect(() => {
    setImageSrc(src)
    setImageState('loading')
  }, [src])

  const handleLoad = () => {
    setImageState('loaded')
    onLoad?.()
  }

  const handleError = () => {
    setImageState('error')
    setImageSrc(fallback)
    onError?.()
  }

  const getBlurDataURL = (width: number = 8, height: number = 8) => {
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    const ctx = canvas.getContext('2d')
    
    if (ctx) {
      const gradient = ctx.createLinearGradient(0, 0, width, height)
      gradient.addColorStop(0, '#f3f4f6')
      gradient.addColorStop(1, '#e5e7eb')
      ctx.fillStyle = gradient
      ctx.fillRect(0, 0, width, height)
    }
    
    return canvas.toDataURL()
  }

  return (
    <div className={cn('relative overflow-hidden', className)}>
      {/* Loading skeleton */}
      {skeleton && imageState === 'loading' && (
        <div className="absolute inset-0 bg-gradient-to-r from-gray-300 via-gray-100 to-gray-300 animate-pulse">
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
        </div>
      )}

      {/* Main image */}
      <Image
        src={imageSrc}
        alt={alt}
        onLoad={handleLoad}
        onError={handleError}
        priority={priority}
        loading={priority ? 'eager' : lazy ? 'lazy' : 'eager'}
        placeholder={blur ? 'blur' : 'empty'}
        blurDataURL={blur ? getBlurDataURL() : undefined}
        className={cn(
          'transition-opacity duration-300',
          imageState === 'loaded' ? 'opacity-100' : 'opacity-0'
        )}
        sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
        quality={85}
        {...props}
      />

      {/* Error state */}
      {imageState === 'error' && imageSrc === fallback && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-100 text-gray-400">
          <svg
            className="w-12 h-12"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"
            />
          </svg>
        </div>
      )}
    </div>
  )
}

// Hook for lazy loading intersection observer
export function useLazyImage(threshold: number = 0.1) {
  const [inView, setInView] = useState(false)
  const [ref, setRef] = useState<Element | null>(null)

  useEffect(() => {
    if (!ref) return

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true)
          observer.disconnect()
        }
      },
      { threshold, rootMargin: '50px' }
    )

    observer.observe(ref)

    return () => observer.disconnect()
  }, [ref, threshold])

  return { ref: setRef, inView }
}

// Progressive image loading with WebP support
export function ProgressiveImage({
  src,
  webpSrc,
  alt,
  className,
  ...props
}: OptimizedImageProps & { webpSrc?: string }) {
  const [currentSrc, setCurrentSrc] = useState<string>('')
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    const img = new window.Image()
    
    // Check WebP support and load appropriate format
    const checkWebPSupport = () => {
      return new Promise<boolean>((resolve) => {
        const webP = new window.Image()
        webP.onload = webP.onerror = () => {
          resolve(webP.height === 2)
        }
        webP.src = 'data:image/webp;base64,UklGRjoAAABXRUJQVlA4IC4AAACyAgCdASoCAAIALmk0mk0iIiIiIgBoSygABc6WWgAA/veff/0PP8bA//LwYAAA'
      })
    }

    checkWebPSupport().then((supportsWebP) => {
      const targetSrc = supportsWebP && webpSrc ? webpSrc : src
      
      img.onload = () => {
        setCurrentSrc(targetSrc as string)
        setLoaded(true)
      }
      
      img.onerror = () => {
        setCurrentSrc(src as string)
        setLoaded(true)
      }
      
      img.src = targetSrc as string
    })
  }, [src, webpSrc])

  if (!loaded || !currentSrc) {
    return <div className={cn('bg-gray-200 animate-pulse', className)} />
  }

  return (
    <OptimizedImage
      src={currentSrc}
      alt={alt}
      className={className}
      {...props}
    />
  )
}