import React, { useState, useRef, useEffect } from 'react';
import { Skeleton } from 'antd';
import { cn } from '../../utils/cn';

interface LazyImageProps extends React.ImgHTMLAttributes<HTMLImageElement> {
  src: string;
  alt: string;
  placeholder?: string;
  fallback?: string;
  className?: string;
  skeletonClassName?: string;
  onLoad?: () => void;
  onError?: () => void;
  threshold?: number;
  rootMargin?: string;
}

export const LazyImage: React.FC<LazyImageProps> = ({
  src,
  alt,
  placeholder,
  fallback = '/images/placeholder.jpg',
  className,
  skeletonClassName,
  onLoad,
  onError,
  threshold = 0.1,
  rootMargin = '50px',
  ...props
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const [hasError, setHasError] = useState(false);
  const imgRef = useRef<HTMLImageElement>(null);
  const [imageSrc, setImageSrc] = useState<string>('');

  // Intersection Observer for lazy loading
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsInView(true);
          observer.disconnect();
        }
      },
      {
        threshold,
        rootMargin,
      }
    );

    if (imgRef.current) {
      observer.observe(imgRef.current);
    }

    return () => observer.disconnect();
  }, [threshold, rootMargin]);

  // Load image when in view
  useEffect(() => {
    if (isInView && src) {
      // 预检查图片格式支持
      const img = new Image();
      
      img.onload = () => {
        setImageSrc(src);
        setIsLoaded(true);
        onLoad?.();
      };
      
      img.onerror = () => {
        setHasError(true);
        setImageSrc(fallback);
        onError?.();
      };
      
      // 尝试加载WebP格式（如果支持）
      const supportsWebP = () => {
        const canvas = document.createElement('canvas');
        return canvas.toDataURL('image/webp').indexOf('data:image/webp') === 0;
      };
      
      // 如果支持WebP且原图不是WebP，尝试WebP版本
      if (supportsWebP() && !src.includes('.webp')) {
        const webpSrc = src.replace(/\.(jpg|jpeg|png)$/i, '.webp');
        const webpImg = new Image();
        
        webpImg.onload = () => {
          setImageSrc(webpSrc);
          setIsLoaded(true);
          onLoad?.();
        };
        
        webpImg.onerror = () => {
          // WebP失败，使用原图
          img.src = src;
        };
        
        webpImg.src = webpSrc;
      } else {
        img.src = src;
      }
    }
  }, [isInView, src, fallback, onLoad, onError]);

  if (!isInView) {
    return (
      <div ref={imgRef} className={cn('relative overflow-hidden', className)}>
        {placeholder ? (
          <img
            src={placeholder}
            alt={alt}
            className={cn('w-full h-full object-cover filter blur-sm', className)}
            {...props}
          />
        ) : (
          <Skeleton.Image
            active
            className={cn('w-full h-full', skeletonClassName)}
          />
        )}
      </div>
    );
  }

  return (
    <div className={cn('relative overflow-hidden', className)}>
      {!isLoaded && (
        <div className="absolute inset-0 z-10">
          {placeholder ? (
            <img
              src={placeholder}
              alt={alt}
              className={cn('w-full h-full object-cover filter blur-sm', className)}
            />
          ) : (
            <Skeleton.Image
              active
              className={cn('w-full h-full', skeletonClassName)}
            />
          )}
        </div>
      )}
      
      <img
        ref={imgRef}
        src={imageSrc}
        alt={alt}
        className={cn(
          'w-full h-full object-cover transition-opacity duration-300',
          isLoaded ? 'opacity-100' : 'opacity-0',
          className
        )}
        loading="lazy"
        decoding="async"
        {...props}
      />
      
      {hasError && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-100 text-gray-400">
          <span className="text-sm">图片加载失败</span>
        </div>
      )}
    </div>
  );
};

export default LazyImage;