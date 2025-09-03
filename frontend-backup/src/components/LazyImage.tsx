import React, { useState, useRef, useEffect } from 'react';
import { Skeleton } from 'antd';

interface LazyImageProps {
  src: string;
  alt: string;
  className?: string;
  placeholder?: React.ReactNode;
  onLoad?: () => void;
  onError?: () => void;
}

export const LazyImage: React.FC<LazyImageProps> = ({
  src,
  alt,
  className = '',
  placeholder,
  onLoad,
  onError
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const [hasError, setHasError] = useState(false);
  const imgRef = useRef<HTMLImageElement>(null);
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    const currentImgRef = imgRef.current;
    
    if (!currentImgRef) return;

    // 创建 Intersection Observer
    observerRef.current = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsInView(true);
          observerRef.current?.disconnect();
        }
      },
      {
        rootMargin: '50px', // 提前50px开始加载
        threshold: 0.1
      }
    );

    observerRef.current.observe(currentImgRef);

    return () => {
      observerRef.current?.disconnect();
    };
  }, []);

  const handleLoad = () => {
    setIsLoaded(true);
    onLoad?.();
  };

  const handleError = () => {
    setHasError(true);
    onError?.();
  };

  const defaultPlaceholder = (
    <Skeleton.Image 
      active 
      className={`w-full h-full ${className}`}
    />
  );

  const errorPlaceholder = (
    <div className={`bg-gray-200 flex items-center justify-center ${className}`}>
      <span className="text-gray-500 text-sm">图片加载失败</span>
    </div>
  );

  return (
    <div className={`relative overflow-hidden ${className}`}>
      <img
        ref={imgRef}
        src={isInView ? src : undefined}
        alt={alt}
        className={`transition-opacity duration-300 ${
          isLoaded ? 'opacity-100' : 'opacity-0'
        } ${className}`}
        onLoad={handleLoad}
        onError={handleError}
        loading="lazy"
        decoding="async"
      />
      
      {/* 占位符 */}
      {!isLoaded && !hasError && (
        <div className="absolute inset-0">
          {placeholder || defaultPlaceholder}
        </div>
      )}
      
      {/* 错误状态 */}
      {hasError && (
        <div className="absolute inset-0">
          {errorPlaceholder}
        </div>
      )}
    </div>
  );
};

export default LazyImage;