import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';

interface VirtualListProps<T> {
  items: T[];
  itemHeight: number;
  containerHeight: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  overscan?: number;
  className?: string;
  onScroll?: (scrollTop: number) => void;
  getItemKey?: (item: T, index: number) => string | number;
}

export function VirtualList<T>({
  items,
  itemHeight,
  containerHeight,
  renderItem,
  overscan = 5,
  className = '',
  onScroll,
  getItemKey
}: VirtualListProps<T>) {
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const scrollElementRef = useRef<HTMLDivElement>(null);

  // 计算可见范围
  const visibleRange = useMemo(() => {
    const startIndex = Math.floor(scrollTop / itemHeight);
    const endIndex = Math.min(
      startIndex + Math.ceil(containerHeight / itemHeight),
      items.length - 1
    );

    return {
      start: Math.max(0, startIndex - overscan),
      end: Math.min(items.length - 1, endIndex + overscan)
    };
  }, [scrollTop, itemHeight, containerHeight, items.length, overscan]);

  // 可见项目
  const visibleItems = useMemo(() => {
    const result = [];
    for (let i = visibleRange.start; i <= visibleRange.end; i++) {
      result.push({
        index: i,
        item: items[i],
        key: getItemKey ? getItemKey(items[i], i) : i
      });
    }
    return result;
  }, [items, visibleRange, getItemKey]);

  // 防抖的滚动处理
  const debouncedOnScroll = useCallback(
    (scrollTop: number) => {
      const timeoutId = setTimeout(() => {
        onScroll?.(scrollTop);
      }, 16);
      return () => clearTimeout(timeoutId);
    },
    [onScroll]
  );

  // 滚动事件处理
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const newScrollTop = e.currentTarget.scrollTop;
    setScrollTop(newScrollTop);
    debouncedOnScroll(newScrollTop);
  }, [debouncedOnScroll]);

  // 滚动到指定索引
  const scrollToIndex = useCallback((index: number, align: 'start' | 'center' | 'end' = 'start') => {
    if (!scrollElementRef.current) return;

    let targetScrollTop = index * itemHeight;

    if (align === 'center') {
      targetScrollTop -= (containerHeight - itemHeight) / 2;
    } else if (align === 'end') {
      targetScrollTop -= containerHeight - itemHeight;
    }

    targetScrollTop = Math.max(0, Math.min(targetScrollTop, (items.length * itemHeight) - containerHeight));

    scrollElementRef.current.scrollTo({
      top: targetScrollTop,
      behavior: 'smooth'
    });
  }, [itemHeight, containerHeight, items.length]);

  // 暴露滚动方法
  useEffect(() => {
    if (containerRef.current) {
      (containerRef.current as HTMLDivElement & { scrollToIndex?: (index: number) => void }).scrollToIndex = scrollToIndex;
    }
  }, [scrollToIndex]);

  const totalHeight = items.length * itemHeight;
  const offsetY = visibleRange.start * itemHeight;

  return (
    <div
      ref={containerRef}
      className={`virtual-list-container ${className}`}
      style={{ height: containerHeight, overflow: 'hidden', position: 'relative' }}
    >
      <div
        ref={scrollElementRef}
        className="virtual-list-scroll"
        style={{
          height: '100%',
          overflow: 'auto',
          scrollbarWidth: 'thin'
        }}
        onScroll={handleScroll}
      >
        <div
          className="virtual-list-spacer"
          style={{ height: totalHeight, position: 'relative' }}
        >
          <div
            className="virtual-list-items"
            style={{
              transform: `translateY(${offsetY}px)`,
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0
            }}
          >
            {visibleItems.map(({ item, index, key }) => (
              <div
                key={key}
                className="virtual-list-item"
                style={{
                  height: itemHeight,
                  overflow: 'hidden'
                }}
                data-index={index}
              >
                {renderItem(item, index)}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// 动态高度虚拟列表
interface DynamicVirtualListProps<T> {
  items: T[];
  estimatedItemHeight: number;
  containerHeight: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  overscan?: number;
  className?: string;
  onScroll?: (scrollTop: number) => void;
  getItemKey?: (item: T, index: number) => string | number;
}

export function DynamicVirtualList<T>({
  items,
  estimatedItemHeight,
  containerHeight,
  renderItem,
  overscan = 5,
  className = '',
  onScroll,
  getItemKey
}: DynamicVirtualListProps<T>) {
  const [scrollTop, setScrollTop] = useState(0);
  const [itemHeights, setItemHeights] = useState<number[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  const scrollElementRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<Map<number, HTMLDivElement>>(new Map());

  // 更新项目高度
  const updateItemHeight = useCallback((index: number, height: number) => {
    setItemHeights(prev => {
      const newHeights = [...prev];
      newHeights[index] = height;
      return newHeights;
    });
  }, []);

  // 计算累积高度
  const cumulativeHeights = useMemo(() => {
    const heights = [];
    let total = 0;
    for (let i = 0; i < items.length; i++) {
      heights.push(total);
      total += itemHeights[i] || estimatedItemHeight;
    }
    heights.push(total);
    return heights;
  }, [items.length, itemHeights, estimatedItemHeight]);

  // 查找可见范围
  const visibleRange = useMemo(() => {
    const findIndex = (offset: number) => {
      let left = 0;
      let right = cumulativeHeights.length - 1;
      while (left < right) {
        const mid = Math.floor((left + right) / 2);
        if (cumulativeHeights[mid] < offset) {
          left = mid + 1;
        } else {
          right = mid;
        }
      }
      return Math.max(0, left - 1);
    };

    const startIndex = findIndex(scrollTop);
    const endIndex = findIndex(scrollTop + containerHeight);

    return {
      start: Math.max(0, startIndex - overscan),
      end: Math.min(items.length - 1, endIndex + overscan)
    };
  }, [scrollTop, containerHeight, cumulativeHeights, overscan, items.length]);

  // 可见项目
  const visibleItems = useMemo(() => {
    const result = [];
    for (let i = visibleRange.start; i <= visibleRange.end; i++) {
      result.push({
        index: i,
        item: items[i],
        key: getItemKey ? getItemKey(items[i], i) : i,
        top: cumulativeHeights[i],
        height: itemHeights[i] || estimatedItemHeight
      });
    }
    return result;
  }, [items, visibleRange, getItemKey, cumulativeHeights, itemHeights, estimatedItemHeight]);

  // 防抖的滚动处理
  const debouncedOnScroll = useCallback(
    (scrollTop: number) => {
      const timeoutId = setTimeout(() => {
        onScroll?.(scrollTop);
      }, 16);
      return () => clearTimeout(timeoutId);
    },
    [onScroll]
  );

  // 滚动事件处理
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const newScrollTop = e.currentTarget.scrollTop;
    setScrollTop(newScrollTop);
    debouncedOnScroll(newScrollTop);
  }, [debouncedOnScroll]);

  // 项目引用回调
  const setItemRef = useCallback((index: number) => {
    return (element: HTMLDivElement | null) => {
      const existingElement = itemRefs.current.get(index);
      if (existingElement && existingElement !== element) {
        // 清理旧的 ResizeObserver
        const observer = (existingElement as HTMLDivElement & { __resizeObserver?: ResizeObserver }).__resizeObserver;
        if (observer) {
          observer.disconnect();
          delete (existingElement as HTMLDivElement & { __resizeObserver?: ResizeObserver }).__resizeObserver;
        }
      }
      
      if (element) {
        itemRefs.current.set(index, element);
        // 使用 ResizeObserver 监控高度变化
        const resizeObserver = new ResizeObserver((entries) => {
          const entry = entries[0];
          if (entry) {
            updateItemHeight(index, entry.contentRect.height);
          }
        });
        resizeObserver.observe(element);
        // 存储 observer 引用以便后续清理
        (element as HTMLDivElement & { __resizeObserver?: ResizeObserver }).__resizeObserver = resizeObserver;
      } else {
        itemRefs.current.delete(index);
      }
    };
  }, [updateItemHeight]);

  const totalHeight = cumulativeHeights[cumulativeHeights.length - 1] || 0;

  return (
    <div
      ref={containerRef}
      className={`dynamic-virtual-list-container ${className}`}
      style={{ height: containerHeight, overflow: 'hidden', position: 'relative' }}
    >
      <div
        ref={scrollElementRef}
        className="dynamic-virtual-list-scroll"
        style={{
          height: '100%',
          overflow: 'auto',
          scrollbarWidth: 'thin'
        }}
        onScroll={handleScroll}
      >
        <div
          className="dynamic-virtual-list-spacer"
          style={{ height: totalHeight, position: 'relative' }}
        >
          {visibleItems.map(({ item, index, key, top, height }) => (
            <div
              key={key}
              ref={setItemRef(index)}
              className="dynamic-virtual-list-item"
              style={{
                position: 'absolute',
                top,
                left: 0,
                right: 0,
                minHeight: height
              }}
              data-index={index}
            >
              {renderItem(item, index)}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// 网格虚拟列表
interface VirtualGridProps<T> {
  items: T[];
  itemWidth: number;
  itemHeight: number;
  containerWidth: number;
  containerHeight: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  gap?: number;
  overscan?: number;
  className?: string;
  getItemKey?: (item: T, index: number) => string | number;
}

export function VirtualGrid<T>({
  items,
  itemWidth,
  itemHeight,
  containerWidth,
  containerHeight,
  renderItem,
  gap = 0,
  overscan = 5,
  className = '',
  getItemKey
}: VirtualGridProps<T>) {
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // 计算列数
  const columnsCount = Math.floor((containerWidth + gap) / (itemWidth + gap));
  const rowsCount = Math.ceil(items.length / columnsCount);

  // 计算可见行范围
  const visibleRowRange = useMemo(() => {
    const rowHeight = itemHeight + gap;
    const startRow = Math.floor(scrollTop / rowHeight);
    const endRow = Math.min(
      startRow + Math.ceil(containerHeight / rowHeight),
      rowsCount - 1
    );

    return {
      start: Math.max(0, startRow - overscan),
      end: Math.min(rowsCount - 1, endRow + overscan)
    };
  }, [scrollTop, itemHeight, gap, containerHeight, rowsCount, overscan]);

  // 可见项目
  const visibleItems = useMemo(() => {
    const result = [];
    for (let row = visibleRowRange.start; row <= visibleRowRange.end; row++) {
      for (let col = 0; col < columnsCount; col++) {
        const index = row * columnsCount + col;
        if (index < items.length) {
          result.push({
            index,
            item: items[index],
            key: getItemKey ? getItemKey(items[index], index) : index,
            row,
            col,
            x: col * (itemWidth + gap),
            y: row * (itemHeight + gap)
          });
        }
      }
    }
    return result;
  }, [items, visibleRowRange, columnsCount, itemWidth, itemHeight, gap, getItemKey]);

  // 滚动事件处理
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, [setScrollTop]);

  const totalHeight = rowsCount * (itemHeight + gap) - gap;
  const offsetY = visibleRowRange.start * (itemHeight + gap);

  return (
    <div
      ref={containerRef}
      className={`virtual-grid-container ${className}`}
      style={{ 
        width: containerWidth,
        height: containerHeight, 
        overflow: 'auto',
        position: 'relative'
      }}
      onScroll={handleScroll}
    >
      <div
        className="virtual-grid-spacer"
        style={{ height: totalHeight, position: 'relative' }}
      >
        <div
          className="virtual-grid-items"
          style={{
            transform: `translateY(${offsetY}px)`,
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0
          }}
        >
          {visibleItems.map(({ item, index, key, x, y }) => (
            <div
              key={key}
              className="virtual-grid-item"
              style={{
                position: 'absolute',
                left: x,
                top: y - offsetY,
                width: itemWidth,
                height: itemHeight
              }}
              data-index={index}
            >
              {renderItem(item, index)}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}