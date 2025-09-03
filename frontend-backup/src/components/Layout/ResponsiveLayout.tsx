/**
 * 现代化响应式布局组件
 * 整合容器、网格和弹性布局的统一响应式解决方案
 */

import React from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import Container from './Container';
import Grid from './Grid';
import Flex from './Flex';

// 断点配置
export const breakpoints = {
  sm: '640px',
  md: '768px',
  lg: '1024px',
  xl: '1280px',
  '2xl': '1536px',
} as const;

export type Breakpoint = keyof typeof breakpoints;

// 响应式值类型
export type ResponsiveValue<T> = T | Partial<Record<Breakpoint, T>>;

// 响应式布局主组件
export interface ResponsiveLayoutProps {
  // 容器配置
  container?: boolean;
  containerSize?: ResponsiveValue<'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full'>;
  padding?: ResponsiveValue<'none' | 'sm' | 'md' | 'lg' | 'xl'>;
  
  // 布局类型
  layout?: 'flex' | 'grid' | 'block';
  
  // Flex 配置
  direction?: ResponsiveValue<'row' | 'row-reverse' | 'col' | 'col-reverse'>;
  justify?: ResponsiveValue<'start' | 'end' | 'center' | 'between' | 'around' | 'evenly'>;
  align?: ResponsiveValue<'start' | 'end' | 'center' | 'baseline' | 'stretch'>;
  wrap?: ResponsiveValue<'nowrap' | 'wrap' | 'wrap-reverse'>;
  
  // Grid 配置
  cols?: ResponsiveValue<1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12>;
  rows?: ResponsiveValue<1 | 2 | 3 | 4 | 5 | 6>;
  autoFit?: boolean;
  minColWidth?: string;
  
  // 间距配置
  gap?: ResponsiveValue<'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl'>;
  gapX?: ResponsiveValue<'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl'>;
  gapY?: ResponsiveValue<'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl'>;
  
  // 显示控制
  show?: ResponsiveValue<boolean>;
  hide?: ResponsiveValue<boolean>;
  
  // 样式
  className?: string;
  children: React.ReactNode;
}

// 响应式值处理函数
// const processResponsiveValue = <T,>(value: ResponsiveValue<T>, property: string): string => {
//   if (typeof value === 'object' && value !== null) {
//     return Object.entries(value)
//       .map(([breakpoint, val]) => {
//         const prefix = breakpoint === 'sm' ? 'sm:' : `${breakpoint}:`;
//         return `${prefix}${property}-${val}`;
//       })
//       .join(' ');
//   }
//   return `${property}-${value}`;
// };

// 显示/隐藏处理函数
const processVisibility = (show?: ResponsiveValue<boolean>, hide?: ResponsiveValue<boolean>): string => {
  const classes: string[] = [];
  
  if (show) {
    if (typeof show === 'object') {
      Object.entries(show).forEach(([breakpoint, visible]) => {
        const prefix = breakpoint === 'sm' ? 'sm:' : `${breakpoint}:`;
        classes.push(visible ? `${prefix}block` : `${prefix}hidden`);
      });
    } else {
      classes.push(show ? 'block' : 'hidden');
    }
  }
  
  if (hide) {
    if (typeof hide === 'object') {
      Object.entries(hide).forEach(([breakpoint, hidden]) => {
        const prefix = breakpoint === 'sm' ? 'sm:' : `${breakpoint}:`;
        classes.push(hidden ? `${prefix}hidden` : `${prefix}block`);
      });
    } else {
      classes.push(hide ? 'hidden' : 'block');
    }
  }
  
  return classes.join(' ');
};

interface ResponsiveLayoutComponent extends React.FC<ResponsiveLayoutProps> {
  GridItem: React.FC<ResponsiveGridItemProps>;
  FlexItem: React.FC<ResponsiveFlexItemProps>;
}

const ResponsiveLayout: ResponsiveLayoutComponent = ({
  container = false,
  containerSize = 'lg',
  padding = 'md',
  layout = 'block',
  direction = 'row',
  justify = 'start',
  align = 'start',
  wrap = 'nowrap',
  cols = 12,
  rows,
  autoFit = false,
  minColWidth = '250px',
  gap,
  gapX,
  gapY,
  show,
  hide,
  className,
  children,
}) => {
  useTheme();

  // 构建响应式类名
  const buildResponsiveClasses = () => {
    const classes: string[] = [];
    
    // 处理显示/隐藏
    const visibilityClasses = processVisibility(show, hide);
    if (visibilityClasses) {
      classes.push(visibilityClasses);
    }
    
    return classes.join(' ');
  };

  // 构建布局组件
  const renderLayout = () => {
    const responsiveClasses = buildResponsiveClasses();
    
    if (layout === 'flex') {
      // 处理 Flex 响应式属性
      const flexResponsive: any = {};
      
      ['sm', 'md', 'lg', 'xl', '2xl'].forEach(bp => {
        const config: any = {};
        
        if (typeof direction === 'object' && direction[bp as Breakpoint]) {
          config.direction = direction[bp as Breakpoint];
        }
        if (typeof justify === 'object' && justify[bp as Breakpoint]) {
          config.justify = justify[bp as Breakpoint];
        }
        if (typeof align === 'object' && align[bp as Breakpoint]) {
          config.align = align[bp as Breakpoint];
        }
        if (typeof wrap === 'object' && wrap[bp as Breakpoint]) {
          config.wrap = wrap[bp as Breakpoint];
        }
        if (typeof gap === 'object' && gap[bp as Breakpoint]) {
          config.gap = gap[bp as Breakpoint];
        }
        if (typeof gapX === 'object' && gapX[bp as Breakpoint]) {
          config.gapX = gapX[bp as Breakpoint];
        }
        if (typeof gapY === 'object' && gapY[bp as Breakpoint]) {
          config.gapY = gapY[bp as Breakpoint];
        }
        
        if (Object.keys(config).length > 0) {
          flexResponsive[bp] = config;
        }
      });
      
      return (
        <Flex
          direction={typeof direction === 'object' ? 'row' : direction}
          justify={typeof justify === 'object' ? 'start' : justify}
          align={typeof align === 'object' ? 'start' : align}
          wrap={typeof wrap === 'object' ? 'nowrap' : wrap}
          gap={typeof gap === 'object' ? undefined : gap}
          gapX={typeof gapX === 'object' ? undefined : gapX}
          gapY={typeof gapY === 'object' ? undefined : gapY}
          responsive={Object.keys(flexResponsive).length > 0 ? flexResponsive : undefined}
          className={cn(responsiveClasses, className)}
        >
          {children}
        </Flex>
      );
    }
    
    if (layout === 'grid') {
      // 处理 Grid 响应式属性
      const gridResponsive: any = {};
      
      ['sm', 'md', 'lg', 'xl', '2xl'].forEach(bp => {
        const config: any = {};
        
        if (typeof cols === 'object' && cols[bp as Breakpoint]) {
          config.cols = cols[bp as Breakpoint];
        }
        if (typeof rows === 'object' && rows[bp as Breakpoint]) {
          config.rows = rows[bp as Breakpoint];
        }
        if (typeof gap === 'object' && gap[bp as Breakpoint]) {
          config.gap = gap[bp as Breakpoint];
        }
        if (typeof gapX === 'object' && gapX[bp as Breakpoint]) {
          config.gapX = gapX[bp as Breakpoint];
        }
        if (typeof gapY === 'object' && gapY[bp as Breakpoint]) {
          config.gapY = gapY[bp as Breakpoint];
        }
        
        if (Object.keys(config).length > 0) {
          gridResponsive[bp] = config;
        }
      });
      
      return (
        <Grid
          cols={typeof cols === 'object' ? 12 : cols}
          rows={typeof rows === 'object' ? undefined : rows}
          gap={typeof gap === 'object' ? undefined : gap}
          gapX={typeof gapX === 'object' ? undefined : gapX}
          gapY={typeof gapY === 'object' ? undefined : gapY}
          autoFit={autoFit}
          minColWidth={minColWidth}
          responsive={Object.keys(gridResponsive).length > 0 ? gridResponsive : undefined}
          className={cn(responsiveClasses, className)}
        >
          {children}
        </Grid>
      );
    }
    
    // 默认块级布局
    return (
      <div className={cn(responsiveClasses, className)}>
        {children}
      </div>
    );
  };

  // 如果需要容器包装
  if (container) {
    const containerResponsive: any = {};
    
    if (typeof containerSize === 'object') {
      ['sm', 'md', 'lg', 'xl', '2xl'].forEach(bp => {
        if (containerSize[bp as Breakpoint]) {
          containerResponsive[bp] = { size: containerSize[bp as Breakpoint] };
        }
      });
    }
    
    return (
      <Container
        size={typeof containerSize === 'object' ? 'lg' : containerSize}
        padding={typeof padding === 'object' ? 'md' : padding}
      >
        {renderLayout()}
      </Container>
    );
  }

  return renderLayout();
};

// 响应式网格项组件
export interface ResponsiveGridItemProps {
  col?: ResponsiveValue<'auto' | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12>;
  colStart?: ResponsiveValue<1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13>;
  colEnd?: ResponsiveValue<1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13>;
  row?: ResponsiveValue<'auto' | 1 | 2 | 3 | 4 | 5 | 6>;
  rowStart?: ResponsiveValue<1 | 2 | 3 | 4 | 5 | 6 | 7>;
  rowEnd?: ResponsiveValue<1 | 2 | 3 | 4 | 5 | 6 | 7>;
  order?: ResponsiveValue<number>;
  show?: ResponsiveValue<boolean>;
  hide?: ResponsiveValue<boolean>;
  className?: string;
  children: React.ReactNode;
}

export const ResponsiveGridItem: React.FC<ResponsiveGridItemProps> = ({
  col,
  colStart,
  colEnd,
  row,
  rowStart,
  rowEnd,
  order,
  show,
  hide,
  className,
  children,
}) => {
  // 构建响应式配置
  const responsive: any = {};
  
  ['sm', 'md', 'lg', 'xl', '2xl'].forEach(bp => {
    const config: any = {};
    
    if (typeof col === 'object' && col[bp as Breakpoint]) {
      config.col = col[bp as Breakpoint];
    }
    if (typeof colStart === 'object' && colStart[bp as Breakpoint]) {
      config.colStart = colStart[bp as Breakpoint];
    }
    if (typeof colEnd === 'object' && colEnd[bp as Breakpoint]) {
      config.colEnd = colEnd[bp as Breakpoint];
    }
    if (typeof row === 'object' && row[bp as Breakpoint]) {
      config.row = row[bp as Breakpoint];
    }
    if (typeof rowStart === 'object' && rowStart[bp as Breakpoint]) {
      config.rowStart = rowStart[bp as Breakpoint];
    }
    if (typeof rowEnd === 'object' && rowEnd[bp as Breakpoint]) {
      config.rowEnd = rowEnd[bp as Breakpoint];
    }
    if (typeof order === 'object' && order[bp as Breakpoint]) {
      config.order = order[bp as Breakpoint];
    }
    
    if (Object.keys(config).length > 0) {
      responsive[bp] = config;
    }
  });
  
  const visibilityClasses = processVisibility(show, hide);
  
  return (
    <ResponsiveGridItem
      col={typeof col === 'object' ? undefined : col}
      colStart={typeof colStart === 'object' ? undefined : colStart}
      colEnd={typeof colEnd === 'object' ? undefined : colEnd}
      row={typeof row === 'object' ? undefined : row}
      rowStart={typeof rowStart === 'object' ? undefined : rowStart}
      rowEnd={typeof rowEnd === 'object' ? undefined : rowEnd}
      className={cn(visibilityClasses, className)}
    >
      {children}
    </ResponsiveGridItem>
  );
};

// 响应式弹性项组件
export interface ResponsiveFlexItemProps {
  flex?: ResponsiveValue<'none' | 'auto' | 'initial' | '1' | number | string>;
  grow?: ResponsiveValue<0 | 1 | number>;
  shrink?: ResponsiveValue<0 | 1 | number>;
  basis?: ResponsiveValue<'auto' | 'full' | 'px' | string>;
  order?: ResponsiveValue<number>;
  alignSelf?: ResponsiveValue<'auto' | 'start' | 'end' | 'center' | 'baseline' | 'stretch'>;
  show?: ResponsiveValue<boolean>;
  hide?: ResponsiveValue<boolean>;
  className?: string;
  children: React.ReactNode;
}

export const ResponsiveFlexItem: React.FC<ResponsiveFlexItemProps> = ({
  flex,
  grow,
  shrink,
  basis,
  order,
  alignSelf,
  show,
  hide,
  className,
  children,
}) => {
  // 构建响应式配置
  const responsive: any = {};
  
  ['sm', 'md', 'lg', 'xl', '2xl'].forEach(bp => {
    const config: any = {};
    
    if (typeof flex === 'object' && flex[bp as Breakpoint]) {
      config.flex = flex[bp as Breakpoint];
    }
    if (typeof grow === 'object' && grow[bp as Breakpoint]) {
      config.grow = grow[bp as Breakpoint];
    }
    if (typeof shrink === 'object' && shrink[bp as Breakpoint]) {
      config.shrink = shrink[bp as Breakpoint];
    }
    if (typeof basis === 'object' && basis[bp as Breakpoint]) {
      config.basis = basis[bp as Breakpoint];
    }
    if (typeof order === 'object' && order[bp as Breakpoint]) {
      config.order = order[bp as Breakpoint];
    }
    if (typeof alignSelf === 'object' && alignSelf[bp as Breakpoint]) {
      config.alignSelf = alignSelf[bp as Breakpoint];
    }
    
    if (Object.keys(config).length > 0) {
      responsive[bp] = config;
    }
  });
  
  const visibilityClasses = processVisibility(show, hide);
  
  return (
    <ResponsiveFlexItem
      flex={typeof flex === 'object' ? undefined : flex}
      grow={typeof grow === 'object' ? undefined : grow}
      shrink={typeof shrink === 'object' ? undefined : shrink}
      basis={typeof basis === 'object' ? undefined : basis}
      order={typeof order === 'object' ? undefined : order}
      alignSelf={typeof alignSelf === 'object' ? undefined : alignSelf}
      className={cn(visibilityClasses, className)}
    >
      {children}
    </ResponsiveFlexItem>
  );
};

// 复合组件
ResponsiveLayout.GridItem = ResponsiveGridItem;
ResponsiveLayout.FlexItem = ResponsiveFlexItem;

export default ResponsiveLayout;