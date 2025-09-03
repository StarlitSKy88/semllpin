/**
 * 现代化网格布局组件
 * 基于CSS Grid和Flexbox的响应式网格系统
 */

import React from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';

// 网格容器组件
export interface GridProps {
  cols?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;
  rows?: 1 | 2 | 3 | 4 | 5 | 6;
  gap?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  gapX?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  gapY?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  responsive?: {
    sm?: Partial<Pick<GridProps, 'cols' | 'rows' | 'gap' | 'gapX' | 'gapY'>>;
    md?: Partial<Pick<GridProps, 'cols' | 'rows' | 'gap' | 'gapX' | 'gapY'>>;
    lg?: Partial<Pick<GridProps, 'cols' | 'rows' | 'gap' | 'gapX' | 'gapY'>>;
    xl?: Partial<Pick<GridProps, 'cols' | 'rows' | 'gap' | 'gapX' | 'gapY'>>;
    '2xl'?: Partial<Pick<GridProps, 'cols' | 'rows' | 'gap' | 'gapX' | 'gapY'>>;
  };
  autoFit?: boolean;
  autoFill?: boolean;
  minColWidth?: string;
  className?: string;
  style?: React.CSSProperties;
  children: React.ReactNode;
}

// 定义复合组件类型
interface GridComponent extends React.FC<GridProps> {
  Item: React.FC<GridItemProps>;
  Simple: React.FC<SimpleGridProps>;
  Card: React.FC<CardGridProps>;
}

const Grid: GridComponent = ({
  cols = 12,
  rows,
  gap = 'md',
  gapX,
  gapY,
  responsive,
  autoFit = false,
  autoFill = false,
  minColWidth = '250px',
  className,
  children,
}) => {
  useTheme();

  // 列数样式映射
  const colsStyles = {
    1: 'grid-cols-1',
    2: 'grid-cols-2',
    3: 'grid-cols-3',
    4: 'grid-cols-4',
    5: 'grid-cols-5',
    6: 'grid-cols-6',
    7: 'grid-cols-7',
    8: 'grid-cols-8',
    9: 'grid-cols-9',
    10: 'grid-cols-10',
    11: 'grid-cols-11',
    12: 'grid-cols-12',
  };

  // 行数样式映射
  const rowsStyles = {
    1: 'grid-rows-1',
    2: 'grid-rows-2',
    3: 'grid-rows-3',
    4: 'grid-rows-4',
    5: 'grid-rows-5',
    6: 'grid-rows-6',
  };

  // 间距样式映射
  const gapStyles = {
    none: 'gap-0',
    xs: 'gap-1',
    sm: 'gap-2',
    md: 'gap-4',
    lg: 'gap-6',
    xl: 'gap-8',
    '2xl': 'gap-12',
  };

  const gapXStyles = {
    none: 'gap-x-0',
    xs: 'gap-x-1',
    sm: 'gap-x-2',
    md: 'gap-x-4',
    lg: 'gap-x-6',
    xl: 'gap-x-8',
    '2xl': 'gap-x-12',
  };

  const gapYStyles = {
    none: 'gap-y-0',
    xs: 'gap-y-1',
    sm: 'gap-y-2',
    md: 'gap-y-4',
    lg: 'gap-y-6',
    xl: 'gap-y-8',
    '2xl': 'gap-y-12',
  };

  // 构建响应式类名
  const buildResponsiveClasses = () => {
    if (!responsive) return '';
    
    const classes: string[] = [];
    
    Object.entries(responsive).forEach(([breakpoint, config]) => {
      const prefix = breakpoint === 'sm' ? 'sm:' : `${breakpoint}:`;
      
      if (config.cols) {
        classes.push(`${prefix}${colsStyles[config.cols]}`);
      }
      if (config.rows) {
        classes.push(`${prefix}${rowsStyles[config.rows]}`);
      }
      if (config.gap) {
        classes.push(`${prefix}${gapStyles[config.gap]}`);
      }
      if (config.gapX) {
        classes.push(`${prefix}${gapXStyles[config.gapX]}`);
      }
      if (config.gapY) {
        classes.push(`${prefix}${gapYStyles[config.gapY]}`);
      }
    });
    
    return classes.join(' ');
  };

  // 自适应网格样式
  const autoGridStyle = (autoFit || autoFill) ? {
    gridTemplateColumns: `repeat(${autoFit ? 'auto-fit' : 'auto-fill'}, minmax(${minColWidth}, 1fr))`,
  } : undefined;

  return (
    <div
      className={cn(
        'grid',
        {
          [colsStyles[cols]]: !autoFit && !autoFill,
          [rowsStyles[rows!]]: rows,
          [gapStyles[gap]]: gap && !gapX && !gapY,
          [gapXStyles[gapX!]]: gapX,
          [gapYStyles[gapY!]]: gapY,
        },
        buildResponsiveClasses(),
        className
      )}
      style={autoGridStyle}
    >
      {children}
    </div>
  );
};

// 网格项组件
export interface GridItemProps {
  col?: 'auto' | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;
  colStart?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13;
  colEnd?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13;
  row?: 'auto' | 1 | 2 | 3 | 4 | 5 | 6;
  rowStart?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  rowEnd?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  responsive?: {
    sm?: Partial<Pick<GridItemProps, 'col' | 'colStart' | 'colEnd' | 'row' | 'rowStart' | 'rowEnd'>>;
    md?: Partial<Pick<GridItemProps, 'col' | 'colStart' | 'colEnd' | 'row' | 'rowStart' | 'rowEnd'>>;
    lg?: Partial<Pick<GridItemProps, 'col' | 'colStart' | 'colEnd' | 'row' | 'rowStart' | 'rowEnd'>>;
    xl?: Partial<Pick<GridItemProps, 'col' | 'colStart' | 'colEnd' | 'row' | 'rowStart' | 'rowEnd'>>;
    '2xl'?: Partial<Pick<GridItemProps, 'col' | 'colStart' | 'colEnd' | 'row' | 'rowStart' | 'rowEnd'>>;
  };
  className?: string;
  children: React.ReactNode;
}

const GridItem: React.FC<GridItemProps> = ({
  col,
  colStart,
  colEnd,
  row,
  rowStart,
  rowEnd,
  responsive,
  className,
  children,
}) => {
  // 列跨度样式
  const colStyles = {
    auto: 'col-auto',
    1: 'col-span-1',
    2: 'col-span-2',
    3: 'col-span-3',
    4: 'col-span-4',
    5: 'col-span-5',
    6: 'col-span-6',
    7: 'col-span-7',
    8: 'col-span-8',
    9: 'col-span-9',
    10: 'col-span-10',
    11: 'col-span-11',
    12: 'col-span-12',
  };

  // 列开始位置样式
  const colStartStyles = {
    1: 'col-start-1',
    2: 'col-start-2',
    3: 'col-start-3',
    4: 'col-start-4',
    5: 'col-start-5',
    6: 'col-start-6',
    7: 'col-start-7',
    8: 'col-start-8',
    9: 'col-start-9',
    10: 'col-start-10',
    11: 'col-start-11',
    12: 'col-start-12',
    13: 'col-start-13',
  };

  // 列结束位置样式
  const colEndStyles = {
    1: 'col-end-1',
    2: 'col-end-2',
    3: 'col-end-3',
    4: 'col-end-4',
    5: 'col-end-5',
    6: 'col-end-6',
    7: 'col-end-7',
    8: 'col-end-8',
    9: 'col-end-9',
    10: 'col-end-10',
    11: 'col-end-11',
    12: 'col-end-12',
    13: 'col-end-13',
  };

  // 行跨度样式
  const rowStyles = {
    auto: 'row-auto',
    1: 'row-span-1',
    2: 'row-span-2',
    3: 'row-span-3',
    4: 'row-span-4',
    5: 'row-span-5',
    6: 'row-span-6',
  };

  // 行开始位置样式
  const rowStartStyles = {
    1: 'row-start-1',
    2: 'row-start-2',
    3: 'row-start-3',
    4: 'row-start-4',
    5: 'row-start-5',
    6: 'row-start-6',
    7: 'row-start-7',
  };

  // 行结束位置样式
  const rowEndStyles = {
    1: 'row-end-1',
    2: 'row-end-2',
    3: 'row-end-3',
    4: 'row-end-4',
    5: 'row-end-5',
    6: 'row-end-6',
    7: 'row-end-7',
  };

  // 构建响应式类名
  const buildResponsiveClasses = () => {
    if (!responsive) return '';
    
    const classes: string[] = [];
    
    Object.entries(responsive).forEach(([breakpoint, config]) => {
      const prefix = breakpoint === 'sm' ? 'sm:' : `${breakpoint}:`;
      
      if (config.col) {
        classes.push(`${prefix}${colStyles[config.col]}`);
      }
      if (config.colStart) {
        classes.push(`${prefix}${colStartStyles[config.colStart]}`);
      }
      if (config.colEnd) {
        classes.push(`${prefix}${colEndStyles[config.colEnd]}`);
      }
      if (config.row) {
        classes.push(`${prefix}${rowStyles[config.row]}`);
      }
      if (config.rowStart) {
        classes.push(`${prefix}${rowStartStyles[config.rowStart]}`);
      }
      if (config.rowEnd) {
        classes.push(`${prefix}${rowEndStyles[config.rowEnd]}`);
      }
    });
    
    return classes.join(' ');
  };

  return (
    <div
      className={cn(
        {
          [colStyles[col!]]: col,
          [colStartStyles[colStart!]]: colStart,
          [colEndStyles[colEnd!]]: colEnd,
          [rowStyles[row!]]: row,
          [rowStartStyles[rowStart!]]: rowStart,
          [rowEndStyles[rowEnd!]]: rowEnd,
        },
        buildResponsiveClasses(),
        className
      )}
    >
      {children}
    </div>
  );
};

// 简化的网格布局组件
export interface SimpleGridProps {
  columns?: 1 | 2 | 3 | 4 | 5 | 6;
  gap?: GridProps['gap'];
  responsive?: boolean;
  className?: string;
  children: React.ReactNode;
}

export const SimpleGrid: React.FC<SimpleGridProps> = ({
  columns = 1,
  gap = 'md',
  responsive = true,
  className,
  children,
}) => {
  const responsiveConfig = responsive ? {
    sm: { cols: Math.min(columns, 2) as GridProps['cols'] },
    md: { cols: Math.min(columns, 3) as GridProps['cols'] },
    lg: { cols: columns as GridProps['cols'] },
  } : undefined;

  return (
    <Grid
      cols={responsive ? 1 : columns as GridProps['cols']}
      gap={gap}
      responsive={responsiveConfig}
      className={className}
    >
      {children}
    </Grid>
  );
};

// 卡片网格组件
export interface CardGridProps extends Omit<GridProps, 'cols'> {
  minCardWidth?: string;
  maxCols?: 1 | 2 | 3 | 4 | 5 | 6;
}

export const CardGrid: React.FC<CardGridProps> = ({
  minCardWidth = '300px',
  maxCols = 4,
  gap = 'lg',
  className,
  children,
  ...props
}) => {
  return (
    <Grid
      {...props}
      autoFit
      minColWidth={minCardWidth}
      gap={gap}
      className={cn('max-w-none', className)}
      style={{
        gridTemplateColumns: `repeat(auto-fit, minmax(${minCardWidth}, 1fr))`,
        maxWidth: `calc(${maxCols} * (${minCardWidth} + var(--gap-${gap}, 1rem)))`,
      }}
    >
      {children}
    </Grid>
  );
};

// 复合组件
Grid.Item = GridItem;
Grid.Simple = SimpleGrid;
Grid.Card = CardGrid;

export default Grid;