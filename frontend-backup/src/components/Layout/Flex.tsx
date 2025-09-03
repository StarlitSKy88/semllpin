/**
 * 现代化弹性布局组件
 * 基于Flexbox的响应式布局系统
 */

import React from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';

// 弹性容器组件
export interface FlexProps {
  direction?: 'row' | 'row-reverse' | 'col' | 'col-reverse';
  wrap?: 'nowrap' | 'wrap' | 'wrap-reverse';
  justify?: 'start' | 'end' | 'center' | 'between' | 'around' | 'evenly';
  align?: 'start' | 'end' | 'center' | 'baseline' | 'stretch';
  gap?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  gapX?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  gapY?: 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  responsive?: {
    sm?: Partial<Pick<FlexProps, 'direction' | 'wrap' | 'justify' | 'align' | 'gap' | 'gapX' | 'gapY'>>;
    md?: Partial<Pick<FlexProps, 'direction' | 'wrap' | 'justify' | 'align' | 'gap' | 'gapX' | 'gapY'>>;
    lg?: Partial<Pick<FlexProps, 'direction' | 'wrap' | 'justify' | 'align' | 'gap' | 'gapX' | 'gapY'>>;
    xl?: Partial<Pick<FlexProps, 'direction' | 'wrap' | 'justify' | 'align' | 'gap' | 'gapX' | 'gapY'>>;
    '2xl'?: Partial<Pick<FlexProps, 'direction' | 'wrap' | 'justify' | 'align' | 'gap' | 'gapX' | 'gapY'>>;
  };
  as?: keyof JSX.IntrinsicElements;
  className?: string;
  children: React.ReactNode;
}

// 定义复合组件类型
interface FlexComponent extends React.FC<FlexProps> {
  Item: React.FC<FlexItemProps>;
  Center: React.FC<CenterProps>;
  Spacer: React.FC<SpacerProps>;
  VStack: React.FC<StackProps>;
  HStack: React.FC<StackProps>;
}

const Flex: FlexComponent = ({
  direction = 'row',
  wrap = 'nowrap',
  justify = 'start',
  align = 'start',
  gap,
  gapX,
  gapY,
  responsive,
  as: Component = 'div',
  className,
  children,
  ...props
}) => {
  useTheme();

  // 方向样式映射
  const directionStyles = {
    row: 'flex-row',
    'row-reverse': 'flex-row-reverse',
    col: 'flex-col',
    'col-reverse': 'flex-col-reverse',
  };

  // 换行样式映射
  const wrapStyles = {
    nowrap: 'flex-nowrap',
    wrap: 'flex-wrap',
    'wrap-reverse': 'flex-wrap-reverse',
  };

  // 主轴对齐样式映射
  const justifyStyles = {
    start: 'justify-start',
    end: 'justify-end',
    center: 'justify-center',
    between: 'justify-between',
    around: 'justify-around',
    evenly: 'justify-evenly',
  };

  // 交叉轴对齐样式映射
  const alignStyles = {
    start: 'items-start',
    end: 'items-end',
    center: 'items-center',
    baseline: 'items-baseline',
    stretch: 'items-stretch',
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
      
      if (config.direction) {
        classes.push(`${prefix}${directionStyles[config.direction]}`);
      }
      if (config.wrap) {
        classes.push(`${prefix}${wrapStyles[config.wrap]}`);
      }
      if (config.justify) {
        classes.push(`${prefix}${justifyStyles[config.justify]}`);
      }
      if (config.align) {
        classes.push(`${prefix}${alignStyles[config.align]}`);
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

  return (
    <Component
      className={cn(
        'flex',
        directionStyles[direction],
        wrapStyles[wrap],
        justifyStyles[justify],
        alignStyles[align],
        {
          [gapStyles[gap!]]: gap && !gapX && !gapY,
          [gapXStyles[gapX!]]: gapX,
          [gapYStyles[gapY!]]: gapY,
        },
        buildResponsiveClasses(),
        className
      )}
      {...props}
    >
      {children}
    </Component>
  );
};

// 弹性项组件
export interface FlexItemProps {
  flex?: 'none' | 'auto' | 'initial' | '1' | number | string;
  grow?: 0 | 1 | number;
  shrink?: 0 | 1 | number;
  basis?: 'auto' | 'full' | 'px' | string;
  order?: number;
  alignSelf?: 'auto' | 'start' | 'end' | 'center' | 'baseline' | 'stretch';
  responsive?: {
    sm?: Partial<Pick<FlexItemProps, 'flex' | 'grow' | 'shrink' | 'basis' | 'order' | 'alignSelf'>>;
    md?: Partial<Pick<FlexItemProps, 'flex' | 'grow' | 'shrink' | 'basis' | 'order' | 'alignSelf'>>;
    lg?: Partial<Pick<FlexItemProps, 'flex' | 'grow' | 'shrink' | 'basis' | 'order' | 'alignSelf'>>;
    xl?: Partial<Pick<FlexItemProps, 'flex' | 'grow' | 'shrink' | 'basis' | 'order' | 'alignSelf'>>;
    '2xl'?: Partial<Pick<FlexItemProps, 'flex' | 'grow' | 'shrink' | 'basis' | 'order' | 'alignSelf'>>;
  };
  as?: keyof JSX.IntrinsicElements;
  className?: string;
  children: React.ReactNode;
}

const FlexItem: React.FC<FlexItemProps> = ({
  flex,
  grow,
  shrink,
  basis,
  order,
  alignSelf,
  responsive,
  as: Component = 'div',
  className,
  children,
  ...props
}) => {
  // flex样式映射
  const flexStyles = {
    none: 'flex-none',
    auto: 'flex-auto',
    initial: 'flex-initial',
    '1': 'flex-1',
  };

  // grow样式映射
  const growStyles = {
    0: 'flex-grow-0',
    1: 'flex-grow',
  };

  // shrink样式映射
  const shrinkStyles = {
    0: 'flex-shrink-0',
    1: 'flex-shrink',
  };

  // basis样式映射
  const basisStyles = {
    auto: 'basis-auto',
    full: 'basis-full',
    px: 'basis-px',
  };

  // alignSelf样式映射
  const alignSelfStyles = {
    auto: 'self-auto',
    start: 'self-start',
    end: 'self-end',
    center: 'self-center',
    baseline: 'self-baseline',
    stretch: 'self-stretch',
  };

  // 构建响应式类名
  const buildResponsiveClasses = () => {
    if (!responsive) return '';
    
    const classes: string[] = [];
    
    Object.entries(responsive).forEach(([breakpoint, config]) => {
      const prefix = breakpoint === 'sm' ? 'sm:' : `${breakpoint}:`;
      
      if (config.flex && typeof config.flex === 'string' && flexStyles[config.flex as keyof typeof flexStyles]) {
        classes.push(`${prefix}${flexStyles[config.flex as keyof typeof flexStyles]}`);
      }
      if (config.grow !== undefined && growStyles[config.grow as keyof typeof growStyles]) {
        classes.push(`${prefix}${growStyles[config.grow as keyof typeof growStyles]}`);
      }
      if (config.shrink !== undefined && shrinkStyles[config.shrink as keyof typeof shrinkStyles]) {
        classes.push(`${prefix}${shrinkStyles[config.shrink as keyof typeof shrinkStyles]}`);
      }
      if (config.basis && basisStyles[config.basis as keyof typeof basisStyles]) {
        classes.push(`${prefix}${basisStyles[config.basis as keyof typeof basisStyles]}`);
      }
      if (config.alignSelf) {
        classes.push(`${prefix}${alignSelfStyles[config.alignSelf]}`);
      }
      if (config.order !== undefined) {
        classes.push(`${prefix}order-${config.order}`);
      }
    });
    
    return classes.join(' ');
  };

  // 构建内联样式
  const buildInlineStyles = () => {
    const styles: React.CSSProperties = {};
    
    if (flex && typeof flex === 'number') {
      styles.flex = flex;
    } else if (flex && typeof flex === 'string' && !flexStyles[flex as keyof typeof flexStyles]) {
      styles.flex = flex;
    }
    
    if (grow && typeof grow === 'number' && grow > 1) {
      styles.flexGrow = grow;
    }
    
    if (shrink && typeof shrink === 'number' && shrink > 1) {
      styles.flexShrink = shrink;
    }
    
    if (basis && typeof basis === 'string' && !basisStyles[basis as keyof typeof basisStyles]) {
      styles.flexBasis = basis;
    }
    
    if (order !== undefined) {
      styles.order = order;
    }
    
    return Object.keys(styles).length > 0 ? styles : undefined;
  };

  return (
    <Component
      className={cn(
        {
          [flexStyles[flex as keyof typeof flexStyles]]: flex && typeof flex === 'string' && flexStyles[flex as keyof typeof flexStyles],
          [growStyles[grow as keyof typeof growStyles]]: grow !== undefined && growStyles[grow as keyof typeof growStyles],
          [shrinkStyles[shrink as keyof typeof shrinkStyles]]: shrink !== undefined && shrinkStyles[shrink as keyof typeof shrinkStyles],
          [basisStyles[basis as keyof typeof basisStyles]]: basis && basisStyles[basis as keyof typeof basisStyles],
          [alignSelfStyles[alignSelf!]]: alignSelf,
          [`order-${order}`]: order !== undefined && order >= 0 && order <= 12,
        },
        buildResponsiveClasses(),
        className
      )}
      style={buildInlineStyles()}
      {...props}
    >
      {children}
    </Component>
  );
};

// 居中容器组件
export interface CenterProps {
  inline?: boolean;
  className?: string;
  children: React.ReactNode;
}

export const Center: React.FC<CenterProps> = ({
  inline = false,
  className,
  children,
}) => {
  return (
    <Flex
      justify="center"
      align="center"
      className={cn(
        {
          'inline-flex': inline,
        },
        className
      )}
    >
      {children}
    </Flex>
  );
};

// 间隔组件
export interface SpacerProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'auto';
  direction?: 'horizontal' | 'vertical';
  className?: string;
}

export const Spacer: React.FC<SpacerProps> = ({
  size = 'auto',
  direction = 'horizontal',
  className,
}) => {
  const sizeStyles = {
    xs: direction === 'horizontal' ? 'w-1' : 'h-1',
    sm: direction === 'horizontal' ? 'w-2' : 'h-2',
    md: direction === 'horizontal' ? 'w-4' : 'h-4',
    lg: direction === 'horizontal' ? 'w-6' : 'h-6',
    xl: direction === 'horizontal' ? 'w-8' : 'h-8',
    '2xl': direction === 'horizontal' ? 'w-12' : 'h-12',
    auto: direction === 'horizontal' ? 'flex-1' : 'flex-1',
  };

  return (
    <div
      className={cn(
        sizeStyles[size],
        {
          'flex-shrink-0': size !== 'auto',
        },
        className
      )}
      aria-hidden="true"
    />
  );
};

// 堆叠组件
export interface StackProps extends Omit<FlexProps, 'direction'> {
  spacing?: FlexProps['gap'];
  divider?: React.ReactNode;
}

export const VStack: React.FC<StackProps> = ({
  spacing = 'md',
  divider,
  children,
  ...props
}) => {
  const childrenArray = React.Children.toArray(children);
  
  return (
    <Flex direction="col" gap={spacing} {...props}>
      {divider
        ? childrenArray.map((child, index) => (
            <React.Fragment key={index}>
              {child}
              {index < childrenArray.length - 1 && divider}
            </React.Fragment>
          ))
        : children}
    </Flex>
  );
};

export const HStack: React.FC<StackProps> = ({
  spacing = 'md',
  divider,
  children,
  ...props
}) => {
  const childrenArray = React.Children.toArray(children);
  
  return (
    <Flex direction="row" gap={spacing} {...props}>
      {divider
        ? childrenArray.map((child, index) => (
            <React.Fragment key={index}>
              {child}
              {index < childrenArray.length - 1 && divider}
            </React.Fragment>
          ))
        : children}
    </Flex>
  );
};

// 复合组件
Flex.Item = FlexItem;
Flex.Center = Center;
Flex.Spacer = Spacer;
Flex.VStack = VStack;
Flex.HStack = HStack;

export default Flex;