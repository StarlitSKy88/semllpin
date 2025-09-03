/**
 * 现代化容器组件
 * 基于设计令牌系统的响应式容器实现
 */

import React from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';

export interface ContainerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full';
  padding?: 'none' | 'sm' | 'md' | 'lg' | 'xl';
  margin?: 'none' | 'auto' | 'sm' | 'md' | 'lg' | 'xl';
  centered?: boolean;
  fluid?: boolean;
  className?: string;
  style?: React.CSSProperties;
  children: React.ReactNode;
}

const Container: React.FC<ContainerProps> = ({
  size = 'lg',
  padding = 'md',
  margin = 'auto',
  centered = true,
  fluid = false,
  className,
  style,
  children,
}) => {
  useTheme();

  // 容器尺寸样式
  const sizeStyles = {
    sm: 'max-w-screen-sm', // 640px
    md: 'max-w-screen-md', // 768px
    lg: 'max-w-screen-lg', // 1024px
    xl: 'max-w-screen-xl', // 1280px
    '2xl': 'max-w-screen-2xl', // 1536px
    full: 'max-w-full',
  };

  // 内边距样式
  const paddingStyles = {
    none: '',
    sm: 'px-4 py-2',
    md: 'px-6 py-4',
    lg: 'px-8 py-6',
    xl: 'px-12 py-8',
  };

  // 外边距样式
  const marginStyles = {
    none: '',
    auto: 'mx-auto',
    sm: 'm-2',
    md: 'm-4',
    lg: 'm-6',
    xl: 'm-8',
  };

  return (
    <div
      className={cn(
        'w-full',
        {
          [sizeStyles[size]]: !fluid,
          'mx-auto': centered && margin === 'auto',
        },
        paddingStyles[padding],
        marginStyles[margin],
        className
      )}
      style={style}
    >
      {children}
    </div>
  );
};

// 响应式容器组件
export interface ResponsiveContainerProps extends Omit<ContainerProps, 'size'> {
  breakpoints?: {
    sm?: ContainerProps['size'];
    md?: ContainerProps['size'];
    lg?: ContainerProps['size'];
    xl?: ContainerProps['size'];
    '2xl'?: ContainerProps['size'];
  };
}

export const ResponsiveContainer: React.FC<ResponsiveContainerProps> = ({
  breakpoints = { sm: 'sm', md: 'md', lg: 'lg', xl: 'xl', '2xl': '2xl' },
  className,
  ...props
}) => {
  const responsiveClasses = Object.entries(breakpoints)
    .map(([breakpoint, size]) => {
      const sizeMap = {
        sm: 'max-w-screen-sm',
        md: 'max-w-screen-md',
        lg: 'max-w-screen-lg',
        xl: 'max-w-screen-xl',
        '2xl': 'max-w-screen-2xl',
        full: 'max-w-full',
      };
      
      if (breakpoint === 'sm') {
        return sizeMap[size!];
      }
      return `${breakpoint}:${sizeMap[size!]}`;
    })
    .join(' ');

  return (
    <Container
      {...props}
      size="full"
      className={cn(responsiveClasses, className)}
    />
  );
};

// 流体容器组件
export interface FluidContainerProps extends Omit<ContainerProps, 'size' | 'fluid'> {
  maxWidth?: string;
  minWidth?: string;
  style?: React.CSSProperties;
}

export const FluidContainer: React.FC<FluidContainerProps> = ({
  maxWidth,
  minWidth,
  className,
  style,
  ...props
}) => {
  const containerStyle = {
    ...style,
    ...(maxWidth && { maxWidth }),
    ...(minWidth && { minWidth }),
  };

  return (
    <Container
      {...props}
      fluid
      className={className}
      style={containerStyle}
    />
  );
};

// 分段容器组件
export interface SectionContainerProps extends ContainerProps {
  as?: keyof JSX.IntrinsicElements;
  background?: 'none' | 'primary' | 'secondary' | 'accent' | 'muted';
  border?: boolean;
  shadow?: 'none' | 'sm' | 'md' | 'lg' | 'xl';
  rounded?: 'none' | 'sm' | 'md' | 'lg' | 'xl' | 'full';
}

export const SectionContainer: React.FC<SectionContainerProps> = ({
  as: Component = 'section',
  background = 'none',
  border = false,
  shadow = 'none',
  rounded = 'none',
  className,
  children,
  ...containerProps
}) => {
  const backgroundStyles = {
    none: '',
    primary: 'bg-blue-50 dark:bg-blue-900/10',
    secondary: 'bg-gray-50 dark:bg-gray-800',
    accent: 'bg-purple-50 dark:bg-purple-900/10',
    muted: 'bg-gray-100 dark:bg-gray-900',
  };

  const shadowStyles = {
    none: '',
    sm: 'shadow-sm',
    md: 'shadow-md',
    lg: 'shadow-lg',
    xl: 'shadow-xl',
  };

  const roundedStyles = {
    none: '',
    sm: 'rounded-sm',
    md: 'rounded-md',
    lg: 'rounded-lg',
    xl: 'rounded-xl',
    full: 'rounded-full',
  };

  return (
    <Component
      className={cn(
        backgroundStyles[background],
        shadowStyles[shadow],
        roundedStyles[rounded],
        {
          'border border-gray-200 dark:border-gray-700': border,
        },
        className
      )}
    >
      <Container {...containerProps}>
        {children}
      </Container>
    </Component>
  );
};

export default Container;