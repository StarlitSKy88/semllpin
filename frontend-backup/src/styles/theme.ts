/**
 * SmellPin 主题配置系统
 * 统一管理应用的主题变量和样式
 */

export const theme = {
  // 颜色系统
  colors: {
    // 主色调
    primary: {
      50: 'var(--color-primary-50)',
      100: 'var(--color-primary-100)',
      200: 'var(--color-primary-200)',
      300: 'var(--color-primary-300)',
      400: 'var(--color-primary-400)',
      500: 'var(--color-primary-500)',
      600: 'var(--color-primary-600)',
      700: 'var(--color-primary-700)',
      800: 'var(--color-primary-800)',
      900: 'var(--color-primary-900)',
      950: 'var(--color-primary-950)',
    },
    // 辅助色
    secondary: {
      50: 'var(--color-secondary-50)',
      100: 'var(--color-secondary-100)',
      200: 'var(--color-secondary-200)',
      300: 'var(--color-secondary-300)',
      400: 'var(--color-secondary-400)',
      500: 'var(--color-secondary-500)',
      600: 'var(--color-secondary-600)',
      700: 'var(--color-secondary-700)',
      800: 'var(--color-secondary-800)',
      900: 'var(--color-secondary-900)',
      950: 'var(--color-secondary-950)',
    },
    // 语义化颜色
    success: {
      50: 'var(--color-success-50)',
      500: 'var(--color-success-500)',
      600: 'var(--color-success-600)',
      700: 'var(--color-success-700)',
    },
    warning: {
      50: 'var(--color-warning-50)',
      500: 'var(--color-warning-500)',
      600: 'var(--color-warning-600)',
      700: 'var(--color-warning-700)',
    },
    error: {
      50: 'var(--color-error-50)',
      500: 'var(--color-error-500)',
      600: 'var(--color-error-600)',
      700: 'var(--color-error-700)',
    },
    info: {
      50: 'var(--color-info-50)',
      500: 'var(--color-info-500)',
      600: 'var(--color-info-600)',
      700: 'var(--color-info-700)',
    },
    // 中性色
    gray: {
      50: 'var(--color-gray-50)',
      100: 'var(--color-gray-100)',
      200: 'var(--color-gray-200)',
      300: 'var(--color-gray-300)',
      400: 'var(--color-gray-400)',
      500: 'var(--color-gray-500)',
      600: 'var(--color-gray-600)',
      700: 'var(--color-gray-700)',
      800: 'var(--color-gray-800)',
      900: 'var(--color-gray-900)',
      950: 'var(--color-gray-950)',
    },
  },

  // 间距系统
  spacing: {
    0: 'var(--spacing-0)',
    1: 'var(--spacing-1)',
    2: 'var(--spacing-2)',
    3: 'var(--spacing-3)',
    4: 'var(--spacing-4)',
    5: 'var(--spacing-5)',
    6: 'var(--spacing-6)',
    8: 'var(--spacing-8)',
    10: 'var(--spacing-10)',
    12: 'var(--spacing-12)',
    16: 'var(--spacing-16)',
    20: 'var(--spacing-20)',
    24: 'var(--spacing-24)',
    32: 'var(--spacing-32)',
    40: 'var(--spacing-40)',
    48: 'var(--spacing-48)',
    56: 'var(--spacing-56)',
    64: 'var(--spacing-64)',
  },

  // 字体系统
  typography: {
    fontFamily: {
      sans: 'var(--font-family-sans)',
      mono: 'var(--font-family-mono)',
    },
    fontSize: {
      xs: 'var(--font-size-xs)',
      sm: 'var(--font-size-sm)',
      base: 'var(--font-size-base)',
      lg: 'var(--font-size-lg)',
      xl: 'var(--font-size-xl)',
      '2xl': 'var(--font-size-2xl)',
      '3xl': 'var(--font-size-3xl)',
      '4xl': 'var(--font-size-4xl)',
      '5xl': 'var(--font-size-5xl)',
      '6xl': 'var(--font-size-6xl)',
    },
    fontWeight: {
      light: 'var(--font-weight-light)',
      normal: 'var(--font-weight-normal)',
      medium: 'var(--font-weight-medium)',
      semibold: 'var(--font-weight-semibold)',
      bold: 'var(--font-weight-bold)',
    },
    lineHeight: {
      tight: 'var(--line-height-tight)',
      normal: 'var(--line-height-normal)',
      relaxed: 'var(--line-height-relaxed)',
    },
  },

  // 圆角系统
  borderRadius: {
    none: 'var(--radius-none)',
    sm: 'var(--radius-sm)',
    md: 'var(--radius-md)',
    lg: 'var(--radius-lg)',
    xl: 'var(--radius-xl)',
    '2xl': 'var(--radius-2xl)',
    '3xl': 'var(--radius-3xl)',
    full: 'var(--radius-full)',
  },

  // 阴影系统
  boxShadow: {
    sm: 'var(--shadow-sm)',
    md: 'var(--shadow-md)',
    lg: 'var(--shadow-lg)',
    xl: 'var(--shadow-xl)',
    '2xl': 'var(--shadow-2xl)',
    inner: 'var(--shadow-inner)',
    none: 'var(--shadow-none)',
  },

  // 动画系统
  animation: {
    duration: {
      instant: 'var(--duration-instant)',
      fast: 'var(--duration-fast)',
      normal: 'var(--duration-normal)',
      slow: 'var(--duration-slow)',
      slower: 'var(--duration-slower)',
      slowest: 'var(--duration-slowest)',
    },
    easing: {
      inOut: 'var(--ease-in-out)',
      out: 'var(--ease-out)',
      in: 'var(--ease-in)',
      bounce: 'var(--ease-bounce)',
      elastic: 'var(--ease-elastic)',
      back: 'var(--ease-back)',
    },
    delay: {
      none: 'var(--delay-none)',
      short: 'var(--delay-short)',
      medium: 'var(--delay-medium)',
      long: 'var(--delay-long)',
    },
  },

  // 组件令牌
  components: {
    button: {
      height: {
        sm: 'var(--button-height-sm)',
        md: 'var(--button-height-md)',
        lg: 'var(--button-height-lg)',
      },
      padding: {
        sm: 'var(--button-padding-x-sm)',
        md: 'var(--button-padding-x-md)',
        lg: 'var(--button-padding-x-lg)',
      },
      fontSize: {
        sm: 'var(--button-font-size-sm)',
        md: 'var(--button-font-size-md)',
        lg: 'var(--button-font-size-lg)',
      },
    },
    input: {
      height: {
        sm: 'var(--input-height-sm)',
        md: 'var(--input-height-md)',
        lg: 'var(--input-height-lg)',
      },
      padding: 'var(--input-padding-x)',
      borderWidth: 'var(--input-border-width)',
    },
    card: {
      padding: {
        sm: 'var(--card-padding-sm)',
        md: 'var(--card-padding-md)',
        lg: 'var(--card-padding-lg)',
      },
      borderWidth: 'var(--card-border-width)',
    },
    modal: {
      backdropOpacity: 'var(--modal-backdrop-opacity)',
      maxWidth: {
        sm: 'var(--modal-max-width-sm)',
        md: 'var(--modal-max-width-md)',
        lg: 'var(--modal-max-width-lg)',
        xl: 'var(--modal-max-width-xl)',
      },
    },
  },

  // 交互状态
  states: {
    hover: {
      opacity: 'var(--hover-opacity)',
      scale: 'var(--hover-scale)',
      translateY: 'var(--hover-translate-y)',
    },
    active: {
      scale: 'var(--active-scale)',
      opacity: 'var(--active-opacity)',
    },
    focus: {
      ringWidth: 'var(--focus-ring-width)',
      ringOffset: 'var(--focus-ring-offset)',
      ringOpacity: 'var(--focus-ring-opacity)',
    },
    disabled: {
      opacity: 'var(--disabled-opacity)',
      cursor: 'var(--disabled-cursor)',
    },
  },

  // 断点系统
  breakpoints: {
    xs: 'var(--breakpoint-xs)',
    sm: 'var(--breakpoint-sm)',
    md: 'var(--breakpoint-md)',
    lg: 'var(--breakpoint-lg)',
    xl: 'var(--breakpoint-xl)',
    '2xl': 'var(--breakpoint-2xl)',
  },

  // 容器系统
  container: {
    xs: 'var(--container-xs)',
    sm: 'var(--container-sm)',
    md: 'var(--container-md)',
    lg: 'var(--container-lg)',
    xl: 'var(--container-xl)',
    '2xl': 'var(--container-2xl)',
  },
} as const;

// 主题类型定义
export type Theme = typeof theme;
export type ThemeColors = keyof typeof theme.colors;
export type ThemeSpacing = keyof typeof theme.spacing;
export type ThemeTypography = keyof typeof theme.typography;

// 主题工具函数
export const getThemeValue = (path: string): string => {
  const keys = path.split('.');
  let value: any = theme;
  
  for (const key of keys) {
    value = value?.[key];
    if (value === undefined) {
      console.warn(`Theme value not found for path: ${path}`);
      return '';
    }
  }
  
  return value;
};

// 响应式断点工具
export const mediaQueries = {
  xs: `@media (min-width: ${theme.breakpoints.xs})`,
  sm: `@media (min-width: ${theme.breakpoints.sm})`,
  md: `@media (min-width: ${theme.breakpoints.md})`,
  lg: `@media (min-width: ${theme.breakpoints.lg})`,
  xl: `@media (min-width: ${theme.breakpoints.xl})`,
  '2xl': `@media (min-width: ${theme.breakpoints['2xl']})`,
} as const;

export default theme;