/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      // 基于设计令牌的响应式断点系统
      screens: {
        'xs': '320px',   // 超小屏幕（小型手机）
        'sm': '640px',   // 小屏幕（大型手机）
        'md': '768px',   // 中等屏幕（平板）
        'lg': '1024px',  // 大屏幕（小型桌面）
        'xl': '1280px',  // 超大屏幕（桌面）
        '2xl': '1536px', // 2倍超大屏幕（大型桌面）
        '3xl': '1920px', // 3倍超大屏幕（超宽屏）
        // 特殊断点
        'tall': { 'raw': '(min-height: 800px)' },
        'short': { 'raw': '(max-height: 600px)' },
        'landscape': { 'raw': '(orientation: landscape)' },
        'portrait': { 'raw': '(orientation: portrait)' },
        'touch': { 'raw': '(hover: none) and (pointer: coarse)' },
        'no-touch': { 'raw': '(hover: hover) and (pointer: fine)' },
        'reduced-motion': { 'raw': '(prefers-reduced-motion: reduce)' },
        'high-contrast': { 'raw': '(prefers-contrast: high)' },
      },
      
      // 基于设计令牌的色彩系统
      colors: {
        // 主色调系统
        primary: {
          50: '#eff6ff',
          100: '#dbeafe', 
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6', // 主色
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        
        // 强调色系统
        accent: {
          50: '#fdf4ff',
          100: '#fae8ff',
          200: '#f5d0fe',
          300: '#f0abfc',
          400: '#e879f9',
          500: '#d946ef', // 强调色
          600: '#c026d3',
          700: '#a21caf',
          800: '#86198f',
          900: '#701a75',
          950: '#4a044e',
        },
        
        // 成功色系统
        success: {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e', // 成功色
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
        },
        
        // 警告色系统
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b', // 警告色
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
          950: '#451a03',
        },
        
        // 错误色系统
        error: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444', // 错误色
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
          950: '#450a0a',
        },
        
        // 中性色系统（暗色主题）
        neutral: {
          50: '#fafafa',
          100: '#f5f5f5',
          200: '#e5e5e5',
          300: '#d4d4d4',
          400: '#a3a3a3',
          500: '#737373',
          600: '#525252',
          700: '#404040',
          800: '#262626',
          900: '#171717',
          950: '#0a0a0a',
        },
        
        // 石榴主题色彩系统
        pomegranate: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
          950: '#450a0a',
          // 石榴特色色调
          'deep': '#8B0000',
          'rich': '#A0522D',
          'wine': '#722F37',
          'burgundy': '#800020',
          'crimson': '#DC143C',
          'ruby': '#E0115F',
          'garnet': '#733635',
          'mahogany': '#C04000',
        },
        
        // 石榴粉色系统
        'pomegranate-pink': {
          50: '#fdf2f8',
          100: '#fce7f3',
          200: '#fbcfe8',
          300: '#f9a8d4',
          400: '#f472b6',
          500: '#ec4899',
          600: '#db2777',
          700: '#be185d',
          800: '#9d174d',
          900: '#831843',
          950: '#500724',
          // 花卉粉色调
          'blossom': '#FFB6C1',
          'rose': '#FF69B4',
          'coral': '#FF7F7F',
          'peach': '#FFCCCB',
          'blush': '#DE5D83',
          'magenta': '#FF1493',
          'fuchsia': '#FF00FF',
          'orchid': '#DA70D6',
        },
        
        // 石榴叶绿色系统
        'pomegranate-leaf': {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
          // 叶片绿色调
          'sage': '#9CAF88',
          'forest': '#228B22',
          'emerald': '#50C878',
          'jade': '#00A86B',
          'mint': '#98FB98',
          'olive': '#808000',
          'pine': '#01796F',
          'moss': '#8A9A5B',
        },
        
        // 花卉色彩系统
        floral: {
          50: '#fefce8',
          100: '#fef9c3',
          200: '#fef08a',
          300: '#fde047',
          400: '#facc15',
          500: '#eab308',
          600: '#ca8a04',
          700: '#a16207',
          800: '#854d0e',
          900: '#713f12',
          950: '#422006',
          // 花卉特色
          'petal': '#FFE4E1',
          'bloom': '#FFF8DC',
          'nectar': '#FFEBCD',
          'honey': '#F0E68C',
          'golden': '#FFD700',
          'amber': '#FFBF00',
          'cream': '#FFFDD0',
          'ivory': '#FFFFF0',
        },
        
        // 语义化色彩映射
        background: {
          primary: '#0a0a0a',     // --bg-primary
          secondary: '#171717',   // --bg-secondary  
          tertiary: '#262626',    // --bg-tertiary
          glass: 'rgba(23, 23, 23, 0.8)', // --bg-glass
        },
        
        text: {
          primary: '#fafafa',     // --text-primary
          secondary: '#d4d4d4',   // --text-secondary
          tertiary: '#a3a3a3',    // --text-tertiary
          inverse: '#0a0a0a',     // --text-inverse
        },
        
        border: {
          DEFAULT: '#404040',     // --border-default
          primary: '#404040',     // --border-primary
          secondary: '#525252',   // --border-secondary
          focus: '#0ea5e9',       // --border-focus
        },
        
        interactive: {
          primary: '#3b82f6',           // --interactive-primary
          'primary-hover': '#2563eb',   // --interactive-primary-hover
          'primary-active': '#1d4ed8',  // --interactive-primary-active
          secondary: '#525252',         // --interactive-secondary
          'secondary-hover': '#737373', // --interactive-secondary-hover
          'secondary-active': '#404040', // --interactive-secondary-active
        },
      },
      animation: {
        'bounce-slow': 'bounce 2s infinite',
        'wiggle': 'wiggle 1s ease-in-out infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'scale-in': 'scaleIn 0.3s ease-out',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'wave': 'wave 1.6s linear infinite',
      },
      // 基于设计令牌的关键帧动画系统
      keyframes: {
        // 基础动画
        wiggle: {
          '0%, 100%': { transform: 'rotate(-3deg)' },
          '50%': { transform: 'rotate(3deg)' },
        },
        shake: {
          '0%, 100%': { transform: 'translateX(0)' },
          '10%, 30%, 50%, 70%, 90%': { transform: 'translateX(-10px)' },
          '20%, 40%, 60%, 80%': { transform: 'translateX(10px)' },
        },
        heartbeat: {
          '0%': { transform: 'scale(1)' },
          '14%': { transform: 'scale(1.3)' },
          '28%': { transform: 'scale(1)' },
          '42%': { transform: 'scale(1.3)' },
          '70%': { transform: 'scale(1)' },
        },
        
        // 淡入动画
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeInUp: {
          '0%': { opacity: '0', transform: 'translateY(30px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeInDown: {
          '0%': { opacity: '0', transform: 'translateY(-30px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeInLeft: {
          '0%': { opacity: '0', transform: 'translateX(-30px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        fadeInRight: {
          '0%': { opacity: '0', transform: 'translateX(30px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        
        // 滑动动画
        slideUp: {
          '0%': { transform: 'translateY(100%)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideDown: {
          '0%': { transform: 'translateY(-100%)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideLeft: {
          '0%': { transform: 'translateX(100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        slideRight: {
          '0%': { transform: 'translateX(-100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        
        // 缩放动画
        scaleIn: {
          '0%': { transform: 'scale(0)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        scaleOut: {
          '0%': { transform: 'scale(1)', opacity: '1' },
          '100%': { transform: 'scale(0)', opacity: '0' },
        },
        zoomIn: {
          '0%': { transform: 'scale(0.3)', opacity: '0' },
          '50%': { opacity: '1' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        zoomOut: {
          '0%': { transform: 'scale(1)', opacity: '1' },
          '50%': { opacity: '1' },
          '100%': { transform: 'scale(0.3)', opacity: '0' },
        },
        
        // 旋转动画
        rotateIn: {
          '0%': { transform: 'rotate(-180deg)', opacity: '0' },
          '100%': { transform: 'rotate(0deg)', opacity: '1' },
        },
        rotateOut: {
          '0%': { transform: 'rotate(0deg)', opacity: '1' },
          '100%': { transform: 'rotate(180deg)', opacity: '0' },
        },
        
        // 特效动画
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.8), 0 0 30px rgba(59, 130, 246, 0.6)' },
        },
        typing: {
          '0%': { width: '0' },
          '100%': { width: '100%' },
        },
        'blink-caret': {
          '0%, 50%': { borderColor: 'transparent' },
          '51%, 100%': { borderColor: 'currentColor' },
        },
        
        // 微交互动画
        buttonPress: {
          '0%': { transform: 'scale(1)' },
          '50%': { transform: 'scale(0.95)' },
          '100%': { transform: 'scale(1)' },
        },
        cardHover: {
          '0%': { transform: 'translateY(0) scale(1)' },
          '100%': { transform: 'translateY(-8px) scale(1.02)' },
        },
        iconBounce: {
          '0%, 20%, 50%, 80%, 100%': { transform: 'translateY(0)' },
          '40%': { transform: 'translateY(-10px)' },
          '60%': { transform: 'translateY(-5px)' },
        },
        
        // 波浪动画（用于骨架屏）
        wave: {
          '0%': { transform: 'translateX(-100%)' },
          '50%': { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      // 基于设计令牌的背景模糊系统
      backdropBlur: {
        'none': '0',
        'xs': '2px',
        'sm': '4px',
        'md': '8px',
        'lg': '12px',
        'xl': '16px',
        '2xl': '24px',
        '3xl': '32px',
        '4xl': '40px',
      },
      
      // 基于设计令牌的阴影系统
      boxShadow: {
        // 基础阴影
        'xs': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'sm': '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
        'DEFAULT': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        'md': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        'lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        'xl': '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
        
        // 特殊效果阴影
        'glass': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
        'glass-sm': '0 4px 16px 0 rgba(31, 38, 135, 0.25)',
        'glass-lg': '0 16px 64px 0 rgba(31, 38, 135, 0.45)',
        
        // 发光效果
        'glow': '0 0 20px rgba(59, 130, 246, 0.5)',
        'glow-sm': '0 0 10px rgba(59, 130, 246, 0.3)',
        'glow-lg': '0 0 40px rgba(59, 130, 246, 0.6)',
        'glow-xl': '0 0 60px rgba(59, 130, 246, 0.7)',
        
        // 彩色发光
        'glow-primary': '0 0 20px rgba(59, 130, 246, 0.5)',
        'glow-accent': '0 0 20px rgba(217, 70, 239, 0.5)',
        'glow-success': '0 0 20px rgba(34, 197, 94, 0.5)',
        'glow-warning': '0 0 20px rgba(245, 158, 11, 0.5)',
        'glow-error': '0 0 20px rgba(239, 68, 68, 0.5)',
        
        // 内阴影
        'inner': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.06)',
        'inner-glow': 'inset 0 2px 4px 0 rgba(59, 130, 246, 0.2)',
        
        // 无阴影
        'none': 'none',
      },
      
      // 基于设计令牌的圆角系统
      borderRadius: {
        'none': '0',
        'xs': '0.0625rem',   // 1px
        'sm': '0.125rem',    // 2px
        'DEFAULT': '0.25rem', // 4px
        'md': '0.375rem',    // 6px
        'lg': '0.5rem',      // 8px
        'xl': '0.75rem',     // 12px
        '2xl': '1rem',       // 16px
        '3xl': '1.5rem',     // 24px
        '4xl': '2rem',       // 32px
        'full': '9999px',
      },
      
      // 基于设计令牌的Z-Index系统
      zIndex: {
        'auto': 'auto',
        '0': '0',
        '10': '10',
        '20': '20',
        '30': '30',
        '40': '40',
        '50': '50',
        // 语义化Z-Index
        'dropdown': '1000',
        'sticky': '1020',
        'fixed': '1030',
        'modal-backdrop': '1040',
        'modal': '1050',
        'popover': '1060',
        'tooltip': '1070',
        'toast': '1080',
        'max': '9999',
      },
      
      // 基于设计令牌的过渡系统
      transitionDuration: {
        '75': '75ms',
        '100': '100ms',
        '150': '150ms',
        '200': '200ms',
        '300': '300ms',
        '500': '500ms',
        '700': '700ms',
        '1000': '1000ms',
      },
      
      transitionTimingFunction: {
        'ease-in-out-back': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
        'ease-out-expo': 'cubic-bezier(0.19, 1, 0.22, 1)',
        'ease-out-circ': 'cubic-bezier(0.075, 0.82, 0.165, 1)',
        'ease-in-circ': 'cubic-bezier(0.6, 0.04, 0.98, 0.335)',
      }
    },
  },
  plugins: [],
}