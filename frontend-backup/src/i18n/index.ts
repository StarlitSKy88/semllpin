import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import Backend from 'i18next-http-backend';

// 导入语言资源
import zhCN from './locales/zh-CN.json';
import enUS from './locales/en-US.json';

// 支持的语言列表
export const supportedLanguages = {
  'zh-CN': {
    name: '简体中文',
    nativeName: '简体中文',
    flag: '🇨🇳',
    rtl: false
  },
  'en-US': {
    name: 'English',
    nativeName: 'English',
    flag: '🇺🇸',
    rtl: false
  }
};

// 默认语言
export const defaultLanguage = 'zh-CN';

// 语言资源
const resources = {
  'zh-CN': {
    translation: zhCN
  },
  'en-US': {
    translation: enUS
  }
};

// 语言检测配置
const detectionOptions = {
  // 检测顺序
  order: ['localStorage', 'navigator', 'htmlTag', 'path', 'subdomain'],
  
  // 缓存用户语言选择
  caches: ['localStorage'],
  
  // 排除的路径
  excludeCacheFor: ['cimode'],
  
  // 检查白名单
  checkWhitelist: true
};

// 初始化 i18n
i18n
  .use(Backend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: defaultLanguage,
    debug: import.meta.env.VITE_NODE_ENV === 'development',
    
    // 语言检测
    detection: detectionOptions,
    
    // 白名单
    supportedLngs: Object.keys(supportedLanguages),
    
    // 插值配置
    interpolation: {
      escapeValue: false, // React 已经安全处理了
      formatSeparator: ','
    },
    
    // 后端配置
    backend: {
      loadPath: '/locales/{{lng}}/{{ns}}.json',
      addPath: '/locales/add/{{lng}}/{{ns}}'
    },
    
    // React 配置
    react: {
      useSuspense: false,
      bindI18n: 'languageChanged',
      bindI18nStore: '',
      transEmptyNodeValue: '',
      transSupportBasicHtmlNodes: true,
      transKeepBasicHtmlNodesFor: ['br', 'strong', 'i']
    },
    
    // 命名空间
    defaultNS: 'translation',
    ns: ['translation'],
    
    // 键分隔符
    keySeparator: '.',
    nsSeparator: ':',
    
    // 复数规则
    pluralSeparator: '_',
    contextSeparator: '_',
    
    // 返回对象
    returnObjects: false,
    returnEmptyString: true,
    returnNull: true,
    
    // 加载配置
    load: 'languageOnly',
    preload: [defaultLanguage],
    
    // 清理代码
    cleanCode: true,
    
    // 错误处理
    missingKeyHandler: (lng, _ns, key) => {
      if (import.meta.env.VITE_NODE_ENV === 'development') {
        console.warn(`Missing translation key: ${key} for language: ${lng}`);
      }
    },
    
    // 解析错误处理
    parseMissingKeyHandler: (key) => {
      if (import.meta.env.VITE_NODE_ENV === 'development') {
        console.warn(`Missing key: ${key}`);
      }
      return key;
    }
  });

// 语言切换函数
export const changeLanguage = (lng: string) => {
  return i18n.changeLanguage(lng);
};

// 获取当前语言
export const getCurrentLanguage = () => {
  return i18n.language || defaultLanguage;
};

// 获取语言信息
export const getLanguageInfo = (lng?: string) => {
  const language = lng || getCurrentLanguage();
  return supportedLanguages[language as keyof typeof supportedLanguages] || supportedLanguages[defaultLanguage];
};

// 检查是否为RTL语言
export const isRTL = (lng?: string) => {
  const languageInfo = getLanguageInfo(lng);
  return languageInfo?.rtl || false;
};

// 格式化数字
export const formatNumber = (number: number, lng?: string) => {
  const language = lng || getCurrentLanguage();
  return new Intl.NumberFormat(language).format(number);
};

// 格式化货币
export const formatCurrency = (amount: number, currency = 'CNY', lng?: string) => {
  const language = lng || getCurrentLanguage();
  return new Intl.NumberFormat(language, {
    style: 'currency',
    currency: currency
  }).format(amount);
};

// 格式化日期
export const formatDate = (date: Date | string, options?: Intl.DateTimeFormatOptions, lng?: string) => {
  const language = lng || getCurrentLanguage();
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  
  const defaultOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  };
  
  return new Intl.DateTimeFormat(language, { ...defaultOptions, ...options }).format(dateObj);
};

// 格式化相对时间
export const formatRelativeTime = (date: Date | string, lng?: string) => {
  const language = lng || getCurrentLanguage();
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000);
  
  const rtf = new Intl.RelativeTimeFormat(language, { numeric: 'auto' });
  
  if (diffInSeconds < 60) {
    return rtf.format(-diffInSeconds, 'second');
  } else if (diffInSeconds < 3600) {
    return rtf.format(-Math.floor(diffInSeconds / 60), 'minute');
  } else if (diffInSeconds < 86400) {
    return rtf.format(-Math.floor(diffInSeconds / 3600), 'hour');
  } else if (diffInSeconds < 2592000) {
    return rtf.format(-Math.floor(diffInSeconds / 86400), 'day');
  } else if (diffInSeconds < 31536000) {
    return rtf.format(-Math.floor(diffInSeconds / 2592000), 'month');
  } else {
    return rtf.format(-Math.floor(diffInSeconds / 31536000), 'year');
  }
};

export default i18n;