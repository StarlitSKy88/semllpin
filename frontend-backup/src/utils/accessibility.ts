/**
 * 无障碍功能增强工具库
 * 确保所有组件符合WCAG 2.1 AA级标准
 */

// 键盘导航常量
export const KEYBOARD_KEYS = {
  ENTER: 'Enter',
  SPACE: ' ',
  TAB: 'Tab',
  ESCAPE: 'Escape',
  ARROW_UP: 'ArrowUp',
  ARROW_DOWN: 'ArrowDown',
  ARROW_LEFT: 'ArrowLeft',
  ARROW_RIGHT: 'ArrowRight',
  HOME: 'Home',
  END: 'End',
  PAGE_UP: 'PageUp',
  PAGE_DOWN: 'PageDown',
} as const;

// ARIA 角色常量
export const ARIA_ROLES = {
  BUTTON: 'button',
  LINK: 'link',
  MENU: 'menu',
  MENUITEM: 'menuitem',
  MENUBAR: 'menubar',
  TAB: 'tab',
  TABLIST: 'tablist',
  TABPANEL: 'tabpanel',
  DIALOG: 'dialog',
  ALERTDIALOG: 'alertdialog',
  ALERT: 'alert',
  STATUS: 'status',
  PROGRESSBAR: 'progressbar',
  SLIDER: 'slider',
  SPINBUTTON: 'spinbutton',
  COMBOBOX: 'combobox',
  LISTBOX: 'listbox',
  OPTION: 'option',
  GRID: 'grid',
  GRIDCELL: 'gridcell',
  TREE: 'tree',
  TREEITEM: 'treeitem',
  REGION: 'region',
  BANNER: 'banner',
  MAIN: 'main',
  NAVIGATION: 'navigation',
  COMPLEMENTARY: 'complementary',
  CONTENTINFO: 'contentinfo',
  SEARCH: 'search',
} as const;

// 焦点管理类
export class FocusManager {
  private static focusableSelectors = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
    '[contenteditable="true"]',
  ].join(', ');

  /**
   * 获取容器内所有可聚焦元素
   */
  static getFocusableElements(container: HTMLElement): HTMLElement[] {
    return Array.from(
      container.querySelectorAll(this.focusableSelectors)
    ) as HTMLElement[];
  }

  /**
   * 获取第一个可聚焦元素
   */
  static getFirstFocusableElement(container: HTMLElement): HTMLElement | null {
    const elements = this.getFocusableElements(container);
    return elements[0] || null;
  }

  /**
   * 获取最后一个可聚焦元素
   */
  static getLastFocusableElement(container: HTMLElement): HTMLElement | null {
    const elements = this.getFocusableElements(container);
    return elements[elements.length - 1] || null;
  }

  /**
   * 焦点陷阱 - 将焦点限制在指定容器内
   */
  static trapFocus(container: HTMLElement): () => void {
    const firstElement = this.getFirstFocusableElement(container);
    const lastElement = this.getLastFocusableElement(container);

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== KEYBOARD_KEYS.TAB) return;

      if (event.shiftKey) {
        // Shift + Tab
        if (document.activeElement === firstElement) {
          event.preventDefault();
          lastElement?.focus();
        }
      } else {
        // Tab
        if (document.activeElement === lastElement) {
          event.preventDefault();
          firstElement?.focus();
        }
      }
    };

    container.addEventListener('keydown', handleKeyDown);
    
    // 自动聚焦到第一个元素
    firstElement?.focus();

    // 返回清理函数
    return () => {
      container.removeEventListener('keydown', handleKeyDown);
    };
  }

  /**
   * 保存当前焦点并返回恢复函数
   */
  static saveFocus(): () => void {
    const activeElement = document.activeElement as HTMLElement;
    
    return () => {
      if (activeElement && typeof activeElement.focus === 'function') {
        activeElement.focus();
      }
    };
  }

  /**
   * 移动焦点到指定元素
   */
  static moveFocus(element: HTMLElement | null, options?: FocusOptions): void {
    if (element && typeof element.focus === 'function') {
      element.focus(options);
    }
  }
}

// 屏幕阅读器公告管理
export class ScreenReaderAnnouncer {
  private static instance: ScreenReaderAnnouncer;
  private liveRegion: HTMLElement;
  private politeRegion: HTMLElement;

  private constructor() {
    this.liveRegion = this.createLiveRegion('assertive');
    this.politeRegion = this.createLiveRegion('polite');
  }

  static getInstance(): ScreenReaderAnnouncer {
    if (!this.instance) {
      this.instance = new ScreenReaderAnnouncer();
    }
    return this.instance;
  }

  private createLiveRegion(politeness: 'assertive' | 'polite'): HTMLElement {
    const region = document.createElement('div');
    region.setAttribute('aria-live', politeness);
    region.setAttribute('aria-atomic', 'true');
    region.style.position = 'absolute';
    region.style.left = '-10000px';
    region.style.width = '1px';
    region.style.height = '1px';
    region.style.overflow = 'hidden';
    document.body.appendChild(region);
    return region;
  }

  /**
   * 立即公告消息（中断当前公告）
   */
  announce(message: string): void {
    this.liveRegion.textContent = message;
  }

  /**
   * 礼貌地公告消息（等待当前公告完成）
   */
  announcePolite(message: string): void {
    this.politeRegion.textContent = message;
  }

  /**
   * 清除所有公告
   */
  clear(): void {
    this.liveRegion.textContent = '';
    this.politeRegion.textContent = '';
  }
}

// 颜色对比度检查
export class ColorContrastChecker {
  /**
   * 计算相对亮度
   */
  private static getRelativeLuminance(rgb: [number, number, number]): number {
    const [r, g, b] = rgb.map(c => {
      c = c / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  /**
   * 计算对比度比率
   */
  static getContrastRatio(color1: [number, number, number], color2: [number, number, number]): number {
    const l1 = this.getRelativeLuminance(color1);
    const l2 = this.getRelativeLuminance(color2);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
  }

  /**
   * 检查是否符合WCAG AA标准
   */
  static meetsWCAG_AA(color1: [number, number, number], color2: [number, number, number], isLargeText = false): boolean {
    const ratio = this.getContrastRatio(color1, color2);
    return isLargeText ? ratio >= 3 : ratio >= 4.5;
  }

  /**
   * 检查是否符合WCAG AAA标准
   */
  static meetsWCAG_AAA(color1: [number, number, number], color2: [number, number, number], isLargeText = false): boolean {
    const ratio = this.getContrastRatio(color1, color2);
    return isLargeText ? ratio >= 4.5 : ratio >= 7;
  }

  /**
   * 从十六进制颜色转换为RGB
   */
  static hexToRgb(hex: string): [number, number, number] | null {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? [
      parseInt(result[1], 16),
      parseInt(result[2], 16),
      parseInt(result[3], 16)
    ] : null;
  }
}

// 键盘导航助手
export class KeyboardNavigationHelper {
  /**
   * 处理箭头键导航
   */
  static handleArrowNavigation(
    event: KeyboardEvent,
    items: HTMLElement[],
    currentIndex: number,
    options: {
      orientation?: 'horizontal' | 'vertical' | 'both';
      loop?: boolean;
      onIndexChange?: (newIndex: number) => void;
    } = {}
  ): number {
    const { orientation = 'vertical', loop = true, onIndexChange } = options;
    let newIndex = currentIndex;

    switch (event.key) {
      case KEYBOARD_KEYS.ARROW_UP:
        if (orientation === 'vertical' || orientation === 'both') {
          event.preventDefault();
          newIndex = currentIndex > 0 ? currentIndex - 1 : (loop ? items.length - 1 : currentIndex);
        }
        break;
      case KEYBOARD_KEYS.ARROW_DOWN:
        if (orientation === 'vertical' || orientation === 'both') {
          event.preventDefault();
          newIndex = currentIndex < items.length - 1 ? currentIndex + 1 : (loop ? 0 : currentIndex);
        }
        break;
      case KEYBOARD_KEYS.ARROW_LEFT:
        if (orientation === 'horizontal' || orientation === 'both') {
          event.preventDefault();
          newIndex = currentIndex > 0 ? currentIndex - 1 : (loop ? items.length - 1 : currentIndex);
        }
        break;
      case KEYBOARD_KEYS.ARROW_RIGHT:
        if (orientation === 'horizontal' || orientation === 'both') {
          event.preventDefault();
          newIndex = currentIndex < items.length - 1 ? currentIndex + 1 : (loop ? 0 : currentIndex);
        }
        break;
      case KEYBOARD_KEYS.HOME:
        event.preventDefault();
        newIndex = 0;
        break;
      case KEYBOARD_KEYS.END:
        event.preventDefault();
        newIndex = items.length - 1;
        break;
    }

    if (newIndex !== currentIndex) {
      items[newIndex]?.focus();
      onIndexChange?.(newIndex);
    }

    return newIndex;
  }

  /**
   * 处理类型搜索（按字母快速导航）
   */
  static handleTypeahead(
    event: KeyboardEvent,
    items: HTMLElement[],
    getItemText: (item: HTMLElement) => string,
    onMatch?: (index: number) => void
  ): void {
    const char = event.key.toLowerCase();
    if (char.length !== 1 || event.ctrlKey || event.metaKey || event.altKey) {
      return;
    }

    const matchIndex = items.findIndex(item => {
      const text = getItemText(item).toLowerCase();
      return text.startsWith(char);
    });

    if (matchIndex !== -1) {
      items[matchIndex].focus();
      onMatch?.(matchIndex);
    }
  }
}

// ARIA 属性助手
export class AriaHelper {
  /**
   * 生成唯一ID
   */
  static generateId(prefix = 'aria'): string {
    return `${prefix}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * 设置ARIA标签
   */
  static setLabel(element: HTMLElement, label: string): void {
    element.setAttribute('aria-label', label);
  }

  /**
   * 设置ARIA描述
   */
  static setDescription(element: HTMLElement, _description: string, descriptionId?: string): string {
    const id = descriptionId || this.generateId('desc');
    element.setAttribute('aria-describedby', id);
    return id;
  }

  /**
   * 设置ARIA展开状态
   */
  static setExpanded(element: HTMLElement, expanded: boolean): void {
    element.setAttribute('aria-expanded', expanded.toString());
  }

  /**
   * 设置ARIA选中状态
   */
  static setSelected(element: HTMLElement, selected: boolean): void {
    element.setAttribute('aria-selected', selected.toString());
  }

  /**
   * 设置ARIA禁用状态
   */
  static setDisabled(element: HTMLElement, disabled: boolean): void {
    if (disabled) {
      element.setAttribute('aria-disabled', 'true');
      element.setAttribute('tabindex', '-1');
    } else {
      element.removeAttribute('aria-disabled');
      element.removeAttribute('tabindex');
    }
  }

  /**
   * 设置ARIA隐藏状态
   */
  static setHidden(element: HTMLElement, hidden: boolean): void {
    if (hidden) {
      element.setAttribute('aria-hidden', 'true');
    } else {
      element.removeAttribute('aria-hidden');
    }
  }

  /**
   * 设置ARIA实时区域
   */
  static setLiveRegion(element: HTMLElement, politeness: 'off' | 'polite' | 'assertive' = 'polite'): void {
    element.setAttribute('aria-live', politeness);
    element.setAttribute('aria-atomic', 'true');
  }
}

// 无障碍验证器
export class AccessibilityValidator {
  /**
   * 验证元素是否有可访问的名称
   */
  static hasAccessibleName(element: HTMLElement): boolean {
    return !!(element.getAttribute('aria-label') ||
             element.getAttribute('aria-labelledby') ||
             element.textContent?.trim() ||
             (element as HTMLInputElement).placeholder ||
             element.getAttribute('title'));
  }

  /**
   * 验证按钮是否可访问
   */
  static validateButton(element: HTMLElement): string[] {
    const issues: string[] = [];

    if (!this.hasAccessibleName(element)) {
      issues.push('按钮缺少可访问的名称');
    }

    if (element.getAttribute('role') === 'button' && !element.hasAttribute('tabindex')) {
      issues.push('自定义按钮缺少tabindex属性');
    }

    return issues;
  }

  /**
   * 验证表单字段是否可访问
   */
  static validateFormField(element: HTMLInputElement): string[] {
    const issues: string[] = [];

    if (!this.hasAccessibleName(element)) {
      issues.push('表单字段缺少标签');
    }

    if (element.hasAttribute('required') && !element.getAttribute('aria-required')) {
      issues.push('必填字段应该设置aria-required属性');
    }

    if (element.hasAttribute('aria-invalid') && element.getAttribute('aria-invalid') === 'true') {
      if (!element.getAttribute('aria-describedby')) {
        issues.push('无效字段应该有错误描述');
      }
    }

    return issues;
  }

  /**
   * 验证图片是否可访问
   */
  static validateImage(element: HTMLImageElement): string[] {
    const issues: string[] = [];

    if (!element.alt && element.alt !== '') {
      issues.push('图片缺少alt属性');
    }

    if (element.alt === element.src) {
      issues.push('alt文本不应该是文件名');
    }

    return issues;
  }
}

// 导出单例实例
export const announcer = ScreenReaderAnnouncer.getInstance();

// 常用的无障碍属性类型
export interface AccessibilityProps {
  'aria-label'?: string;
  'aria-labelledby'?: string;
  'aria-describedby'?: string;
  'aria-expanded'?: boolean;
  'aria-selected'?: boolean;
  'aria-disabled'?: boolean;
  'aria-hidden'?: boolean;
  'aria-live'?: 'off' | 'polite' | 'assertive';
  'aria-atomic'?: boolean;
  'aria-controls'?: string;
  'aria-owns'?: string;
  'aria-activedescendant'?: string;
  'aria-current'?: boolean | 'page' | 'step' | 'location' | 'date' | 'time';
  'aria-invalid'?: boolean | 'grammar' | 'spelling';
  'aria-required'?: boolean;
  role?: string;
  tabIndex?: number;
}

// 无障碍钩子类型
export interface UseAccessibilityOptions {
  announceOnMount?: string;
  announceOnUnmount?: string;
  trapFocus?: boolean;
  restoreFocus?: boolean;
}