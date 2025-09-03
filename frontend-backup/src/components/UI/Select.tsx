/**
 * Select 组件
 * 现代化的选择器组件，支持单选、多选、搜索等功能，并增强无障碍功能
 */

import React, { forwardRef, useState, useRef, useEffect, useId, useCallback } from 'react';
import { ChevronDown, Check, X, Search } from 'lucide-react';
import { cn } from '../../utils/cn';
// import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useKeyboardNavigation, useAnnouncer } from '../../hooks/useAccessibility';

export interface SelectOption {
  value: string;
  label: string;
  description?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  group?: string;
}

export interface SelectProps extends AccessibilityProps {
  value?: string | string[];
  defaultValue?: string | string[];
  placeholder?: string;
  options: SelectOption[];
  multiple?: boolean;
  searchable?: boolean;
  clearable?: boolean;
  disabled?: boolean;
  loading?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'flushed';
  error?: boolean | string;
  className?: string;
  dropdownClassName?: string;
  maxHeight?: number;
  onCreate?: (inputValue: string) => void;
  onSearch?: (searchValue: string) => void;
  onChange?: (value: string | string[]) => void;
  onFocus?: () => void;
  onBlur?: () => void;
}

const Select = forwardRef<HTMLDivElement, SelectProps>((
  {
    value,
    defaultValue,
    placeholder = '请选择...',
    options = [],
    multiple = false,
    searchable = false,
    clearable = false,
    disabled = false,
    loading = false,
    size = 'md',
    variant = 'default',
    error,
    className,
    dropdownClassName,
    maxHeight = 200,
    onCreate,
    onSearch,
    onChange,
    onFocus,
    onBlur,
    ...accessibilityProps
  },
  ref
) => {
  const selectId = useId();
  const listboxId = useId();
  const searchInputId = useId();
  const errorId = useId();
  
  const [isOpen, setIsOpen] = useState(false);
  const [searchValue, setSearchValue] = useState('');
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const [internalValue, setInternalValue] = useState<string | string[]>(
    value !== undefined ? value : (defaultValue || (multiple ? [] : ''))
  );

  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  
  // 无障碍功能
  const { announce } = useAnnouncer();
  
  // 过滤选项
  const filteredOptions = options.filter(option => 
    !searchValue || option.label.toLowerCase().includes(searchValue.toLowerCase())
  );
  
  // 键盘导航
  const { handleKeyDown: handleNavigationKeyDown } = useKeyboardNavigation(
    [],
    {
      onIndexChange: (index: number) => {
        const option = filteredOptions[index];
        if (option) {
          handleOptionSelect(option);
        }
      }
    }
  );

  // 受控/非受控值管理
  const currentValue = value !== undefined ? value : internalValue;

  // 获取显示文本
  const getDisplayText = () => {
    if (multiple) {
      const selectedOptions = options.filter(option => 
        (currentValue as string[]).includes(option.value)
      );
      if (selectedOptions.length === 0) return placeholder;
      if (selectedOptions.length === 1) return selectedOptions[0].label;
      return `已选择 ${selectedOptions.length} 项`;
    } else {
      const selectedOption = options.find(option => option.value === currentValue);
      return selectedOption ? selectedOption.label : placeholder;
    }
  };

  // 处理选项选择
  const handleOptionSelect = useCallback((option: SelectOption) => {
    if (option.disabled) return;

    let newValue: string | string[];
    let announceMessage = '';
    
    if (multiple) {
      const currentArray = currentValue as string[];
      if (currentArray.includes(option.value)) {
        newValue = currentArray.filter(v => v !== option.value);
        announceMessage = `已取消选择 ${option.label}`;
      } else {
        newValue = [...currentArray, option.value];
        announceMessage = `已选择 ${option.label}`;
      }
    } else {
      newValue = option.value;
      announceMessage = `已选择 ${option.label}`;
      setIsOpen(false);
    }

    // 语音播报选择结果
    announce(announceMessage);

    if (value === undefined) {
      setInternalValue(newValue);
    }
    onChange?.(newValue);
  }, [currentValue, multiple, value, announce, onChange]);

  // 清空选择
  const handleClear = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    const newValue = multiple ? [] : '';
    
    // 语音播报清空操作
    announce(multiple ? '已清空所有选择' : '已清空选择');
    
    if (value === undefined) {
      setInternalValue(newValue);
    }
    onChange?.(newValue);
  }, [multiple, value, announce, onChange]);

  // 键盘事件处理
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (disabled) return;

    switch (e.key) {
      case 'Enter':
      case ' ':
        e.preventDefault();
        if (!isOpen) {
          setIsOpen(true);
          announce(`${multiple ? '多选' : '单选'}列表已展开，共 ${filteredOptions.length} 个选项`);
        } else if (highlightedIndex >= 0) {
          handleOptionSelect(filteredOptions[highlightedIndex]);
        }
        break;
      case 'Escape':
        e.preventDefault();
        setIsOpen(false);
        setHighlightedIndex(-1);
        announce('列表已关闭');
        break;
      case 'ArrowDown':
        e.preventDefault();
        if (!isOpen) {
          setIsOpen(true);
          announce(`${multiple ? '多选' : '单选'}列表已展开，共 ${filteredOptions.length} 个选项`);
        } else {
          const newIndex = highlightedIndex < filteredOptions.length - 1 ? highlightedIndex + 1 : 0;
          setHighlightedIndex(newIndex);
          const option = filteredOptions[newIndex];
          if (option) {
            announce(`${option.label}${option.description ? `, ${option.description}` : ''}`);
          }
        }
        break;
      case 'ArrowUp':
        e.preventDefault();
        if (!isOpen) {
          setIsOpen(true);
          announce(`${multiple ? '多选' : '单选'}列表已展开，共 ${filteredOptions.length} 个选项`);
        } else {
          const newIndex = highlightedIndex > 0 ? highlightedIndex - 1 : filteredOptions.length - 1;
          setHighlightedIndex(newIndex);
          const option = filteredOptions[newIndex];
          if (option) {
            announce(`${option.label}${option.description ? `, ${option.description}` : ''}`);
          }
        }
        break;
      case 'Tab':
        setIsOpen(false);
        break;
      default:
        // 处理其他键盘导航
        handleNavigationKeyDown(e.nativeEvent);
        break;
    }
  }, [disabled, isOpen, multiple, filteredOptions, highlightedIndex, handleOptionSelect, announce, handleNavigationKeyDown]);

  // 点击外部关闭
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  // 自动聚焦搜索框
  useEffect(() => {
    if (isOpen && searchable && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isOpen, searchable]);

  // 滚动到高亮项
  useEffect(() => {
    if (highlightedIndex >= 0 && listRef.current) {
      const highlightedElement = listRef.current.children[highlightedIndex] as HTMLElement;
      if (highlightedElement) {
        highlightedElement.scrollIntoView({
          block: 'nearest',
          behavior: 'smooth'
        });
      }
    }
  }, [highlightedIndex]);

  const hasValue = multiple 
    ? (currentValue as string[]).length > 0 
    : currentValue !== '';

  return (
    <div
      ref={ref || containerRef}
      className={cn('relative', className)}
      {...accessibilityProps}
    >
      {/* 选择器触发器 */}
      <div
        id={selectId}
        role="combobox"
        aria-expanded={isOpen}
        aria-haspopup="listbox"
        aria-controls={isOpen ? listboxId : undefined}
        aria-owns={isOpen ? listboxId : undefined}
        aria-activedescendant={highlightedIndex >= 0 ? `${selectId}-option-${highlightedIndex}` : undefined}
        aria-invalid={error ? 'true' : 'false'}
        aria-describedby={error && typeof error === 'string' ? errorId : undefined}
        aria-required={accessibilityProps['aria-required']}
        tabIndex={disabled ? -1 : 0}
        className={cn(
          // 基础样式
          'flex items-center justify-between w-full border transition-all duration-200 cursor-pointer',
          'focus:outline-none focus:ring-2',
          // 尺寸样式
          {
            'h-8 px-3 text-sm': size === 'sm',
            'h-10 px-4 text-base': size === 'md',
            'h-12 px-5 text-lg': size === 'lg',
          },
          // 变体样式
          {
            // default 变体
            'bg-white dark:bg-gray-800 border-pomegranate-300 dark:border-pomegranate-600 rounded-md': variant === 'default',
            'focus:border-pomegranate-500 focus:ring-pomegranate-500/20 hover:border-pomegranate-400': variant === 'default' && !error,
            'border-red-500 focus:border-red-500 focus:ring-red-500/20': variant === 'default' && error,
            
            // filled 变体
            'bg-gradient-to-br from-floral-50 to-floral-100 dark:from-gray-700 dark:to-gray-800 border-transparent rounded-md': variant === 'filled',
            'focus:from-white focus:to-white dark:focus:from-gray-800 dark:focus:to-gray-800 focus:border-pomegranate-500 focus:ring-pomegranate-500/20 hover:from-floral-100 hover:to-floral-200': variant === 'filled' && !error,
            'from-red-50 to-red-100 dark:from-red-900/20 dark:to-red-900/30 border-red-500 focus:border-red-500 focus:ring-red-500/20': variant === 'filled' && error,
            
            // flushed 变体
            'bg-transparent border-0 border-b-2 border-pomegranate-300 dark:border-pomegranate-600 rounded-none': variant === 'flushed',
            'focus:border-pomegranate-500 hover:border-pomegranate-400': variant === 'flushed' && !error,
            'border-red-500 focus:border-red-500': variant === 'flushed' && error,
          },
          // 禁用状态
          {
            'opacity-50 cursor-not-allowed': disabled,
          }
        )}
        onClick={() => !disabled && setIsOpen(!isOpen)}
        onKeyDown={handleKeyDown}
        onFocus={() => {
          onFocus?.();
        }}
        onBlur={(_e) => {
          // 延迟关闭，允许点击选项
          setTimeout(() => {
            if (!containerRef.current?.contains(document.activeElement)) {
              setIsOpen(false);
              onBlur?.();
            }
          }, 150);
        }}
      >
        {/* 显示文本 */}
        <span className={cn(
          'flex-1 text-left truncate',
          {
            'text-gray-400 dark:text-gray-500': !hasValue,
            'text-gray-900 dark:text-gray-100': hasValue,
          }
        )}>
          {getDisplayText()}
        </span>

        {/* 右侧图标区域 */}
        <div className="flex items-center gap-1">
          {/* 清空按钮 */}
          {clearable && hasValue && !disabled && (
            <button
              type="button"
              className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
              onClick={handleClear}
              aria-label="清空选择"
            >
              <X className={cn(
                'text-gray-400 hover:text-gray-600',
                {
                  'w-3 h-3': size === 'sm',
                  'w-4 h-4': size === 'md',
                  'w-5 h-5': size === 'lg',
                }
              )} />
            </button>
          )}

          {/* 加载指示器 */}
          {loading && (
            <div className={cn(
              'animate-spin rounded-full border-2 border-gray-300 border-t-pomegranate-600',
              {
                'w-3 h-3': size === 'sm',
                'w-4 h-4': size === 'md',
                'w-5 h-5': size === 'lg',
              }
            )} aria-hidden="true" />
          )}

          {/* 下拉箭头 */}
          <ChevronDown
            className={cn(
              'transition-transform duration-200',
              {
                'w-4 h-4': size === 'sm',
                'w-5 h-5': size === 'md',
                'w-6 h-6': size === 'lg',
              },
              {
                'transform rotate-180': isOpen,
              },
              'text-gray-400'
            )}
            aria-hidden="true"
          />
        </div>
      </div>

      {/* 下拉选项列表 */}
      {isOpen && (
        <div className={cn(
          'absolute z-50 w-full mt-1 bg-white dark:bg-gray-800 border border-pomegranate-200 dark:border-pomegranate-700',
          'rounded-md shadow-lg shadow-pomegranate-100/20 dark:shadow-pomegranate-900/20',
          dropdownClassName
        )}>
          {/* 搜索框 */}
          {searchable && (
            <div className="p-2 border-b border-pomegranate-200 dark:border-pomegranate-700">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" aria-hidden="true" />
                <input
                  ref={searchInputRef}
                  id={searchInputId}
                  type="text"
                  role="searchbox"
                  placeholder="搜索选项..."
                  value={searchValue}
                  aria-label="搜索选项"
                  aria-controls={listboxId}
                  className={cn(
                    'w-full pl-10 pr-4 py-2 text-sm',
                    'bg-transparent border-0 focus:outline-none',
                    'text-gray-900 dark:text-gray-100 placeholder-gray-400'
                  )}
                  onChange={(e) => {
                    setSearchValue(e.target.value);
                    onSearch?.(e.target.value);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'ArrowDown' && filteredOptions.length > 0) {
                      e.preventDefault();
                      setHighlightedIndex(0);
                    }
                  }}
                />
              </div>
            </div>
          )}

          {/* 选项列表 */}
          <ul
            ref={listRef}
            id={listboxId}
            role="listbox"
            aria-multiselectable={multiple}
            aria-label={multiple ? '多选列表' : '单选列表'}
            className={cn(
              'max-h-60 overflow-auto py-1',
              `max-h-[${maxHeight}px]`
            )}
          >
            {filteredOptions.length === 0 ? (
              <li className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">
                {searchValue ? '未找到匹配选项' : '暂无选项'}
              </li>
            ) : (
              filteredOptions.map((option, index) => {
                const isSelected = multiple 
                  ? (currentValue as string[]).includes(option.value)
                  : currentValue === option.value;
                const isHighlighted = index === highlightedIndex;

                return (
                  <li
                    key={option.value}
                    id={`${selectId}-option-${index}`}
                    role="option"
                    aria-selected={isSelected}
                    aria-disabled={option.disabled}
                    className={cn(
                      'flex items-center justify-between px-4 py-2 cursor-pointer transition-colors',
                      {
                        'bg-gradient-to-r from-pomegranate-50 to-floral-50 dark:from-pomegranate-900/20 dark:to-floral-900/20 text-pomegranate-600 dark:text-pomegranate-400': isHighlighted,
                        'text-gray-900 dark:text-gray-100 hover:bg-pomegranate-50/50 dark:hover:bg-pomegranate-900/10': !isHighlighted,
                        'opacity-50 cursor-not-allowed': option.disabled,
                      }
                    )}
                    onClick={() => !option.disabled && handleOptionSelect(option)}
                    onMouseEnter={() => setHighlightedIndex(index)}
                  >
                    <div className="flex items-center gap-3">
                      {option.icon && (
                        <span className="flex-shrink-0" aria-hidden="true">
                          {option.icon}
                        </span>
                      )}
                      <div>
                        <div className="font-medium">{option.label}</div>
                        {option.description && (
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {option.description}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {isSelected && (
                      <Check className="w-4 h-4 text-pomegranate-600 dark:text-pomegranate-400" aria-hidden="true" />
                    )}
                  </li>
                );
              })
            )}

            {/* 创建新选项 */}
            {onCreate && searchValue && !filteredOptions.some(opt => opt.label.toLowerCase() === searchValue.toLowerCase()) && (
              <li
                role="option"
                className="px-4 py-2 cursor-pointer text-pomegranate-600 dark:text-pomegranate-400 hover:bg-gradient-to-r hover:from-pomegranate-50 hover:to-floral-50 dark:hover:from-pomegranate-900/20 dark:hover:to-floral-900/20 transition-colors border-t border-pomegranate-200 dark:border-pomegranate-700"
                onClick={() => {
                  onCreate(searchValue);
                  setSearchValue('');
                  setIsOpen(false);
                }}
              >
                创建 "{searchValue}"
              </li>
            )}
          </ul>
        </div>
      )}
      
      {/* 错误信息 */}
      {error && typeof error === 'string' && (
        <div
          id={errorId}
          role="alert"
          aria-live="polite"
          className="mt-1 text-sm text-pomegranate-600 dark:text-pomegranate-400"
        >
          {error}
        </div>
      )}
    </div>
  );
});

Select.displayName = 'Select';

export default Select;