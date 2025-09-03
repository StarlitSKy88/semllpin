/**
 * 现代化表单组件
 * 基于设计令牌系统的统一表单实现
 */

import React, { forwardRef, createContext, useContext, useId } from 'react';
import { cn } from '../../utils/cn';
import { useTheme } from '../../contexts/ThemeContext';
import type { AccessibilityProps } from '../../utils/accessibility';
import { useFormAccessibility } from '../../hooks/useAccessibility';
import Input, { type InputProps, Textarea, type TextareaProps } from './Input';
import Button, { type ButtonProps } from './Button';

// 表单上下文
interface FormContextType {
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  disabled?: boolean;
  errors?: Record<string, string>;
  touched?: Record<string, boolean>;
}

const FormContext = createContext<FormContextType>({});

export const useFormContext = () => useContext(FormContext);

// 表单组件
export interface FormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'outline';
  layout?: 'vertical' | 'horizontal' | 'inline';
  disabled?: boolean;
  errors?: Record<string, string>;
  touched?: Record<string, boolean>;
  children: React.ReactNode;
}

const Form = forwardRef<HTMLFormElement, FormProps>((
  {
    className,
    size = 'md',
    variant = 'outline',
    layout = 'vertical',
    disabled = false,
    errors = {},
    touched = {},
    children,
    ...props
  },
  ref
) => {
  useTheme();

  // 布局样式
  const layoutStyles = {
    vertical: 'space-y-6',
    horizontal: 'space-y-4',
    inline: 'flex flex-wrap items-end gap-4',
  };

  const contextValue: FormContextType = {
    size,
    variant,
    disabled,
    errors,
    touched,
  };

  return (
    <FormContext.Provider value={contextValue}>
      <form
        ref={ref}
        className={cn(
          'w-full',
          layoutStyles[layout],
          disabled && 'opacity-60 pointer-events-none',
          className
        )}
        {...props}
      >
        {children}
      </form>
    </FormContext.Provider>
  );
});

Form.displayName = 'Form';

// 表单项组件
export interface FormItemProps extends AccessibilityProps {
  label?: string;
  name?: string;
  required?: boolean;
  error?: string;
  help?: string;
  className?: string;
  labelClassName?: string;
  children: React.ReactNode;
}

export const FormItem: React.FC<FormItemProps> = ({
  label,
  name,
  required = false,
  error,
  help,
  className,
  labelClassName,
  children,
  ...accessibilityProps
}) => {
  const { errors, touched } = useFormContext();
  useFormAccessibility();
  
  // 从上下文获取错误信息
  const fieldError = error || (name && errors?.[name]);
  const isFieldTouched = name && touched?.[name];
  const showError = fieldError && (isFieldTouched || error);
  
  const labelId = useId();
  const helpTextId = useId();
  const errorId = useId();

  return (
    <div className={cn('w-full', className)}>
      {/* 标签 */}
      {label && (
        <label
          id={labelId}
          htmlFor={name}
          className={cn(
            'block text-sm font-medium mb-2',
            showError
              ? 'text-pomegranate-600 dark:text-pomegranate-400'
              : 'text-pomegranate-700 dark:text-pomegranate-300',
            labelClassName
          )}
        >
          {label}
          {required && (
            <span className="text-pomegranate-500 ml-1" aria-label="必填">
              *
            </span>
          )}
        </label>
      )}

      {/* 表单控件 */}
      <div className="relative">
        {React.Children.map(children, (child) => {
          if (React.isValidElement(child)) {
            const childProps: any = {
              id: name,
              name: name,
              error: showError ? fieldError : undefined,
              'aria-invalid': showError ? 'true' : 'false',
              'aria-labelledby': label ? labelId : undefined,
              'aria-describedby': showError ? errorId : (help ? helpTextId : undefined),
              'aria-required': required,
              ...accessibilityProps,
              ...child.props,
            };
            
            // 过滤掉undefined的属性
            const filteredProps = Object.fromEntries(
              Object.entries(childProps).filter(([_, value]) => value !== undefined)
            );
            
            return React.cloneElement(child as React.ReactElement<any>, filteredProps);
          }
          return child;
        })}
      </div>

      {/* 帮助文本 */}
      {help && !showError && (
        <div
          id={helpTextId}
          className="mt-2 text-sm text-pomegranate-500 dark:text-pomegranate-400"
        >
          {help}
        </div>
      )}

      {/* 错误信息 */}
      {showError && (
        <div
          id={errorId}
          className="mt-2 text-sm text-pomegranate-600 dark:text-pomegranate-400"
          role="alert"
        >
          {fieldError}
        </div>
      )}
    </div>
  );
};

// 表单输入框组件
export interface FormInputProps extends Omit<InputProps, 'error'> {
  name: string;
}

export const FormInput = forwardRef<HTMLInputElement, FormInputProps>((
  { name, ...props },
  ref
) => {
  const { size, variant, disabled, errors, touched } = useFormContext();
  
  const error = errors?.[name];
  const isFieldTouched = touched?.[name];
  const showError = error && isFieldTouched;

  return (
    <Input
      ref={ref}
      name={name}
      size={size}
      variant={variant}
      disabled={disabled}
      error={showError ? error : undefined}
      {...props}
    />
  );
});

FormInput.displayName = 'FormInput';

// 表单文本域组件
export interface FormTextareaProps extends Omit<TextareaProps, 'error'> {
  name: string;
}

export const FormTextarea = forwardRef<HTMLTextAreaElement, FormTextareaProps>((
  { name, ...props },
  ref
) => {
  const { size, variant, disabled, errors, touched } = useFormContext();
  
  const error = errors?.[name];
  const isFieldTouched = touched?.[name];
  const showError = error && isFieldTouched;

  return (
    <Textarea
      ref={ref}
      name={name}
      size={size}
      variant={variant}
      disabled={disabled}
      error={showError ? error : undefined}
      {...props}
    />
  );
});

FormTextarea.displayName = 'FormTextarea';

// 表单按钮组件
export interface FormButtonProps extends ButtonProps {
  htmlType?: 'button' | 'submit' | 'reset';
}

export const FormButton = forwardRef<HTMLButtonElement, FormButtonProps>((
  { htmlType = 'button', ...props },
  ref
) => {
  const { size, disabled } = useFormContext();

  return (
    <Button
      ref={ref}
      type={htmlType}
      size={size}
      disabled={disabled}
      {...props}
    />
  );
});

FormButton.displayName = 'FormButton';

// 表单组组件
export interface FormGroupProps {
  title?: string;
  description?: string;
  className?: string;
  children: React.ReactNode;
}

export const FormGroup: React.FC<FormGroupProps> = ({
  title,
  description,
  className,
  children,
}) => {
  return (
    <div className={cn('space-y-4', className)}>
      {(title || description) && (
        <div className="border-b border-pomegranate-200 dark:border-pomegranate-700 pb-4">
          {title && (
            <h3 className="text-lg font-medium text-pomegranate-900 dark:text-pomegranate-100">
              {title}
            </h3>
          )}
          {description && (
            <p className="mt-1 text-sm text-pomegranate-600 dark:text-pomegranate-400">
              {description}
            </p>
          )}
        </div>
      )}
      <div className="space-y-4">
        {children}
      </div>
    </div>
  );
};

// 表单操作区域组件
export interface FormActionsProps {
  align?: 'left' | 'center' | 'right';
  className?: string;
  children: React.ReactNode;
}

export const FormActions: React.FC<FormActionsProps> = ({
  align = 'right',
  className,
  children,
}) => {
  const alignStyles = {
    left: 'justify-start',
    center: 'justify-center',
    right: 'justify-end',
  };

  return (
    <div
      className={cn(
        'flex items-center gap-3 pt-6 border-t border-pomegranate-200 dark:border-pomegranate-700 bg-gradient-to-r from-floral-50 to-pomegranate-50 dark:from-pomegranate-900 dark:to-floral-900 rounded-lg p-4',
        alignStyles[align],
        className
      )}
    >
      {children}
    </div>
  );
};

// 选择框组件
export interface FormSelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  name: string;
  label?: string;
  options: Array<{ value: string | number; label: string; disabled?: boolean }>;
  placeholder?: string;
  error?: string;
}

export const FormSelect = forwardRef<HTMLSelectElement, FormSelectProps>((
  {
    name,
    label,
    options,
    placeholder,
    error,
    className,
    ...props
  },
  ref
) => {
  const { size, variant, disabled, errors, touched } = useFormContext();
  
  const fieldError = error || errors?.[name];
  const isFieldTouched = touched?.[name];
  const showError = fieldError && (isFieldTouched || error);

  // 尺寸样式
  const sizeStyles = {
    sm: 'h-9 px-3 text-sm',
    md: 'h-10 px-4 text-base',
    lg: 'h-12 px-5 text-lg',
  };

  // 变体样式
  const variantStyles = {
    default: [
      'border border-pomegranate-300 bg-gradient-to-r from-floral-50 to-pomegranate-50',
      'focus:border-pomegranate-500 focus:ring-1 focus:ring-pomegranate-500',
      'dark:border-pomegranate-600 dark:from-pomegranate-900 dark:to-floral-900',
      'dark:focus:border-pomegranate-400 dark:focus:ring-pomegranate-400',
    ],
    filled: [
      'border-0 bg-gradient-to-r from-floral-100 to-pomegranate-100',
      'focus:bg-gradient-to-r focus:from-floral-50 focus:to-pomegranate-50 focus:ring-2 focus:ring-pomegranate-500',
      'dark:from-pomegranate-800 dark:to-floral-800',
      'dark:focus:from-pomegranate-700 dark:focus:to-floral-700 dark:focus:ring-pomegranate-400',
    ],
    outline: [
      'border-2 border-pomegranate-200 bg-transparent',
      'focus:border-pomegranate-500 focus:ring-0',
      'dark:border-pomegranate-700',
      'dark:focus:border-pomegranate-400',
    ],
  };

  return (
    <div className="w-full">
      {label && (
        <label
          htmlFor={name}
          className={cn(
            'block text-sm font-medium mb-2',
            showError
              ? 'text-pomegranate-600 dark:text-pomegranate-400'
              : 'text-pomegranate-700 dark:text-pomegranate-300'
          )}
        >
          {label}
        </label>
      )}
      
      <select
        ref={ref}
        id={name}
        name={name}
        className={cn(
          'w-full rounded-md transition-all duration-200',
          'text-gray-900 dark:text-gray-100',
          'focus:outline-none',
          'disabled:opacity-50 disabled:cursor-not-allowed',
          sizeStyles[size || 'md'],
          variantStyles[variant || 'outline'],
          showError && [
            'border-red-500 focus:border-red-500 focus:ring-red-500',
            'dark:border-red-400 dark:focus:border-red-400 dark:focus:ring-red-400',
          ],
          className
        )}
        disabled={disabled}
        aria-invalid={showError ? 'true' : 'false'}
        {...props}
      >
        {placeholder && (
          <option value="" disabled>
            {placeholder}
          </option>
        )}
        {options.map((option) => (
          <option
            key={option.value}
            value={option.value}
            disabled={option.disabled}
          >
            {option.label}
          </option>
        ))}
      </select>

      {showError && (
        <div className="mt-2 text-sm text-pomegranate-600 dark:text-pomegranate-400">
          {fieldError}
        </div>
      )}
    </div>
  );
});

FormSelect.displayName = 'FormSelect';

export default Form;