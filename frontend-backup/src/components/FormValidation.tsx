import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, CheckCircle, Eye, EyeOff, Info } from 'lucide-react';
import { useFormValidation } from '../hooks/useFormValidation';

// 表单验证Hook已移动到 ../hooks/useFormValidation.ts

// 错误消息组件
interface ErrorMessageProps {
  errors: string[];
  show: boolean;
  className?: string;
}

export const ErrorMessage: React.FC<ErrorMessageProps> = ({ 
  errors, 
  show, 
  className = '' 
}) => {
  return (
    <AnimatePresence>
      {show && errors.length > 0 && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.2 }}
          className={`mt-1 ${className}`}
          role="alert"
          aria-live="polite"
        >
          {errors.map((error, index) => (
            <div
              key={`item-${index}`}
              className="flex items-center text-sm text-red-600 mb-1"
            >
              <AlertCircle className="w-4 h-4 mr-1 flex-shrink-0" />
              <span>{error}</span>
            </div>
          ))}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// 成功消息组件
interface SuccessMessageProps {
  message: string;
  show: boolean;
  className?: string;
}

export const SuccessMessage: React.FC<SuccessMessageProps> = ({ 
  message, 
  show, 
  className = '' 
}) => {
  return (
    <AnimatePresence>
      {show && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.2 }}
          className={`flex items-center text-sm text-green-600 mt-1 ${className}`}
          role="status"
          aria-live="polite"
        >
          <CheckCircle className="w-4 h-4 mr-1" />
          <span>{message}</span>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// 输入字段组件
interface InputFieldProps {
  label: string;
  name: string;
  type?: 'text' | 'email' | 'password' | 'tel' | 'url';
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  placeholder?: string;
  errors?: string[];
  touched?: boolean;
  required?: boolean;
  disabled?: boolean;
  className?: string;
  helpText?: string;
  showPasswordToggle?: boolean;
}

export const InputField: React.FC<InputFieldProps> = ({
  label,
  name,
  type = 'text',
  value,
  onChange,
  onBlur,
  placeholder,
  errors = [],
  touched = false,
  required = false,
  disabled = false,
  className = '',
  helpText,
  showPasswordToggle = false
}) => {
  const [showPassword, setShowPassword] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  
  const hasErrors = touched && errors.length > 0;
  const inputType = type === 'password' && showPassword ? 'text' : type;

  const getInputClasses = () => {
    const baseClasses = `
      w-full px-4 py-3 border rounded-lg
      transition-all duration-200
      focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent
      disabled:bg-gray-50 disabled:text-gray-500 disabled:cursor-not-allowed
    `;
    
    if (hasErrors) {
      return `${baseClasses} border-red-300 bg-red-50 focus:ring-red-500`;
    }
    
    if (isFocused) {
      return `${baseClasses} border-purple-300 bg-white`;
    }
    
    return `${baseClasses} border-gray-300 bg-white hover:border-gray-400`;
  };

  return (
    <div className={`space-y-1 ${className}`}>
      {/* 标签 */}
      <label 
        htmlFor={name}
        className="block text-sm font-medium text-gray-700"
      >
        {label}
        {required && <span className="text-red-500 ml-1">*</span>}
      </label>

      {/* 输入框容器 */}
      <div className="relative">
        <input
          id={name}
          name={name}
          type={inputType}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onBlur={() => {
            setIsFocused(false);
            onBlur?.();
          }}
          onFocus={() => setIsFocused(true)}
          placeholder={placeholder}
          disabled={disabled}
          className={getInputClasses()}
          aria-invalid={hasErrors}
          aria-describedby={`${name}-error ${name}-help`}
        />
        
        {/* 密码显示切换按钮 */}
        {type === 'password' && showPasswordToggle && (
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
            aria-label={showPassword ? '隐藏密码' : '显示密码'}
          >
            {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
          </button>
        )}
      </div>

      {/* 帮助文本 */}
      {helpText && (
        <div 
          id={`${name}-help`}
          className="flex items-center text-sm text-gray-500"
        >
          <Info className="w-4 h-4 mr-1" />
          <span>{helpText}</span>
        </div>
      )}

      {/* 错误消息 */}
      <ErrorMessage 
        errors={errors} 
        show={touched} 
      />
    </div>
  );
};

// 文本域组件
interface TextAreaFieldProps {
  label: string;
  name: string;
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  placeholder?: string;
  errors?: string[];
  touched?: boolean;
  required?: boolean;
  disabled?: boolean;
  rows?: number;
  maxLength?: number;
  className?: string;
  helpText?: string;
}

export const TextAreaField: React.FC<TextAreaFieldProps> = ({
  label,
  name,
  value,
  onChange,
  onBlur,
  placeholder,
  errors = [],
  touched = false,
  required = false,
  disabled = false,
  rows = 4,
  maxLength,
  className = '',
  helpText
}) => {
  const [isFocused, setIsFocused] = useState(false);
  const hasErrors = touched && errors.length > 0;
  const characterCount = value.length;

  const getTextAreaClasses = () => {
    const baseClasses = `
      w-full px-4 py-3 border rounded-lg resize-vertical
      transition-all duration-200
      focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent
      disabled:bg-gray-50 disabled:text-gray-500 disabled:cursor-not-allowed
    `;
    
    if (hasErrors) {
      return `${baseClasses} border-red-300 bg-red-50 focus:ring-red-500`;
    }
    
    if (isFocused) {
      return `${baseClasses} border-purple-300 bg-white`;
    }
    
    return `${baseClasses} border-gray-300 bg-white hover:border-gray-400`;
  };

  return (
    <div className={`space-y-1 ${className}`}>
      {/* 标签 */}
      <div className="flex justify-between items-center">
        <label 
          htmlFor={name}
          className="block text-sm font-medium text-gray-700"
        >
          {label}
          {required && <span className="text-red-500 ml-1">*</span>}
        </label>
        
        {/* 字符计数 */}
        {maxLength && (
          <span className={`text-sm ${
            characterCount > maxLength ? 'text-red-500' : 'text-gray-500'
          }`}>
            {characterCount}/{maxLength}
          </span>
        )}
      </div>

      {/* 文本域 */}
      <textarea
        id={name}
        name={name}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={() => {
          setIsFocused(false);
          onBlur?.();
        }}
        onFocus={() => setIsFocused(true)}
        placeholder={placeholder}
        disabled={disabled}
        rows={rows}
        maxLength={maxLength}
        className={getTextAreaClasses()}
        aria-invalid={hasErrors}
        aria-describedby={`${name}-error ${name}-help`}
      />

      {/* 帮助文本 */}
      {helpText && (
        <div 
          id={`${name}-help`}
          className="flex items-center text-sm text-gray-500"
        >
          <Info className="w-4 h-4 mr-1" />
          <span>{helpText}</span>
        </div>
      )}

      {/* 错误消息 */}
      <ErrorMessage 
        errors={errors} 
        show={touched} 
      />
    </div>
  );
};

// 表单提交按钮组件
interface SubmitButtonProps {
  children: React.ReactNode;
  isLoading?: boolean;
  disabled?: boolean;
  className?: string;
  onClick?: () => void;
}

export const SubmitButton: React.FC<SubmitButtonProps> = ({
  children,
  isLoading = false,
  disabled = false,
  className = '',
  onClick
}) => {
  return (
    <motion.button
      type="submit"
      onClick={onClick}
      disabled={disabled || isLoading}
      whileHover={{ scale: disabled ? 1 : 1.02 }}
      whileTap={{ scale: disabled ? 1 : 0.98 }}
      className={`
        w-full py-3 px-6 rounded-lg font-medium
        transition-all duration-200
        focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2
        disabled:opacity-50 disabled:cursor-not-allowed
        ${
          disabled || isLoading
            ? 'bg-gray-300 text-gray-500'
            : 'bg-purple-600 hover:bg-purple-700 text-white'
        }
        ${className}
      `}
    >
      {isLoading ? (
        <div className="flex items-center justify-center">
          <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
          <span>提交中...</span>
        </div>
      ) : (
        children
      )}
    </motion.button>
  );
};

export default {
  useFormValidation,
  ErrorMessage,
  SuccessMessage,
  InputField,
  TextAreaField,
  SubmitButton
};