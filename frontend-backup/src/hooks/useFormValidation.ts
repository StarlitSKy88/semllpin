import { useState } from 'react';

// 验证规则接口
interface ValidationRule {
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  custom?: (value: string) => boolean;
  message: string;
}

// 字段验证配置
type FieldValidation = {
  [fieldName: string]: ValidationRule[];
};

// 验证结果
interface ValidationResult {
  isValid: boolean;
  errors: { [fieldName: string]: string[] };
}

// 表单验证Hook
export const useFormValidation = (validationRules: FieldValidation) => {
  const [errors, setErrors] = useState<{ [key: string]: string[] }>({});
  const [touched, setTouched] = useState<{ [key: string]: boolean }>({});

  const validateField = (fieldName: string, value: string): string[] => {
    const rules = validationRules[fieldName] || [];
    const fieldErrors: string[] = [];

    rules.forEach(rule => {
      if (rule.required && (!value || value.trim() === '')) {
        fieldErrors.push(rule.message);
      } else if (value) {
        if (rule.minLength && value.length < rule.minLength) {
          fieldErrors.push(rule.message);
        }
        if (rule.maxLength && value.length > rule.maxLength) {
          fieldErrors.push(rule.message);
        }
        if (rule.pattern && !rule.pattern.test(value)) {
          fieldErrors.push(rule.message);
        }
        if (rule.custom && !rule.custom(value)) {
          fieldErrors.push(rule.message);
        }
      }
    });

    return fieldErrors;
  };

  const validateForm = (formData: { [key: string]: string }): ValidationResult => {
    const newErrors: { [key: string]: string[] } = {};
    let isValid = true;

    Object.keys(validationRules).forEach(fieldName => {
      const fieldErrors = validateField(fieldName, formData[fieldName] || '');
      if (fieldErrors.length > 0) {
        newErrors[fieldName] = fieldErrors;
        isValid = false;
      }
    });

    setErrors(newErrors);
    return { isValid, errors: newErrors };
  };

  const validateSingleField = (fieldName: string, value: string) => {
    const fieldErrors = validateField(fieldName, value);
    setErrors(prev => ({
      ...prev,
      [fieldName]: fieldErrors
    }));
    return fieldErrors.length === 0;
  };

  const setFieldTouched = (fieldName: string) => {
    setTouched(prev => ({ ...prev, [fieldName]: true }));
  };

  const clearErrors = () => {
    setErrors({});
    setTouched({});
  };

  return {
    errors,
    touched,
    validateForm,
    validateSingleField,
    setFieldTouched,
    clearErrors
  };
};

export type { ValidationRule, FieldValidation, ValidationResult };