import React from 'react';
import { Select } from 'antd';
import { GlobalOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { supportedLanguages, changeLanguage, getCurrentLanguage } from '../../i18n';

const { Option } = Select;

interface LanguageSwitcherProps {
  size?: 'small' | 'middle' | 'large';
  showIcon?: boolean;
  style?: React.CSSProperties;
  className?: string;
}

const LanguageSwitcher: React.FC<LanguageSwitcherProps> = ({
  size = 'middle',
  showIcon = true,
  style,
  className,
}) => {
  const { t } = useTranslation();
  const currentLanguage = getCurrentLanguage();

  const handleLanguageChange = (value: string) => {
    changeLanguage(value);
  };

  return (
    <Select
      value={currentLanguage}
      onChange={handleLanguageChange}
      size={size}
      style={{ minWidth: 120, ...style }}
      className={className}
      suffixIcon={showIcon ? <GlobalOutlined /> : undefined}
      placeholder={t('common.language')}
    >
      {Object.entries(supportedLanguages).map(([code, lang]) => (
        <Option key={code} value={code}>
          <span style={{ marginRight: 8 }}>{lang.flag}</span>
          {lang.nativeName}
        </Option>
      ))}
    </Select>
  );
};

export default LanguageSwitcher;