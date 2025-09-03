import React, { useEffect, useState, useCallback } from 'react';


interface KeyboardNavigationProps {
  children: React.ReactNode;
  showHelp?: boolean;
  className?: string;
}

/**
 * 键盘导航增强组件
 * 提供键盘导航提示和焦点管理
 */
export const KeyboardNavigation: React.FC<KeyboardNavigationProps> = ({
  children,
  showHelp = false,
  className = ''
}) => {
  const [isKeyboardUser, setIsKeyboardUser] = useState(false);
  const [showKeyboardHelp, setShowKeyboardHelp] = useState(false);

  // 检测用户是否使用键盘导航
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (event.key === 'Tab') {
      setIsKeyboardUser(true);
    }
    
    // 显示键盘帮助 (按 ? 键)
    if (event.key === '?' && event.shiftKey && showHelp) {
      setShowKeyboardHelp(prev => !prev);
    }
    
    // ESC 键关闭帮助
    if (event.key === 'Escape') {
      setShowKeyboardHelp(false);
    }
  }, [showHelp]);

  const handleMouseDown = useCallback(() => {
    setIsKeyboardUser(false);
  }, []);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleMouseDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleMouseDown);
    };
  }, [handleKeyDown, handleMouseDown]);

  // 键盘快捷键帮助内容
  const keyboardShortcuts = [
    { key: 'Tab', description: '移动到下一个可聚焦元素' },
    { key: 'Shift + Tab', description: '移动到上一个可聚焦元素' },
    { key: 'Enter', description: '激活按钮或链接' },
    { key: 'Space', description: '激活按钮或复选框' },
    { key: '↑↓←→', description: '在菜单或列表中导航' },
    { key: 'Esc', description: '关闭模态框或菜单' },
    { key: '?', description: '显示/隐藏键盘快捷键帮助' }
  ];

  return (
    <div className={`keyboard-navigation ${isKeyboardUser ? 'keyboard-user' : ''} ${className}`}>
      {children}
      
      {/* 键盘导航样式 */}
      <style>{`
        .keyboard-navigation.keyboard-user *:focus {
          outline: 3px solid #4A90E2 !important;
          outline-offset: 2px !important;
          box-shadow: 0 0 0 1px rgba(74, 144, 226, 0.3) !important;
        }
        
        .keyboard-navigation.keyboard-user button:focus,
        .keyboard-navigation.keyboard-user a:focus,
        .keyboard-navigation.keyboard-user input:focus,
        .keyboard-navigation.keyboard-user select:focus,
        .keyboard-navigation.keyboard-user textarea:focus {
          outline: 3px solid #4A90E2 !important;
          outline-offset: 2px !important;
          box-shadow: 0 0 0 1px rgba(74, 144, 226, 0.3) !important;
          position: relative;
          z-index: 1;
        }
        
        .keyboard-help-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.8);
          z-index: 9999;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
        }
        
        .keyboard-help-content {
          background: white;
          border-radius: 8px;
          padding: 24px;
          max-width: 500px;
          width: 100%;
          max-height: 80vh;
          overflow-y: auto;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .keyboard-help-title {
          font-size: 20px;
          font-weight: bold;
          margin-bottom: 16px;
          color: #333;
        }
        
        .keyboard-shortcut {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 0;
          border-bottom: 1px solid #eee;
        }
        
        .keyboard-shortcut:last-child {
          border-bottom: none;
        }
        
        .keyboard-key {
          background: #f5f5f5;
          border: 1px solid #ddd;
          border-radius: 4px;
          padding: 4px 8px;
          font-family: monospace;
          font-size: 12px;
          font-weight: bold;
          color: #333;
        }
        
        .keyboard-description {
          color: #666;
          font-size: 14px;
        }
        
        .close-help-button {
          margin-top: 16px;
          width: 100%;
          padding: 8px;
          background: #4A90E2;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 14px;
        }
        
        .close-help-button:hover {
          background: #357ABD;
        }
        
        .close-help-button:focus {
          outline: 3px solid #4A90E2;
          outline-offset: 2px;
        }
      `}</style>
      
      {/* 键盘快捷键帮助覆盖层 */}
      {showKeyboardHelp && (
        <div 
          className="keyboard-help-overlay"
          onClick={() => setShowKeyboardHelp(false)}
          role="dialog"
          aria-modal={true}
          aria-labelledby="keyboard-help-title"
        >
          <div 
            className="keyboard-help-content"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="keyboard-help-title" className="keyboard-help-title">
              键盘快捷键帮助
            </h2>
            
            <div role="list">
              {keyboardShortcuts.map((shortcut, index) => (
                <div key={`item-${index}`} className="keyboard-shortcut" role="listitem">
                  <span className="keyboard-key">{shortcut.key}</span>
                  <span className="keyboard-description">{shortcut.description}</span>
                </div>
              ))}
            </div>
            
            <button 
              className="close-help-button"
              onClick={() => setShowKeyboardHelp(false)}
              autoFocus
            >
              关闭帮助 (Esc)
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * 焦点指示器组件
 * 为当前聚焦元素提供视觉指示
 */
export const FocusIndicator: React.FC = () => {
  const [focusedElement, setFocusedElement] = useState<Element | null>(null);
  const [indicatorStyle, setIndicatorStyle] = useState<React.CSSProperties>({});

  useEffect(() => {
    const updateFocusIndicator = () => {
      const activeElement = document.activeElement;
      
      if (activeElement && activeElement !== document.body) {
        const rect = activeElement.getBoundingClientRect();
        setFocusedElement(activeElement);
        setIndicatorStyle({
          position: 'fixed',
          top: rect.top - 4,
          left: rect.left - 4,
          width: rect.width + 8,
          height: rect.height + 8,
          border: '3px solid #4A90E2',
          borderRadius: '4px',
          pointerEvents: 'none',
          zIndex: 9998,
          transition: 'all 0.2s ease',
          boxShadow: '0 0 0 1px rgba(74, 144, 226, 0.3)'
        });
      } else {
        setFocusedElement(null);
      }
    };

    const handleFocusIn = () => updateFocusIndicator();
    const handleFocusOut = () => setFocusedElement(null);
    const handleResize = () => updateFocusIndicator();
    const handleScroll = () => updateFocusIndicator();

    document.addEventListener('focusin', handleFocusIn);
    document.addEventListener('focusout', handleFocusOut);
    window.addEventListener('resize', handleResize);
    window.addEventListener('scroll', handleScroll, true);

    return () => {
      document.removeEventListener('focusin', handleFocusIn);
      document.removeEventListener('focusout', handleFocusOut);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('scroll', handleScroll, true);
    };
  }, []);

  if (!focusedElement) return null;

  return (
    <div 
      style={indicatorStyle}
      aria-hidden={true}
      className="focus-indicator"
    />
  );
};

/**
 * 键盘导航提示组件
 */
export const KeyboardHint: React.FC<{
  message: string;
  keys: string[];
  className?: string;
}> = ({ message: hintMessage, keys, className = '' }) => {
  return (
    <div className={`keyboard-hint ${className}`}>
      <span className="hint-message">{hintMessage}</span>
      <div className="hint-keys">
        {keys.map((key, index) => (
          <kbd key={`item-${index}`} className="hint-key">
            {key}
          </kbd>
        ))}
      </div>
      
      <style>{`
        .keyboard-hint {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 12px;
          background: #f8f9fa;
          border: 1px solid #e9ecef;
          border-radius: 4px;
          font-size: 12px;
          color: #6c757d;
        }
        
        .hint-message {
          flex: 1;
        }
        
        .hint-keys {
          display: flex;
          gap: 4px;
        }
        
        .hint-key {
          background: #fff;
          border: 1px solid #ced4da;
          border-radius: 3px;
          padding: 2px 6px;
          font-family: monospace;
          font-size: 11px;
          font-weight: bold;
          color: #495057;
          box-shadow: 0 1px 0 rgba(0, 0, 0, 0.1);
        }
      `}</style>
    </div>
  );
};

export default KeyboardNavigation;