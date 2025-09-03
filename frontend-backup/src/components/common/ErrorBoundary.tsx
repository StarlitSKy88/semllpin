import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home, Bug, Copy } from 'lucide-react';
import { toast } from 'sonner';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorId: string;
  retryCount: number;
  showDetails: boolean;
  isReporting: boolean;
}

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  showDetails?: boolean;
  level?: 'page' | 'component' | 'critical';
  enableRetry?: boolean;
  maxRetries?: number;
  enableErrorReporting?: boolean;
}

/**
 * 错误边界组件
 * 捕获并处理 React 组件树中的 JavaScript 错误
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private retryTimeoutId: number | null = null;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: '',
      retryCount: 0,
      showDetails: false,
      isReporting: false
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    // 生成错误ID用于追踪
    const errorId = `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // 清理可能导致无限循环的localStorage数据
    try {
      const keys = Object.keys(localStorage);
      keys.forEach(key => {
        if (key.includes('temp_') || key.includes('cache_')) {
          localStorage.removeItem(key);
        }
      });
    } catch (e) {
      console.warn('清理localStorage失败:', e);
    }
    
    return {
      hasError: true,
      error,
      errorId
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo, isReporting: true });
    
    // 调用错误回调
    if (this.props.onError) {
      this.props.onError(error, errorInfo);
    }
    
    // 记录错误到控制台
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    // 发送错误报告
    if (this.props.enableErrorReporting !== false) {
      this.reportError(error, errorInfo);
    } else {
      this.setState({ isReporting: false });
    }
    
    // 保存错误日志到本地存储
    this.saveErrorToLocalStorage(error, errorInfo);
  }

  componentWillUnmount() {
    if (this.retryTimeoutId) {
      clearTimeout(this.retryTimeoutId);
    }
  }

  private reportError = async (error: Error, errorInfo: ErrorInfo) => {
    try {
      const errorReport = {
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href,
        errorId: this.state.errorId,
        level: this.props.level || 'component',
        retryCount: this.state.retryCount
      };
      
      // 发送到后端API
      const response = await fetch('/api/errors/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(errorReport)
      });
      
      if (response.ok) {
        console.log('错误报告已发送:', errorReport);
        toast.success('错误报告已发送');
      } else {
        throw new Error('发送失败');
      }
    } catch (e) {
      console.warn('发送错误报告失败:', e);
      toast.error('错误报告发送失败');
    } finally {
      this.setState({ isReporting: false });
    }
  };
  
  private saveErrorToLocalStorage = (error: Error, errorInfo: ErrorInfo) => {
    try {
      const errorLog = {
        errorId: this.state.errorId,
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        level: this.props.level || 'component'
      };
      
      const existingLogs = JSON.parse(localStorage.getItem('errorLogs') || '[]');
      existingLogs.push(errorLog);
      
      // 只保留最近50个错误日志
      if (existingLogs.length > 50) {
        existingLogs.splice(0, existingLogs.length - 50);
      }
      
      localStorage.setItem('errorLogs', JSON.stringify(existingLogs));
    } catch (e) {
      console.warn('保存错误日志失败:', e);
    }
  };

  private toggleDetails = () => {
    this.setState(prevState => ({
      showDetails: !prevState.showDetails
    }));
  };
  
  private handleRetry = () => {
    const { maxRetries = 3 } = this.props;
    
    if (this.state.retryCount >= maxRetries) {
      toast.error(`已达到最大重试次数 (${maxRetries})`);
      return;
    }
    
    this.setState(prevState => ({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: '',
      retryCount: prevState.retryCount + 1,
      showDetails: false,
      isReporting: false
    }));
    
    toast.success('正在重试...');
  };

  private handleReload = () => {
    window.location.reload();
  };

  private handleGoHome = () => {
    window.location.href = '/';
  };

  private copyErrorDetails = () => {
    const { error, errorInfo, errorId } = this.state;
    const errorDetails = `
错误ID: ${errorId}
时间: ${new Date().toLocaleString()}
错误信息: ${error?.message}
页面URL: ${window.location.href}
用户代理: ${navigator.userAgent}
错误堆栈:
${error?.stack}
组件堆栈:
${errorInfo?.componentStack}
    `;
    
    navigator.clipboard.writeText(errorDetails).then(() => {
      toast.success('错误详情已复制到剪贴板');
    }).catch(() => {
      toast.error('复制失败');
    });
  };

  render() {
    const { hasError, error, errorInfo, errorId, showDetails, isReporting } = this.state;
    const { fallback, level = 'component', enableRetry = true } = this.props;

    if (hasError) {
      // 如果提供了自定义fallback，使用它
      if (fallback) {
        return fallback;
      }

      return (
        <div className={`flex items-center justify-center min-h-[200px] p-6 bg-gray-50 border border-gray-200 rounded-lg m-4 ${
          level === 'page' ? 'min-h-[50vh]' : ''
        } ${
          level === 'critical' ? 'bg-red-50 border-red-200' : ''
        }`}>
          <div className="text-center max-w-2xl w-full">
            <div className="mb-6">
              <AlertTriangle 
                className={`w-16 h-16 mx-auto mb-4 ${
                  level === 'critical' ? 'text-red-500' : 'text-orange-500'
                }`} 
              />
              <h2 className={`font-bold mb-3 ${
                level === 'page' ? 'text-2xl' : 'text-xl'
              } text-gray-800`}>
                {level === 'critical' ? '严重错误' : '出现了一些问题'}
              </h2>
              <p className="text-gray-600 mb-2">
                {level === 'critical' 
                  ? '应用遇到了严重错误，请刷新页面或联系技术支持。'
                  : '很抱歉，这个组件出现了错误。您可以尝试重新加载或返回首页。'
                }
              </p>
              <p className="text-sm text-gray-500 font-mono bg-gray-100 px-3 py-1 rounded inline-block">
                错误ID: {errorId}
              </p>
            </div>

            <div className="flex flex-wrap gap-3 justify-center mb-6">
              {enableRetry && (
                <button
                  onClick={this.handleRetry}
                  className="flex items-center gap-2 px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  重试
                </button>
              )}
              
              <button
                onClick={this.handleReload}
                className="flex items-center gap-2 px-4 py-2 bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                重新加载
              </button>
              
              <button
                onClick={this.handleGoHome}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
              >
                <Home className="w-4 h-4" />
                返回首页
              </button>
              
              <button
                onClick={this.copyErrorDetails}
                className="flex items-center gap-2 px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors"
              >
                <Copy className="w-4 h-4" />
                复制错误信息
              </button>
            </div>

            <div className="text-left">
              <button 
                onClick={this.toggleDetails}
                className="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-800 transition-colors mb-3"
              >
                <Bug className="w-4 h-4" />
                {showDetails ? '隐藏' : '查看'}错误详情
              </button>
              
              {showDetails && (
                <div className="p-4 bg-gray-100 rounded-lg border text-left">
                  <div className="space-y-3 text-xs font-mono">
                    <div>
                      <strong className="text-gray-700">错误ID:</strong>
                      <pre className="mt-1 p-2 bg-white rounded border">{errorId}</pre>
                    </div>
                    
                    <div>
                      <strong className="text-gray-700">错误信息:</strong>
                      <pre className="mt-1 p-2 bg-white rounded border whitespace-pre-wrap">{error?.message}</pre>
                    </div>
                    
                    {error?.stack && (
                      <div>
                        <strong className="text-gray-700">错误堆栈:</strong>
                        <pre className="mt-1 p-2 bg-red-50 rounded border whitespace-pre-wrap text-red-700 max-h-40 overflow-y-auto">{error.stack}</pre>
                      </div>
                    )}
                    
                    {errorInfo?.componentStack && (
                      <div>
                        <strong className="text-gray-700">组件堆栈:</strong>
                        <pre className="mt-1 p-2 bg-blue-50 rounded border whitespace-pre-wrap text-blue-700 max-h-40 overflow-y-auto">{errorInfo.componentStack}</pre>
                      </div>
                    )}
                    
                    <div>
                      <strong className="text-gray-700">时间戳:</strong>
                      <pre className="mt-1 p-2 bg-white rounded border">{new Date().toISOString()}</pre>
                    </div>
                    
                    <div>
                      <strong className="text-gray-700">页面URL:</strong>
                      <pre className="mt-1 p-2 bg-white rounded border">{window.location.href}</pre>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {isReporting && (
              <div className="mt-4 text-sm text-gray-500">
                正在发送错误报告...
              </div>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

/**
 * 异步错误边界组件
 * 用于捕获异步操作中的错误
 */
export class AsyncErrorBoundary extends Component<
  ErrorBoundaryProps & { onAsyncError?: (error: Error) => void },
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps & { onAsyncError?: (error: Error) => void }) {
    super(props);
    
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: '',
      retryCount: 0,
      showDetails: false,
      isReporting: false
    };
    
    // 监听未捕获的Promise错误
    window.addEventListener('unhandledrejection', this.handleUnhandledRejection);
  }

  componentWillUnmount() {
    window.removeEventListener('unhandledrejection', this.handleUnhandledRejection);
  }

  private handleUnhandledRejection = (event: PromiseRejectionEvent) => {
    const error = event.reason instanceof Error ? event.reason : new Error(String(event.reason));
    
    if (this.props.onAsyncError) {
      this.props.onAsyncError(error);
    }
    
    this.setState({
      hasError: true,
      error,
      errorId: `async_error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    });
    
    // 阻止默认的控制台错误输出
    event.preventDefault();
  };

  render() {
    return (
      <ErrorBoundary {...this.props}>
        {this.props.children}
      </ErrorBoundary>
    );
  }
}

export default ErrorBoundary;