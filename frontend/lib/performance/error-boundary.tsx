/**
 * Error Boundary Higher-Order Component
 * Production-ready error handling with fallback UI and error reporting
 */

'use client';

import React, { Component, ReactNode, ErrorInfo } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

// ==================== TYPES ====================

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorId: string | null;
}

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: React.ComponentType<ErrorFallbackProps>;
  onError?: (error: Error, errorInfo: ErrorInfo, errorId: string) => void;
  isolate?: boolean; // Whether to isolate this boundary from parent boundaries
  resetOnPropsChange?: boolean;
  resetKeys?: Array<string | number>;
}

interface ErrorFallbackProps {
  error: Error | null;
  errorInfo: ErrorInfo | null;
  resetError: () => void;
  errorId: string | null;
}

// ==================== UTILITIES ====================

/**
 * Generate unique error ID for tracking
 */
function generateErrorId(): string {
  return `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Extract component stack from error info
 */
function getComponentStack(errorInfo: ErrorInfo): string {
  return errorInfo.componentStack || '';
}

/**
 * Sanitize error for reporting
 */
function sanitizeError(error: Error): Record<string, any> {
  return {
    name: error.name,
    message: error.message,
    stack: error.stack,
  };
}

/**
 * Report error to monitoring service
 */
async function reportError(
  error: Error,
  errorInfo: ErrorInfo,
  errorId: string,
  additionalContext?: Record<string, any>
): Promise<void> {
  try {
    const errorReport = {
      errorId,
      timestamp: new Date().toISOString(),
      error: sanitizeError(error),
      componentStack: getComponentStack(errorInfo),
      userAgent: navigator.userAgent,
      url: window.location.href,
      userId: null, // Would be populated from auth context
      sessionId: sessionStorage.getItem('session_id'),
      additionalContext,
    };

    // Send to monitoring service (e.g., Sentry, LogRocket, etc.)
    if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
      // Sentry error reporting would go here
      console.error('Error reported to Sentry:', errorReport);
    }

    // Also send to our own analytics
    if (process.env.NEXT_PUBLIC_API_URL) {
      await fetch(`${process.env.NEXT_PUBLIC_API_URL}/v1/errors`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(errorReport),
      }).catch(() => {
        // Ignore reporting failures
      });
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.group(`🚨 Error Boundary Caught Error [${errorId}]`);
      console.error('Error:', error);
      console.error('Error Info:', errorInfo);
      console.error('Component Stack:', getComponentStack(errorInfo));
      console.groupEnd();
    }
  } catch (reportingError) {
    console.error('Failed to report error:', reportingError);
  }
}

// ==================== DEFAULT ERROR FALLBACK ====================

const DefaultErrorFallback: React.FC<ErrorFallbackProps> = ({
  error,
  errorInfo,
  resetError,
  errorId,
}) => {
  const handleReload = () => {
    window.location.reload();
  };

  const handleGoHome = () => {
    window.location.href = '/';
  };

  const isDevelopment = process.env.NODE_ENV === 'development';

  return (
    <div className="min-h-[400px] flex items-center justify-center p-6">
      <Card className="max-w-md w-full p-6 text-center">
        <div className="flex items-center justify-center w-16 h-16 mx-auto mb-4 rounded-full bg-destructive/10">
          <AlertTriangle className="w-8 h-8 text-destructive" />
        </div>
        
        <h2 className="text-xl font-semibold mb-2 text-foreground">
          Something went wrong
        </h2>
        
        <p className="text-muted-foreground mb-6">
          We're sorry, but something unexpected happened. Our team has been notified.
        </p>

        {isDevelopment && error && (
          <details className="text-left mb-6 p-4 bg-muted rounded-lg">
            <summary className="cursor-pointer font-medium text-sm mb-2">
              Error Details (Development Only)
            </summary>
            <div className="text-xs space-y-2">
              <div>
                <strong>Error:</strong> {error.message}
              </div>
              <div>
                <strong>Error ID:</strong> {errorId}
              </div>
              {error.stack && (
                <div>
                  <strong>Stack:</strong>
                  <pre className="whitespace-pre-wrap text-xs mt-1 p-2 bg-background rounded">
                    {error.stack}
                  </pre>
                </div>
              )}
            </div>
          </details>
        )}

        <div className="flex flex-col sm:flex-row gap-3">
          <Button
            onClick={resetError}
            variant="outline"
            className="flex items-center justify-center"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Try Again
          </Button>
          
          <Button
            onClick={handleGoHome}
            variant="outline"
            className="flex items-center justify-center"
          >
            <Home className="w-4 h-4 mr-2" />
            Go Home
          </Button>
          
          <Button
            onClick={handleReload}
            className="flex items-center justify-center"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Reload Page
          </Button>
        </div>

        {errorId && (
          <p className="text-xs text-muted-foreground mt-4">
            Error ID: {errorId}
          </p>
        )}
      </Card>
    </div>
  );
};

// ==================== ERROR BOUNDARY CLASS ====================

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private resetTimeoutId: NodeJS.Timeout | null = null;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
      errorId: generateErrorId(),
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const errorId = this.state.errorId || generateErrorId();
    
    this.setState({
      error,
      errorInfo,
      errorId,
    });

    // Report error
    this.props.onError?.(error, errorInfo, errorId);
    
    // Report to monitoring service
    reportError(error, errorInfo, errorId, {
      isolate: this.props.isolate,
      resetKeys: this.props.resetKeys,
    });
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    const { resetOnPropsChange, resetKeys } = this.props;
    const { hasError } = this.state;

    if (hasError && resetOnPropsChange) {
      if (resetKeys) {
        const hasResetKeyChanged = resetKeys.some((resetKey, index) =>
          prevProps.resetKeys?.[index] !== resetKey
        );
        
        if (hasResetKeyChanged) {
          this.resetError();
        }
      }
    }
  }

  componentWillUnmount() {
    if (this.resetTimeoutId) {
      clearTimeout(this.resetTimeoutId);
    }
  }

  resetError = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null,
    });
  };

  render() {
    if (this.state.hasError) {
      const FallbackComponent = this.props.fallback || DefaultErrorFallback;
      
      return (
        <FallbackComponent
          error={this.state.error}
          errorInfo={this.state.errorInfo}
          resetError={this.resetError}
          errorId={this.state.errorId}
        />
      );
    }

    return this.props.children;
  }
}

// ==================== HOC WRAPPER ====================

/**
 * Higher-order component for wrapping components with error boundaries
 */
export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  errorBoundaryProps?: Omit<ErrorBoundaryProps, 'children'>
): React.ComponentType<P> {
  const WrappedComponent = (props: P) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <Component {...props} />
    </ErrorBoundary>
  );

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`;

  return WrappedComponent;
}

// ==================== HOOK FOR ERROR REPORTING ====================

/**
 * Hook for manually reporting errors
 */
export function useErrorHandler() {
  const reportError = React.useCallback((error: Error, additionalContext?: Record<string, any>) => {
    const errorId = generateErrorId();
    const errorInfo: ErrorInfo = {
      componentStack: '',
    };

    // Report to monitoring service
    reportError(error, errorInfo, errorId, additionalContext);
  }, []);

  return reportError;
}

// ==================== ASYNC ERROR BOUNDARY ====================

/**
 * Error boundary specifically for async operations
 */
export const AsyncErrorBoundary: React.FC<{
  children: ReactNode;
  onError?: (error: Error) => void;
  fallback?: React.ComponentType<{ error: Error; retry: () => void }>;
}> = ({ children, onError, fallback: Fallback }) => {
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      const error = event.reason instanceof Error ? event.reason : new Error(String(event.reason));
      setError(error);
      onError?.(error);
      
      // Prevent the error from appearing in console
      event.preventDefault();
    };

    window.addEventListener('unhandledrejection', handleUnhandledRejection);
    
    return () => {
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, [onError]);

  const retry = React.useCallback(() => {
    setError(null);
  }, []);

  if (error && Fallback) {
    return <Fallback error={error} retry={retry} />;
  }

  if (error) {
    return (
      <div className="p-4 border border-destructive rounded-lg bg-destructive/5">
        <h3 className="font-medium text-destructive mb-2">Async Error</h3>
        <p className="text-sm text-muted-foreground mb-3">{error.message}</p>
        <Button onClick={retry} size="sm" variant="outline">
          Try Again
        </Button>
      </div>
    );
  }

  return <>{children}</>;
};

// ==================== EXPORTS ====================

export default ErrorBoundary;
export type { ErrorBoundaryProps, ErrorFallbackProps };