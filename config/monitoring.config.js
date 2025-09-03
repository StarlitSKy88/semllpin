// 监控和日志系统配置
// 支持多种监控服务：Prometheus、Grafana、ELK Stack、Sentry等

const MONITORING_CONFIG = {
  // Prometheus配置
  prometheus: {
    enabled: process.env.PROMETHEUS_ENABLED === 'true',
    port: parseInt(process.env.PROMETHEUS_PORT) || 9090,
    endpoint: '/metrics',
    
    // 指标配置
    metrics: {
      // HTTP请求指标
      httpRequests: {
        name: 'http_requests_total',
        help: 'Total number of HTTP requests',
        labelNames: ['method', 'route', 'status_code']
      },
      
      // HTTP请求持续时间
      httpDuration: {
        name: 'http_request_duration_seconds',
        help: 'Duration of HTTP requests in seconds',
        labelNames: ['method', 'route', 'status_code'],
        buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
      },
      
      // 数据库连接池
      dbConnections: {
        name: 'db_connections_total',
        help: 'Total number of database connections',
        labelNames: ['state'] // active, idle, waiting
      },
      
      // 数据库查询持续时间
      dbQueryDuration: {
        name: 'db_query_duration_seconds',
        help: 'Duration of database queries in seconds',
        labelNames: ['operation', 'table'],
        buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5]
      },
      
      // Redis操作
      redisOperations: {
        name: 'redis_operations_total',
        help: 'Total number of Redis operations',
        labelNames: ['operation', 'status']
      },
      
      // 内存使用
      memoryUsage: {
        name: 'memory_usage_bytes',
        help: 'Memory usage in bytes',
        labelNames: ['type'] // rss, heapTotal, heapUsed, external
      },
      
      // CPU使用率
      cpuUsage: {
        name: 'cpu_usage_percent',
        help: 'CPU usage percentage',
        labelNames: ['core']
      },
      
      // 业务指标
      businessMetrics: {
        // 用户注册
        userRegistrations: {
          name: 'user_registrations_total',
          help: 'Total number of user registrations',
          labelNames: ['source']
        },
        
        // 标注创建
        annotationsCreated: {
          name: 'annotations_created_total',
          help: 'Total number of annotations created',
          labelNames: ['type', 'status']
        },
        
        // 奖励发放
        rewardsDistributed: {
          name: 'rewards_distributed_total',
          help: 'Total amount of rewards distributed',
          labelNames: ['type']
        },
        
        // 支付交易
        paymentTransactions: {
          name: 'payment_transactions_total',
          help: 'Total number of payment transactions',
          labelNames: ['method', 'status']
        }
      }
    },
    
    // 采集间隔
    scrapeInterval: '15s',
    
    // 数据保留期
    retention: '30d'
  },
  
  // Grafana配置
  grafana: {
    enabled: process.env.GRAFANA_ENABLED === 'true',
    url: process.env.GRAFANA_URL || 'http://localhost:3001',
    apiKey: process.env.GRAFANA_API_KEY,
    
    // 仪表板配置
    dashboards: {
      // 系统概览
      systemOverview: {
        title: 'SmellPin System Overview',
        panels: [
          'http_requests_rate',
          'response_time_percentiles',
          'error_rate',
          'active_users',
          'system_resources'
        ]
      },
      
      // 业务指标
      businessMetrics: {
        title: 'SmellPin Business Metrics',
        panels: [
          'user_registrations',
          'annotations_created',
          'rewards_distributed',
          'revenue_metrics',
          'user_engagement'
        ]
      },
      
      // 基础设施
      infrastructure: {
        title: 'Infrastructure Monitoring',
        panels: [
          'database_performance',
          'redis_metrics',
          'server_resources',
          'network_metrics'
        ]
      }
    },
    
    // 告警规则
    alertRules: {
      // 高错误率
      highErrorRate: {
        condition: 'rate(http_requests_total{status_code=~"5.."}[5m]) > 0.05',
        duration: '2m',
        severity: 'critical',
        message: 'High error rate detected: {{ $value }}%'
      },
      
      // 响应时间过长
      highResponseTime: {
        condition: 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2',
        duration: '3m',
        severity: 'warning',
        message: 'High response time: {{ $value }}s'
      },
      
      // 数据库连接池耗尽
      dbConnectionPoolExhausted: {
        condition: 'db_connections_total{state="waiting"} > 10',
        duration: '1m',
        severity: 'critical',
        message: 'Database connection pool exhausted'
      },
      
      // 内存使用过高
      highMemoryUsage: {
        condition: 'memory_usage_bytes{type="rss"} / (1024*1024*1024) > 2',
        duration: '5m',
        severity: 'warning',
        message: 'High memory usage: {{ $value }}GB'
      }
    }
  },
  
  // Sentry错误监控
  sentry: {
    enabled: process.env.SENTRY_ENABLED === 'true',
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    release: process.env.APP_VERSION || '1.0.0',
    
    // 采样率
    sampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
    
    // 性能监控
    tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
    
    // 集成配置
    integrations: {
      http: true,
      express: true,
      postgres: true,
      redis: true
    },
    
    // 过滤器
    beforeSend: (event) => {
      // 过滤敏感信息
      if (event.request && event.request.headers) {
        delete event.request.headers.authorization;
        delete event.request.headers.cookie;
      }
      return event;
    }
  },
  
  // 健康检查配置
  healthCheck: {
    enabled: true,
    endpoint: '/health',
    interval: 30000, // 30秒
    timeout: 5000, // 5秒
    
    // 检查项目
    checks: {
      database: {
        enabled: true,
        timeout: 3000,
        query: 'SELECT 1'
      },
      
      redis: {
        enabled: true,
        timeout: 2000,
        operation: 'ping'
      },
      
      externalServices: {
        enabled: true,
        timeout: 5000,
        services: [
          {
            name: 'payment_gateway',
            url: process.env.PAYMENT_GATEWAY_HEALTH_URL
          },
          {
            name: 'sms_service',
            url: process.env.SMS_SERVICE_HEALTH_URL
          }
        ]
      }
    }
  }
};

// 日志配置
const LOGGING_CONFIG = {
  // Winston日志配置
  winston: {
    level: process.env.LOG_LEVEL || 'info',
    format: 'json',
    
    // 传输器配置
    transports: {
      // 控制台输出
      console: {
        enabled: true,
        level: 'debug',
        format: 'simple',
        colorize: true
      },
      
      // 文件输出
      file: {
        enabled: process.env.NODE_ENV === 'production',
        level: 'info',
        filename: 'logs/app.log',
        maxsize: 10485760, // 10MB
        maxFiles: 5,
        tailable: true
      },
      
      // 错误文件
      errorFile: {
        enabled: true,
        level: 'error',
        filename: 'logs/error.log',
        maxsize: 10485760,
        maxFiles: 10
      },
      
      // HTTP日志
      httpFile: {
        enabled: process.env.NODE_ENV === 'production',
        level: 'info',
        filename: 'logs/http.log',
        maxsize: 52428800, // 50MB
        maxFiles: 7
      }
    },
    
    // 日志格式化
    formatters: {
      timestamp: () => new Date().toISOString(),
      errors: true,
      metadata: true
    }
  },
  
  // ELK Stack配置
  elk: {
    enabled: process.env.ELK_ENABLED === 'true',
    
    // Elasticsearch配置
    elasticsearch: {
      host: process.env.ELASTICSEARCH_HOST || 'localhost:9200',
      index: 'smellpin-logs',
      type: '_doc',
      
      // 认证
      auth: {
        username: process.env.ELASTICSEARCH_USERNAME,
        password: process.env.ELASTICSEARCH_PASSWORD
      },
      
      // SSL配置
      ssl: {
        enabled: process.env.ELASTICSEARCH_SSL === 'true',
        rejectUnauthorized: false
      }
    },
    
    // Logstash配置
    logstash: {
      host: process.env.LOGSTASH_HOST || 'localhost',
      port: parseInt(process.env.LOGSTASH_PORT) || 5000,
      protocol: 'tcp'
    },
    
    // Kibana配置
    kibana: {
      url: process.env.KIBANA_URL || 'http://localhost:5601',
      
      // 仪表板
      dashboards: {
        application: 'SmellPin Application Logs',
        errors: 'SmellPin Error Analysis',
        performance: 'SmellPin Performance Metrics',
        security: 'SmellPin Security Events'
      }
    }
  },
  
  // 日志分类
  categories: {
    // 应用日志
    application: {
      level: 'info',
      fields: ['timestamp', 'level', 'message', 'service', 'version']
    },
    
    // HTTP访问日志
    http: {
      level: 'info',
      fields: ['timestamp', 'method', 'url', 'status', 'responseTime', 'userAgent', 'ip']
    },
    
    // 数据库日志
    database: {
      level: 'debug',
      fields: ['timestamp', 'query', 'duration', 'rows', 'error']
    },
    
    // 安全日志
    security: {
      level: 'warn',
      fields: ['timestamp', 'event', 'userId', 'ip', 'userAgent', 'details']
    },
    
    // 业务日志
    business: {
      level: 'info',
      fields: ['timestamp', 'event', 'userId', 'data', 'result']
    },
    
    // 错误日志
    error: {
      level: 'error',
      fields: ['timestamp', 'error', 'stack', 'context', 'userId', 'requestId']
    }
  },
  
  // 日志轮转
  rotation: {
    enabled: true,
    frequency: 'daily',
    maxFiles: 30,
    maxSize: '100m',
    compress: true
  },
  
  // 敏感信息过滤
  sanitization: {
    enabled: true,
    fields: ['password', 'token', 'apiKey', 'secret', 'authorization'],
    replacement: '[REDACTED]'
  }
};

// 告警配置
const ALERTING_CONFIG = {
  // 告警渠道
  channels: {
    // 邮件告警
    email: {
      enabled: process.env.EMAIL_ALERTS_ENABLED === 'true',
      smtp: {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      },
      recipients: {
        critical: process.env.ALERT_EMAIL_CRITICAL?.split(',') || [],
        warning: process.env.ALERT_EMAIL_WARNING?.split(',') || [],
        info: process.env.ALERT_EMAIL_INFO?.split(',') || []
      }
    },
    
    // Slack告警
    slack: {
      enabled: process.env.SLACK_ALERTS_ENABLED === 'true',
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      channels: {
        critical: '#alerts-critical',
        warning: '#alerts-warning',
        info: '#alerts-info'
      }
    },
    
    // 短信告警
    sms: {
      enabled: process.env.SMS_ALERTS_ENABLED === 'true',
      provider: process.env.SMS_PROVIDER || 'aliyun',
      config: {
        accessKeyId: process.env.SMS_ACCESS_KEY_ID,
        accessKeySecret: process.env.SMS_ACCESS_KEY_SECRET,
        signName: process.env.SMS_SIGN_NAME,
        templateCode: process.env.SMS_TEMPLATE_CODE
      },
      recipients: {
        critical: process.env.ALERT_SMS_CRITICAL?.split(',') || []
      }
    },
    
    // 钉钉告警
    dingtalk: {
      enabled: process.env.DINGTALK_ALERTS_ENABLED === 'true',
      webhookUrl: process.env.DINGTALK_WEBHOOK_URL,
      secret: process.env.DINGTALK_SECRET
    }
  },
  
  // 告警规则
  rules: {
    // 系统级告警
    system: {
      // 服务不可用
      serviceDown: {
        severity: 'critical',
        condition: 'service_up == 0',
        duration: '1m',
        message: 'Service {{ $labels.service }} is down'
      },
      
      // 高CPU使用率
      highCpuUsage: {
        severity: 'warning',
        condition: 'cpu_usage_percent > 80',
        duration: '5m',
        message: 'High CPU usage: {{ $value }}%'
      },
      
      // 高内存使用率
      highMemoryUsage: {
        severity: 'warning',
        condition: 'memory_usage_percent > 85',
        duration: '5m',
        message: 'High memory usage: {{ $value }}%'
      },
      
      // 磁盘空间不足
      lowDiskSpace: {
        severity: 'critical',
        condition: 'disk_usage_percent > 90',
        duration: '2m',
        message: 'Low disk space: {{ $value }}% used'
      }
    },
    
    // 应用级告警
    application: {
      // 高错误率
      highErrorRate: {
        severity: 'critical',
        condition: 'error_rate > 5',
        duration: '2m',
        message: 'High error rate: {{ $value }}%'
      },
      
      // 响应时间过长
      slowResponse: {
        severity: 'warning',
        condition: 'response_time_p95 > 2000',
        duration: '3m',
        message: 'Slow response time: {{ $value }}ms'
      },
      
      // 数据库连接失败
      dbConnectionFailure: {
        severity: 'critical',
        condition: 'db_connection_errors > 0',
        duration: '1m',
        message: 'Database connection failures detected'
      }
    },
    
    // 业务级告警
    business: {
      // 支付失败率过高
      highPaymentFailureRate: {
        severity: 'critical',
        condition: 'payment_failure_rate > 10',
        duration: '5m',
        message: 'High payment failure rate: {{ $value }}%'
      },
      
      // 用户注册异常
      abnormalRegistrations: {
        severity: 'warning',
        condition: 'registration_rate > 100',
        duration: '10m',
        message: 'Abnormal registration rate: {{ $value }}/min'
      }
    }
  },
  
  // 告警抑制
  suppression: {
    enabled: true,
    rules: [
      {
        // 维护期间抑制所有告警
        name: 'maintenance_window',
        condition: 'maintenance_mode == 1',
        duration: '24h'
      },
      {
        // 相同告警5分钟内只发送一次
        name: 'duplicate_suppression',
        groupBy: ['alertname', 'instance'],
        duration: '5m'
      }
    ]
  }
};

// 导出配置
module.exports = {
  MONITORING_CONFIG,
  LOGGING_CONFIG,
  ALERTING_CONFIG
};

// 环境特定配置
if (process.env.NODE_ENV === 'production') {
  // 生产环境优化
  LOGGING_CONFIG.winston.level = 'warn';
  MONITORING_CONFIG.prometheus.scrapeInterval = '30s';
} else if (process.env.NODE_ENV === 'development') {
  // 开发环境优化
  LOGGING_CONFIG.winston.level = 'debug';
  MONITORING_CONFIG.prometheus.scrapeInterval = '5s';
}