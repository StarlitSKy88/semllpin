/**
 * SmellPin多代理用户行为模拟器
 * 支持并行测试和真实用户行为模拟
 */
import { faker } from '@faker-js/faker';
import axios, { AxiosInstance } from 'axios';
import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface AgentConfig {
  id: string;
  name: string;
  behavior: 'explorer' | 'annotator' | 'social' | 'merchant' | 'validator';
  intensity: 'low' | 'medium' | 'high';
  duration: number; // 测试持续时间(分钟)
  baseUrl: string;
}

export interface TestScenario {
  name: string;
  description: string;
  agents: AgentConfig[];
  concurrency: number;
  expectedOutcomes: string[];
}

export interface AgentMetrics {
  agentId: string;
  startTime: number;
  endTime?: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  errors: string[];
  actions: AgentAction[];
}

export interface AgentAction {
  timestamp: number;
  action: string;
  endpoint: string;
  duration: number;
  success: boolean;
  error?: string;
  responseData?: any;
}

class UserAgent extends EventEmitter {
  private config: AgentConfig;
  private httpClient: AxiosInstance;
  private metrics: AgentMetrics;
  private isRunning: boolean = false;
  private authToken?: string;
  private userProfile?: any;

  constructor(config: AgentConfig) {
    super();
    this.config = config;
    this.httpClient = axios.create({
      baseURL: config.baseUrl,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `SmellPin-Agent-${config.id}/${faker.system.semver()}`
      }
    });
    
    this.metrics = {
      agentId: config.id,
      startTime: Date.now(),
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      errors: [],
      actions: []
    };

    this.setupInterceptors();
  }

  private setupInterceptors() {
    this.httpClient.interceptors.request.use((config) => {
      if (this.authToken) {
        config.headers.Authorization = `Bearer ${this.authToken}`;
      }
      return config;
    });

    this.httpClient.interceptors.response.use(
      (response) => {
        this.metrics.successfulRequests++;
        return response;
      },
      (error) => {
        this.metrics.failedRequests++;
        this.metrics.errors.push(error.message);
        return Promise.reject(error);
      }
    );
  }

  async start(): Promise<void> {
    this.isRunning = true;
    this.metrics.startTime = Date.now();
    this.emit('started', { agentId: this.config.id, timestamp: Date.now() });

    try {
      // 初始化用户
      await this.initializeUser();
      
      // 根据代理类型执行不同的行为模式
      await this.executeBehaviorPattern();
      
    } catch (error) {
      this.emit('error', { agentId: this.config.id, error: error.message });
      this.metrics.errors.push(error.message);
    } finally {
      this.stop();
    }
  }

  private async initializeUser(): Promise<void> {
    const action = this.createAction('user_initialization', '/api/auth/register');
    
    try {
      // 创建随机用户
      this.userProfile = {
        username: faker.internet.userName(),
        email: faker.internet.email(),
        password: faker.internet.password(),
        nickname: faker.person.fullName(),
        location: {
          lat: faker.location.latitude({ min: 39.8, max: 40.2 }),
          lng: faker.location.longitude({ min: 116.2, max: 116.6 })
        }
      };

      const response = await this.httpClient.post('/api/auth/register', this.userProfile);
      this.authToken = response.data.token;
      
      action.success = true;
      action.responseData = { userId: response.data.user?.id };
      
      this.emit('userCreated', { 
        agentId: this.config.id, 
        userId: response.data.user?.id,
        profile: this.userProfile 
      });
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
      throw error;
    } finally {
      this.recordAction(action);
    }
  }

  private async executeBehaviorPattern(): Promise<void> {
    const duration = this.config.duration * 60 * 1000; // 转换为毫秒
    const endTime = Date.now() + duration;
    const intensityMultiplier = this.getIntensityMultiplier();
    
    while (this.isRunning && Date.now() < endTime) {
      try {
        switch (this.config.behavior) {
          case 'explorer':
            await this.explorerBehavior();
            break;
          case 'annotator':
            await this.annotatorBehavior();
            break;
          case 'social':
            await this.socialBehavior();
            break;
          case 'merchant':
            await this.merchantBehavior();
            break;
          case 'validator':
            await this.validatorBehavior();
            break;
        }
        
        // 根据强度调整等待时间
        const waitTime = faker.number.int({ min: 1000 / intensityMultiplier, max: 5000 / intensityMultiplier });
        await this.sleep(waitTime);
        
      } catch (error) {
        this.emit('behaviorError', { 
          agentId: this.config.id, 
          behavior: this.config.behavior, 
          error: error.message 
        });
        await this.sleep(2000); // 错误后等待较长时间
      }
    }
  }

  private async explorerBehavior(): Promise<void> {
    const actions = [
      () => this.searchNearbyAnnotations(),
      () => this.viewAnnotationDetails(),
      () => this.checkRewards(),
      () => this.updateLocation(),
      () => this.browseMap()
    ];
    
    const randomAction = faker.helpers.arrayElement(actions);
    await randomAction();
  }

  private async annotatorBehavior(): Promise<void> {
    const actions = [
      () => this.createAnnotation(),
      () => this.uploadMedia(),
      () => this.updateAnnotation(),
      () => this.searchNearbyAnnotations(),
      () => this.managePayments()
    ];
    
    const randomAction = faker.helpers.arrayElement(actions);
    await randomAction();
  }

  private async socialBehavior(): Promise<void> {
    const actions = [
      () => this.likeAnnotation(),
      () => this.shareAnnotation(),
      () => this.followUser(),
      () => this.commentOnAnnotation(),
      () => this.viewUserProfile()
    ];
    
    const randomAction = faker.helpers.arrayElement(actions);
    await randomAction();
  }

  private async merchantBehavior(): Promise<void> {
    const actions = [
      () => this.processPayment(),
      () => this.checkBalance(),
      () => this.withdrawEarnings(),
      () => this.viewTransactionHistory(),
      () => this.createPaidAnnotation()
    ];
    
    const randomAction = faker.helpers.arrayElement(actions);
    await randomAction();
  }

  private async validatorBehavior(): Promise<void> {
    const actions = [
      () => this.validateAnnotation(),
      () => this.reportSpam(),
      () => this.moderateContent(),
      () => this.reviewUserBehavior(),
      () => this.checkSystemHealth()
    ];
    
    const randomAction = faker.helpers.arrayElement(actions);
    await randomAction();
  }

  // 具体行为实现
  private async searchNearbyAnnotations(): Promise<void> {
    const action = this.createAction('search_nearby', '/api/annotations/nearby');
    
    try {
      const params = {
        lat: this.userProfile.location.lat + faker.number.float({ min: -0.01, max: 0.01 }),
        lng: this.userProfile.location.lng + faker.number.float({ min: -0.01, max: 0.01 }),
        radius: faker.number.int({ min: 500, max: 5000 })
      };
      
      const response = await this.httpClient.get('/api/annotations/nearby', { params });
      action.success = true;
      action.responseData = { count: response.data.annotations?.length || 0 };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async createAnnotation(): Promise<void> {
    const action = this.createAction('create_annotation', '/api/annotations');
    
    try {
      const annotationData = {
        title: faker.lorem.sentence({ min: 3, max: 8 }),
        description: faker.lorem.paragraphs(2),
        location: {
          lat: this.userProfile.location.lat + faker.number.float({ min: -0.005, max: 0.005 }),
          lng: this.userProfile.location.lng + faker.number.float({ min: -0.005, max: 0.005 })
        },
        category: faker.helpers.arrayElement(['industrial', 'sewage', 'garbage', 'chemical', 'food', 'other']),
        intensity: faker.number.int({ min: 1, max: 10 }),
        tags: faker.helpers.arrayElements(['臭味', '污染', '环境', '工业'], { min: 1, max: 3 })
      };
      
      const response = await this.httpClient.post('/api/annotations', annotationData);
      action.success = true;
      action.responseData = { annotationId: response.data.id };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async processPayment(): Promise<void> {
    const action = this.createAction('process_payment', '/api/payments/stripe');
    
    try {
      const paymentData = {
        amount: faker.number.int({ min: 100, max: 1000 }), // 分为单位
        currency: 'cny',
        description: '标注费用支付'
      };
      
      const response = await this.httpClient.post('/api/payments/stripe', paymentData);
      action.success = true;
      action.responseData = { paymentId: response.data.id };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async viewAnnotationDetails(): Promise<void> {
    const action = this.createAction('view_annotation', '/api/annotations/:id');
    
    try {
      // 模拟获取一个随机注释ID
      const randomId = faker.string.uuid();
      const response = await this.httpClient.get(`/api/annotations/${randomId}`);
      action.success = true;
      action.responseData = response.data;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async checkRewards(): Promise<void> {
    const action = this.createAction('check_rewards', '/api/rewards/my');
    
    try {
      const response = await this.httpClient.get('/api/rewards/my');
      action.success = true;
      action.responseData = { rewards: response.data.rewards || [] };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async updateLocation(): Promise<void> {
    const action = this.createAction('update_location', '/api/users/location');
    
    try {
      this.userProfile.location = {
        lat: this.userProfile.location.lat + faker.number.float({ min: -0.001, max: 0.001 }),
        lng: this.userProfile.location.lng + faker.number.float({ min: -0.001, max: 0.001 })
      };
      
      const response = await this.httpClient.put('/api/users/location', this.userProfile.location);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async browseMap(): Promise<void> {
    const action = this.createAction('browse_map', '/api/map/data');
    
    try {
      const bounds = {
        north: this.userProfile.location.lat + 0.02,
        south: this.userProfile.location.lat - 0.02,
        east: this.userProfile.location.lng + 0.02,
        west: this.userProfile.location.lng - 0.02
      };
      
      const response = await this.httpClient.get('/api/map/data', { params: bounds });
      action.success = true;
      action.responseData = { mapData: response.data };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async uploadMedia(): Promise<void> {
    const action = this.createAction('upload_media', '/api/media/upload');
    
    try {
      // 模拟图片上传
      const mockImageData = Buffer.from(faker.lorem.paragraphs(10));
      const formData = new FormData();
      
      const response = await this.httpClient.post('/api/media/upload', {
        filename: faker.system.fileName({ extensionCount: 1 }),
        mimeType: 'image/jpeg',
        size: mockImageData.length
      });
      
      action.success = true;
      action.responseData = { mediaId: response.data.id };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async likeAnnotation(): Promise<void> {
    const action = this.createAction('like_annotation', '/api/annotations/:id/like');
    
    try {
      const randomId = faker.string.uuid();
      const response = await this.httpClient.post(`/api/annotations/${randomId}/like`);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async shareAnnotation(): Promise<void> {
    const action = this.createAction('share_annotation', '/api/annotations/:id/share');
    
    try {
      const randomId = faker.string.uuid();
      const shareData = {
        platform: faker.helpers.arrayElement(['wechat', 'weibo', 'qq', 'email']),
        message: faker.lorem.sentence()
      };
      
      const response = await this.httpClient.post(`/api/annotations/${randomId}/share`, shareData);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async followUser(): Promise<void> {
    const action = this.createAction('follow_user', '/api/users/:id/follow');
    
    try {
      const randomUserId = faker.string.uuid();
      const response = await this.httpClient.post(`/api/users/${randomUserId}/follow`);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async commentOnAnnotation(): Promise<void> {
    const action = this.createAction('comment_annotation', '/api/annotations/:id/comments');
    
    try {
      const randomId = faker.string.uuid();
      const commentData = {
        content: faker.lorem.sentences({ min: 1, max: 3 }),
        rating: faker.number.int({ min: 1, max: 5 })
      };
      
      const response = await this.httpClient.post(`/api/annotations/${randomId}/comments`, commentData);
      action.success = true;
      action.responseData = { commentId: response.data.id };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async viewUserProfile(): Promise<void> {
    const action = this.createAction('view_user_profile', '/api/users/:id');
    
    try {
      const randomUserId = faker.string.uuid();
      const response = await this.httpClient.get(`/api/users/${randomUserId}`);
      action.success = true;
      action.responseData = response.data;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async checkBalance(): Promise<void> {
    const action = this.createAction('check_balance', '/api/wallet/balance');
    
    try {
      const response = await this.httpClient.get('/api/wallet/balance');
      action.success = true;
      action.responseData = { balance: response.data.balance };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async withdrawEarnings(): Promise<void> {
    const action = this.createAction('withdraw_earnings', '/api/wallet/withdraw');
    
    try {
      const withdrawData = {
        amount: faker.number.int({ min: 100, max: 5000 }),
        method: faker.helpers.arrayElement(['alipay', 'wechat', 'bank_card'])
      };
      
      const response = await this.httpClient.post('/api/wallet/withdraw', withdrawData);
      action.success = true;
      action.responseData = { withdrawId: response.data.id };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async viewTransactionHistory(): Promise<void> {
    const action = this.createAction('view_transactions', '/api/wallet/transactions');
    
    try {
      const params = {
        page: faker.number.int({ min: 1, max: 5 }),
        limit: faker.number.int({ min: 10, max: 50 })
      };
      
      const response = await this.httpClient.get('/api/wallet/transactions', { params });
      action.success = true;
      action.responseData = { transactions: response.data.transactions || [] };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async createPaidAnnotation(): Promise<void> {
    const action = this.createAction('create_paid_annotation', '/api/annotations/paid');
    
    try {
      const annotationData = {
        title: faker.lorem.sentence({ min: 3, max: 8 }),
        description: faker.lorem.paragraphs(3),
        location: {
          lat: this.userProfile.location.lat + faker.number.float({ min: -0.005, max: 0.005 }),
          lng: this.userProfile.location.lng + faker.number.float({ min: -0.005, max: 0.005 })
        },
        category: faker.helpers.arrayElement(['industrial', 'sewage', 'garbage', 'chemical']),
        intensity: faker.number.int({ min: 6, max: 10 }),
        tags: faker.helpers.arrayElements(['严重污染', '紧急处理', '环境危害'], { min: 1, max: 3 }),
        paymentAmount: faker.number.int({ min: 500, max: 2000 })
      };
      
      const response = await this.httpClient.post('/api/annotations/paid', annotationData);
      action.success = true;
      action.responseData = { annotationId: response.data.id, paymentId: response.data.paymentId };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async validateAnnotation(): Promise<void> {
    const action = this.createAction('validate_annotation', '/api/annotations/:id/validate');
    
    try {
      const randomId = faker.string.uuid();
      const validationData = {
        isValid: faker.datatype.boolean({ probability: 0.8 }),
        reason: faker.lorem.sentence(),
        confidence: faker.number.float({ min: 0.6, max: 1.0 })
      };
      
      const response = await this.httpClient.post(`/api/annotations/${randomId}/validate`, validationData);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async reportSpam(): Promise<void> {
    const action = this.createAction('report_spam', '/api/reports/spam');
    
    try {
      const reportData = {
        targetId: faker.string.uuid(),
        targetType: faker.helpers.arrayElement(['annotation', 'comment', 'user']),
        reason: faker.helpers.arrayElement(['spam', 'fake', 'inappropriate', 'offensive']),
        description: faker.lorem.sentences(2)
      };
      
      const response = await this.httpClient.post('/api/reports/spam', reportData);
      action.success = true;
      action.responseData = { reportId: response.data.id };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async moderateContent(): Promise<void> {
    const action = this.createAction('moderate_content', '/api/moderation/review');
    
    try {
      const moderationData = {
        contentId: faker.string.uuid(),
        action: faker.helpers.arrayElement(['approve', 'reject', 'flag']),
        notes: faker.lorem.sentence()
      };
      
      const response = await this.httpClient.post('/api/moderation/review', moderationData);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async reviewUserBehavior(): Promise<void> {
    const action = this.createAction('review_user_behavior', '/api/users/:id/behavior');
    
    try {
      const randomUserId = faker.string.uuid();
      const response = await this.httpClient.get(`/api/users/${randomUserId}/behavior`);
      action.success = true;
      action.responseData = response.data;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async checkSystemHealth(): Promise<void> {
    const action = this.createAction('check_system_health', '/api/health');
    
    try {
      const response = await this.httpClient.get('/api/health');
      action.success = true;
      action.responseData = response.data;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async updateAnnotation(): Promise<void> {
    const action = this.createAction('update_annotation', '/api/annotations/:id');
    
    try {
      const randomId = faker.string.uuid();
      const updateData = {
        description: faker.lorem.paragraphs(2),
        intensity: faker.number.int({ min: 1, max: 10 }),
        tags: faker.helpers.arrayElements(['更新', '修正', '补充'], { min: 1, max: 2 })
      };
      
      const response = await this.httpClient.put(`/api/annotations/${randomId}`, updateData);
      action.success = true;
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private async managePayments(): Promise<void> {
    const action = this.createAction('manage_payments', '/api/payments/manage');
    
    try {
      const response = await this.httpClient.get('/api/payments/manage');
      action.success = true;
      action.responseData = { payments: response.data.payments || [] };
      
    } catch (error) {
      action.success = false;
      action.error = error.message;
    } finally {
      this.recordAction(action);
    }
  }

  private createAction(actionName: string, endpoint: string): AgentAction {
    return {
      timestamp: Date.now(),
      action: actionName,
      endpoint,
      duration: 0,
      success: false
    };
  }

  private recordAction(action: AgentAction): void {
    action.duration = Date.now() - action.timestamp;
    this.metrics.actions.push(action);
    this.metrics.totalRequests++;
    
    // 更新平均响应时间
    const totalDuration = this.metrics.actions.reduce((sum, a) => sum + a.duration, 0);
    this.metrics.averageResponseTime = totalDuration / this.metrics.actions.length;
    
    this.emit('actionCompleted', { 
      agentId: this.config.id, 
      action: action.action, 
      success: action.success,
      duration: action.duration
    });
  }

  private getIntensityMultiplier(): number {
    switch (this.config.intensity) {
      case 'low': return 1;
      case 'medium': return 2;
      case 'high': return 4;
      default: return 1;
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  stop(): void {
    this.isRunning = false;
    this.metrics.endTime = Date.now();
    this.emit('stopped', { agentId: this.config.id, metrics: this.metrics });
  }

  getMetrics(): AgentMetrics {
    return { ...this.metrics };
  }
}

export class MultiAgentSimulator extends EventEmitter {
  private agents: Map<string, UserAgent> = new Map();
  private scenarios: Map<string, TestScenario> = new Map();
  private isRunning: boolean = false;
  private startTime?: number;
  private endTime?: number;
  private reportDir: string;

  constructor(reportDir: string = './test-results') {
    super();
    this.reportDir = reportDir;
    this.setupDefaultScenarios();
  }

  private setupDefaultScenarios(): void {
    // 冒烟测试场景
    this.scenarios.set('smoke', {
      name: '冒烟测试',
      description: '基础功能验证，快速检测系统核心功能',
      concurrency: 5,
      expectedOutcomes: ['用户注册成功', '基础API响应正常', '数据库连接正常'],
      agents: [
        {
          id: 'smoke-explorer-1',
          name: '探索者1',
          behavior: 'explorer',
          intensity: 'low',
          duration: 2,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        },
        {
          id: 'smoke-annotator-1',
          name: '标注者1',
          behavior: 'annotator',
          intensity: 'low',
          duration: 2,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        },
        {
          id: 'smoke-social-1',
          name: '社交用户1',
          behavior: 'social',
          intensity: 'low',
          duration: 2,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        }
      ]
    });

    // 全面测试场景
    this.scenarios.set('full', {
      name: '全面测试',
      description: '完整的用户行为模拟，包含所有功能模块',
      concurrency: 15,
      expectedOutcomes: [
        '所有用户角色正常工作',
        '支付流程完整',
        '社交功能正常',
        '性能指标达标',
        '错误率低于5%'
      ],
      agents: [
        ...Array.from({ length: 3 }, (_, i) => ({
          id: `full-explorer-${i + 1}`,
          name: `探索者${i + 1}`,
          behavior: 'explorer' as const,
          intensity: faker.helpers.arrayElement(['low', 'medium', 'high'] as const),
          duration: 10,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        })),
        ...Array.from({ length: 4 }, (_, i) => ({
          id: `full-annotator-${i + 1}`,
          name: `标注者${i + 1}`,
          behavior: 'annotator' as const,
          intensity: faker.helpers.arrayElement(['medium', 'high'] as const),
          duration: 10,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        })),
        ...Array.from({ length: 3 }, (_, i) => ({
          id: `full-social-${i + 1}`,
          name: `社交用户${i + 1}`,
          behavior: 'social' as const,
          intensity: faker.helpers.arrayElement(['low', 'medium', 'high'] as const),
          duration: 10,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        })),
        ...Array.from({ length: 3 }, (_, i) => ({
          id: `full-merchant-${i + 1}`,
          name: `商户${i + 1}`,
          behavior: 'merchant' as const,
          intensity: faker.helpers.arrayElement(['medium', 'high'] as const),
          duration: 10,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        })),
        ...Array.from({ length: 2 }, (_, i) => ({
          id: `full-validator-${i + 1}`,
          name: `验证者${i + 1}`,
          behavior: 'validator' as const,
          intensity: 'medium' as const,
          duration: 10,
          baseUrl: process.env.API_BASE_URL || 'http://localhost:3000'
        }))
      ]
    });
  }

  async runScenario(scenarioName: string): Promise<void> {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Unknown scenario: ${scenarioName}`);
    }

    console.log(`🚀 开始执行测试场景: ${scenario.name}`);
    console.log(`📝 描述: ${scenario.description}`);
    console.log(`👥 代理数量: ${scenario.agents.length}`);
    console.log(`⚡ 并发数: ${scenario.concurrency}`);
    console.log(`⏱️  预计时长: ${Math.max(...scenario.agents.map(a => a.duration))} 分钟\n`);

    this.isRunning = true;
    this.startTime = Date.now();

    // 创建并启动代理
    const agentPromises: Promise<void>[] = [];
    
    for (let i = 0; i < scenario.agents.length; i += scenario.concurrency) {
      const batch = scenario.agents.slice(i, i + scenario.concurrency);
      
      for (const config of batch) {
        const agent = new UserAgent(config);
        this.agents.set(config.id, agent);
        
        // 监听代理事件
        this.setupAgentEventListeners(agent);
        
        agentPromises.push(agent.start());
      }
      
      // 批次间等待，避免同时启动过多代理
      if (i + scenario.concurrency < scenario.agents.length) {
        await this.sleep(2000);
      }
    }

    // 等待所有代理完成
    await Promise.allSettled(agentPromises);
    
    this.endTime = Date.now();
    this.isRunning = false;

    // 生成报告
    await this.generateReport(scenarioName);
    
    console.log(`\n✅ 测试场景完成: ${scenario.name}`);
    console.log(`⏱️  总耗时: ${((this.endTime - this.startTime!) / 1000 / 60).toFixed(2)} 分钟`);
  }

  private setupAgentEventListeners(agent: UserAgent): void {
    agent.on('started', (data) => {
      console.log(`👤 代理启动: ${data.agentId}`);
    });

    agent.on('userCreated', (data) => {
      console.log(`✨ 用户创建成功: ${data.agentId} -> ${data.userId}`);
    });

    agent.on('actionCompleted', (data) => {
      const status = data.success ? '✅' : '❌';
      console.log(`${status} [${data.agentId}] ${data.action} (${data.duration}ms)`);
    });

    agent.on('error', (data) => {
      console.log(`💥 代理错误 [${data.agentId}]: ${data.error}`);
    });

    agent.on('behaviorError', (data) => {
      console.log(`⚠️  行为错误 [${data.agentId}] ${data.behavior}: ${data.error}`);
    });

    agent.on('stopped', (data) => {
      console.log(`🛑 代理停止: ${data.agentId}`);
    });
  }

  private async generateReport(scenarioName: string): Promise<void> {
    const scenario = this.scenarios.get(scenarioName)!;
    const allMetrics = Array.from(this.agents.values()).map(agent => agent.getMetrics());
    
    const report = {
      scenario: scenario.name,
      description: scenario.description,
      startTime: this.startTime!,
      endTime: this.endTime!,
      duration: this.endTime! - this.startTime!,
      totalAgents: allMetrics.length,
      summary: this.calculateSummary(allMetrics),
      agents: allMetrics,
      expectedOutcomes: scenario.expectedOutcomes,
      actualOutcomes: this.evaluateOutcomes(allMetrics, scenario.expectedOutcomes)
    };

    // 确保报告目录存在
    await fs.mkdir(this.reportDir, { recursive: true });
    
    // 生成JSON报告
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const jsonPath = path.join(this.reportDir, `${scenarioName}-test-report-${timestamp}.json`);
    await fs.writeFile(jsonPath, JSON.stringify(report, null, 2));
    
    // 生成HTML报告
    const htmlPath = path.join(this.reportDir, `${scenarioName}-test-report-${timestamp}.html`);
    await this.generateHtmlReport(report, htmlPath);
    
    console.log(`\n📊 测试报告已生成:`);
    console.log(`   JSON: ${jsonPath}`);
    console.log(`   HTML: ${htmlPath}`);
    
    // 输出简要统计
    this.printSummary(report.summary);
  }

  private calculateSummary(metrics: AgentMetrics[]): any {
    const totalRequests = metrics.reduce((sum, m) => sum + m.totalRequests, 0);
    const totalSuccessful = metrics.reduce((sum, m) => sum + m.successfulRequests, 0);
    const totalFailed = metrics.reduce((sum, m) => sum + m.failedRequests, 0);
    const avgResponseTime = metrics.reduce((sum, m) => sum + m.averageResponseTime, 0) / metrics.length;
    
    return {
      totalRequests,
      successfulRequests: totalSuccessful,
      failedRequests: totalFailed,
      successRate: totalRequests > 0 ? (totalSuccessful / totalRequests * 100).toFixed(2) : '0.00',
      errorRate: totalRequests > 0 ? (totalFailed / totalRequests * 100).toFixed(2) : '0.00',
      averageResponseTime: avgResponseTime.toFixed(2),
      totalErrors: metrics.reduce((sum, m) => sum + m.errors.length, 0),
      agentsByBehavior: this.groupMetricsByBehavior(metrics)
    };
  }

  private groupMetricsByBehavior(metrics: AgentMetrics[]): any {
    const groups: { [key: string]: any } = {};
    
    for (const metric of metrics) {
      // 从agentId中提取behavior（假设格式为 "prefix-behavior-number"）
      const parts = metric.agentId.split('-');
      const behavior = parts[1] || 'unknown';
      
      if (!groups[behavior]) {
        groups[behavior] = {
          count: 0,
          totalRequests: 0,
          successfulRequests: 0,
          failedRequests: 0,
          averageResponseTime: 0
        };
      }
      
      groups[behavior].count++;
      groups[behavior].totalRequests += metric.totalRequests;
      groups[behavior].successfulRequests += metric.successfulRequests;
      groups[behavior].failedRequests += metric.failedRequests;
      groups[behavior].averageResponseTime += metric.averageResponseTime;
    }
    
    // 计算平均值
    Object.keys(groups).forEach(behavior => {
      const group = groups[behavior];
      group.averageResponseTime = (group.averageResponseTime / group.count).toFixed(2);
      group.successRate = group.totalRequests > 0 ? 
        (group.successfulRequests / group.totalRequests * 100).toFixed(2) : '0.00';
    });
    
    return groups;
  }

  private evaluateOutcomes(metrics: AgentMetrics[], expectedOutcomes: string[]): any {
    const outcomes: { [key: string]: boolean } = {};
    
    // 简单的评估逻辑，可以根据实际需求扩展
    outcomes['用户注册成功'] = metrics.some(m => m.actions.some(a => a.action === 'user_initialization' && a.success));
    outcomes['基础API响应正常'] = metrics.some(m => m.successfulRequests > 0);
    outcomes['数据库连接正常'] = metrics.some(m => m.actions.some(a => a.success));
    outcomes['所有用户角色正常工作'] = Object.keys(this.groupMetricsByBehavior(metrics)).length >= 3;
    outcomes['支付流程完整'] = metrics.some(m => m.actions.some(a => a.action === 'process_payment' && a.success));
    outcomes['社交功能正常'] = metrics.some(m => m.actions.some(a => ['like_annotation', 'share_annotation', 'follow_user'].includes(a.action) && a.success));
    outcomes['性能指标达标'] = metrics.every(m => m.averageResponseTime < 3000);
    outcomes['错误率低于5%'] = parseFloat(this.calculateSummary(metrics).errorRate) < 5;
    
    return outcomes;
  }

  private async generateHtmlReport(report: any, htmlPath: string): Promise<void> {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin 测试报告 - ${report.scenario}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #e0e0e0; padding-bottom: 20px; }
        .title { color: #333; margin-bottom: 10px; }
        .subtitle { color: #666; font-size: 16px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .metric-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { font-size: 0.9em; opacity: 0.9; }
        .section { margin: 40px 0; }
        .section-title { font-size: 1.5em; color: #333; margin-bottom: 20px; border-left: 4px solid #667eea; padding-left: 15px; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background: #f8f9fa; font-weight: 600; }
        .table tr:hover { background: #f8f9fa; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
        .warning { color: #ffc107; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-error { background: #f8d7da; color: #721c24; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .chart-container { height: 300px; background: #f8f9fa; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin: 20px 0; }
        .outcomes { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
        .outcome-item { display: flex; align-items: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .outcome-icon { margin-right: 15px; font-size: 1.5em; }
        .agent-details { margin: 20px 0; }
        .agent-card { background: #f8f9fa; padding: 20px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #667eea; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">🧪 SmellPin 自动化测试报告</h1>
            <p class="subtitle">${report.scenario} - ${new Date(report.startTime).toLocaleString('zh-CN')}</p>
            <p class="subtitle">测试时长: ${(report.duration / 1000 / 60).toFixed(2)} 分钟 | 代理数量: ${report.totalAgents}</p>
        </div>

        <div class="section">
            <h2 class="section-title">📊 总体统计</h2>
            <div class="summary">
                <div class="metric-card">
                    <div class="metric-value">${report.summary.totalRequests}</div>
                    <div class="metric-label">总请求数</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.summary.successRate}%</div>
                    <div class="metric-label">成功率</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.summary.averageResponseTime}ms</div>
                    <div class="metric-label">平均响应时间</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.summary.totalErrors}</div>
                    <div class="metric-label">错误总数</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">🎯 测试结果评估</h2>
            <div class="outcomes">
                ${Object.entries(report.actualOutcomes).map(([outcome, success]) => `
                <div class="outcome-item">
                    <div class="outcome-icon">${success ? '✅' : '❌'}</div>
                    <div>
                        <strong>${outcome}</strong>
                        <div class="badge ${success ? 'badge-success' : 'badge-error'}">
                            ${success ? '通过' : '失败'}
                        </div>
                    </div>
                </div>
                `).join('')}
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">👥 用户角色统计</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>用户角色</th>
                        <th>代理数量</th>
                        <th>总请求</th>
                        <th>成功请求</th>
                        <th>失败请求</th>
                        <th>成功率</th>
                        <th>平均响应时间</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(report.summary.agentsByBehavior).map(([behavior, stats]: [string, any]) => `
                    <tr>
                        <td><strong>${this.getBehaviorName(behavior)}</strong></td>
                        <td>${stats.count}</td>
                        <td>${stats.totalRequests}</td>
                        <td class="success">${stats.successfulRequests}</td>
                        <td class="error">${stats.failedRequests}</td>
                        <td>${stats.successRate}%</td>
                        <td>${stats.averageResponseTime}ms</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2 class="section-title">🤖 代理详细信息</h2>
            <div class="agent-details">
                ${report.agents.slice(0, 10).map((agent: any) => `
                <div class="agent-card">
                    <h4>${agent.agentId}</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 15px 0;">
                        <div><strong>总请求:</strong> ${agent.totalRequests}</div>
                        <div><strong>成功:</strong> <span class="success">${agent.successfulRequests}</span></div>
                        <div><strong>失败:</strong> <span class="error">${agent.failedRequests}</span></div>
                        <div><strong>响应时间:</strong> ${agent.averageResponseTime.toFixed(2)}ms</div>
                        <div><strong>运行时长:</strong> ${agent.endTime ? ((agent.endTime - agent.startTime) / 1000 / 60).toFixed(2) : 'N/A'} 分钟</div>
                        <div><strong>错误数:</strong> ${agent.errors.length}</div>
                    </div>
                    ${agent.errors.length > 0 ? `
                    <div style="margin-top: 15px;">
                        <strong>错误信息:</strong>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            ${agent.errors.slice(0, 3).map((error: string) => `<li class="error">${error}</li>`).join('')}
                            ${agent.errors.length > 3 ? `<li class="warning">... 还有 ${agent.errors.length - 3} 个错误</li>` : ''}
                        </ul>
                    </div>
                    ` : ''}
                </div>
                `).join('')}
                ${report.agents.length > 10 ? `<p class="warning">只显示前10个代理的详细信息，完整信息请查看JSON报告</p>` : ''}
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📈 性能图表</h2>
            <div class="chart-container">
                <p>📊 详细的性能图表将在后续版本中提供</p>
            </div>
        </div>

        <div class="section">
            <p style="text-align: center; color: #666; margin-top: 40px;">
                报告生成时间: ${new Date().toLocaleString('zh-CN')}<br>
                SmellPin 自动化测试框架 v2.0
            </p>
        </div>
    </div>
</body>
</html>
    `;
    
    await fs.writeFile(htmlPath, html);
  }

  private getBehaviorName(behavior: string): string {
    const names: { [key: string]: string } = {
      explorer: '🔍 探索者',
      annotator: '📝 标注者',
      social: '👥 社交用户',
      merchant: '💰 商户',
      validator: '✅ 验证者'
    };
    return names[behavior] || behavior;
  }

  private printSummary(summary: any): void {
    console.log('\n📊 测试摘要:');
    console.log('─'.repeat(50));
    console.log(`📈 总请求数: ${summary.totalRequests}`);
    console.log(`✅ 成功请求: ${summary.successfulRequests} (${summary.successRate}%)`);
    console.log(`❌ 失败请求: ${summary.failedRequests} (${summary.errorRate}%)`);
    console.log(`⏱️  平均响应时间: ${summary.averageResponseTime}ms`);
    console.log(`🐛 错误总数: ${summary.totalErrors}`);
    
    console.log('\n👥 用户角色分布:');
    Object.entries(summary.agentsByBehavior).forEach(([behavior, stats]: [string, any]) => {
      console.log(`   ${this.getBehaviorName(behavior)}: ${stats.count} 个代理, 成功率 ${stats.successRate}%`);
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  addCustomScenario(name: string, scenario: TestScenario): void {
    this.scenarios.set(name, scenario);
  }

  getAvailableScenarios(): string[] {
    return Array.from(this.scenarios.keys());
  }

  stopAll(): void {
    this.isRunning = false;
    this.agents.forEach(agent => agent.stop());
  }
}

// 导出默认实例
export const simulator = new MultiAgentSimulator();

// 如果直接运行此文件，执行命令行模式
if (require.main === module) {
  const scenarioName = process.argv[2] || 'smoke';
  
  console.log('🚀 SmellPin 多代理测试启动...');
  console.log(`📋 执行场景: ${scenarioName}`);
  
  simulator.runScenario(scenarioName)
    .then(() => {
      console.log('\n🎉 测试完成!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 测试失败:', error);
      process.exit(1);
    });
}
