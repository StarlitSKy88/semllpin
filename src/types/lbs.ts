// LBS奖励系统相关类型定义

// 位置上报记录
export interface LocationReport {
  id: string;
  userId: string;
  latitude: number;
  longitude: number;
  accuracy: number; // GPS精度(米)
  speed?: number; // 移动速度(km/h)
  heading?: number; // 移动方向(度)
  altitude?: number; // 海拔高度(米)
  timestamp: Date;
  deviceInfo?: Record<string, any>; // 设备信息
  batteryLevel?: number; // 电池电量百分比
  networkType?: string; // 网络类型
  reportType: string; // 上报类型
  createdAt?: Date;
}

// 地理围栏配置
export interface GeofenceConfig {
  id: string;
  annotationId: string;
  radiusMeters: number; // 围栏半径(米)
  detectionFrequency: number; // 检测频率(秒)
  minAccuracyMeters: number; // 最小GPS精度要求(米)
  minStayDuration: number; // 最小停留时间(秒)
  maxSpeedKmh: number; // 最大允许速度(km/h)
  isActive: boolean;
  rewardBasePercentage: number; // 基础奖励百分比
  timeDecayEnabled: boolean; // 是否启用时间衰减
  firstFinderBonus: number; // 首次发现奖励百分比
  comboBonusEnabled: boolean; // 是否启用连击奖励
  createdAt: Date;
  updatedAt: Date;
}

// LBS奖励记录
export interface LBSReward {
  id: string;
  userId: string;
  annotationId: string;
  amount: number;
  rewardType: 'discovery' | 'first_finder' | 'combo' | 'time_bonus';
  status: 'pending' | 'verified' | 'claimed' | 'rejected' | 'expired';
  locationReportId: string;
  createdAt: Date;
  claimedAt?: Date;
  updatedAt: Date;
  // 可选的详细信息
  locationVerified?: boolean;
  verificationData?: Record<string, any>; // GPS精度、移动轨迹等验证数据
  gpsAccuracy?: number; // GPS精度(米)
  movementSpeed?: number; // 移动速度(km/h)
  stayDuration?: number; // 停留时间(秒)
  distanceToAnnotation?: number; // 到标注点的距离(米)
  timeDecayFactor?: number; // 时间衰减因子
  expiresAt?: Date;
  antiFraudScore?: number; // 防作弊评分
  deviceFingerprint?: string; // 设备指纹
  ipAddress?: string; // IP地址
  metadata?: Record<string, any>; // 额外元数据
}

// 防作弊检测记录
export interface AntiFraudLog {
  id: string;
  userId: string;
  detectionType: string; // 检测类型
  riskScore: number; // 风险评分(0-1)
  details: Record<string, any>; // 检测详情
  actionTaken?: string; // 采取的行动
  locationReportId?: string;
  lbsRewardId?: string;
  createdAt: Date;
}

// LBS奖励统计
export interface LBSRewardStats {
  id: string;
  userId: string;
  totalRewardsEarned: number; // 总奖励金额
  totalDiscoveries: number; // 总发现次数
  firstFinderCount: number; // 首次发现次数
  comboCount: number; // 连击次数
  maxComboStreak: number; // 最大连击数
  currentComboStreak: number; // 当前连击数
  lastDiscoveryAt?: Date; // 最后发现时间
  fraudDetectionCount: number; // 被检测作弊次数
  verificationSuccessRate: number; // 验证成功率
  createdAt: Date;
  updatedAt: Date;
}

// 位置上报请求
export interface LocationReportRequest {
  latitude: number;
  longitude: number;
  accuracy: number;
  speed?: number;
  heading?: number;
  altitude?: number;
  timestamp: string; // ISO字符串
  deviceInfo?: Record<string, any>;
  batteryLevel?: number;
  networkType?: string;
}

// 奖励查询响应
export interface RewardQueryResponse {
  rewards: LBSReward[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
  summary: {
    totalAmount: number;
    claimedAmount: number;
    pendingAmount: number;
  };
}

// 奖励领取请求
export interface ClaimRewardRequest {
  rewardIds: string[];
  verificationCode?: string; // 可选的验证码
}

// 奖励领取响应
export interface ClaimRewardResponse {
  success: boolean;
  amount: number;
  claimedRewards: LBSReward[];
  newWalletBalance: number;
}

// 地理围栏触发结果
export interface GeofenceTriggerResult {
  annotationId: string;
  distanceMeters: number;
  rewardEligible: boolean;
  estimatedReward?: number;
  config?: GeofenceConfig;
}

// 防作弊检测结果
export interface AntiFraudResult {
  isFraudulent: boolean;
  fraudScore: number;
  reasons: string[];
  checkResults: Array<{
    passed: boolean;
    reason: string;
    score: number;
  }>;
  actionRequired?: 'none' | 'warning' | 'block' | 'manual_review';
  details?: Record<string, any>;
}

// 奖励计算参数
export interface RewardCalculationParams {
  annotationId: string;
  userId: string;
  rewardType: LBSReward['rewardType'];
  baseAmount: number;
  timeDecayFactor?: number;
  isFirstFinder?: boolean;
  comboMultiplier?: number;
  locationData: {
    latitude: number;
    longitude: number;
    accuracy: number;
    stayDuration: number;
  };
}

// 奖励计算结果
export interface RewardCalculationResult {
  finalAmount: number;
  breakdown: {
    baseAmount: number;
    timeDecayFactor: number;
    firstFinderBonus: number;
    comboBonus: number;
    finalAmount: number;
  };
  eligibility: {
    eligible: boolean;
    reasons: string[];
  };
}
