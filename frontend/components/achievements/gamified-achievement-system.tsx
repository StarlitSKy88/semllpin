'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence, useAnimation } from 'framer-motion';
import { 
  Trophy, Star, Crown, Medal, Award, Target, Zap, 
  MapPin, Camera, Users, Clock, TrendingUp, Gift,
  Lock, Unlock, CheckCircle, Flame, Shield, Heart,
  Coffee, TreePine, Building, Laugh, Eye, Sparkles,
  Calendar, BarChart3, Progress as ProgressIcon
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

interface Achievement {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  category: 'explorer' | 'creator' | 'social' | 'special';
  tier: 'bronze' | 'silver' | 'gold' | 'platinum' | 'legendary';
  isUnlocked: boolean;
  unlockedAt?: string;
  progress: number;
  maxProgress: number;
  reward: number;
  rarity: 'common' | 'rare' | 'epic' | 'legendary';
}

interface UserStats {
  level: number;
  totalXP: number;
  nextLevelXP: number;
  annotationsCreated: number;
  annotationsDiscovered: number;
  totalRewardsEarned: number;
  streak: number;
  totalDistance: number;
  categoriesExplored: string[];
  daysActive: number;
}

interface GamifiedAchievementSystemProps {
  userStats: UserStats;
  achievements: Achievement[];
  onAchievementClaim?: (achievementId: string) => void;
  className?: string;
}

// Mock achievements data
const mockAchievements: Achievement[] = [
  // Explorer Category
  {
    id: 'first_steps',
    title: '初入江湖',
    description: '创建你的第一个标注',
    icon: MapPin,
    category: 'explorer',
    tier: 'bronze',
    isUnlocked: true,
    unlockedAt: '2024-01-15T10:30:00Z',
    progress: 1,
    maxProgress: 1,
    reward: 10,
    rarity: 'common'
  },
  {
    id: 'distance_walker',
    title: '行走者',
    description: '累计步行10公里',
    icon: TrendingUp,
    category: 'explorer',
    tier: 'silver',
    isUnlocked: false,
    progress: 7.2,
    maxProgress: 10,
    reward: 50,
    rarity: 'rare'
  },
  {
    id: 'treasure_hunter',
    title: '寻宝达人',
    description: '发现50个标注',
    icon: Eye,
    category: 'explorer',
    tier: 'gold',
    isUnlocked: false,
    progress: 32,
    maxProgress: 50,
    reward: 200,
    rarity: 'epic'
  },
  
  // Creator Category
  {
    id: 'storyteller',
    title: '故事大师',
    description: '创建包含详细描述的标注10个',
    icon: Coffee,
    category: 'creator',
    tier: 'silver',
    isUnlocked: true,
    unlockedAt: '2024-01-20T14:15:00Z',
    progress: 10,
    maxProgress: 10,
    reward: 100,
    rarity: 'rare'
  },
  {
    id: 'photographer',
    title: '摄影师',
    description: '上传100张高质量图片',
    icon: Camera,
    category: 'creator',
    tier: 'gold',
    isUnlocked: false,
    progress: 67,
    maxProgress: 100,
    reward: 300,
    rarity: 'epic'
  },
  
  // Social Category
  {
    id: 'social_butterfly',
    title: '社交达人',
    description: '获得其他用户点赞100次',
    icon: Heart,
    category: 'social',
    tier: 'gold',
    isUnlocked: false,
    progress: 78,
    maxProgress: 100,
    reward: 250,
    rarity: 'epic'
  },
  {
    id: 'community_leader',
    title: '社区领袖',
    description: '帮助10位新用户发现第一个标注',
    icon: Users,
    category: 'social',
    tier: 'platinum',
    isUnlocked: false,
    progress: 3,
    maxProgress: 10,
    reward: 500,
    rarity: 'legendary'
  },
  
  // Special Category
  {
    id: 'streak_master',
    title: '坚持不懈',
    description: '连续30天使用应用',
    icon: Flame,
    category: 'special',
    tier: 'platinum',
    isUnlocked: false,
    progress: 18,
    maxProgress: 30,
    reward: 1000,
    rarity: 'legendary'
  },
  {
    id: 'legend',
    title: '传说',
    description: '达到最高等级',
    icon: Crown,
    category: 'special',
    tier: 'legendary',
    isUnlocked: false,
    progress: 15,
    maxProgress: 50,
    reward: 5000,
    rarity: 'legendary'
  }
];

const mockUserStats: UserStats = {
  level: 15,
  totalXP: 8750,
  nextLevelXP: 9500,
  annotationsCreated: 23,
  annotationsDiscovered: 156,
  totalRewardsEarned: 2340,
  streak: 18,
  totalDistance: 7.2,
  categoriesExplored: ['funny', 'nature', 'urban', 'food'],
  daysActive: 45
};

const GamifiedAchievementSystem: React.FC<GamifiedAchievementSystemProps> = ({
  userStats = mockUserStats,
  achievements = mockAchievements,
  onAchievementClaim,
  className = ""
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [showUnlockedOnly, setShowUnlockedOnly] = useState(false);
  const [celebrationAchievement, setCelebrationAchievement] = useState<Achievement | null>(null);
  
  const sparkleAnimation = useAnimation();

  // Filter achievements
  const filteredAchievements = useMemo(() => {
    let filtered = achievements;
    
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(a => a.category === selectedCategory);
    }
    
    if (showUnlockedOnly) {
      filtered = filtered.filter(a => a.isUnlocked);
    }
    
    return filtered.sort((a, b) => {
      // Sort by unlocked status, then by progress percentage
      if (a.isUnlocked !== b.isUnlocked) {
        return a.isUnlocked ? -1 : 1;
      }
      const aProgress = a.progress / a.maxProgress;
      const bProgress = b.progress / b.maxProgress;
      return bProgress - aProgress;
    });
  }, [achievements, selectedCategory, showUnlockedOnly]);

  // Calculate completion stats
  const completionStats = useMemo(() => {
    const total = achievements.length;
    const unlocked = achievements.filter(a => a.isUnlocked).length;
    const inProgress = achievements.filter(a => !a.isUnlocked && a.progress > 0).length;
    
    return {
      total,
      unlocked,
      inProgress,
      percentage: Math.round((unlocked / total) * 100)
    };
  }, [achievements]);

  // Get tier color and gradient
  const getTierColor = (tier: Achievement['tier']) => {
    const colors = {
      bronze: 'from-amber-600 to-orange-500',
      silver: 'from-gray-400 to-gray-600',
      gold: 'from-yellow-400 to-yellow-600',
      platinum: 'from-cyan-400 to-blue-500',
      legendary: 'from-purple-500 to-pink-500'
    };
    return colors[tier];
  };

  // Get rarity indicator
  const getRarityColor = (rarity: Achievement['rarity']) => {
    const colors = {
      common: 'border-gray-500',
      rare: 'border-blue-500',
      epic: 'border-purple-500',
      legendary: 'border-yellow-500'
    };
    return colors[rarity];
  };

  // Handle achievement unlock celebration
  const triggerCelebration = (achievement: Achievement) => {
    setCelebrationAchievement(achievement);
    sparkleAnimation.start({
      scale: [1, 1.2, 1],
      rotate: [0, 10, -10, 0],
      transition: { duration: 0.8 }
    });
    
    setTimeout(() => setCelebrationAchievement(null), 3000);
  };

  // Calculate level progress
  const levelProgress = ((userStats.totalXP - (userStats.level - 1) * 500) / 500) * 100;

  return (
    <div className={`space-y-6 ${className}`}>
      {/* User Level & Stats Overview */}
      <Card className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 backdrop-blur-xl border-white/20">
        <CardContent className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-4">
              <motion.div
                className="w-16 h-16 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center"
                animate={sparkleAnimation}
              >
                <Crown className="w-8 h-8 text-white" />
              </motion.div>
              <div>
                <h2 className="text-2xl font-bold text-white">等级 {userStats.level}</h2>
                <p className="text-white/70">探索大师</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-yellow-400">¥{userStats.totalRewardsEarned}</div>
              <p className="text-white/70 text-sm">总收益</p>
            </div>
          </div>

          {/* Level Progress */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-white/70">经验值进度</span>
              <span className="text-white">{userStats.totalXP} / {userStats.nextLevelXP} XP</span>
            </div>
            <Progress value={levelProgress} className="h-3 bg-white/20" />
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-4 gap-4 mt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-400">{userStats.annotationsDiscovered}</div>
              <p className="text-xs text-white/70">已发现</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-400">{userStats.annotationsCreated}</div>
              <p className="text-xs text-white/70">已创建</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-400">{userStats.streak}</div>
              <p className="text-xs text-white/70">连续天数</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-400">{userStats.totalDistance.toFixed(1)}km</div>
              <p className="text-xs text-white/70">总距离</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Achievement Progress Overview */}
      <Card className="bg-white/10 backdrop-blur-xl border-white/20">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-white flex items-center gap-2">
              <Trophy className="w-5 h-5 text-yellow-400" />
              成就进度
            </CardTitle>
            <Badge className="bg-gradient-to-r from-green-500 to-emerald-500 text-white">
              {completionStats.percentage}% 完成
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="text-center p-3 bg-white/5 rounded-lg">
              <div className="text-xl font-bold text-yellow-400">{completionStats.unlocked}</div>
              <p className="text-xs text-white/70">已解锁</p>
            </div>
            <div className="text-center p-3 bg-white/5 rounded-lg">
              <div className="text-xl font-bold text-blue-400">{completionStats.inProgress}</div>
              <p className="text-xs text-white/70">进行中</p>
            </div>
            <div className="text-center p-3 bg-white/5 rounded-lg">
              <div className="text-xl font-bold text-white">{completionStats.total}</div>
              <p className="text-xs text-white/70">总数</p>
            </div>
          </div>
          <Progress value={completionStats.percentage} className="h-2" />
        </CardContent>
      </Card>

      {/* Achievement Categories */}
      <Card className="bg-white/10 backdrop-blur-xl border-white/20">
        <CardHeader>
          <CardTitle className="text-white">成就列表</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={selectedCategory} onValueChange={setSelectedCategory}>
            <TabsList className="grid grid-cols-5 w-full bg-white/10">
              <TabsTrigger value="all">全部</TabsTrigger>
              <TabsTrigger value="explorer">探索</TabsTrigger>
              <TabsTrigger value="creator">创作</TabsTrigger>
              <TabsTrigger value="social">社交</TabsTrigger>
              <TabsTrigger value="special">特殊</TabsTrigger>
            </TabsList>
            
            <TabsContent value={selectedCategory} className="mt-6">
              {/* Filter Toggle */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-sm text-white/70">
                  <ProgressIcon className="w-4 h-4" />
                  显示 {filteredAchievements.length} 项成就
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowUnlockedOnly(!showUnlockedOnly)}
                  className="bg-white/10 border-white/20 text-white hover:bg-white/20"
                >
                  {showUnlockedOnly ? '显示全部' : '仅已解锁'}
                </Button>
              </div>

              {/* Achievement Grid */}
              <div className="grid gap-4">
                <AnimatePresence>
                  {filteredAchievements.map((achievement, index) => {
                    const IconComponent = achievement.icon;
                    const progressPercentage = (achievement.progress / achievement.maxProgress) * 100;
                    
                    return (
                      <motion.div
                        key={achievement.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ delay: index * 0.1 }}
                        className={`relative p-4 rounded-xl border-2 backdrop-blur-sm transition-all hover:scale-[1.02] ${
                          achievement.isUnlocked
                            ? `bg-gradient-to-r ${getTierColor(achievement.tier)}/20 ${getRarityColor(achievement.rarity)} shadow-lg`
                            : 'bg-white/5 border-white/10 hover:bg-white/10'
                        }`}
                      >
                        <div className="flex items-start gap-4">
                          {/* Achievement Icon */}
                          <div className="relative">
                            <motion.div
                              className={`w-12 h-12 rounded-full flex items-center justify-center ${
                                achievement.isUnlocked
                                  ? `bg-gradient-to-r ${getTierColor(achievement.tier)}`
                                  : 'bg-gray-600'
                              }`}
                              animate={achievement.isUnlocked ? { scale: [1, 1.05, 1] } : {}}
                              transition={{ duration: 2, repeat: Infinity }}
                            >
                              {achievement.isUnlocked ? (
                                <IconComponent className="w-6 h-6 text-white" />
                              ) : (
                                <Lock className="w-6 h-6 text-gray-300" />
                              )}
                            </motion.div>
                            
                            {/* Tier Badge */}
                            <Badge
                              className={`absolute -top-1 -right-1 text-xs px-1 ${
                                achievement.isUnlocked
                                  ? `bg-gradient-to-r ${getTierColor(achievement.tier)}`
                                  : 'bg-gray-500'
                              }`}
                            >
                              {achievement.tier === 'bronze' && '铜'}
                              {achievement.tier === 'silver' && '银'}
                              {achievement.tier === 'gold' && '金'}
                              {achievement.tier === 'platinum' && '白金'}
                              {achievement.tier === 'legendary' && '传说'}
                            </Badge>
                          </div>

                          {/* Achievement Info */}
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <h4 className="font-semibold text-white">{achievement.title}</h4>
                              {achievement.isUnlocked && (
                                <CheckCircle className="w-4 h-4 text-green-400" />
                              )}
                            </div>
                            <p className="text-sm text-white/70 mb-2">{achievement.description}</p>
                            
                            {/* Progress Bar */}
                            <div className="space-y-1">
                              <div className="flex justify-between text-xs">
                                <span className="text-white/60">
                                  进度: {achievement.progress} / {achievement.maxProgress}
                                </span>
                                <span className="text-white/60">{progressPercentage.toFixed(0)}%</span>
                              </div>
                              <Progress
                                value={progressPercentage}
                                className="h-2 bg-white/20"
                              />
                            </div>

                            {/* Unlock Date */}
                            {achievement.isUnlocked && achievement.unlockedAt && (
                              <div className="flex items-center gap-1 mt-2 text-xs text-green-400">
                                <Calendar className="w-3 h-3" />
                                解锁于 {new Date(achievement.unlockedAt).toLocaleDateString()}
                              </div>
                            )}
                          </div>

                          {/* Reward */}
                          <div className="text-right">
                            <div className="flex items-center gap-1 text-yellow-400 font-bold">
                              <Gift className="w-4 h-4" />
                              ¥{achievement.reward}
                            </div>
                            {achievement.isUnlocked && (
                              <Badge variant="outline" className="mt-1 bg-green-500/20 text-green-400 border-green-500/30">
                                已获得
                              </Badge>
                            )}
                          </div>
                        </div>

                        {/* Rarity Glow Effect */}
                        {achievement.rarity === 'legendary' && achievement.isUnlocked && (
                          <motion.div
                            className="absolute inset-0 rounded-xl bg-gradient-to-r from-purple-500/20 to-pink-500/20 blur-lg -z-10"
                            animate={{ opacity: [0.5, 1, 0.5] }}
                            transition={{ duration: 2, repeat: Infinity }}
                          />
                        )}
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Achievement Unlock Celebration */}
      <AnimatePresence>
        {celebrationAchievement && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50"
          >
            <motion.div
              initial={{ scale: 0, rotate: -180 }}
              animate={{ scale: 1, rotate: 0 }}
              exit={{ scale: 0, rotate: 180 }}
              className="bg-gradient-to-r from-yellow-500/20 to-orange-500/20 backdrop-blur-xl border border-yellow-500/30 rounded-3xl p-8 max-w-md text-center"
              transition={{ type: "spring", stiffness: 200, damping: 15 }}
            >
              {/* Sparkle Effects */}
              {Array.from({ length: 8 }).map((_, i) => (
                <motion.div
                  key={i}
                  className="absolute w-2 h-2 bg-yellow-400 rounded-full"
                  initial={{ 
                    x: 0, 
                    y: 0, 
                    scale: 0,
                    opacity: 1 
                  }}
                  animate={{
                    x: Math.cos((i / 8) * Math.PI * 2) * 100,
                    y: Math.sin((i / 8) * Math.PI * 2) * 100,
                    scale: [0, 1, 0],
                    opacity: [1, 1, 0],
                  }}
                  transition={{
                    duration: 2,
                    delay: 0.5,
                    ease: "easeOut"
                  }}
                  style={{
                    left: '50%',
                    top: '50%',
                  }}
                />
              ))}

              <motion.div
                animate={{ rotate: [0, 10, -10, 0] }}
                transition={{ duration: 0.5, repeat: 3 }}
                className={`w-24 h-24 rounded-full mx-auto mb-4 bg-gradient-to-r ${getTierColor(celebrationAchievement.tier)} flex items-center justify-center`}
              >
                {React.createElement(celebrationAchievement.icon, { className: "w-12 h-12 text-white" })}
              </motion.div>

              <h3 className="text-2xl font-bold text-white mb-2">成就解锁！</h3>
              <h4 className="text-xl text-yellow-400 mb-2">{celebrationAchievement.title}</h4>
              <p className="text-white/70 mb-4">{celebrationAchievement.description}</p>
              
              <div className="flex items-center justify-center gap-2 text-yellow-400 text-lg font-bold">
                <Gift className="w-5 h-5" />
                奖励: ¥{celebrationAchievement.reward}
              </div>

              <Button
                onClick={() => setCelebrationAchievement(null)}
                className="mt-6 bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-white"
              >
                <Sparkles className="w-4 h-4 mr-2" />
                太棒了！
              </Button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default GamifiedAchievementSystem;