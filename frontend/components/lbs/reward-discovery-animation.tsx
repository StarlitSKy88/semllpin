'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence, useAnimation } from 'framer-motion';
import { Gift, Zap, Star, Target, CheckCircle, Award, TrendingUp, MapPin } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface RewardDiscoveryProps {
  isVisible: boolean;
  rewardAmount: number;
  title: string;
  description?: string;
  category?: string;
  onClaim: () => void;
  onClose: () => void;
  distanceToTarget?: number;
  accuracy?: number;
}

interface GeofenceAnimationProps {
  isInRange: boolean;
  progress: number;
  className?: string;
}

// Pulsing geofence indicator
const GeofenceAnimation: React.FC<GeofenceAnimationProps> = ({ 
  isInRange, 
  progress,
  className = "" 
}) => {
  return (
    <div className={`relative ${className}`}>
      <motion.div
        className="absolute inset-0 rounded-full border-2 border-blue-400/50"
        animate={{
          scale: isInRange ? [1, 1.2, 1] : 1,
          opacity: isInRange ? [0.5, 1, 0.5] : 0.3,
        }}
        transition={{
          duration: 2,
          repeat: isInRange ? Infinity : 0,
          ease: "easeInOut"
        }}
      />
      <motion.div
        className="absolute inset-0 rounded-full border-2 border-blue-400/30"
        animate={{
          scale: isInRange ? [1.2, 1.6, 1.2] : 1,
          opacity: isInRange ? [0.3, 0.7, 0.3] : 0.1,
        }}
        transition={{
          duration: 2,
          repeat: isInRange ? Infinity : 0,
          ease: "easeInOut",
          delay: 0.5
        }}
      />
      <motion.div
        className="absolute inset-0 rounded-full bg-blue-400/10"
        initial={{ scale: 0 }}
        animate={{ scale: progress }}
        transition={{ duration: 0.3 }}
      />
    </div>
  );
};

// Floating reward particles
const RewardParticles: React.FC<{ isActive: boolean }> = ({ isActive }) => {
  const particles = Array.from({ length: 12 }, (_, i) => ({
    id: i,
    delay: i * 0.1,
    angle: (i / 12) * 360,
  }));

  return (
    <AnimatePresence>
      {isActive && particles.map((particle) => (
        <motion.div
          key={particle.id}
          className="absolute w-2 h-2 bg-yellow-400 rounded-full"
          initial={{
            x: 0,
            y: 0,
            scale: 0,
            opacity: 1,
          }}
          animate={{
            x: Math.cos(particle.angle * Math.PI / 180) * 80,
            y: Math.sin(particle.angle * Math.PI / 180) * 80,
            scale: [0, 1, 0],
            opacity: [1, 1, 0],
          }}
          transition={{
            duration: 2,
            delay: particle.delay,
            ease: "easeOut"
          }}
          style={{
            left: '50%',
            top: '50%',
          }}
        />
      ))}
    </AnimatePresence>
  );
};

// Main reward discovery animation component
const RewardDiscoveryAnimation: React.FC<RewardDiscoveryProps> = ({
  isVisible,
  rewardAmount,
  title,
  description,
  category = 'general',
  onClaim,
  onClose,
  distanceToTarget = 0,
  accuracy = 10
}) => {
  const [animationPhase, setAnimationPhase] = useState<'entering' | 'discovery' | 'claiming' | 'claimed'>('entering');
  const [showParticles, setShowParticles] = useState(false);
  const [progress, setProgress] = useState(0);
  
  const controls = useAnimation();
  const isInRange = distanceToTarget <= 50; // Within 50 meters

  useEffect(() => {
    if (isVisible && isInRange) {
      setAnimationPhase('discovery');
      setProgress(Math.max(0, Math.min(1, (50 - distanceToTarget) / 50)));
    } else if (isVisible) {
      setAnimationPhase('entering');
      setProgress(0);
    }
  }, [isVisible, isInRange, distanceToTarget]);

  const handleClaim = async () => {
    setAnimationPhase('claiming');
    setShowParticles(true);
    
    // Animate the claiming process
    await controls.start({
      scale: [1, 1.2, 1],
      rotate: [0, 10, -10, 0],
      transition: { duration: 0.8 }
    });
    
    setTimeout(() => {
      setAnimationPhase('claimed');
      onClaim();
    }, 1000);
  };

  const getCategoryColor = (cat: string) => {
    const colors = {
      historical: 'from-amber-500 to-orange-500',
      nature: 'from-green-500 to-emerald-500',
      urban: 'from-blue-500 to-cyan-500',
      funny: 'from-pink-500 to-rose-500',
      weird: 'from-purple-500 to-indigo-500',
      general: 'from-gray-500 to-slate-500'
    };
    return colors[cat as keyof typeof colors] || colors.general;
  };

  const getCategoryIcon = (cat: string) => {
    const icons = {
      historical: Award,
      nature: MapPin,
      urban: Target,
      funny: Star,
      weird: Zap,
      general: Gift
    };
    return icons[cat as keyof typeof icons] || Gift;
  };

  const CategoryIcon = getCategoryIcon(category);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <motion.div
            animate={controls}
            className="relative"
          >
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0, opacity: 0 }}
              className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-3xl p-8 max-w-md w-full text-white shadow-2xl"
              transition={{
                type: "spring",
                stiffness: 300,
                damping: 25
              }}
            >
              {/* Header */}
              <div className="text-center mb-6">
                <motion.div
                  className="relative mx-auto w-20 h-20 mb-4"
                  animate={animationPhase === 'discovery' ? {
                    scale: [1, 1.1, 1],
                    rotate: [0, 5, -5, 0]
                  } : {}}
                  transition={{
                    duration: 2,
                    repeat: animationPhase === 'discovery' ? Infinity : 0,
                    ease: "easeInOut"
                  }}
                >
                  <div className={`w-full h-full rounded-full bg-gradient-to-r ${getCategoryColor(category)} flex items-center justify-center shadow-lg`}>
                    <CategoryIcon className="w-8 h-8 text-white" />
                  </div>
                  
                  {/* Geofence animation */}
                  <GeofenceAnimation 
                    isInRange={isInRange}
                    progress={progress}
                    className="w-full h-full"
                  />
                  
                  {/* Reward particles */}
                  <RewardParticles isActive={showParticles} />
                </motion.div>

                <motion.h2 
                  className="text-2xl font-bold mb-2"
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  {animationPhase === 'claimed' ? '奖励已获得！' : title}
                </motion.h2>

                {description && animationPhase !== 'claimed' && (
                  <motion.p 
                    className="text-white/70 text-sm"
                    initial={{ y: 20, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    transition={{ delay: 0.3 }}
                  >
                    {description}
                  </motion.p>
                )}
              </div>

              {/* Distance and accuracy info */}
              {animationPhase !== 'claimed' && (
                <motion.div 
                  className="mb-6 space-y-3"
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.4 }}
                >
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white/70">距离目标</span>
                    <Badge variant="outline" className="bg-white/10 border-white/20 text-white">
                      {distanceToTarget.toFixed(0)}m
                    </Badge>
                  </div>
                  
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white/70">定位精度</span>
                    <Badge 
                      variant="outline" 
                      className={`bg-white/10 border-white/20 ${
                        accuracy <= 10 ? 'text-green-400' : 
                        accuracy <= 30 ? 'text-yellow-400' : 'text-red-400'
                      }`}
                    >
                      ±{accuracy.toFixed(0)}m
                    </Badge>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full bg-white/20 rounded-full h-2">
                    <motion.div
                      className="h-full bg-gradient-to-r from-blue-400 to-cyan-400 rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${progress * 100}%` }}
                      transition={{ duration: 0.5 }}
                    />
                  </div>
                  
                  <div className="text-center">
                    {isInRange ? (
                      <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                        <Target className="w-3 h-3 mr-1" />
                        在范围内
                      </Badge>
                    ) : (
                      <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">
                        <TrendingUp className="w-3 h-3 mr-1" />
                        继续靠近
                      </Badge>
                    )}
                  </div>
                </motion.div>
              )}

              {/* Reward amount display */}
              <motion.div 
                className="text-center mb-6"
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.5, type: "spring", stiffness: 200 }}
              >
                <div className="inline-flex items-center gap-2 bg-gradient-to-r from-yellow-500 to-orange-500 text-white px-6 py-3 rounded-2xl shadow-lg">
                  <Zap className="w-5 h-5" />
                  <span className="text-2xl font-bold">¥{rewardAmount}</span>
                </div>
              </motion.div>

              {/* Action buttons */}
              <motion.div 
                className="flex gap-3"
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.6 }}
              >
                {animationPhase === 'claimed' ? (
                  <Button
                    onClick={onClose}
                    className="w-full bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white"
                  >
                    <CheckCircle className="w-4 h-4 mr-2" />
                    太棒了！
                  </Button>
                ) : (
                  <>
                    <Button
                      onClick={handleClaim}
                      disabled={!isInRange || animationPhase === 'claiming'}
                      className={`flex-1 ${
                        isInRange 
                          ? 'bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600' 
                          : 'bg-gray-500/50 cursor-not-allowed'
                      } text-white transition-all duration-300`}
                    >
                      {animationPhase === 'claiming' ? (
                        <motion.div
                          animate={{ rotate: 360 }}
                          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                          className="w-4 h-4 mr-2"
                        >
                          <Gift className="w-4 h-4" />
                        </motion.div>
                      ) : (
                        <Gift className="w-4 h-4 mr-2" />
                      )}
                      {animationPhase === 'claiming' ? '领取中...' : '领取奖励'}
                    </Button>
                    
                    <Button
                      onClick={onClose}
                      variant="outline"
                      className="bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20"
                    >
                      稍后
                    </Button>
                  </>
                )}
              </motion.div>

              {/* Helpful tips */}
              {!isInRange && animationPhase !== 'claimed' && (
                <motion.div 
                  className="mt-4 p-3 bg-blue-500/20 border border-blue-500/30 rounded-xl text-sm text-blue-300"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.8 }}
                >
                  💡 提示：移动到距离目标50米内即可领取奖励。当前定位精度为±{accuracy}米。
                </motion.div>
              )}
            </motion.div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// Hook for managing geofence discovery
export const useRewardDiscovery = () => {
  const [activeReward, setActiveReward] = useState<{
    id: string;
    title: string;
    description?: string;
    amount: number;
    category?: string;
    distance: number;
  } | null>(null);

  const triggerRewardDiscovery = (reward: {
    id: string;
    title: string;
    description?: string;
    amount: number;
    category?: string;
    distance: number;
  }) => {
    setActiveReward(reward);
  };

  const closeRewardDiscovery = () => {
    setActiveReward(null);
  };

  return {
    activeReward,
    triggerRewardDiscovery,
    closeRewardDiscovery,
  };
};

export default RewardDiscoveryAnimation;