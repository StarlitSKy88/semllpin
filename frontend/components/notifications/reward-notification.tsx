/**
 * Reward Notification System
 * Production-ready notification system for rewards, achievements, and LBS events
 */

'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Gift, 
  Zap, 
  Trophy, 
  MapPin,
  X,
  ExternalLink,
  TrendingUp,
  Target,
  Star,
  Coins,
  Award
} from 'lucide-react';

import type { Reward, Toast, ID } from '@/types';
import { useRewardStore, useUIStore } from '@/lib/store';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

// ==================== TYPES ====================

export interface RewardNotificationProps {
  reward: Reward;
  onClaim?: (rewardId: ID) => Promise<void>;
  onDismiss?: (rewardId: ID) => void;
  onViewDetails?: (rewardId: ID) => void;
  className?: string;
}

export interface NotificationSystemProps {
  position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' | 'top-center' | 'bottom-center';
  maxVisible?: number;
  autoRemove?: boolean;
  autoRemoveDelay?: number;
  className?: string;
}

export interface AchievementNotificationProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  level?: number;
  points?: number;
  onDismiss?: () => void;
}

export interface LocationEventNotificationProps {
  type: 'geofence_enter' | 'geofence_exit' | 'reward_discovered' | 'milestone_reached';
  location: string;
  reward?: number;
  description?: string;
  onDismiss?: () => void;
}

// ==================== NOTIFICATION ICONS ====================

const getRewardIcon = (type: string) => {
  const iconMap: Record<string, React.ReactNode> = {
    checkin: <MapPin className="w-5 h-5" />,
    annotation_view: <Gift className="w-5 h-5" />,
    annotation_like: <Star className="w-5 h-5" />,
    referral: <TrendingUp className="w-5 h-5" />,
    milestone: <Trophy className="w-5 h-5" />,
    daily_bonus: <Zap className="w-5 h-5" />,
    location_discovery: <Target className="w-5 h-5" />,
  };

  return iconMap[type] || <Gift className="w-5 h-5" />;
};

const getRewardColor = (type: string) => {
  const colorMap: Record<string, string> = {
    checkin: 'bg-blue-500',
    annotation_view: 'bg-purple-500',
    annotation_like: 'bg-yellow-500',
    referral: 'bg-green-500',
    milestone: 'bg-orange-500',
    daily_bonus: 'bg-indigo-500',
    location_discovery: 'bg-pink-500',
  };

  return colorMap[type] || 'bg-gray-500';
};

// ==================== REWARD NOTIFICATION COMPONENT ====================

export const RewardNotification: React.FC<RewardNotificationProps> = ({
  reward,
  onClaim,
  onDismiss,
  onViewDetails,
  className,
}) => {
  const [isLoading, setIsLoading] = useState(false);

  const handleClaim = useCallback(async () => {
    if (!onClaim || isLoading) return;

    setIsLoading(true);
    try {
      await onClaim(reward.id);
    } catch (error) {
      console.error('Failed to claim reward:', error);
    } finally {
      setIsLoading(false);
    }
  }, [reward.id, onClaim, isLoading]);

  const handleDismiss = useCallback(() => {
    onDismiss?.(reward.id);
  }, [reward.id, onDismiss]);

  const handleViewDetails = useCallback(() => {
    onViewDetails?.(reward.id);
  }, [reward.id, onViewDetails]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.8, y: -20 }}
      layout
      className={cn('w-full max-w-sm', className)}
    >
      <Card className="p-4 bg-card/95 backdrop-blur-sm border-l-4 border-l-primary shadow-lg">
        <div className="flex items-start gap-3">
          {/* Icon */}
          <div className={cn(
            'flex items-center justify-center w-10 h-10 rounded-full text-white shrink-0',
            getRewardColor(reward.type)
          )}>
            {getRewardIcon(reward.type)}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1">
              <h4 className="font-semibold text-sm text-foreground truncate">
                New Reward Available!
              </h4>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
                onClick={handleDismiss}
              >
                <X className="w-4 h-4" />
              </Button>
            </div>

            <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
              {reward.reason}
            </p>

            {/* Reward Details */}
            <div className="flex items-center gap-2 mb-3">
              <Badge variant="secondary" className="text-xs">
                {reward.type.replace('_', ' ')}
              </Badge>
              <div className="flex items-center gap-1 text-green-600">
                <Coins className="w-3 h-3" />
                <span className="text-sm font-medium">
                  {reward.currency} {reward.amount}
                </span>
              </div>
            </div>

            {/* Location Info */}
            {reward.location && (
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-3">
                <MapPin className="w-3 h-3" />
                <span>{reward.location.address || 'Location-based reward'}</span>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center gap-2">
              {reward.status === 'pending' && (
                <Button
                  size="sm"
                  className="h-7 px-3 text-xs"
                  onClick={handleClaim}
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <div className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <>
                      <Gift className="w-3 h-3 mr-1" />
                      Claim
                    </>
                  )}
                </Button>
              )}
              
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-3 text-xs"
                onClick={handleViewDetails}
              >
                <ExternalLink className="w-3 h-3 mr-1" />
                Details
              </Button>
            </div>

            {/* Expiry Warning */}
            {reward.expiresAt && (
              <div className="mt-2 text-xs text-amber-600">
                <span>Expires: {new Date(reward.expiresAt).toLocaleDateString()}</span>
              </div>
            )}
          </div>
        </div>
      </Card>
    </motion.div>
  );
};

// ==================== ACHIEVEMENT NOTIFICATION ====================

export const AchievementNotification: React.FC<AchievementNotificationProps> = ({
  title,
  description,
  icon = <Trophy className="w-6 h-6" />,
  level,
  points,
  onDismiss,
}) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      onDismiss?.();
    }, 8000);

    return () => clearTimeout(timer);
  }, [onDismiss]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.5, rotate: -10 }}
      animate={{ opacity: 1, scale: 1, rotate: 0 }}
      exit={{ opacity: 0, scale: 0.5, rotate: 10 }}
      className="w-full max-w-sm"
    >
      <Card className="p-4 bg-gradient-to-r from-amber-500/20 to-orange-500/20 border-amber-500/50 shadow-lg">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-12 h-12 rounded-full bg-amber-500 text-white shrink-0 shadow-md">
            {icon}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1">
              <h4 className="font-bold text-foreground">Achievement Unlocked!</h4>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0"
                onClick={onDismiss}
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
            
            <h5 className="font-semibold text-amber-700 dark:text-amber-300 mb-1">
              {title}
            </h5>
            
            <p className="text-sm text-muted-foreground mb-2">
              {description}
            </p>
            
            <div className="flex items-center gap-2">
              {level && (
                <Badge variant="outline" className="text-xs">
                  Level {level}
                </Badge>
              )}
              {points && (
                <Badge variant="secondary" className="text-xs">
                  +{points} pts
                </Badge>
              )}
            </div>
          </div>
        </div>
      </Card>
    </motion.div>
  );
};

// ==================== LOCATION EVENT NOTIFICATION ====================

export const LocationEventNotification: React.FC<LocationEventNotificationProps> = ({
  type,
  location,
  reward,
  description,
  onDismiss,
}) => {
  const getEventIcon = () => {
    switch (type) {
      case 'geofence_enter':
        return <Target className="w-5 h-5" />;
      case 'geofence_exit':
        return <MapPin className="w-5 h-5" />;
      case 'reward_discovered':
        return <Gift className="w-5 h-5" />;
      case 'milestone_reached':
        return <Award className="w-5 h-5" />;
      default:
        return <MapPin className="w-5 h-5" />;
    }
  };

  const getEventTitle = () => {
    switch (type) {
      case 'geofence_enter':
        return 'Entered Area';
      case 'geofence_exit':
        return 'Left Area';
      case 'reward_discovered':
        return 'Reward Discovered';
      case 'milestone_reached':
        return 'Milestone Reached';
      default:
        return 'Location Event';
    }
  };

  const getEventColor = () => {
    switch (type) {
      case 'geofence_enter':
        return 'bg-green-500';
      case 'geofence_exit':
        return 'bg-blue-500';
      case 'reward_discovered':
        return 'bg-purple-500';
      case 'milestone_reached':
        return 'bg-orange-500';
      default:
        return 'bg-gray-500';
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      onDismiss?.();
    }, 6000);

    return () => clearTimeout(timer);
  }, [onDismiss]);

  return (
    <motion.div
      initial={{ opacity: 0, x: 300 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 300 }}
      className="w-full max-w-sm"
    >
      <Card className="p-3 bg-card/95 backdrop-blur-sm border-l-4 border-l-blue-500 shadow-lg">
        <div className="flex items-center gap-3">
          <div className={cn(
            'flex items-center justify-center w-8 h-8 rounded-full text-white shrink-0',
            getEventColor()
          )}>
            {getEventIcon()}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <h4 className="font-medium text-sm text-foreground">
                {getEventTitle()}
              </h4>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0"
                onClick={onDismiss}
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
            
            <p className="text-xs text-muted-foreground mb-1">
              {location}
            </p>
            
            {description && (
              <p className="text-xs text-muted-foreground mb-2">
                {description}
              </p>
            )}
            
            {reward && (
              <div className="flex items-center gap-1 text-green-600">
                <Coins className="w-3 h-3" />
                <span className="text-xs font-medium">+{reward}</span>
              </div>
            )}
          </div>
        </div>
      </Card>
    </motion.div>
  );
};

// ==================== NOTIFICATION SYSTEM ====================

export const NotificationSystem: React.FC<NotificationSystemProps> = ({
  position = 'top-right',
  maxVisible = 5,
  autoRemove = true,
  autoRemoveDelay = 6000,
  className,
}) => {
  const { toasts, removeToast } = useUIStore();
  const { 
    availableRewards, 
    claimReward,
    isLoading 
  } = useRewardStore();

  // Filter toasts for reward notifications
  const rewardToasts = toasts.filter(toast => toast.type === 'success');
  
  // Get pending rewards for notifications
  const pendingRewards = availableRewards.filter(reward => reward.status === 'pending');

  // Auto-remove toasts
  useEffect(() => {
    if (!autoRemove) return;

    const timers = rewardToasts.map(toast => {
      return setTimeout(() => {
        removeToast(toast.id);
      }, toast.duration || autoRemoveDelay);
    });

    return () => {
      timers.forEach(timer => clearTimeout(timer));
    };
  }, [rewardToasts, autoRemove, autoRemoveDelay, removeToast]);

  // Position classes
  const getPositionClasses = () => {
    const baseClasses = 'fixed z-50 flex flex-col gap-2 p-4';
    
    switch (position) {
      case 'top-right':
        return `${baseClasses} top-0 right-0`;
      case 'top-left':
        return `${baseClasses} top-0 left-0`;
      case 'bottom-right':
        return `${baseClasses} bottom-0 right-0`;
      case 'bottom-left':
        return `${baseClasses} bottom-0 left-0`;
      case 'top-center':
        return `${baseClasses} top-0 left-1/2 transform -translate-x-1/2`;
      case 'bottom-center':
        return `${baseClasses} bottom-0 left-1/2 transform -translate-x-1/2`;
      default:
        return `${baseClasses} top-0 right-0`;
    }
  };

  // Handle reward claim
  const handleClaimReward = useCallback(async (rewardId: ID) => {
    try {
      await claimReward(rewardId);
    } catch (error) {
      console.error('Failed to claim reward:', error);
    }
  }, [claimReward]);

  // Handle dismiss
  const handleDismissReward = useCallback((rewardId: ID) => {
    // Remove from local state or mark as dismissed
    // Implementation depends on your state management
  }, []);

  return (
    <div className={cn(getPositionClasses(), className)}>
      <AnimatePresence mode="popLayout">
        {/* Reward Notifications */}
        {pendingRewards.slice(0, maxVisible).map((reward) => (
          <RewardNotification
            key={reward.id}
            reward={reward}
            onClaim={handleClaimReward}
            onDismiss={handleDismissReward}
          />
        ))}

        {/* Toast Notifications */}
        {rewardToasts.slice(0, maxVisible - pendingRewards.length).map((toast) => (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, scale: 0.8, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.8, y: -20 }}
            layout
          >
            <Card className="p-4 bg-card/95 backdrop-blur-sm shadow-lg max-w-sm">
              <div className="flex items-start gap-3">
                <div className="flex items-center justify-center w-8 h-8 rounded-full bg-green-500 text-white shrink-0">
                  <Gift className="w-4 h-4" />
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="font-medium text-sm text-foreground">
                      {toast.title}
                    </h4>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      onClick={() => removeToast(toast.id)}
                    >
                      <X className="w-4 h-4" />
                    </Button>
                  </div>
                  
                  <p className="text-sm text-muted-foreground">
                    {toast.message}
                  </p>
                  
                  {toast.action && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 px-3 text-xs mt-2"
                      onClick={toast.action.onClick}
                    >
                      {toast.action.label}
                    </Button>
                  )}
                </div>
              </div>
            </Card>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};

export default NotificationSystem;