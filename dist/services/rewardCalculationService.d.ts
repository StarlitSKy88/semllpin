import { RewardCalculationParams, RewardCalculationResult, LBSReward } from '../types/lbs';
export declare class RewardCalculationService {
    constructor();
    calculateReward(params: RewardCalculationParams): Promise<RewardCalculationResult>;
    calculateRewardWithDB(annotationId: string, userId: string, rewardType: LBSReward['rewardType']): Promise<number>;
    private calculateTimeDecayFactor;
    private calculateTimeDecayFactorLocal;
    private isFirstFinder;
    private getUserComboStreak;
    private calculateComboBonus;
    private getAnnotation;
    private getGeofenceConfig;
    private checkExistingReward;
    private createIneligibleResult;
}
//# sourceMappingURL=rewardCalculationService.d.ts.map