import { authApi } from './api';

interface SendCodeOptions {
  phone: string;
  type: 'login' | 'register';
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

class SMSService {
  private cooldownMap = new Map<string, number>();
  private readonly COOLDOWN_TIME = 60000; // 60秒冷却时间

  /**
   * 发送验证码
   */
  async sendCode({ phone, type, onSuccess, onError }: SendCodeOptions): Promise<boolean> {
    try {
      // 检查冷却时间
      if (this.isInCooldown(phone)) {
        const remainingTime = this.getRemainingCooldownTime(phone);
        const errorMsg = `请等待 ${Math.ceil(remainingTime / 1000)} 秒后再试`;
        onError?.(errorMsg);
        return false;
      }

      // 验证手机号格式
      if (!this.validatePhoneNumber(phone)) {
        const errorMsg = '请输入正确的手机号码';
        onError?.(errorMsg);
        return false;
      }

      // 发送验证码
      await authApi.sendCode(phone, type);
      
      // 设置冷却时间
      this.setCooldown(phone);
      
      onSuccess?.();
      return true;
    } catch (error: any) {
      const errorMsg = error.message || '发送验证码失败，请稍后重试';
      onError?.(errorMsg);
      return false;
    }
  }

  /**
   * 验证手机号格式
   */
  private validatePhoneNumber(phone: string): boolean {
    const phoneRegex = /^1[3-9]\d{9}$/;
    return phoneRegex.test(phone);
  }

  /**
   * 检查是否在冷却时间内
   */
  private isInCooldown(phone: string): boolean {
    const cooldownEndTime = this.cooldownMap.get(phone);
    if (!cooldownEndTime) return false;
    
    const now = Date.now();
    if (now >= cooldownEndTime) {
      this.cooldownMap.delete(phone);
      return false;
    }
    
    return true;
  }

  /**
   * 获取剩余冷却时间
   */
  private getRemainingCooldownTime(phone: string): number {
    const cooldownEndTime = this.cooldownMap.get(phone);
    if (!cooldownEndTime) return 0;
    
    return Math.max(0, cooldownEndTime - Date.now());
  }

  /**
   * 设置冷却时间
   */
  private setCooldown(phone: string): void {
    const cooldownEndTime = Date.now() + this.COOLDOWN_TIME;
    this.cooldownMap.set(phone, cooldownEndTime);
  }

  /**
   * 清除冷却时间
   */
  clearCooldown(phone: string): void {
    this.cooldownMap.delete(phone);
  }

  /**
   * 获取冷却时间倒计时
   */
  getCooldownCountdown(phone: string): number {
    if (!this.isInCooldown(phone)) return 0;
    return Math.ceil(this.getRemainingCooldownTime(phone) / 1000);
  }
}

// 导出单例实例
export const smsService = new SMSService();
export default smsService;