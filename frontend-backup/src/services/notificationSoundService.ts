// 通知声音服务
class NotificationSoundService {
  private audioContext: AudioContext | null = null;
  private soundEnabled = true;
  private volume = 0.5;
  private soundCache: Map<string, AudioBuffer> = new Map();
  private customSounds: Map<string, string> = new Map();

  constructor() {
    this.initializeAudioContext();
    this.loadDefaultSounds();
    this.loadUserPreferences();
  }

  // 初始化音频上下文
  private async initializeAudioContext(): Promise<void> {
    try {
      this.audioContext = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
      
      // 处理浏览器的自动播放策略
      if (this.audioContext.state === 'suspended') {
        document.addEventListener('click', this.resumeAudioContext.bind(this), { once: true });
        document.addEventListener('touchstart', this.resumeAudioContext.bind(this), { once: true });
      }
    } catch (error) {
      console.warn('音频上下文初始化失败:', error);
    }
  }

  // 恢复音频上下文
  private async resumeAudioContext(): Promise<void> {
    if (this.audioContext && this.audioContext.state === 'suspended') {
      try {
        await this.audioContext.resume();
        console.log('音频上下文已恢复');
      } catch (error) {
        console.warn('恢复音频上下文失败:', error);
      }
    }
  }

  // 加载默认声音
  private async loadDefaultSounds(): Promise<void> {
    const defaultSounds = {
      'notification': this.generateNotificationSound(),
      'success': this.generateSuccessSound(),
      'warning': this.generateWarningSound(),
      'error': this.generateErrorSound(),
      'message': this.generateMessageSound(),
      'map_notification': this.generateMapNotificationSound()
    };

    for (const [name, soundData] of Object.entries(defaultSounds)) {
      try {
        const audioBuffer = await this.createAudioBuffer(soundData);
        this.soundCache.set(name, audioBuffer);
      } catch (error) {
        console.warn(`加载默认声音 ${name} 失败:`, error);
      }
    }
  }

  // 生成通知声音
  private generateNotificationSound(): Float32Array {
    const sampleRate = 44100;
    const duration = 0.3;
    const samples = sampleRate * duration;
    const buffer = new Float32Array(samples);

    for (let i = 0; i < samples; i++) {
      const t = i / sampleRate;
      const frequency1 = 800;
      const frequency2 = 1000;
      const envelope = Math.exp(-t * 3);
      
      buffer[i] = envelope * (
        Math.sin(2 * Math.PI * frequency1 * t) * 0.3 +
        Math.sin(2 * Math.PI * frequency2 * t) * 0.2
      );
    }

    return buffer;
  }

  // 生成成功声音
  private generateSuccessSound(): Float32Array {
    const sampleRate = 44100;
    const duration = 0.4;
    const samples = sampleRate * duration;
    const buffer = new Float32Array(samples);

    for (let i = 0; i < samples; i++) {
      const t = i / sampleRate;
      const frequency = 523 + (t * 200); // C5 上升
      const envelope = Math.exp(-t * 2);
      
      buffer[i] = envelope * Math.sin(2 * Math.PI * frequency * t) * 0.3;
    }

    return buffer;
  }

  // 生成警告声音
  private generateWarningSound(): Float32Array {
    const sampleRate = 44100;
    const duration = 0.5;
    const samples = sampleRate * duration;
    const buffer = new Float32Array(samples);

    for (let i = 0; i < samples; i++) {
      const t = i / sampleRate;
      const frequency = 440 + Math.sin(t * 10) * 100; // 颤音效果
      const envelope = Math.exp(-t * 1.5);
      
      buffer[i] = envelope * Math.sin(2 * Math.PI * frequency * t) * 0.4;
    }

    return buffer;
  }

  // 生成错误声音
  private generateErrorSound(): Float32Array {
    const sampleRate = 44100;
    const duration = 0.6;
    const samples = sampleRate * duration;
    const buffer = new Float32Array(samples);

    for (let i = 0; i < samples; i++) {
      const t = i / sampleRate;
      const frequency = 200 + Math.sin(t * 20) * 50; // 低频颤音
      const envelope = Math.exp(-t * 1);
      
      buffer[i] = envelope * Math.sin(2 * Math.PI * frequency * t) * 0.5;
    }

    return buffer;
  }

  // 生成消息声音
  private generateMessageSound(): Float32Array {
    const sampleRate = 44100;
    const duration = 0.2;
    const samples = sampleRate * duration;
    const buffer = new Float32Array(samples);

    for (let i = 0; i < samples; i++) {
      const t = i / sampleRate;
      const frequency = 660; // E5
      const envelope = Math.exp(-t * 5);
      
      buffer[i] = envelope * Math.sin(2 * Math.PI * frequency * t) * 0.25;
    }

    return buffer;
  }

  // 生成地图通知声音
  private generateMapNotificationSound(): Float32Array {
    const sampleRate = 44100;
    const duration = 0.4;
    const samples = sampleRate * duration;
    const buffer = new Float32Array(samples);

    for (let i = 0; i < samples; i++) {
      const t = i / sampleRate;
      const frequency1 = 880; // A5
      const frequency2 = 1320; // E6
      const envelope = Math.exp(-t * 3);
      const phase = t < 0.2 ? 0 : Math.PI; // 两个音符
      
      buffer[i] = envelope * (
        Math.sin(2 * Math.PI * frequency1 * t + phase) * 0.2 +
        Math.sin(2 * Math.PI * frequency2 * t + phase) * 0.15
      );
    }

    return buffer;
  }

  // 创建音频缓冲区
  private async createAudioBuffer(soundData: Float32Array): Promise<AudioBuffer> {
    if (!this.audioContext) {
      throw new Error('音频上下文未初始化');
    }

    const audioBuffer = this.audioContext.createBuffer(1, soundData.length, 44100);
    audioBuffer.copyToChannel(soundData, 0);
    return audioBuffer;
  }

  // 播放声音
  async playSound(
    soundType: string,
    options: {
      volume?: number;
      pitch?: number;
      delay?: number;
    } = {}
  ): Promise<void> {
    if (!this.soundEnabled || !this.audioContext) {
      return;
    }

    try {
      const {
        volume = this.volume,
        pitch = 1,
        delay = 0
      } = options;

      // 获取声音缓冲区
      let audioBuffer = this.soundCache.get(soundType);
      if (!audioBuffer) {
        // 尝试加载自定义声音
        const customSoundUrl = this.customSounds.get(soundType);
        if (customSoundUrl) {
          audioBuffer = await this.loadCustomSound(customSoundUrl);
          this.soundCache.set(soundType, audioBuffer);
        } else {
          console.warn(`未找到声音类型: ${soundType}`);
          return;
        }
      }

      // 创建音频源
      const source = this.audioContext.createBufferSource();
      const gainNode = this.audioContext.createGain();
      
      source.buffer = audioBuffer;
      source.playbackRate.value = pitch;
      gainNode.gain.value = volume;
      
      // 连接音频节点
      source.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      // 播放声音
      const startTime = this.audioContext.currentTime + delay;
      source.start(startTime);
      
      // 清理资源
      source.onended = () => {
        source.disconnect();
        gainNode.disconnect();
      };
    } catch (error) {
      console.warn(`播放声音失败 (${soundType}):`, error);
    }
  }

  // 加载自定义声音
  private async loadCustomSound(url: string): Promise<AudioBuffer> {
    if (!this.audioContext) {
      throw new Error('音频上下文未初始化');
    }

    try {
      const response = await fetch(url);
      const arrayBuffer = await response.arrayBuffer();
      return await this.audioContext.decodeAudioData(arrayBuffer);
    } catch (error) {
      throw new Error(`加载自定义声音失败: ${error}`);
    }
  }

  // 播放通知声音
  async playNotificationSound(
    notificationType: string,
    priority: 'low' | 'medium' | 'high' = 'medium'
  ): Promise<void> {
    const soundMap: Record<string, string> = {
      'new_annotation': 'map_notification',
      'nearby_activity': 'notification',
      'trending_spot': 'success',
      'location_alert': 'warning',
      'system_message': 'message',
      'error': 'error',
      'success': 'success',
      'warning': 'warning',
      'info': 'notification'
    };

    const soundType = soundMap[notificationType] || 'notification';
    
    // 根据优先级调整音量和音调
    const options = {
      volume: priority === 'high' ? this.volume * 1.2 : 
              priority === 'medium' ? this.volume : 
              this.volume * 0.7,
      pitch: priority === 'high' ? 1.1 : 
             priority === 'medium' ? 1.0 : 
             0.9
    };

    await this.playSound(soundType, options);
  }

  // 播放序列声音
  async playSequence(
    sequence: Array<{
      soundType: string;
      delay: number;
      volume?: number;
      pitch?: number;
    }>
  ): Promise<void> {
    for (const item of sequence) {
      await this.playSound(item.soundType, {
        volume: item.volume,
        pitch: item.pitch,
        delay: item.delay / 1000 // 转换为秒
      });
    }
  }

  // 设置自定义声音
  setCustomSound(soundType: string, audioUrl: string): void {
    this.customSounds.set(soundType, audioUrl);
    // 清除缓存，下次播放时重新加载
    this.soundCache.delete(soundType);
    this.saveUserPreferences();
  }

  // 移除自定义声音
  removeCustomSound(soundType: string): void {
    this.customSounds.delete(soundType);
    this.soundCache.delete(soundType);
    this.saveUserPreferences();
  }

  // 启用/禁用声音
  setSoundEnabled(enabled: boolean): void {
    this.soundEnabled = enabled;
    this.saveUserPreferences();
  }

  // 设置音量
  setVolume(volume: number): void {
    this.volume = Math.max(0, Math.min(1, volume));
    this.saveUserPreferences();
  }

  // 获取声音设置
  getSoundSettings(): {
    enabled: boolean;
    volume: number;
    customSounds: Record<string, string>;
    availableSounds: string[];
  } {
    return {
      enabled: this.soundEnabled,
      volume: this.volume,
      customSounds: Object.fromEntries(this.customSounds),
      availableSounds: Array.from(this.soundCache.keys())
    };
  }

  // 测试声音
  async testSound(soundType: string): Promise<void> {
    await this.playSound(soundType, { volume: this.volume });
  }

  // 保存用户偏好
  private saveUserPreferences(): void {
    try {
      const preferences = {
        soundEnabled: this.soundEnabled,
        volume: this.volume,
        customSounds: Object.fromEntries(this.customSounds)
      };
      localStorage.setItem('notificationSoundPreferences', JSON.stringify(preferences));
    } catch (error) {
      console.warn('保存声音偏好失败:', error);
    }
  }

  // 加载用户偏好
  private loadUserPreferences(): void {
    try {
      const saved = localStorage.getItem('notificationSoundPreferences');
      if (saved) {
        const preferences = JSON.parse(saved);
        this.soundEnabled = preferences.soundEnabled ?? true;
        this.volume = preferences.volume ?? 0.5;
        this.customSounds = new Map(Object.entries(preferences.customSounds || {}));
      }
    } catch (error) {
      console.warn('加载声音偏好失败:', error);
    }
  }

  // 清理资源
  cleanup(): void {
    if (this.audioContext) {
      this.audioContext.close();
      this.audioContext = null;
    }
    this.soundCache.clear();
    this.customSounds.clear();
  }
}

// 导出单例实例
export const notificationSoundService = new NotificationSoundService();
export default notificationSoundService;