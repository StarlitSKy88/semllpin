import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  User,
  Bell,
  Shield,
  Palette,
  Database,
  Eye,
  Save,
  X,
  Volume2,
  VolumeX,
  Key,
  Monitor,
  Moon,
  Sun,
  Camera,
  Edit,
  Mail
} from 'lucide-react';
import { toast } from 'sonner';
import { useMobile } from '../hooks/useMobile';
import { useNetworkStatus } from '../hooks/useNetworkStatus';
import EmptyState from '../components/EmptyState';
import { LoadingButton } from '../components/LoadingButton';
import { NetworkDependent } from '../components/NetworkDependent';
import { DecorativeElements } from '../components/UI/DecorativeElements';

// 个人资料设置组件
const ProfileSettings: React.FC = () => {
  const [profile, setProfile] = useState({
    username: '',
    email: '',
    bio: '',
    avatar: '',
    location: '',
    website: '',
    birthday: '',
    gender: '',
    phone: ''
  });
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    // 从localStorage加载用户资料
    const savedProfile = localStorage.getItem('userProfile');
    if (savedProfile) {
      setProfile(JSON.parse(savedProfile));
    }
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
    try {
      // 模拟API调用
      await new Promise(resolve => setTimeout(resolve, 1000));
      localStorage.setItem('userProfile', JSON.stringify(profile));
      setIsEditing(false);
      toast.success('个人资料已更新');
    } catch {
      toast.error('保存失败，请重试');
    } finally {
      setIsSaving(false);
    }
  };

  const handleCancel = () => {
    // 重新加载保存的数据
    const savedProfile = localStorage.getItem('userProfile');
    if (savedProfile) {
      setProfile(JSON.parse(savedProfile));
    }
    setIsEditing(false);
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-gray-800">个人资料</h2>
        {!isEditing ? (
          <button
            onClick={() => setIsEditing(true)}
            className="flex items-center gap-2 px-4 py-2 text-blue-600 hover:text-blue-700 transition-colors"
          >
            <Edit className="w-4 h-4" />
            编辑
          </button>
        ) : (
          <div className="flex gap-2">
            <button
              onClick={handleCancel}
              className="flex items-center gap-2 px-4 py-2 text-gray-600 hover:text-gray-700 transition-colors"
            >
              <X className="w-4 h-4" />
              取消
            </button>
            <LoadingButton
              onClick={handleSave}
              loading={isSaving}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Save className="w-4 h-4" />
              保存
            </LoadingButton>
          </div>
        )}
      </div>

      <div className="space-y-6">
        {/* 头像 */}
        <div className="flex items-center gap-4">
          <div className="w-20 h-20 bg-gray-200 rounded-full flex items-center justify-center overflow-hidden">
            {profile.avatar ? (
              <img src={profile.avatar} alt="头像" className="w-full h-full object-cover" />
            ) : (
              <User className="w-8 h-8 text-gray-400" />
            )}
          </div>
          {isEditing && (
            <div>
              <button className="flex items-center gap-2 px-3 py-2 text-sm text-blue-600 hover:text-blue-700 transition-colors">
                <Camera className="w-4 h-4" />
                更换头像
              </button>
            </div>
          )}
        </div>

        {/* 基本信息 */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              用户名
            </label>
            <input
              type="text"
              value={profile.username}
              onChange={(e) => setProfile({ ...profile, username: e.target.value })}
              disabled={!isEditing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
              placeholder="请输入用户名"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              邮箱
            </label>
            <input
              type="email"
              value={profile.email}
              onChange={(e) => setProfile({ ...profile, email: e.target.value })}
              disabled={!isEditing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
              placeholder="请输入邮箱"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              手机号
            </label>
            <input
              type="tel"
              value={profile.phone}
              onChange={(e) => setProfile({ ...profile, phone: e.target.value })}
              disabled={!isEditing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
              placeholder="请输入手机号"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              生日
            </label>
            <input
              type="date"
              value={profile.birthday}
              onChange={(e) => setProfile({ ...profile, birthday: e.target.value })}
              disabled={!isEditing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              性别
            </label>
            <select
              value={profile.gender}
              onChange={(e) => setProfile({ ...profile, gender: e.target.value })}
              disabled={!isEditing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
            >
              <option value="">请选择</option>
              <option value="male">男</option>
              <option value="female">女</option>
              <option value="other">其他</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              所在地
            </label>
            <input
              type="text"
              value={profile.location}
              onChange={(e) => setProfile({ ...profile, location: e.target.value })}
              disabled={!isEditing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
              placeholder="请输入所在地"
            />
          </div>
        </div>

        {/* 个人网站 */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            个人网站
          </label>
          <input
            type="url"
            value={profile.website}
            onChange={(e) => setProfile({ ...profile, website: e.target.value })}
            disabled={!isEditing}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
            placeholder="https://"
          />
        </div>

        {/* 个人简介 */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            个人简介
          </label>
          <textarea
            value={profile.bio}
            onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
            disabled={!isEditing}
            rows={4}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500 resize-none"
            placeholder="介绍一下自己..."
          />
        </div>
      </div>
    </div>
  );
};

// 通知设置组件
const NotificationSettings: React.FC = () => {
  const [notifications, setNotifications] = useState({
    email: {
      newFollower: true,
      newComment: true,
      newLike: false,
      systemUpdate: true,
      newsletter: false
    },
    push: {
      newFollower: true,
      newComment: true,
      newLike: false,
      systemUpdate: true,
      newsletter: false
    },
    sound: {
      enabled: true,
      volume: 50
    },
    doNotDisturb: {
      enabled: false,
      startTime: '22:00',
      endTime: '08:00'
    }
  });

  useEffect(() => {
    const savedNotifications = localStorage.getItem('notificationSettings');
    if (savedNotifications) {
      setNotifications(JSON.parse(savedNotifications));
    }
  }, []);

  const handleSave = () => {
    localStorage.setItem('notificationSettings', JSON.stringify(notifications));
    toast.success('通知设置已保存');
  };

  const updateEmailNotification = (key: string, value: boolean) => {
    setNotifications(prev => ({
      ...prev,
      email: { ...prev.email, [key]: value }
    }));
  };

  const updatePushNotification = (key: string, value: boolean) => {
    setNotifications(prev => ({
      ...prev,
      push: { ...prev.push, [key]: value }
    }));
  };

  const updateSoundSettings = (key: string, value: boolean | number) => {
    setNotifications(prev => ({
      ...prev,
      sound: { ...prev.sound, [key]: value }
    }));
  };

  const updateDoNotDisturb = (key: string, value: boolean | string) => {
    setNotifications(prev => ({
      ...prev,
      doNotDisturb: { ...prev.doNotDisturb, [key]: value }
    }));
  };

  return (
    <div className="space-y-6">
      {/* 邮件通知 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Mail className="w-5 h-5 text-blue-600" />
          <h3 className="text-lg font-semibold text-gray-800">邮件通知</h3>
        </div>
        
        <div className="space-y-4">
          {[
            { key: 'newFollower', label: '新关注者', desc: '有人关注了您时发送邮件' },
            { key: 'newComment', label: '新评论', desc: '有人评论了您的内容时发送邮件' },
            { key: 'newLike', label: '新点赞', desc: '有人点赞了您的内容时发送邮件' },
            { key: 'systemUpdate', label: '系统更新', desc: '系统有重要更新时发送邮件' },
            { key: 'newsletter', label: '新闻简报', desc: '定期发送平台动态和精选内容' }
          ].map(item => (
            <div key={item.key} className="flex items-center justify-between">
              <div>
                <div className="font-medium text-gray-800">{item.label}</div>
                <div className="text-sm text-gray-600">{item.desc}</div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={notifications.email[item.key as keyof typeof notifications.email]}
                  onChange={(e) => updateEmailNotification(item.key, e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>
          ))}
        </div>
      </div>

      {/* 推送通知 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Bell className="w-5 h-5 text-green-600" />
          <h3 className="text-lg font-semibold text-gray-800">推送通知</h3>
        </div>
        
        <div className="space-y-4">
          {[
            { key: 'newFollower', label: '新关注者', desc: '有人关注了您时推送通知' },
            { key: 'newComment', label: '新评论', desc: '有人评论了您的内容时推送通知' },
            { key: 'newLike', label: '新点赞', desc: '有人点赞了您的内容时推送通知' },
            { key: 'systemUpdate', label: '系统更新', desc: '系统有重要更新时推送通知' },
            { key: 'newsletter', label: '新闻简报', desc: '定期推送平台动态和精选内容' }
          ].map(item => (
            <div key={item.key} className="flex items-center justify-between">
              <div>
                <div className="font-medium text-gray-800">{item.label}</div>
                <div className="text-sm text-gray-600">{item.desc}</div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={notifications.push[item.key as keyof typeof notifications.push]}
                  onChange={(e) => updatePushNotification(item.key, e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-green-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
              </label>
            </div>
          ))}
        </div>
      </div>

      {/* 声音设置 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          {notifications.sound.enabled ? (
            <Volume2 className="w-5 h-5 text-purple-600" />
          ) : (
            <VolumeX className="w-5 h-5 text-gray-400" />
          )}
          <h3 className="text-lg font-semibold text-gray-800">声音设置</h3>
        </div>
        
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-800">启用通知声音</div>
              <div className="text-sm text-gray-600">接收通知时播放提示音</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={notifications.sound.enabled}
                onChange={(e) => updateSoundSettings('enabled', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
            </label>
          </div>
          
          {notifications.sound.enabled && (
            <div>
              <div className="font-medium text-gray-800 mb-2">音量</div>
              <input
                type="range"
                min="0"
                max="100"
                value={notifications.sound.volume}
                onChange={(e) => updateSoundSettings('volume', parseInt(e.target.value))}
                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
              />
              <div className="flex justify-between text-sm text-gray-600 mt-1">
                <span>静音</span>
                <span>{notifications.sound.volume}%</span>
                <span>最大</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 免打扰模式 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Moon className="w-5 h-5 text-indigo-600" />
          <h3 className="text-lg font-semibold text-gray-800">免打扰模式</h3>
        </div>
        
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-800">启用免打扰模式</div>
              <div className="text-sm text-gray-600">在指定时间段内不接收通知</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={notifications.doNotDisturb.enabled}
                onChange={(e) => updateDoNotDisturb('enabled', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-indigo-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
            </label>
          </div>
          
          {notifications.doNotDisturb.enabled && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  开始时间
                </label>
                <input
                  type="time"
                  value={notifications.doNotDisturb.startTime}
                  onChange={(e) => updateDoNotDisturb('startTime', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  结束时间
                </label>
                <input
                  type="time"
                  value={notifications.doNotDisturb.endTime}
                  onChange={(e) => updateDoNotDisturb('endTime', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 保存按钮 */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Save className="w-4 h-4" />
          保存设置
        </button>
      </div>
    </div>
  );
};

// 隐私安全设置组件
const PrivacySettings: React.FC = () => {
  const [privacy, setPrivacy] = useState({
    profileVisibility: 'public', // public, friends, private
    showEmail: false,
    showPhone: false,
    showLocation: false,
    allowMessages: 'everyone', // everyone, friends, none
    allowComments: 'everyone', // everyone, friends, none
    allowTagging: true,
    dataCollection: {
      analytics: true,
      personalization: true,
      marketing: false
    },
    twoFactorAuth: {
      enabled: false,
      method: 'sms' // sms, email, app
    },
    loginAlerts: true,
    sessionTimeout: 30 // minutes
  });

  const [showChangePassword, setShowChangePassword] = useState(false);
  const [passwords, setPasswords] = useState({
    current: '',
    new: '',
    confirm: ''
  });

  useEffect(() => {
    const savedPrivacy = localStorage.getItem('privacySettings');
    if (savedPrivacy) {
      setPrivacy(JSON.parse(savedPrivacy));
    }
  }, []);

  const handleSave = () => {
    localStorage.setItem('privacySettings', JSON.stringify(privacy));
    toast.success('隐私设置已保存');
  };

  const handleChangePassword = async () => {
    if (passwords.new !== passwords.confirm) {
      toast.error('新密码确认不匹配');
      return;
    }
    if (passwords.new.length < 8) {
      toast.error('密码长度至少8位');
      return;
    }
    
    try {
      // 模拟API调用
      await new Promise(resolve => setTimeout(resolve, 1000));
      toast.success('密码修改成功');
      setPasswords({ current: '', new: '', confirm: '' });
      setShowChangePassword(false);
    } catch {
      toast.error('密码修改失败');
    }
  };

  const updateDataCollection = (key: string, value: boolean) => {
    setPrivacy(prev => ({
      ...prev,
      dataCollection: { ...prev.dataCollection, [key]: value }
    }));
  };

  const updateTwoFactorAuth = (key: string, value: boolean | string) => {
    setPrivacy(prev => ({
      ...prev,
      twoFactorAuth: { ...prev.twoFactorAuth, [key]: value }
    }));
  };

  return (
    <div className="space-y-6">
      {/* 账户安全 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="w-5 h-5 text-green-600" />
          <h3 className="text-lg font-semibold text-gray-800">账户安全</h3>
        </div>
        
        <div className="space-y-6">
          {/* 修改密码 */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="font-medium text-gray-800">登录密码</div>
                <div className="text-sm text-gray-600">定期更换密码以保护账户安全</div>
              </div>
              <button
                onClick={() => setShowChangePassword(!showChangePassword)}
                className="flex items-center gap-2 px-4 py-2 text-blue-600 hover:text-blue-700 transition-colors"
              >
                <Key className="w-4 h-4" />
                修改密码
              </button>
            </div>
            
            {showChangePassword && (
              <div className="bg-gray-50 rounded-lg p-4 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    当前密码
                  </label>
                  <input
                    type="password"
                    value={passwords.current}
                    onChange={(e) => setPasswords({ ...passwords, current: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="请输入当前密码"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    新密码
                  </label>
                  <input
                    type="password"
                    value={passwords.new}
                    onChange={(e) => setPasswords({ ...passwords, new: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="请输入新密码（至少8位）"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    确认新密码
                  </label>
                  <input
                    type="password"
                    value={passwords.confirm}
                    onChange={(e) => setPasswords({ ...passwords, confirm: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="请再次输入新密码"
                  />
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setShowChangePassword(false)}
                    className="px-4 py-2 text-gray-600 hover:text-gray-700 transition-colors"
                  >
                    取消
                  </button>
                  <button
                    onClick={handleChangePassword}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    确认修改
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* 两步验证 */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="font-medium text-gray-800">两步验证</div>
                <div className="text-sm text-gray-600">为您的账户添加额外的安全保护</div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={privacy.twoFactorAuth.enabled}
                  onChange={(e) => updateTwoFactorAuth('enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-green-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
              </label>
            </div>
            
            {privacy.twoFactorAuth.enabled && (
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="mb-3">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    验证方式
                  </label>
                  <div className="space-y-2">
                    {[
                      { value: 'sms', label: '短信验证', desc: '通过手机短信接收验证码' },
                      { value: 'email', label: '邮箱验证', desc: '通过邮箱接收验证码' },
                      { value: 'app', label: '身份验证器', desc: '使用身份验证器应用生成验证码' }
                    ].map(method => (
                      <label key={method.value} className="flex items-start gap-3 cursor-pointer">
                        <input
                          type="radio"
                          name="twoFactorMethod"
                          value={method.value}
                          checked={privacy.twoFactorAuth.method === method.value}
                          onChange={(e) => updateTwoFactorAuth('method', e.target.value)}
                          className="mt-1"
                        />
                        <div>
                          <div className="font-medium text-gray-800">{method.label}</div>
                          <div className="text-sm text-gray-600">{method.desc}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* 登录提醒 */}
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-800">登录提醒</div>
              <div className="text-sm text-gray-600">有新设备登录时发送通知</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={privacy.loginAlerts}
                onChange={(e) => setPrivacy({ ...privacy, loginAlerts: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          {/* 会话超时 */}
          <div>
            <div className="font-medium text-gray-800 mb-2">会话超时</div>
            <div className="text-sm text-gray-600 mb-3">无操作时自动退出登录的时间</div>
            <select
              value={privacy.sessionTimeout}
              onChange={(e) => setPrivacy({ ...privacy, sessionTimeout: parseInt(e.target.value) })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value={15}>15分钟</option>
              <option value={30}>30分钟</option>
              <option value={60}>1小时</option>
              <option value={120}>2小时</option>
              <option value={240}>4小时</option>
              <option value={0}>永不超时</option>
            </select>
          </div>
        </div>
      </div>

      {/* 隐私控制 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <Eye className="w-5 h-5 text-purple-600" />
          <h3 className="text-lg font-semibold text-gray-800">隐私控制</h3>
        </div>
        
        <div className="space-y-6">
          {/* 资料可见性 */}
          <div>
            <div className="font-medium text-gray-800 mb-2">资料可见性</div>
            <div className="text-sm text-gray-600 mb-3">控制谁可以查看您的个人资料</div>
            <div className="space-y-2">
              {[
                { value: 'public', label: '公开', desc: '所有人都可以查看' },
                { value: 'friends', label: '仅好友', desc: '只有好友可以查看' },
                { value: 'private', label: '私密', desc: '只有自己可以查看' }
              ].map(option => (
                <label key={option.value} className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="profileVisibility"
                    value={option.value}
                    checked={privacy.profileVisibility === option.value}
                    onChange={(e) => setPrivacy({ ...privacy, profileVisibility: e.target.value })}
                    className="mt-1"
                  />
                  <div>
                    <div className="font-medium text-gray-800">{option.label}</div>
                    <div className="text-sm text-gray-600">{option.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* 联系信息显示 */}
          <div>
            <div className="font-medium text-gray-800 mb-3">联系信息显示</div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-800">显示邮箱</div>
                  <div className="text-sm text-gray-600">在个人资料中显示邮箱地址</div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={privacy.showEmail}
                    onChange={(e) => setPrivacy({ ...privacy, showEmail: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                </label>
              </div>
              
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-800">显示手机号</div>
                  <div className="text-sm text-gray-600">在个人资料中显示手机号码</div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={privacy.showPhone}
                    onChange={(e) => setPrivacy({ ...privacy, showPhone: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                </label>
              </div>
              
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-800">显示位置</div>
                  <div className="text-sm text-gray-600">在个人资料中显示所在地</div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={privacy.showLocation}
                    onChange={(e) => setPrivacy({ ...privacy, showLocation: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                </label>
              </div>
            </div>
          </div>

          {/* 互动权限 */}
          <div>
            <div className="font-medium text-gray-800 mb-3">互动权限</div>
            <div className="space-y-4">
              <div>
                <div className="font-medium text-gray-800 mb-2">谁可以给我发消息</div>
                <select
                  value={privacy.allowMessages}
                  onChange={(e) => setPrivacy({ ...privacy, allowMessages: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                >
                  <option value="everyone">所有人</option>
                  <option value="friends">仅好友</option>
                  <option value="none">不允许</option>
                </select>
              </div>
              
              <div>
                <div className="font-medium text-gray-800 mb-2">谁可以评论我的内容</div>
                <select
                  value={privacy.allowComments}
                  onChange={(e) => setPrivacy({ ...privacy, allowComments: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                >
                  <option value="everyone">所有人</option>
                  <option value="friends">仅好友</option>
                  <option value="none">不允许</option>
                </select>
              </div>
              
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-800">允许标记我</div>
                  <div className="text-sm text-gray-600">其他用户可以在内容中标记您</div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={privacy.allowTagging}
                    onChange={(e) => setPrivacy({ ...privacy, allowTagging: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 数据收集 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <Database className="w-5 h-5 text-orange-600" />
          <h3 className="text-lg font-semibold text-gray-800">数据收集</h3>
        </div>
        
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-800">使用分析</div>
              <div className="text-sm text-gray-600">收集使用数据以改善产品体验</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={privacy.dataCollection.analytics}
                onChange={(e) => updateDataCollection('analytics', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600"></div>
            </label>
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-800">个性化推荐</div>
              <div className="text-sm text-gray-600">基于您的偏好提供个性化内容</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={privacy.dataCollection.personalization}
                onChange={(e) => updateDataCollection('personalization', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600"></div>
            </label>
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-800">营销推广</div>
              <div className="text-sm text-gray-600">接收相关产品和服务的推广信息</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={privacy.dataCollection.marketing}
                onChange={(e) => updateDataCollection('marketing', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600"></div>
            </label>
          </div>
        </div>
      </div>

      {/* 保存按钮 */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Save className="w-4 h-4" />
          保存设置
        </button>
      </div>
    </div>
  );
};

// 外观主题设置组件
const AppearanceSettings: React.FC = () => {
  const [appearance, setAppearance] = useState({
    theme: 'light', // light, dark, auto
    colorScheme: 'blue', // blue, green, purple, orange, red
    fontSize: 'medium', // small, medium, large
    compactMode: false,
    animations: true,
    highContrast: false,
    reducedMotion: false,
    customColors: {
      primary: '#3B82F6',
      secondary: '#6B7280',
      accent: '#10B981'
    }
  });

  useEffect(() => {
    const savedAppearance = localStorage.getItem('appearanceSettings');
    if (savedAppearance) {
      setAppearance(JSON.parse(savedAppearance));
    }
  }, []);

  const handleSave = () => {
    localStorage.setItem('appearanceSettings', JSON.stringify(appearance));
    // 应用主题设置
    document.documentElement.setAttribute('data-theme', appearance.theme);
    document.documentElement.setAttribute('data-color-scheme', appearance.colorScheme);
    document.documentElement.setAttribute('data-font-size', appearance.fontSize);
    if (appearance.compactMode) {
      document.documentElement.classList.add('compact-mode');
    } else {
      document.documentElement.classList.remove('compact-mode');
    }
    if (appearance.highContrast) {
      document.documentElement.classList.add('high-contrast');
    } else {
      document.documentElement.classList.remove('high-contrast');
    }
    if (appearance.reducedMotion) {
      document.documentElement.classList.add('reduced-motion');
    } else {
      document.documentElement.classList.remove('reduced-motion');
    }
    toast.success('外观设置已保存');
  };

  const updateCustomColor = (key: string, value: string) => {
    setAppearance(prev => ({
      ...prev,
      customColors: { ...prev.customColors, [key]: value }
    }));
  };

  return (
    <div className="space-y-6">
      {/* 主题设置 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <Palette className="w-5 h-5 text-purple-600" />
          <h3 className="text-lg font-semibold text-gray-800">主题设置</h3>
        </div>
        
        <div className="space-y-6">
          {/* 主题模式 */}
          <div>
            <div className="font-medium text-gray-800 mb-3">主题模式</div>
            <div className="grid grid-cols-3 gap-3">
              {[
                { value: 'light', label: '浅色', icon: Sun, desc: '明亮的界面主题' },
                { value: 'dark', label: '深色', icon: Moon, desc: '深色的界面主题' },
                { value: 'auto', label: '自动', icon: Monitor, desc: '跟随系统设置' }
              ].map(theme => {
                const IconComponent = theme.icon;
                return (
                  <label
                    key={theme.value}
                    className={`flex flex-col items-center p-4 border-2 rounded-lg cursor-pointer transition-colors ${
                      appearance.theme === theme.value
                        ? 'border-purple-500 bg-purple-50'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <input
                      type="radio"
                      name="theme"
                      value={theme.value}
                      checked={appearance.theme === theme.value}
                      onChange={(e) => setAppearance({ ...appearance, theme: e.target.value })}
                      className="sr-only"
                    />
                    <IconComponent className={`w-6 h-6 mb-2 ${
                      appearance.theme === theme.value ? 'text-purple-600' : 'text-gray-400'
                    }`} />
                    <div className={`font-medium ${
                      appearance.theme === theme.value ? 'text-purple-800' : 'text-gray-800'
                    }`}>
                      {theme.label}
                    </div>
                    <div className="text-xs text-gray-600 text-center mt-1">
                      {theme.desc}
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          {/* 配色方案 */}
          <div>
            <div className="font-medium text-gray-800 mb-3">配色方案</div>
            <div className="grid grid-cols-5 gap-3">
              {[
                { value: 'blue', label: '蓝色', color: '#3B82F6' },
                { value: 'green', label: '绿色', color: '#10B981' },
                { value: 'purple', label: '紫色', color: '#8B5CF6' },
                { value: 'orange', label: '橙色', color: '#F59E0B' },
                { value: 'red', label: '红色', color: '#EF4444' }
              ].map(scheme => (
                <label
                  key={scheme.value}
                  className={`flex flex-col items-center p-3 border-2 rounded-lg cursor-pointer transition-colors ${
                    appearance.colorScheme === scheme.value
                      ? 'border-gray-800 bg-gray-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <input
                    type="radio"
                    name="colorScheme"
                    value={scheme.value}
                    checked={appearance.colorScheme === scheme.value}
                    onChange={(e) => setAppearance({ ...appearance, colorScheme: e.target.value })}
                    className="sr-only"
                  />
                  <div
                     className="w-8 h-8 rounded-full border-2 border-white shadow-sm"
                     style={{ backgroundColor: scheme.color }}
                   ></div>
                   <div className={`text-xs mt-1 ${
                     appearance.colorScheme === scheme.value ? 'text-gray-800' : 'text-gray-600'
                   }`}>
                     {scheme.label}
                   </div>
                 </label>
               ))}
             </div>
           </div>

           {/* 字体大小 */}
           <div>
             <div className="font-medium text-gray-800 mb-3">字体大小</div>
             <div className="grid grid-cols-3 gap-3">
               {[
                 { value: 'small', label: '小', desc: '紧凑显示' },
                 { value: 'medium', label: '中', desc: '标准显示' },
                 { value: 'large', label: '大', desc: '舒适显示' }
               ].map(size => (
                 <label
                   key={size.value}
                   className={`flex flex-col items-center p-3 border-2 rounded-lg cursor-pointer transition-colors ${
                     appearance.fontSize === size.value
                       ? 'border-purple-500 bg-purple-50'
                       : 'border-gray-200 hover:border-gray-300'
                   }`}
                 >
                   <input
                     type="radio"
                     name="fontSize"
                     value={size.value}
                     checked={appearance.fontSize === size.value}
                     onChange={(e) => setAppearance({ ...appearance, fontSize: e.target.value })}
                     className="sr-only"
                   />
                   <div className={`font-medium mb-1 ${
                     size.value === 'small' ? 'text-sm' : size.value === 'large' ? 'text-lg' : 'text-base'
                   } ${
                     appearance.fontSize === size.value ? 'text-purple-800' : 'text-gray-800'
                   }`}>
                     {size.label}
                   </div>
                   <div className="text-xs text-gray-600 text-center">
                     {size.desc}
                   </div>
                 </label>
               ))}
             </div>
           </div>

           {/* 界面选项 */}
           <div>
             <div className="font-medium text-gray-800 mb-3">界面选项</div>
             <div className="space-y-4">
               <div className="flex items-center justify-between">
                 <div>
                   <div className="font-medium text-gray-800">紧凑模式</div>
                   <div className="text-sm text-gray-600">减少界面元素间距，显示更多内容</div>
                 </div>
                 <label className="relative inline-flex items-center cursor-pointer">
                   <input
                     type="checkbox"
                     checked={appearance.compactMode}
                     onChange={(e) => setAppearance({ ...appearance, compactMode: e.target.checked })}
                     className="sr-only peer"
                   />
                   <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                 </label>
               </div>

               <div className="flex items-center justify-between">
                 <div>
                   <div className="font-medium text-gray-800">动画效果</div>
                   <div className="text-sm text-gray-600">启用界面过渡动画和交互效果</div>
                 </div>
                 <label className="relative inline-flex items-center cursor-pointer">
                   <input
                     type="checkbox"
                     checked={appearance.animations}
                     onChange={(e) => setAppearance({ ...appearance, animations: e.target.checked })}
                     className="sr-only peer"
                   />
                   <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                 </label>
               </div>

               <div className="flex items-center justify-between">
                 <div>
                   <div className="font-medium text-gray-800">高对比度</div>
                   <div className="text-sm text-gray-600">提高文字和背景的对比度，便于阅读</div>
                 </div>
                 <label className="relative inline-flex items-center cursor-pointer">
                   <input
                     type="checkbox"
                     checked={appearance.highContrast}
                     onChange={(e) => setAppearance({ ...appearance, highContrast: e.target.checked })}
                     className="sr-only peer"
                   />
                   <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                 </label>
               </div>

               <div className="flex items-center justify-between">
                 <div>
                   <div className="font-medium text-gray-800">减少动效</div>
                   <div className="text-sm text-gray-600">减少动画和过渡效果，适合敏感用户</div>
                 </div>
                 <label className="relative inline-flex items-center cursor-pointer">
                   <input
                     type="checkbox"
                     checked={appearance.reducedMotion}
                     onChange={(e) => setAppearance({ ...appearance, reducedMotion: e.target.checked })}
                     className="sr-only peer"
                   />
                   <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                 </label>
               </div>
             </div>
           </div>

           {/* 自定义颜色 */}
           <div>
             <div className="font-medium text-gray-800 mb-3">自定义颜色</div>
             <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-2">
                   主色调
                 </label>
                 <div className="flex items-center gap-2">
                   <input
                     type="color"
                     value={appearance.customColors.primary}
                     onChange={(e) => updateCustomColor('primary', e.target.value)}
                     className="w-12 h-10 border border-gray-300 rounded-lg cursor-pointer"
                   />
                   <input
                     type="text"
                     value={appearance.customColors.primary}
                     onChange={(e) => updateCustomColor('primary', e.target.value)}
                     className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                     placeholder="#3B82F6"
                   />
                 </div>
               </div>

               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-2">
                   辅助色
                 </label>
                 <div className="flex items-center gap-2">
                   <input
                     type="color"
                     value={appearance.customColors.secondary}
                     onChange={(e) => updateCustomColor('secondary', e.target.value)}
                     className="w-12 h-10 border border-gray-300 rounded-lg cursor-pointer"
                   />
                   <input
                     type="text"
                     value={appearance.customColors.secondary}
                     onChange={(e) => updateCustomColor('secondary', e.target.value)}
                     className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                     placeholder="#6B7280"
                   />
                 </div>
               </div>

               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-2">
                   强调色
                 </label>
                 <div className="flex items-center gap-2">
                   <input
                     type="color"
                     value={appearance.customColors.accent}
                     onChange={(e) => updateCustomColor('accent', e.target.value)}
                     className="w-12 h-10 border border-gray-300 rounded-lg cursor-pointer"
                   />
                   <input
                     type="text"
                     value={appearance.customColors.accent}
                     onChange={(e) => updateCustomColor('accent', e.target.value)}
                     className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                     placeholder="#10B981"
                   />
                 </div>
               </div>
             </div>
           </div>
         </div>
       </div>

       {/* 保存按钮 */}
       <div className="flex justify-end">
         <button
           onClick={handleSave}
           className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
         >
           <Save className="w-4 h-4" />
           保存设置
         </button>
       </div>
     </div>
   );
 };

 // 主设置页面组件
 const Settings: React.FC = () => {
   const [activeTab, setActiveTab] = useState('profile');
   const { isMobile } = useMobile();
   const { isOnline } = useNetworkStatus();

   const tabs = [
     { id: 'profile', label: '个人资料', icon: User },
     { id: 'notifications', label: '通知设置', icon: Bell },
     { id: 'privacy', label: '隐私安全', icon: Shield },
     { id: 'appearance', label: '外观主题', icon: Palette }
   ];

   const renderTabContent = () => {
     switch (activeTab) {
       case 'profile':
         return <ProfileSettings />;
       case 'notifications':
         return <NotificationSettings />;
       case 'privacy':
         return <PrivacySettings />;
       case 'appearance':
         return <AppearanceSettings />;
       default:
         return <ProfileSettings />;
     }
   };

   if (!isOnline) {
     return (
       <div className="min-h-screen bg-gray-50 flex items-center justify-center">
         <EmptyState
           type="offline"
           title="网络连接已断开"
           description="请检查您的网络连接后重试"
         />
       </div>
     );
   }

   return (
     <NetworkDependent>
       <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
         {/* Background decorative elements */}
         <DecorativeElements variant="background" animate={true} />
         
         {/* Floating decorative elements */}
         <DecorativeElements variant="floating" position="top-left" animate={true} />
         <DecorativeElements variant="floating" position="top-right" animate={true} />
         <DecorativeElements variant="floating" position="bottom-left" animate={true} />
         <DecorativeElements variant="floating" position="bottom-right" animate={true} />
         
         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
           {/* 页面标题 */}
           <div className="mb-8">
             <h1 className="text-3xl font-bold text-pomegranate-900">设置</h1>
             <p className="mt-2 text-pomegranate-600">管理您的账户设置和偏好</p>
           </div>

           <div className={`${isMobile ? 'space-y-6' : 'flex gap-8'}`}>
             {/* 侧边栏导航 */}
             <div className={`${isMobile ? 'w-full' : 'w-64'} flex-shrink-0`}>
               <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                 <nav className="space-y-1">
                   {tabs.map(tab => {
                     const IconComponent = tab.icon;
                     return (
                       <button
                         key={tab.id}
                         onClick={() => setActiveTab(tab.id)}
                         className={`w-full flex items-center gap-3 px-3 py-2 text-left rounded-lg transition-colors ${
                           activeTab === tab.id
                             ? 'bg-pomegranate-50 text-pomegranate-700 border border-pomegranate-200'
                             : 'text-gray-700 hover:bg-gray-50'
                         }`}
                       >
                         <IconComponent className={`w-5 h-5 ${
                           activeTab === tab.id ? 'text-pomegranate-600' : 'text-gray-500'
                         }`} />
                         <span className="font-medium">{tab.label}</span>
                       </button>
                     );
                   })}
                 </nav>
               </div>
             </div>

             {/* 主内容区域 */}
             <div className="flex-1">
               <motion.div
                 key={activeTab}
                 initial={{ opacity: 0, y: 20 }}
                 animate={{ opacity: 1, y: 0 }}
                 transition={{ duration: 0.3 }}
               >
                 {renderTabContent()}
               </motion.div>
             </div>
           </div>
         </div>
       </div>
     </NetworkDependent>
   );
 };

 export default Settings;