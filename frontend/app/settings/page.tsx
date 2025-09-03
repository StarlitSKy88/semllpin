'use client';

import { useEffect, useState } from 'react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { authApi } from '@/lib/services/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { 
  AlertDialog, 
  AlertDialogAction, 
  AlertDialogCancel, 
  AlertDialogContent, 
  AlertDialogDescription, 
  AlertDialogFooter, 
  AlertDialogHeader, 
  AlertDialogTitle, 
  AlertDialogTrigger 
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import {
  Shield,
  Bell,
  Eye,
  Lock,
  Trash2,
  Save,
  User,
  Mail,
  Phone,
  Globe,
  MapPin,
  Heart,
  MessageCircle,
  Settings as SettingsIcon
} from 'lucide-react';
import { useRouter } from 'next/navigation';

export default function SettingsPage() {
  const { user, isAuthenticated, logout } = useAuthStore();
  const router = useRouter();
  
  // 密码设置状态
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  // 通知设置状态
  const [notificationSettings, setNotificationSettings] = useState({
    emailNotifications: true,
    pushNotifications: true,
    smsNotifications: false,
    annotationLikes: true,
    annotationComments: true,
    nearbyAnnotations: true,
    systemUpdates: true,
    marketingEmails: false
  });

  // 隐私设置状态
  const [privacySettings, setPrivacySettings] = useState({
    profileVisible: true,
    locationVisible: true,
    activityVisible: true,
    allowFriendRequests: true,
    showOnlineStatus: true
  });

  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      router.push('/');
      return;
    }

    // 这里可以加载用户的设置
    loadUserSettings();
  }, [isAuthenticated, router]);

  const loadUserSettings = async () => {
    try {
      // TODO: 从API加载用户设置
      // const settings = await settingsApi.getUserSettings();
      // setNotificationSettings(settings.notifications);
      // setPrivacySettings(settings.privacy);
    } catch (error) {
      console.error('Failed to load user settings:', error);
    }
  };

  const handlePasswordChange = async () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast.error('新密码与确认密码不匹配');
      return;
    }

    if (passwordForm.newPassword.length < 6) {
      toast.error('密码长度至少6位');
      return;
    }

    try {
      setLoading(true);
      await authApi.changePassword(passwordForm.currentPassword, passwordForm.newPassword);
      toast.success('密码修改成功');
      setPasswordForm({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      });
    } catch (error: any) {
      toast.error(error.message || '密码修改失败');
    } finally {
      setLoading(false);
    }
  };

  const handleNotificationSettingsUpdate = async () => {
    try {
      setLoading(true);
      // TODO: 调用更新通知设置API
      // await settingsApi.updateNotificationSettings(notificationSettings);
      toast.success('通知设置已保存');
    } catch (error) {
      toast.error('保存失败');
    } finally {
      setLoading(false);
    }
  };

  const handlePrivacySettingsUpdate = async () => {
    try {
      setLoading(true);
      // TODO: 调用更新隐私设置API
      // await settingsApi.updatePrivacySettings(privacySettings);
      toast.success('隐私设置已保存');
    } catch (error) {
      toast.error('保存失败');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteAccount = async () => {
    try {
      setLoading(true);
      // TODO: 调用删除账户API
      // await authApi.deleteAccount();
      toast.success('账户已删除');
      logout();
      router.push('/');
    } catch (error) {
      toast.error('删除账户失败');
    } finally {
      setLoading(false);
    }
  };

  if (!isAuthenticated || !user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-black pt-20 pb-10">
      <div className="container mx-auto px-4 max-w-4xl">
        <div className="flex items-center gap-2 mb-8">
          <SettingsIcon className="h-6 w-6 text-white" />
          <h1 className="text-2xl font-bold text-white">账户设置</h1>
        </div>

        <div className="space-y-8">
          {/* 密码设置 */}
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Lock className="h-5 w-5" />
                修改密码
              </CardTitle>
              <CardDescription>
                定期更换密码以确保账户安全
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="current-password" className="text-white">当前密码</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={passwordForm.currentPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                  className="bg-gray-800 border-gray-700 text-white"
                  placeholder="请输入当前密码"
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="new-password" className="text-white">新密码</Label>
                  <Input
                    id="new-password"
                    type="password"
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                    className="bg-gray-800 border-gray-700 text-white"
                    placeholder="请输入新密码"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirm-password" className="text-white">确认新密码</Label>
                  <Input
                    id="confirm-password"
                    type="password"
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                    className="bg-gray-800 border-gray-700 text-white"
                    placeholder="再次输入新密码"
                  />
                </div>
              </div>
              <Button 
                onClick={handlePasswordChange} 
                disabled={loading || !passwordForm.currentPassword || !passwordForm.newPassword}
              >
                <Save className="h-4 w-4 mr-2" />
                更新密码
              </Button>
            </CardContent>
          </Card>

          {/* 通知设置 */}
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Bell className="h-5 w-5" />
                通知设置
              </CardTitle>
              <CardDescription>
                管理您希望接收的通知类型
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <h4 className="text-white font-medium">通知方式</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center justify-between p-3 border border-gray-800 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Mail className="h-4 w-4 text-gray-400" />
                      <span className="text-white text-sm">邮件通知</span>
                    </div>
                    <Switch
                      checked={notificationSettings.emailNotifications}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, emailNotifications: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between p-3 border border-gray-800 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Bell className="h-4 w-4 text-gray-400" />
                      <span className="text-white text-sm">推送通知</span>
                    </div>
                    <Switch
                      checked={notificationSettings.pushNotifications}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, pushNotifications: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between p-3 border border-gray-800 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Phone className="h-4 w-4 text-gray-400" />
                      <span className="text-white text-sm">短信通知</span>
                    </div>
                    <Switch
                      checked={notificationSettings.smsNotifications}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, smsNotifications: checked })
                      }
                    />
                  </div>
                </div>
              </div>

              <Separator className="bg-gray-800" />

              <div className="space-y-4">
                <h4 className="text-white font-medium">通知内容</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Heart className="h-4 w-4 text-red-500" />
                      <span className="text-white text-sm">标注被点赞</span>
                    </div>
                    <Switch
                      checked={notificationSettings.annotationLikes}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, annotationLikes: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <MessageCircle className="h-4 w-4 text-blue-500" />
                      <span className="text-white text-sm">标注被评论</span>
                    </div>
                    <Switch
                      checked={notificationSettings.annotationComments}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, annotationComments: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-green-500" />
                      <span className="text-white text-sm">附近新标注</span>
                    </div>
                    <Switch
                      checked={notificationSettings.nearbyAnnotations}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, nearbyAnnotations: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <SettingsIcon className="h-4 w-4 text-purple-500" />
                      <span className="text-white text-sm">系统更新</span>
                    </div>
                    <Switch
                      checked={notificationSettings.systemUpdates}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, systemUpdates: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-orange-500" />
                      <span className="text-white text-sm">营销邮件</span>
                    </div>
                    <Switch
                      checked={notificationSettings.marketingEmails}
                      onCheckedChange={(checked) => 
                        setNotificationSettings({ ...notificationSettings, marketingEmails: checked })
                      }
                    />
                  </div>
                </div>
              </div>

              <Button onClick={handleNotificationSettingsUpdate} disabled={loading}>
                <Save className="h-4 w-4 mr-2" />
                保存通知设置
              </Button>
            </CardContent>
          </Card>

          {/* 隐私设置 */}
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Eye className="h-5 w-5" />
                隐私设置
              </CardTitle>
              <CardDescription>
                控制其他用户可以看到的信息
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white text-sm">公开个人资料</p>
                    <p className="text-gray-400 text-xs">允许其他用户查看您的个人资料</p>
                  </div>
                  <Switch
                    checked={privacySettings.profileVisible}
                    onCheckedChange={(checked) => 
                      setPrivacySettings({ ...privacySettings, profileVisible: checked })
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white text-sm">显示位置信息</p>
                    <p className="text-gray-400 text-xs">在标注中显示您的大致位置</p>
                  </div>
                  <Switch
                    checked={privacySettings.locationVisible}
                    onCheckedChange={(checked) => 
                      setPrivacySettings({ ...privacySettings, locationVisible: checked })
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white text-sm">显示活动状态</p>
                    <p className="text-gray-400 text-xs">显示您的最后活跃时间</p>
                  </div>
                  <Switch
                    checked={privacySettings.activityVisible}
                    onCheckedChange={(checked) => 
                      setPrivacySettings({ ...privacySettings, activityVisible: checked })
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white text-sm">允许好友请求</p>
                    <p className="text-gray-400 text-xs">其他用户可以向您发送好友请求</p>
                  </div>
                  <Switch
                    checked={privacySettings.allowFriendRequests}
                    onCheckedChange={(checked) => 
                      setPrivacySettings({ ...privacySettings, allowFriendRequests: checked })
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white text-sm">显示在线状态</p>
                    <p className="text-gray-400 text-xs">让好友知道您是否在线</p>
                  </div>
                  <Switch
                    checked={privacySettings.showOnlineStatus}
                    onCheckedChange={(checked) => 
                      setPrivacySettings({ ...privacySettings, showOnlineStatus: checked })
                    }
                  />
                </div>
              </div>

              <Button onClick={handlePrivacySettingsUpdate} disabled={loading}>
                <Save className="h-4 w-4 mr-2" />
                保存隐私设置
              </Button>
            </CardContent>
          </Card>

          {/* 危险操作 */}
          <Card className="bg-gray-900/50 border-red-800">
            <CardHeader>
              <CardTitle className="text-red-500 flex items-center gap-2">
                <Shield className="h-5 w-5" />
                危险操作
              </CardTitle>
              <CardDescription>
                这些操作不可逆，请谨慎考虑
              </CardDescription>
            </CardHeader>
            <CardContent>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button variant="destructive" className="w-full sm:w-auto">
                    <Trash2 className="h-4 w-4 mr-2" />
                    删除账户
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent className="bg-gray-900 border-gray-800">
                  <AlertDialogHeader>
                    <AlertDialogTitle className="text-white">确认删除账户</AlertDialogTitle>
                    <AlertDialogDescription className="text-gray-400">
                      此操作不可逆转。删除账户将永久移除您的所有数据，包括：
                      <ul className="list-disc list-inside mt-2 space-y-1">
                        <li>个人资料信息</li>
                        <li>创建的所有标注</li>
                        <li>评论和互动记录</li>
                        <li>钱包余额（请先提现）</li>
                      </ul>
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel className="bg-gray-800 border-gray-700 text-white hover:bg-gray-700">
                      取消
                    </AlertDialogCancel>
                    <AlertDialogAction
                      onClick={handleDeleteAccount}
                      className="bg-red-600 hover:bg-red-700"
                      disabled={loading}
                    >
                      确认删除
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}