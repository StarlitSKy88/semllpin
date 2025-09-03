'use client';

import { useState } from 'react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { toast } from 'sonner';
import {
  Shield,
  Bell,
  Globe,
  CreditCard,
  Smartphone,
  Mail,
  Lock,
  Trash2,
  AlertTriangle,
  Eye,
  EyeOff,
  ArrowLeft
} from 'lucide-react';
import Link from 'next/link';

interface NotificationSettings {
  emailNotifications: boolean;
  pushNotifications: boolean;
  smsNotifications: boolean;
  discoveryAlerts: boolean;
  earningsAlerts: boolean;
  systemUpdates: boolean;
  marketingEmails: boolean;
}

interface PrivacySettings {
  profileVisibility: 'public' | 'friends' | 'private';
  showLocation: boolean;
  showEarnings: boolean;
  showAnnotations: boolean;
  allowMessages: boolean;
  allowFriendRequests: boolean;
}

interface SecuritySettings {
  twoFactorEnabled: boolean;
  loginAlerts: boolean;
  sessionTimeout: number;
}

export default function SettingsPage() {
  const { user } = useAuthStore();
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false
  });

  const [notificationSettings, setNotificationSettings] = useState<NotificationSettings>({
    emailNotifications: true,
    pushNotifications: true,
    smsNotifications: false,
    discoveryAlerts: true,
    earningsAlerts: true,
    systemUpdates: true,
    marketingEmails: false
  });

  const [privacySettings, setPrivacySettings] = useState<PrivacySettings>({
    profileVisibility: 'public',
    showLocation: true,
    showEarnings: false,
    showAnnotations: true,
    allowMessages: true,
    allowFriendRequests: true
  });

  const [securitySettings, setSecuritySettings] = useState<SecuritySettings>({
    twoFactorEnabled: false,
    loginAlerts: true,
    sessionTimeout: 30
  });

  const handleSaveNotifications = async () => {
    try {
      // TODO: 调用API保存通知设置
      toast.success('通知设置已保存');
    } catch (error) {
      toast.error('保存失败，请重试');
    }
  };

  const handleSavePrivacy = async () => {
    try {
      // TODO: 调用API保存隐私设置
      toast.success('隐私设置已保存');
    } catch (error) {
      toast.error('保存失败，请重试');
    }
  };

  const handleSaveSecurity = async () => {
    try {
      // TODO: 调用API保存安全设置
      toast.success('安全设置已保存');
    } catch (error) {
      toast.error('保存失败，请重试');
    }
  };

  const handleChangePassword = async () => {
    if (newPassword !== confirmPassword) {
      toast.error('新密码和确认密码不匹配');
      return;
    }
    
    if (newPassword.length < 8) {
      toast.error('密码长度至少8位');
      return;
    }

    try {
      // TODO: 调用API修改密码
      toast.success('密码修改成功');
      setShowPasswordDialog(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      toast.error('密码修改失败，请重试');
    }
  };

  const handleDeleteAccount = async () => {
    try {
      // TODO: 调用API删除账户
      toast.success('账户删除成功');
      setShowDeleteDialog(false);
    } catch (error) {
      toast.error('删除失败，请重试');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-cyan-50 py-8">
      <div className="container mx-auto px-4 max-w-4xl">
        {/* 页面头部 */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/profile">
            <Button variant="outline" size="sm">
              <ArrowLeft className="w-4 h-4 mr-2" />
              返回个人中心
            </Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold">账户设置</h1>
            <p className="text-gray-600">管理您的账户偏好和安全设置</p>
          </div>
        </div>

        <Tabs defaultValue="notifications" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="notifications">通知设置</TabsTrigger>
            <TabsTrigger value="privacy">隐私设置</TabsTrigger>
            <TabsTrigger value="security">安全设置</TabsTrigger>
            <TabsTrigger value="account">账户管理</TabsTrigger>
          </TabsList>

          {/* 通知设置 */}
          <TabsContent value="notifications">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="w-5 h-5" />
                  通知设置
                </CardTitle>
                <CardDescription>
                  选择您希望接收的通知类型和方式
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* 通知方式 */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">通知方式</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Mail className="w-4 h-4 text-blue-500" />
                        <div>
                          <Label>邮件通知</Label>
                          <p className="text-sm text-gray-500">通过邮件接收通知</p>
                        </div>
                      </div>
                      <Switch
                        checked={notificationSettings.emailNotifications}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, emailNotifications: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Bell className="w-4 h-4 text-green-500" />
                        <div>
                          <Label>推送通知</Label>
                          <p className="text-sm text-gray-500">浏览器推送通知</p>
                        </div>
                      </div>
                      <Switch
                        checked={notificationSettings.pushNotifications}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, pushNotifications: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Smartphone className="w-4 h-4 text-purple-500" />
                        <div>
                          <Label>短信通知</Label>
                          <p className="text-sm text-gray-500">重要通知通过短信发送</p>
                        </div>
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

                <Separator />

                {/* 通知内容 */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">通知内容</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>发现提醒</Label>
                        <p className="text-sm text-gray-500">当您的标注被发现时通知</p>
                      </div>
                      <Switch
                        checked={notificationSettings.discoveryAlerts}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, discoveryAlerts: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>收益提醒</Label>
                        <p className="text-sm text-gray-500">收益到账时通知</p>
                      </div>
                      <Switch
                        checked={notificationSettings.earningsAlerts}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, earningsAlerts: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>系统更新</Label>
                        <p className="text-sm text-gray-500">系统维护和更新通知</p>
                      </div>
                      <Switch
                        checked={notificationSettings.systemUpdates}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, systemUpdates: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>营销邮件</Label>
                        <p className="text-sm text-gray-500">产品更新和优惠信息</p>
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

                <div className="flex justify-end">
                  <Button onClick={handleSaveNotifications}>
                    保存设置
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 隐私设置 */}
          <TabsContent value="privacy">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  隐私设置
                </CardTitle>
                <CardDescription>
                  控制您的个人信息可见性
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>个人资料可见性</Label>
                    <Select
                      value={privacySettings.profileVisibility}
                      onValueChange={(value: 'public' | 'friends' | 'private') =>
                        setPrivacySettings({ ...privacySettings, profileVisibility: value })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="public">公开 - 所有人可见</SelectItem>
                        <SelectItem value="friends">好友 - 仅好友可见</SelectItem>
                        <SelectItem value="private">私密 - 仅自己可见</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>显示位置信息</Label>
                        <p className="text-sm text-gray-500">在个人资料中显示位置</p>
                      </div>
                      <Switch
                        checked={privacySettings.showLocation}
                        onCheckedChange={(checked) =>
                          setPrivacySettings({ ...privacySettings, showLocation: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>显示收益信息</Label>
                        <p className="text-sm text-gray-500">在个人资料中显示收益统计</p>
                      </div>
                      <Switch
                        checked={privacySettings.showEarnings}
                        onCheckedChange={(checked) =>
                          setPrivacySettings({ ...privacySettings, showEarnings: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>显示标注记录</Label>
                        <p className="text-sm text-gray-500">允许他人查看您的标注</p>
                      </div>
                      <Switch
                        checked={privacySettings.showAnnotations}
                        onCheckedChange={(checked) =>
                          setPrivacySettings({ ...privacySettings, showAnnotations: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>允许私信</Label>
                        <p className="text-sm text-gray-500">允许其他用户给您发送私信</p>
                      </div>
                      <Switch
                        checked={privacySettings.allowMessages}
                        onCheckedChange={(checked) =>
                          setPrivacySettings({ ...privacySettings, allowMessages: checked })
                        }
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>允许好友请求</Label>
                        <p className="text-sm text-gray-500">允许其他用户向您发送好友请求</p>
                      </div>
                      <Switch
                        checked={privacySettings.allowFriendRequests}
                        onCheckedChange={(checked) =>
                          setPrivacySettings({ ...privacySettings, allowFriendRequests: checked })
                        }
                      />
                    </div>
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button onClick={handleSavePrivacy}>
                    保存设置
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 安全设置 */}
          <TabsContent value="security">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="w-5 h-5" />
                  安全设置
                </CardTitle>
                <CardDescription>
                  保护您的账户安全
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label>双重认证</Label>
                      <p className="text-sm text-gray-500">使用手机验证码增强账户安全</p>
                    </div>
                    <Switch
                      checked={securitySettings.twoFactorEnabled}
                      onCheckedChange={(checked) =>
                        setSecuritySettings({ ...securitySettings, twoFactorEnabled: checked })
                      }
                    />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <Label>登录提醒</Label>
                      <p className="text-sm text-gray-500">新设备登录时发送通知</p>
                    </div>
                    <Switch
                      checked={securitySettings.loginAlerts}
                      onCheckedChange={(checked) =>
                        setSecuritySettings({ ...securitySettings, loginAlerts: checked })
                      }
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label>会话超时时间（分钟）</Label>
                    <Select
                      value={securitySettings.sessionTimeout.toString()}
                      onValueChange={(value) =>
                        setSecuritySettings({ ...securitySettings, sessionTimeout: parseInt(value) })
                      }
                    >
                      <SelectTrigger className="w-48">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="15">15分钟</SelectItem>
                        <SelectItem value="30">30分钟</SelectItem>
                        <SelectItem value="60">1小时</SelectItem>
                        <SelectItem value="120">2小时</SelectItem>
                        <SelectItem value="0">永不超时</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Separator />

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">密码管理</h3>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label>修改密码</Label>
                      <p className="text-sm text-gray-500">定期更换密码以保护账户安全</p>
                    </div>
                    <Dialog open={showPasswordDialog} onOpenChange={setShowPasswordDialog}>
                      <DialogTrigger asChild>
                        <Button variant="outline">修改密码</Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>修改密码</DialogTitle>
                          <DialogDescription>
                            请输入当前密码和新密码
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div className="space-y-2">
                            <Label htmlFor="current-password">当前密码</Label>
                            <div className="relative">
                              <Input
                                id="current-password"
                                type={showPasswords.current ? 'text' : 'password'}
                                value={currentPassword}
                                onChange={(e) => setCurrentPassword(e.target.value)}
                                placeholder="请输入当前密码"
                              />
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                onClick={() => setShowPasswords({ ...showPasswords, current: !showPasswords.current })}
                              >
                                {showPasswords.current ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                              </Button>
                            </div>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="new-password">新密码</Label>
                            <div className="relative">
                              <Input
                                id="new-password"
                                type={showPasswords.new ? 'text' : 'password'}
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                placeholder="请输入新密码（至少8位）"
                              />
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                onClick={() => setShowPasswords({ ...showPasswords, new: !showPasswords.new })}
                              >
                                {showPasswords.new ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                              </Button>
                            </div>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="confirm-password">确认新密码</Label>
                            <div className="relative">
                              <Input
                                id="confirm-password"
                                type={showPasswords.confirm ? 'text' : 'password'}
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="请再次输入新密码"
                              />
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                onClick={() => setShowPasswords({ ...showPasswords, confirm: !showPasswords.confirm })}
                              >
                                {showPasswords.confirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                              </Button>
                            </div>
                          </div>
                        </div>
                        <DialogFooter>
                          <Button variant="outline" onClick={() => setShowPasswordDialog(false)}>
                            取消
                          </Button>
                          <Button onClick={handleChangePassword}>
                            确认修改
                          </Button>
                        </DialogFooter>
                      </DialogContent>
                    </Dialog>
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button onClick={handleSaveSecurity}>
                    保存设置
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 账户管理 */}
          <TabsContent value="account">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CreditCard className="w-5 h-5" />
                  账户管理
                </CardTitle>
                <CardDescription>
                  管理您的账户信息和数据
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="p-4 border rounded-lg">
                    <h3 className="font-semibold mb-2">账户信息</h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-500">用户名：</span>
                        <span className="font-medium">{user?.username}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">邮箱：</span>
                        <span className="font-medium">{user?.email}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">注册时间：</span>
                        <span className="font-medium">
                          {user?.createdAt ? new Date(user.createdAt).toLocaleDateString('zh-CN') : '未知'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">用户等级：</span>
                        <span className="font-medium">Lv.{user?.level}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <h3 className="font-semibold">数据管理</h3>
                    <div className="space-y-2">
                      <Button variant="outline" className="w-full justify-start">
                        <Globe className="w-4 h-4 mr-2" />
                        导出我的数据
                      </Button>
                      <p className="text-sm text-gray-500 ml-6">
                        下载您在SmellPin上的所有数据副本
                      </p>
                    </div>
                  </div>
                </div>

                <Separator />

                <div className="space-y-4">
                  <h3 className="font-semibold text-red-600">危险操作</h3>
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      以下操作不可逆转，请谨慎操作
                    </AlertDescription>
                  </Alert>
                  
                  <div className="space-y-3">
                    <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
                      <DialogTrigger asChild>
                        <Button variant="destructive" className="w-full justify-start">
                          <Trash2 className="w-4 h-4 mr-2" />
                          删除账户
                        </Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>确认删除账户</DialogTitle>
                          <DialogDescription>
                            此操作将永久删除您的账户和所有相关数据，包括：
                            <ul className="list-disc list-inside mt-2 space-y-1">
                              <li>个人资料和设置</li>
                              <li>所有标注记录</li>
                              <li>收益和交易记录</li>
                              <li>好友关系和消息</li>
                            </ul>
                            <strong className="text-red-600">此操作不可撤销！</strong>
                          </DialogDescription>
                        </DialogHeader>
                        <DialogFooter>
                          <Button variant="outline" onClick={() => setShowDeleteDialog(false)}>
                            取消
                          </Button>
                          <Button variant="destructive" onClick={handleDeleteAccount}>
                            确认删除
                          </Button>
                        </DialogFooter>
                      </DialogContent>
                    </Dialog>
                    <p className="text-sm text-gray-500 ml-6">
                      永久删除您的账户和所有数据
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}