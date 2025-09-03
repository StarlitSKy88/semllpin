'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { Settings, DollarSign, Shield, Bell, Globe, Database } from 'lucide-react';

// 模拟系统设置数据
const mockSettings = {
  platform: {
    siteName: 'SmellPin',
    siteDescription: '基于地理位置的搞笑恶搞标注平台',
    contactEmail: 'admin@smellpin.com',
    supportPhone: '400-123-4567',
    maintenanceMode: false,
    registrationEnabled: true,
  },
  payment: {
    minAnnotationAmount: 1,
    maxAnnotationAmount: 1000,
    platformFeeRate: 8,
    minWithdrawAmount: 10,
    withdrawFeeRate: 2,
    autoWithdrawEnabled: true,
  },
  content: {
    autoReviewEnabled: true,
    manualReviewRequired: true,
    maxReportCount: 5,
    bannedKeywords: ['违法', '色情', '暴力', '诈骗'],
    maxContentLength: 500,
    imageUploadEnabled: true,
    maxImageSize: 5, // MB
  },
  notification: {
    emailNotificationEnabled: true,
    smsNotificationEnabled: true,
    pushNotificationEnabled: true,
    marketingEmailEnabled: false,
  },
  security: {
    passwordMinLength: 8,
    loginAttemptLimit: 5,
    sessionTimeout: 24, // hours
    twoFactorEnabled: false,
    ipWhitelistEnabled: false,
    ipWhitelist: [],
  },
  api: {
    rateLimit: 1000, // requests per hour
    apiKeyRequired: true,
    corsEnabled: true,
    allowedOrigins: ['https://smellpin.com'],
  },
};

export default function SystemSettings() {
  const [settings, setSettings] = useState(mockSettings);
  const [loading, setLoading] = useState(false);
  const [newKeyword, setNewKeyword] = useState('');
  const [newOrigin, setNewOrigin] = useState('');
  const [newIp, setNewIp] = useState('');

  const handleSaveSettings = async (category: string) => {
    setLoading(true);
    try {
      // TODO: 调用API保存设置
      await new Promise(resolve => setTimeout(resolve, 1000));
      toast.success(`${getCategoryName(category)}设置已保存`);
    } catch (error) {
      toast.error('保存设置失败');
    } finally {
      setLoading(false);
    }
  };

  const getCategoryName = (category: string) => {
    const names: Record<string, string> = {
      platform: '平台',
      payment: '支付',
      content: '内容',
      notification: '通知',
      security: '安全',
      api: 'API',
    };
    return names[category] || category;
  };

  const updateSetting = (category: string, key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category as keyof typeof prev],
        [key]: value,
      },
    }));
  };

  const addKeyword = () => {
    if (newKeyword.trim()) {
      updateSetting('content', 'bannedKeywords', [
        ...settings.content.bannedKeywords,
        newKeyword.trim(),
      ]);
      setNewKeyword('');
    }
  };

  const removeKeyword = (keyword: string) => {
    updateSetting('content', 'bannedKeywords', 
      settings.content.bannedKeywords.filter(k => k !== keyword)
    );
  };

  const addOrigin = () => {
    if (newOrigin.trim()) {
      updateSetting('api', 'allowedOrigins', [
        ...settings.api.allowedOrigins,
        newOrigin.trim(),
      ]);
      setNewOrigin('');
    }
  };

  const removeOrigin = (origin: string) => {
    updateSetting('api', 'allowedOrigins', 
      settings.api.allowedOrigins.filter(o => o !== origin)
    );
  };

  const addIp = () => {
    if (newIp.trim()) {
      updateSetting('security', 'ipWhitelist', [
        ...settings.security.ipWhitelist,
        newIp.trim(),
      ]);
      setNewIp('');
    }
  };

  const removeIp = (ip: string) => {
    updateSetting('security', 'ipWhitelist', 
      settings.security.ipWhitelist.filter(i => i !== ip)
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-2">
        <Settings className="h-6 w-6" />
        <h2 className="text-2xl font-bold">系统设置</h2>
      </div>

      <Tabs defaultValue="platform" className="space-y-6">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="platform">平台设置</TabsTrigger>
          <TabsTrigger value="payment">支付设置</TabsTrigger>
          <TabsTrigger value="content">内容设置</TabsTrigger>
          <TabsTrigger value="notification">通知设置</TabsTrigger>
          <TabsTrigger value="security">安全设置</TabsTrigger>
          <TabsTrigger value="api">API设置</TabsTrigger>
        </TabsList>

        {/* 平台设置 */}
        <TabsContent value="platform">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Globe className="h-5 w-5" />
                <span>平台基础设置</span>
              </CardTitle>
              <CardDescription>配置平台的基本信息和功能开关</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="siteName">网站名称</Label>
                  <Input
                    id="siteName"
                    value={settings.platform.siteName}
                    onChange={(e) => updateSetting('platform', 'siteName', e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="contactEmail">联系邮箱</Label>
                  <Input
                    id="contactEmail"
                    type="email"
                    value={settings.platform.contactEmail}
                    onChange={(e) => updateSetting('platform', 'contactEmail', e.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="siteDescription">网站描述</Label>
                <Textarea
                  id="siteDescription"
                  value={settings.platform.siteDescription}
                  onChange={(e) => updateSetting('platform', 'siteDescription', e.target.value)}
                  rows={3}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="supportPhone">客服电话</Label>
                <Input
                  id="supportPhone"
                  value={settings.platform.supportPhone}
                  onChange={(e) => updateSetting('platform', 'supportPhone', e.target.value)}
                />
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>维护模式</Label>
                    <p className="text-sm text-gray-500">开启后用户无法访问网站</p>
                  </div>
                  <Switch
                    checked={settings.platform.maintenanceMode}
                    onCheckedChange={(checked) => updateSetting('platform', 'maintenanceMode', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>允许用户注册</Label>
                    <p className="text-sm text-gray-500">关闭后新用户无法注册</p>
                  </div>
                  <Switch
                    checked={settings.platform.registrationEnabled}
                    onCheckedChange={(checked) => updateSetting('platform', 'registrationEnabled', checked)}
                  />
                </div>
              </div>

              <Button 
                onClick={() => handleSaveSettings('platform')}
                disabled={loading}
                className="w-full"
              >
                保存平台设置
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 支付设置 */}
        <TabsContent value="payment">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <DollarSign className="h-5 w-5" />
                <span>支付系统设置</span>
              </CardTitle>
              <CardDescription>配置支付相关的参数和费率</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="minAmount">最小标注金额 (元)</Label>
                  <Input
                    id="minAmount"
                    type="number"
                    value={settings.payment.minAnnotationAmount}
                    onChange={(e) => updateSetting('payment', 'minAnnotationAmount', Number(e.target.value))}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="maxAmount">最大标注金额 (元)</Label>
                  <Input
                    id="maxAmount"
                    type="number"
                    value={settings.payment.maxAnnotationAmount}
                    onChange={(e) => updateSetting('payment', 'maxAnnotationAmount', Number(e.target.value))}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="platformFee">平台手续费率 (%)</Label>
                  <Input
                    id="platformFee"
                    type="number"
                    value={settings.payment.platformFeeRate}
                    onChange={(e) => updateSetting('payment', 'platformFeeRate', Number(e.target.value))}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="withdrawFee">提现手续费率 (%)</Label>
                  <Input
                    id="withdrawFee"
                    type="number"
                    value={settings.payment.withdrawFeeRate}
                    onChange={(e) => updateSetting('payment', 'withdrawFeeRate', Number(e.target.value))}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="minWithdraw">最小提现金额 (元)</Label>
                <Input
                  id="minWithdraw"
                  type="number"
                  value={settings.payment.minWithdrawAmount}
                  onChange={(e) => updateSetting('payment', 'minWithdrawAmount', Number(e.target.value))}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>自动提现</Label>
                  <p className="text-sm text-gray-500">达到条件时自动处理提现申请</p>
                </div>
                <Switch
                  checked={settings.payment.autoWithdrawEnabled}
                  onCheckedChange={(checked) => updateSetting('payment', 'autoWithdrawEnabled', checked)}
                />
              </div>

              <Button 
                onClick={() => handleSaveSettings('payment')}
                disabled={loading}
                className="w-full"
              >
                保存支付设置
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 内容设置 */}
        <TabsContent value="content">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>内容审核设置</span>
              </CardTitle>
              <CardDescription>配置内容审核规则和限制</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>自动审核</Label>
                    <p className="text-sm text-gray-500">使用AI进行内容预审核</p>
                  </div>
                  <Switch
                    checked={settings.content.autoReviewEnabled}
                    onCheckedChange={(checked) => updateSetting('content', 'autoReviewEnabled', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>人工复审</Label>
                    <p className="text-sm text-gray-500">所有内容都需要人工审核</p>
                  </div>
                  <Switch
                    checked={settings.content.manualReviewRequired}
                    onCheckedChange={(checked) => updateSetting('content', 'manualReviewRequired', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>允许图片上传</Label>
                    <p className="text-sm text-gray-500">用户可以上传图片到标注</p>
                  </div>
                  <Switch
                    checked={settings.content.imageUploadEnabled}
                    onCheckedChange={(checked) => updateSetting('content', 'imageUploadEnabled', checked)}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="maxReports">最大举报次数</Label>
                  <Input
                    id="maxReports"
                    type="number"
                    value={settings.content.maxReportCount}
                    onChange={(e) => updateSetting('content', 'maxReportCount', Number(e.target.value))}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="maxLength">最大内容长度</Label>
                  <Input
                    id="maxLength"
                    type="number"
                    value={settings.content.maxContentLength}
                    onChange={(e) => updateSetting('content', 'maxContentLength', Number(e.target.value))}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="maxImageSize">最大图片大小 (MB)</Label>
                <Input
                  id="maxImageSize"
                  type="number"
                  value={settings.content.maxImageSize}
                  onChange={(e) => updateSetting('content', 'maxImageSize', Number(e.target.value))}
                />
              </div>

              <div className="space-y-4">
                <Label>禁用关键词</Label>
                <div className="flex space-x-2">
                  <Input
                    placeholder="添加禁用关键词"
                    value={newKeyword}
                    onChange={(e) => setNewKeyword(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addKeyword()}
                  />
                  <Button onClick={addKeyword}>添加</Button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {settings.content.bannedKeywords.map((keyword, index) => (
                    <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeKeyword(keyword)}>
                      {keyword} ×
                    </Badge>
                  ))}
                </div>
              </div>

              <Button 
                onClick={() => handleSaveSettings('content')}
                disabled={loading}
                className="w-full"
              >
                保存内容设置
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 通知设置 */}
        <TabsContent value="notification">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Bell className="h-5 w-5" />
                <span>通知系统设置</span>
              </CardTitle>
              <CardDescription>配置各种通知渠道的开关</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>邮件通知</Label>
                    <p className="text-sm text-gray-500">发送重要通知邮件</p>
                  </div>
                  <Switch
                    checked={settings.notification.emailNotificationEnabled}
                    onCheckedChange={(checked) => updateSetting('notification', 'emailNotificationEnabled', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>短信通知</Label>
                    <p className="text-sm text-gray-500">发送验证码和重要提醒</p>
                  </div>
                  <Switch
                    checked={settings.notification.smsNotificationEnabled}
                    onCheckedChange={(checked) => updateSetting('notification', 'smsNotificationEnabled', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>推送通知</Label>
                    <p className="text-sm text-gray-500">发送APP推送消息</p>
                  </div>
                  <Switch
                    checked={settings.notification.pushNotificationEnabled}
                    onCheckedChange={(checked) => updateSetting('notification', 'pushNotificationEnabled', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>营销邮件</Label>
                    <p className="text-sm text-gray-500">发送活动和推广邮件</p>
                  </div>
                  <Switch
                    checked={settings.notification.marketingEmailEnabled}
                    onCheckedChange={(checked) => updateSetting('notification', 'marketingEmailEnabled', checked)}
                  />
                </div>
              </div>

              <Button 
                onClick={() => handleSaveSettings('notification')}
                disabled={loading}
                className="w-full"
              >
                保存通知设置
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 安全设置 */}
        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>安全策略设置</span>
              </CardTitle>
              <CardDescription>配置系统安全相关参数</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="passwordLength">密码最小长度</Label>
                  <Input
                    id="passwordLength"
                    type="number"
                    value={settings.security.passwordMinLength}
                    onChange={(e) => updateSetting('security', 'passwordMinLength', Number(e.target.value))}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="loginAttempts">登录尝试次数限制</Label>
                  <Input
                    id="loginAttempts"
                    type="number"
                    value={settings.security.loginAttemptLimit}
                    onChange={(e) => updateSetting('security', 'loginAttemptLimit', Number(e.target.value))}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="sessionTimeout">会话超时时间 (小时)</Label>
                <Input
                  id="sessionTimeout"
                  type="number"
                  value={settings.security.sessionTimeout}
                  onChange={(e) => updateSetting('security', 'sessionTimeout', Number(e.target.value))}
                />
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>双因子认证</Label>
                    <p className="text-sm text-gray-500">强制用户启用2FA</p>
                  </div>
                  <Switch
                    checked={settings.security.twoFactorEnabled}
                    onCheckedChange={(checked) => updateSetting('security', 'twoFactorEnabled', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>IP白名单</Label>
                    <p className="text-sm text-gray-500">只允许白名单IP访问管理后台</p>
                  </div>
                  <Switch
                    checked={settings.security.ipWhitelistEnabled}
                    onCheckedChange={(checked) => updateSetting('security', 'ipWhitelistEnabled', checked)}
                  />
                </div>
              </div>

              {settings.security.ipWhitelistEnabled && (
                <div className="space-y-4">
                  <Label>IP白名单</Label>
                  <div className="flex space-x-2">
                    <Input
                      placeholder="添加IP地址"
                      value={newIp}
                      onChange={(e) => setNewIp(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && addIp()}
                    />
                    <Button onClick={addIp}>添加</Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {settings.security.ipWhitelist.map((ip, index) => (
                      <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeIp(ip)}>
                        {ip} ×
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              <Button 
                onClick={() => handleSaveSettings('security')}
                disabled={loading}
                className="w-full"
              >
                保存安全设置
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API设置 */}
        <TabsContent value="api">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Database className="h-5 w-5" />
                <span>API接口设置</span>
              </CardTitle>
              <CardDescription>配置API访问控制和限制</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="rateLimit">API调用频率限制 (次/小时)</Label>
                <Input
                  id="rateLimit"
                  type="number"
                  value={settings.api.rateLimit}
                  onChange={(e) => updateSetting('api', 'rateLimit', Number(e.target.value))}
                />
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>API密钥验证</Label>
                    <p className="text-sm text-gray-500">要求API调用提供有效密钥</p>
                  </div>
                  <Switch
                    checked={settings.api.apiKeyRequired}
                    onCheckedChange={(checked) => updateSetting('api', 'apiKeyRequired', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>CORS跨域</Label>
                    <p className="text-sm text-gray-500">允许跨域API调用</p>
                  </div>
                  <Switch
                    checked={settings.api.corsEnabled}
                    onCheckedChange={(checked) => updateSetting('api', 'corsEnabled', checked)}
                  />
                </div>
              </div>

              {settings.api.corsEnabled && (
                <div className="space-y-4">
                  <Label>允许的域名</Label>
                  <div className="flex space-x-2">
                    <Input
                      placeholder="添加允许的域名"
                      value={newOrigin}
                      onChange={(e) => setNewOrigin(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && addOrigin()}
                    />
                    <Button onClick={addOrigin}>添加</Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {settings.api.allowedOrigins.map((origin, index) => (
                      <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeOrigin(origin)}>
                        {origin} ×
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              <Button 
                onClick={() => handleSaveSettings('api')}
                disabled={loading}
                className="w-full"
              >
                保存API设置
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}