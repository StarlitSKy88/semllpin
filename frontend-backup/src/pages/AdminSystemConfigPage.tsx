import React, { useState, useEffect, useCallback } from 'react';
import { Alert, Button, Card, Col, Divider, Form, Input, InputNumber, Modal, Row, Select, Slider, Space, Switch, Tabs, Typography, message } from 'antd';
import { DecorativeElements } from '../components/UI/DecorativeElements';

import { BellOutlined, DollarOutlined, ExclamationCircleOutlined, GlobalOutlined, InfoCircleOutlined, ReloadOutlined, SaveOutlined, SecurityScanOutlined, SettingOutlined, UserOutlined } from '@ant-design/icons';
// import adminApi from '../services/adminApi'; // Removed as unused

const { Title, Text } = Typography; // Paragraph removed as unused
const { TextArea } = Input;
const { TabPane } = Tabs;
const { confirm } = Modal;

interface SystemConfig {
  // 基础设置
  siteName: string;
  siteDescription: string;
  siteKeywords: string;
  maintenanceMode: boolean;
  maintenanceMessage: string;
  
  // 用户设置
  allowRegistration: boolean;
  requireEmailVerification: boolean;
  defaultUserLevel: number;
  defaultUserPoints: number;
  maxUsernameLength: number;
  minPasswordLength: number;
  
  // 内容设置
  maxAnnotationLength: number;
  maxCommentLength: number;
  allowImageUpload: boolean;
  maxImageSize: number; // MB
  allowedImageTypes: string[];
  contentModerationEnabled: boolean;
  autoApproveContent: boolean;
  
  // 支付设置
  paymentEnabled: boolean;
  minPaymentAmount: number;
  maxPaymentAmount: number;
  paymentFeeRate: number; // 手续费率
  withdrawMinAmount: number;
  withdrawFeeRate: number;
  
  // 通知设置
  emailNotificationEnabled: boolean;
  pushNotificationEnabled: boolean;
  smsNotificationEnabled: boolean;
  notificationRetentionDays: number;
  
  // 安全设置
  rateLimitEnabled: boolean;
  maxRequestsPerMinute: number;
  ipWhitelist: string[];
  ipBlacklist: string[];
  sessionTimeout: number; // 分钟
  maxLoginAttempts: number;
  lockoutDuration: number; // 分钟
  
  // 地图设置
  mapProvider: string;
  mapApiKey: string;
  defaultMapZoom: number;
  maxMapZoom: number;
  minMapZoom: number;
  mapCenterLat: number;
  mapCenterLng: number;
  
  // 缓存设置
  cacheEnabled: boolean;
  cacheExpiration: number; // 小时
  redisCacheEnabled: boolean;
  
  // 日志设置
  logLevel: string;
  logRetentionDays: number;
  auditLogEnabled: boolean;
}

const AdminSystemConfigPage: React.FC = () => {
  const [form] = Form.useForm();
  // const [, setLoading] = useState(false); // loading removed as unused
  const [saving, setSaving] = useState(false);
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [activeTab, setActiveTab] = useState('basic');
  const [hasChanges, setHasChanges] = useState(false);

  // 加载系统配置
  const loadConfig = useCallback(async () => {
    // setLoading(true);
    try {
      // 这里应该调用实际的API
      // const response = await adminApi.getSystemConfig();
      // setConfig(response.data);
      // form.setFieldsValue(response.data);
      
      // 模拟数据
      const mockConfig: SystemConfig = {
        siteName: 'SmellPin',
        siteDescription: '基于地理位置的搞笑娱乐平台',
        siteKeywords: 'LBS,搞笑,娱乐,地图,标注',
        maintenanceMode: false,
        maintenanceMessage: '系统维护中，请稍后访问',
        
        allowRegistration: true,
        requireEmailVerification: true,
        defaultUserLevel: 1,
        defaultUserPoints: 100,
        maxUsernameLength: 20,
        minPasswordLength: 6,
        
        maxAnnotationLength: 500,
        maxCommentLength: 200,
        allowImageUpload: true,
        maxImageSize: 5,
        allowedImageTypes: ['jpg', 'jpeg', 'png', 'gif'],
        contentModerationEnabled: true,
        autoApproveContent: false,
        
        paymentEnabled: true,
        minPaymentAmount: 1,
        maxPaymentAmount: 1000,
        paymentFeeRate: 0.03,
        withdrawMinAmount: 10,
        withdrawFeeRate: 0.01,
        
        emailNotificationEnabled: true,
        pushNotificationEnabled: true,
        smsNotificationEnabled: false,
        notificationRetentionDays: 30,
        
        rateLimitEnabled: true,
        maxRequestsPerMinute: 100,
        ipWhitelist: [],
        ipBlacklist: [],
        sessionTimeout: 120,
        maxLoginAttempts: 5,
        lockoutDuration: 15,
        
        mapProvider: 'amap',
        mapApiKey: '',
        defaultMapZoom: 13,
        maxMapZoom: 18,
        minMapZoom: 3,
        mapCenterLat: 39.9042,
        mapCenterLng: 116.4074,
        
        cacheEnabled: true,
        cacheExpiration: 24,
        redisCacheEnabled: true,
        
        logLevel: 'info',
        logRetentionDays: 30,
        auditLogEnabled: true
      };
      
      setConfig(mockConfig);
      form.setFieldsValue(mockConfig);
    } catch {
      message.error('加载系统配置失败');
    } finally {
      // setLoading(false);
    }
  }, [form]);

  // 保存配置
  const saveConfig = async () => {
    try {
      const values = await form.validateFields();
      setSaving(true);
      
      // 这里应该调用实际的API
      // await adminApi.updateSystemConfig(values);
      
      setConfig(values);
      setHasChanges(false);
      message.success('系统配置保存成功');
    } catch {
      message.error('保存系统配置失败');
    } finally {
      setSaving(false);
    }
  };

  // 重置配置
  const resetConfig = () => {
    confirm({
      title: '确认重置配置？',
      icon: <ExclamationCircleOutlined />,
      content: '重置后将恢复到上次保存的状态，未保存的修改将丢失',
      onOk: () => {
        if (config) {
          form.setFieldsValue(config);
          setHasChanges(false);
        }
      }
    });
  };

  // 监听表单变化
  const handleFormChange = () => {
    setHasChanges(true);
  };

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      <DecorativeElements variant="background" />
      <DecorativeElements variant="floating" position="top-left" />
      <DecorativeElements variant="floating" position="top-right" />
      <DecorativeElements variant="floating" position="bottom-left" />
      <DecorativeElements variant="floating" position="bottom-right" />
      
      <div className="relative z-10 p-6">
        <div className="mb-6">
          <Title level={2} style={{ color: '#7f1d1d' }}>系统配置</Title>
        <Text type="secondary">管理系统的各项配置参数</Text>
      </div>

      {hasChanges && (
        <Alert
          message="配置已修改"
          description="您有未保存的配置修改，请及时保存"
          type="warning"
          showIcon
          className="mb-4"
          action={
            <Space>
              <Button size="small" onClick={resetConfig}>
                重置
              </Button>
              <Button size="small" type="primary" onClick={saveConfig}>
                保存
              </Button>
            </Space>
          }
        />
      )}

      <Card>
        <Form
          form={form}
          layout="vertical"
          onValuesChange={handleFormChange}
        >
          <Tabs activeKey={activeTab} onChange={setActiveTab}>
            {/* 基础设置 */}
            <TabPane
              tab={
                <span>
                  <SettingOutlined />
                  基础设置
                </span>
              }
              key="basic"
            >
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    name="siteName"
                    label="站点名称"
                    rules={[{ required: true, message: '请输入站点名称' }]}
                  >
                    <Input placeholder="请输入站点名称" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="siteKeywords"
                    label="站点关键词"
                    tooltip="用于SEO优化，多个关键词用逗号分隔"
                  >
                    <Input placeholder="请输入站点关键词" />
                  </Form.Item>
                </Col>
                <Col span={24}>
                  <Form.Item
                    name="siteDescription"
                    label="站点描述"
                  >
                    <TextArea rows={3} placeholder="请输入站点描述" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maintenanceMode"
                    label="维护模式"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maintenanceMessage"
                    label="维护提示信息"
                  >
                    <Input placeholder="维护模式下显示的提示信息" />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>

            {/* 用户设置 */}
            <TabPane
              tab={
                <span>
                  <UserOutlined />
                  用户设置
                </span>
              }
              key="user"
            >
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    name="allowRegistration"
                    label="允许用户注册"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="允许" unCheckedChildren="禁止" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="requireEmailVerification"
                    label="邮箱验证"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="必须" unCheckedChildren="可选" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="defaultUserLevel"
                    label="默认用户等级"
                  >
                    <InputNumber min={1} max={10} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="defaultUserPoints"
                    label="默认用户积分"
                  >
                    <InputNumber min={0} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maxUsernameLength"
                    label="用户名最大长度"
                  >
                    <InputNumber min={1} max={50} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="minPasswordLength"
                    label="密码最小长度"
                  >
                    <InputNumber min={4} max={20} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>

            {/* 内容设置 */}
            <TabPane
              tab={
                <span>
                  <InfoCircleOutlined />
                  内容设置
                </span>
              }
              key="content"
            >
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    name="maxAnnotationLength"
                    label="标注最大长度"
                  >
                    <InputNumber min={10} max={1000} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maxCommentLength"
                    label="评论最大长度"
                  >
                    <InputNumber min={10} max={500} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="allowImageUpload"
                    label="允许图片上传"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="允许" unCheckedChildren="禁止" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maxImageSize"
                    label="图片最大大小(MB)"
                  >
                    <InputNumber min={1} max={20} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={24}>
                  <Form.Item
                    name="allowedImageTypes"
                    label="允许的图片类型"
                  >
                    <Select
                      mode="multiple"
                      placeholder="选择允许的图片类型"
                      options={[
                        { label: 'JPG', value: 'jpg' },
                        { label: 'JPEG', value: 'jpeg' },
                        { label: 'PNG', value: 'png' },
                        { label: 'GIF', value: 'gif' },
                        { label: 'WEBP', value: 'webp' }
                      ]}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="contentModerationEnabled"
                    label="内容审核"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="autoApproveContent"
                    label="自动通过审核"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>

            {/* 支付设置 */}
            <TabPane
              tab={
                <span>
                  <DollarOutlined />
                  支付设置
                </span>
              }
              key="payment"
            >
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    name="paymentEnabled"
                    label="启用支付功能"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="paymentFeeRate"
                    label="支付手续费率"
                    tooltip="平台收取的手续费比例，0.03表示3%"
                  >
                    <InputNumber
                      min={0}
                      max={1}
                      step={0.001}
                      formatter={value => `${(Number(value) * 100).toFixed(1)}%`}
                      parser={(value: string | undefined) => {
                        if (!value) return 0;
                        const num = Number(value.replace('%', '')) / 100;
                        return isNaN(num) ? 0 : num;
                      }}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="minPaymentAmount"
                    label="最小支付金额"
                  >
                    <InputNumber
                      min={0.01}
                      precision={2}
                      formatter={value => `¥ ${value}`}
                      parser={(value: string | undefined) => {
                        if (!value) return 0.01;
                        const num = Number(value.replace('¥ ', ''));
                        return isNaN(num) ? 0.01 : num;
                      }}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maxPaymentAmount"
                    label="最大支付金额"
                  >
                    <InputNumber
                      min={1}
                      precision={2}
                      formatter={(value) => `¥ ${value}`}
                      parser={(value: string | undefined) => {
                        if (!value) return 0.01;
                        const num = parseFloat(value.replace('¥ ', ''));
                        return isNaN(num) ? 0.01 : num;
                      }}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="withdrawMinAmount"
                    label="最小提现金额"
                  >
                    <InputNumber
                      min={1}
                      precision={2}
                      formatter={(value) => `¥ ${value}`}
                      parser={(value: string | undefined) => {
                         if (!value) return 1;
                         const num = parseFloat(value.replace('¥ ', ''));
                         return isNaN(num) ? 1 : num;
                       }}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="withdrawFeeRate"
                    label="提现手续费率"
                  >
                    <InputNumber
                      min={0}
                      max={1}
                      step={0.001}
                      formatter={(value) => `${(Number(value) * 100).toFixed(1)}%`}
                      parser={(value: string | undefined) => {
                         if (!value) return 0;
                         const num = parseFloat(value.replace('%', '')) / 100;
                         return isNaN(num) ? 0 : num;
                       }}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>

            {/* 安全设置 */}
            <TabPane
              tab={
                <span>
                  <SecurityScanOutlined />
                  安全设置
                </span>
              }
              key="security"
            >
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    name="rateLimitEnabled"
                    label="启用频率限制"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maxRequestsPerMinute"
                    label="每分钟最大请求数"
                  >
                    <InputNumber min={1} max={1000} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="sessionTimeout"
                    label="会话超时时间(分钟)"
                  >
                    <InputNumber min={5} max={1440} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="maxLoginAttempts"
                    label="最大登录尝试次数"
                  >
                    <InputNumber min={3} max={10} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="lockoutDuration"
                    label="锁定时长(分钟)"
                  >
                    <InputNumber min={1} max={1440} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>

            {/* 通知设置 */}
            <TabPane
              tab={
                <span>
                  <BellOutlined />
                  通知设置
                </span>
              }
              key="notification"
            >
              <Row gutter={24}>
                <Col span={8}>
                  <Form.Item
                    name="emailNotificationEnabled"
                    label="邮件通知"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="pushNotificationEnabled"
                    label="推送通知"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="smsNotificationEnabled"
                    label="短信通知"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="notificationRetentionDays"
                    label="通知保留天数"
                  >
                    <InputNumber min={1} max={365} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>

            {/* 地图设置 */}
            <TabPane
              tab={
                <span>
                  <GlobalOutlined />
                  地图设置
                </span>
              }
              key="map"
            >
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    name="mapProvider"
                    label="地图服务商"
                  >
                    <Select
                      options={[
                        { label: '高德地图', value: 'amap' },
                        { label: '百度地图', value: 'baidu' },
                        { label: '腾讯地图', value: 'tencent' },
                        { label: 'Google Maps', value: 'google' }
                      ]}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="mapApiKey"
                    label="地图API密钥"
                  >
                    <Input.Password placeholder="请输入地图API密钥" />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="defaultMapZoom"
                    label="默认缩放级别"
                  >
                    <Slider min={3} max={18} marks={{ 3: '3', 10: '10', 18: '18' }} />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="minMapZoom"
                    label="最小缩放级别"
                  >
                    <Slider min={1} max={10} marks={{ 1: '1', 5: '5', 10: '10' }} />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="maxMapZoom"
                    label="最大缩放级别"
                  >
                    <Slider min={10} max={20} marks={{ 10: '10', 15: '15', 20: '20' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="mapCenterLat"
                    label="地图中心纬度"
                  >
                    <InputNumber
                      min={-90}
                      max={90}
                      precision={6}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="mapCenterLng"
                    label="地图中心经度"
                  >
                    <InputNumber
                      min={-180}
                      max={180}
                      precision={6}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
              </Row>
            </TabPane>
          </Tabs>

          <Divider />
          
          <div className="text-center">
            <Space size="large">
              <Button
                icon={<ReloadOutlined />}
                onClick={resetConfig}
                disabled={!hasChanges}
              >
                重置
              </Button>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                loading={saving}
                onClick={saveConfig}
                disabled={!hasChanges}
              >
                保存配置
              </Button>
            </Space>
          </div>
        </Form>
      </Card>
      </div>
    </div>
  );
};

export default AdminSystemConfigPage;