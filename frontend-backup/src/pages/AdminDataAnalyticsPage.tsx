import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  Row,
  Col,
  Statistic,
  DatePicker,
  Select,
  Button,
  Tabs,
  Space,

  Table,
  Tag,
  Progress,
  List,
  Avatar,
  Empty,
  Alert,
} from 'antd';
import { DecorativeElements } from '../components/UI/DecorativeElements';
import {
  DownloadOutlined,
  ReloadOutlined,
  UserOutlined,
  EnvironmentOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
  HeartOutlined,
  ShareAltOutlined,
} from '@ant-design/icons';
import {
  Line,
  Column,
  Pie,

} from '@ant-design/plots';
import dayjs from 'dayjs';
import type {
  UserBehaviorAnalytics,
  RevenueAnalytics,
  GeographicAnalytics,
  ContentAnalytics,
  AnalyticsParams
} from '../services/adminApi';
import adminApi, { formatCurrency, formatNumber, formatPercentage, formatGrowthRate } from '../services/adminApi';

const { RangePicker } = DatePicker;
const { Option } = Select;
const { TabPane } = Tabs;

const AdminDataAnalyticsPage: React.FC = () => {
  const [dateRange, setDateRange] = useState<[dayjs.Dayjs, dayjs.Dayjs]>([
    dayjs().subtract(30, 'day'),
    dayjs()
  ]);
  const [selectedRegion, setSelectedRegion] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [userBehaviorStats, setUserBehaviorStats] = useState<UserBehaviorAnalytics | null>(null);
  const [revenueAnalytics, setRevenueAnalytics] = useState<RevenueAnalytics | null>(null);
  const [geographicData, setGeographicData] = useState<GeographicAnalytics | null>(null);
  const [contentAnalytics, setContentAnalytics] = useState<ContentAnalytics | null>(null);
  const [realTimeMetrics, setRealTimeMetrics] = useState<{
    onlineUsers: number;
    activeAnnotations: number;
    recentTransactions: number;
    systemLoad: number;
  } | null>(null);

  const loadAnalyticsData = useCallback(async () => {
    try {
      const params: AnalyticsParams = {
        startDate: dateRange?.[0]?.format('YYYY-MM-DD'),
        endDate: dateRange?.[1]?.format('YYYY-MM-DD'),
        region: selectedRegion === 'all' ? undefined : selectedRegion
      };
      
      const [userRes, revenueRes, geoRes, contentRes, realTimeRes] = await Promise.all([
        adminApi.getUserBehaviorAnalytics(params),
        adminApi.getRevenueAnalytics(params),
        adminApi.getGeographicAnalytics(params),
        adminApi.getContentAnalytics(params),
        adminApi.getRealTimeMetrics()
      ]);
      
      setUserBehaviorStats(userRes);
      setRevenueAnalytics(revenueRes);
      setGeographicData(geoRes);
      setContentAnalytics(contentRes);
      setRealTimeMetrics(realTimeRes);
    } catch (error) {
      console.error('加载分析数据失败:', error);
    }
  }, [dateRange, selectedRegion]);

  useEffect(() => {
    loadAnalyticsData();
    
    // 设置实时数据更新
    const interval = setInterval(loadRealTimeMetrics, 30000); // 每30秒更新一次
    return () => clearInterval(interval);
  }, [dateRange, selectedRegion, loadAnalyticsData]);

  const loadRealTimeMetrics = async () => {
    try {
      const response = await adminApi.getRealTimeMetrics();
      setRealTimeMetrics(response);
    } catch (error) {
      console.error('加载实时数据失败:', error);
    }
  };

  const exportAnalyticsData = async () => {
    try {
      const response = await adminApi.exportAnalyticsReport('user', {
        startDate: dateRange?.[0]?.format('YYYY-MM-DD'),
        endDate: dateRange?.[1]?.format('YYYY-MM-DD'),
        region: selectedRegion === 'all' ? undefined : selectedRegion
      });
      
      const blob = new Blob([response as BlobPart], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `analytics-report-${dayjs().format('YYYY-MM-DD')}.xlsx`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('导出失败:', error);
    }
  };

  const renderOverview = () => (
    <div>
      {/* 实时指标 */}
      <Alert
        message="实时监控"
        description={`在线用户: ${realTimeMetrics?.onlineUsers || 0} | 活跃标注: ${realTimeMetrics?.activeAnnotations || 0} | 系统负载: ${realTimeMetrics?.systemLoad || 0}%`}
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
        action={
          <Button size="small" icon={<ReloadOutlined />} onClick={loadRealTimeMetrics}>
            刷新
          </Button>
        }
      />
      
      {/* 核心指标 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="总用户数"
              value={userBehaviorStats?.totalUsers || 0}
              prefix={<UserOutlined />}
              formatter={(value) => formatNumber(Number(value))}
              suffix={
                <span style={{ fontSize: 14, color: '#52c41a' }}>
                  <ArrowUpOutlined /> +{userBehaviorStats?.newUsers || 0}
                </span>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="活跃用户"
              value={userBehaviorStats?.activeUsers || 0}
              prefix={<HeartOutlined />}
              formatter={(value) => formatNumber(Number(value))}
              suffix={
                <span style={{ fontSize: 14, color: '#1890ff' }}>
                  {formatPercentage((userBehaviorStats?.activeUsers || 0) / (userBehaviorStats?.totalUsers || 1))}
                </span>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="总收入"
              value={revenueAnalytics?.totalRevenue || 0}
              precision={2}
              prefix="¥"
              formatter={(value) => formatCurrency(Number(value))}
              suffix={
                  <span style={{ fontSize: 14, color: revenueAnalytics?.revenueGrowthRate && revenueAnalytics.revenueGrowthRate > 0 ? '#52c41a' : '#ff4d4f' }}>
                  {revenueAnalytics?.revenueGrowthRate && revenueAnalytics.revenueGrowthRate > 0 ? <ArrowUpOutlined /> : <ArrowDownOutlined />}
                  {formatGrowthRate(revenueAnalytics?.revenueGrowthRate || 0)}
                </span>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="收入增长率"
              value={revenueAnalytics?.revenueGrowthRate || 0}
              precision={2}
              suffix="%"
              prefix={<ShareAltOutlined />}
              formatter={(value) => formatPercentage(Number(value))}
              valueStyle={{ color: revenueAnalytics?.revenueGrowthRate && revenueAnalytics.revenueGrowthRate > 0 ? '#3f8600' : '#cf1322' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 趋势图表 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="用户增长趋势">
            {userBehaviorStats?.userGrowthTrend && (
              <Line
                data={userBehaviorStats.userGrowthTrend}
                xField="date"
                yField="count"
                smooth
                color="#1890ff"
                height={300}
              />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="收入趋势" style={{ marginTop: 16 }}>
            <Column
              data={revenueAnalytics?.revenueByCategory || []}
              xField="category"
              yField="amount"
              color="#52c41a"
              height={300}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );

  const renderUserAnalytics = () => (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}>
        <Card title="用户增长趋势">
          {userBehaviorStats?.userGrowthTrend && (
            <Line
              data={userBehaviorStats.userGrowthTrend}
              xField="date"
              yField="count"
              height={300}
              smooth
            />
          )}
        </Card>
      </Col>
      <Col xs={24} lg={12}>
          <Card title="地区分布">
            {geographicData?.annotationsByRegion && (
              <Pie
                data={geographicData.annotationsByRegion}
                angleField="count"
                colorField="region"
                radius={0.8}
                height={300}
              />
            )}
          </Card>
        </Col>
      <Col xs={24}>
        <Card title="用户留存率">
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <Progress
              type="circle"
              percent={userBehaviorStats?.retentionRate || 0}
              format={(percent) => `${percent}%`}
              width={200}
              strokeColor={{
                '0%': '#108ee9',
                '100%': '#87d068'
              }}
            />
            <div style={{ marginTop: 16, fontSize: 16, color: '#666' }}>
              平均会话时长: {Math.round((userBehaviorStats?.averageSessionDuration || 0) / 60)} 分钟
            </div>
          </div>
        </Card>
      </Col>
    </Row>
  );

  const renderRevenueAnalytics = () => (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={16}>
        <Card title="收入趋势">
          {revenueAnalytics?.revenueTrend && (
            <Line
              data={revenueAnalytics.revenueTrend}
              xField="date"
              yField="amount"
              height={300}
              smooth
              color="#52c41a"
            />
          )}
        </Card>
      </Col>
      <Col xs={24} lg={8}>
        <Card title="收入构成">
          {revenueAnalytics?.revenueByCategory && (
            <Pie
              data={revenueAnalytics.revenueByCategory}
              angleField="revenue"
              colorField="category"
              radius={0.8}
              height={300}
              label={{
                type: 'inner',
                content: '{percentage}'
              }}
            />
          )}
        </Card>
      </Col>
      <Col xs={24}>
        <Card title="收入统计">
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={8}>
              <Statistic
                title="总收入"
                value={revenueAnalytics?.totalRevenue || 0}
                precision={2}
                prefix="¥"
                formatter={(value) => formatCurrency(Number(value))}
              />
            </Col>
            <Col xs={24} sm={8}>
              <Statistic
                title="月收入"
                value={revenueAnalytics?.monthlyRevenue || 0}
                precision={2}
                prefix="¥"
                formatter={(value) => formatCurrency(Number(value))}
              />
            </Col>
            <Col xs={24} sm={8}>
              <Statistic
                title="平均用户收入"
                value={revenueAnalytics?.averageRevenuePerUser || 0}
                precision={2}
                prefix="¥"
                formatter={(value) => formatCurrency(Number(value))}
              />
            </Col>
          </Row>
        </Card>
      </Col>
    </Row>
  );

  const renderGeographicAnalytics = () => (
    <Row gutter={[16, 16]}>
      <Col xs={24}>
        <Card title="地理热力图" extra={<Button icon={<EnvironmentOutlined />}>查看地图</Button>}>
          <div style={{ height: 400, background: '#f0f2f5', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Empty description="地图组件加载中..." />
          </div>
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="城市排行">
          <Table
            dataSource={geographicData?.cityStats || []}
            pagination={false}
            size="small"
            columns={[
              {
                title: '城市',
                dataIndex: 'city',
                key: 'city'
              },
              {
                title: '标注数',
                dataIndex: 'annotations',
                key: 'annotations',
                sorter: (a: { city: string; annotations: number; revenue: number; users: number }, b: { city: string; annotations: number; revenue: number; users: number }) => a.annotations - b.annotations
              },
              {
                title: '收入',
                dataIndex: 'revenue',
                key: 'revenue',
                render: (value: number) => `¥${value.toFixed(2)}`,
                sorter: (a: { city: string; annotations: number; revenue: number; users: number }, b: { city: string; annotations: number; revenue: number; users: number }) => a.revenue - b.revenue
              },
              {
                title: '用户数',
                dataIndex: 'users',
                key: 'users',
                sorter: (a: { city: string; annotations: number; revenue: number; users: number }, b: { city: string; annotations: number; revenue: number; users: number }) => a.users - b.users
              }
            ]}
          />
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="热门地点">
          <List
            dataSource={geographicData?.cityStats || []}
            renderItem={(item: { city: string; annotations: number; revenue: number; users: number }) => (
              <List.Item>
                <List.Item.Meta
                  avatar={<Avatar icon={<EnvironmentOutlined />} />}
                  title={item.city}
                  description={
                    <div>
                      <Space>
                        <Tag>标注: {item.annotations}</Tag>
                        <Tag color="green">收入: ¥{item.revenue.toFixed(2)}</Tag>
                        <Tag color="blue">用户: {item.users}</Tag>
                      </Space>
                    </div>
                  }
                />
              </List.Item>
            )}
          />
        </Card>
      </Col>
    </Row>
  );

  const renderContentAnalytics = () => (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={8}>
        <Card title="内容审核概览">
          <div style={{ textAlign: 'center' }}>
            <Statistic
              title="总标注数"
              value={contentAnalytics?.totalAnnotations || 0}
              style={{ marginBottom: 16 }}
            />
            <Progress
              percent={((contentAnalytics?.approvedAnnotations || 0) / (contentAnalytics?.totalAnnotations || 1)) * 100}
              format={() => `通过率 ${(((contentAnalytics?.approvedAnnotations || 0) / (contentAnalytics?.totalAnnotations || 1)) * 100).toFixed(1)}%`}
              strokeColor="#52c41a"
            />
            <div style={{ marginTop: 16, fontSize: 14, color: '#666' }}>
              平均审核时间: {Math.round((contentAnalytics?.averageApprovalTime || 0) / 60)} 分钟
            </div>
          </div>
        </Card>
      </Col>
      <Col xs={24} lg={16}>
        <Card title="内容分类统计">
          {contentAnalytics?.contentByCategory && (
            <Column
              data={contentAnalytics.contentByCategory}
              xField="category"
              yField="count"
              color="#722ed1"
              height={300}
            />
          )}
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="举报原因统计" style={{ marginTop: 16 }}>
          <Column
            data={contentAnalytics?.reportsByReason || []}
            xField="reason"
            yField="count"
            color="#ff7875"
            height={300}
          />
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="内容分类详情">
          <List
            dataSource={contentAnalytics?.contentByCategory || []}
            renderItem={(item: { category: string; count: number }) => (
              <List.Item>
                <List.Item.Meta
                  title={item.category}
                  description={
                    <Space>
                      <Tag>数量: {item.count}</Tag>
                      <Tag color="blue">占比: {((item.count / (contentAnalytics?.totalAnnotations || 1)) * 100).toFixed(1)}%</Tag>
                    </Space>
                  }
                />
              </List.Item>
            )}
          />
        </Card>
      </Col>
    </Row>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-pomegranate-50 to-floral-50">
      <DecorativeElements variant="background" />
      <DecorativeElements variant="floating" position="top-left" />
      <DecorativeElements variant="floating" position="top-right" />
      <DecorativeElements variant="floating" position="bottom-left" />
      <DecorativeElements variant="floating" position="bottom-right" />
      
      <div className="relative z-10" style={{ padding: 24 }}>
        <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h1 style={{ color: '#7f1d1d' }}>数据分析</h1>
        <Space>
          <RangePicker
            value={dateRange}
            onChange={(dates) => {
              if (dates && dates[0] && dates[1]) {
                setDateRange([dates[0], dates[1]]);
              }
            }}
            placeholder={['开始日期', '结束日期']}
          />
          <Select
            value={selectedRegion}
            onChange={setSelectedRegion}
            style={{ width: 120 }}
            placeholder="选择地区"
          >
            <Option value="all">全部地区</Option>
            <Option value="beijing">北京</Option>
            <Option value="shanghai">上海</Option>
            <Option value="guangzhou">广州</Option>
            <Option value="shenzhen">深圳</Option>
          </Select>
          <Button icon={<DownloadOutlined />} onClick={exportAnalyticsData}>
            导出报告
          </Button>
        </Space>
      </div>

      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        <TabPane tab="数据概览" key="overview">
          {renderOverview()}
        </TabPane>
        
        <TabPane tab="用户分析" key="user">
          {renderUserAnalytics()}
        </TabPane>
        
        <TabPane tab="收入分析" key="revenue">
          {renderRevenueAnalytics()}
        </TabPane>
        
        <TabPane tab="地理分析" key="geographic">
          {renderGeographicAnalytics()}
        </TabPane>
        
        <TabPane tab="内容分析" key="content">
          {renderContentAnalytics()}
        </TabPane>
      </Tabs>
      </div>
    </div>
  );
};

export default AdminDataAnalyticsPage;