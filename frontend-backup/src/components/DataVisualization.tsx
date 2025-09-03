import { Tooltip } from 'antd';
import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Area,
  AreaChart,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ScatterChart,
  Scatter,

} from 'recharts';
import {
  TrendingUp,
  TrendingDown,
  Activity,
  MapPin,
  Users,
  Eye,
  Heart,
  Download,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Maximize2,
  Minimize2,
  MoreVertical,
  Globe,
  Smartphone,
  Monitor,
  Tablet
} from 'lucide-react';
// import { MicroInteraction, LoadingButton, showToast } from './InteractionFeedback';
// import { useMobile } from './MobileOptimization';
// import { useNetworkStatus } from './NetworkStatus';
// import EmptyState, { LoadingState } from './EmptyState';

interface ChartData {
  name: string;
  value: number;
  category?: string;
  date?: string;
  percentage?: number;
  growth?: number;
  color?: string;
}

interface MetricCard {
  id: string;
  title: string;
  value: string | number;
  change: number;
  changeType: 'increase' | 'decrease' | 'neutral';
  icon: React.ComponentType<any>;
  color: string;
  description?: string;
  trend?: ChartData[];
}

interface DataVisualizationProps {
  timeRange?: '7d' | '30d' | '90d' | '1y';
  showMetrics?: boolean;
  showCharts?: boolean;
  showExport?: boolean;
  className?: string;
}

const DataVisualization: React.FC<DataVisualizationProps> = ({
  timeRange = '30d',
  showMetrics = true,
  showCharts = true,
  showExport = true,
  className = ''
}) => {
  const [selectedTimeRange, setSelectedTimeRange] = useState(timeRange);
  const [selectedChart, setSelectedChart] = useState<'bar' | 'line' | 'pie' | 'area' | 'radar' | 'scatter'>('bar');
  const [isLoading, setIsLoading] = useState(true);
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const [fullscreenChart, setFullscreenChart] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [refreshing, setRefreshing] = useState(false);
  
  // const isMobile = false; // 简化处理
  const isOnline = true; // 简化处理

  // 模拟数据
  const mockMetrics: MetricCard[] = [
    {
      id: 'total-pins',
      title: '总标注数',
      value: '2,847',
      change: 12.5,
      changeType: 'increase',
      icon: MapPin,
      color: 'blue',
      description: '用户创建的气味标注总数',
      trend: [
        { name: '1月', value: 2100 },
        { name: '2月', value: 2300 },
        { name: '3月', value: 2500 },
        { name: '4月', value: 2700 },
        { name: '5月', value: 2847 }
      ]
    },
    {
      id: 'active-users',
      title: '活跃用户',
      value: '1,234',
      change: 8.3,
      changeType: 'increase',
      icon: Users,
      color: 'green',
      description: '过去30天内活跃的用户数量',
      trend: [
        { name: '1月', value: 980 },
        { name: '2月', value: 1050 },
        { name: '3月', value: 1150 },
        { name: '4月', value: 1200 },
        { name: '5月', value: 1234 }
      ]
    },
    {
      id: 'page-views',
      title: '页面浏览量',
      value: '45.2K',
      change: -2.1,
      changeType: 'decrease',
      icon: Eye,
      color: 'purple',
      description: '网站总页面浏览量',
      trend: [
        { name: '1月', value: 42000 },
        { name: '2月', value: 44000 },
        { name: '3月', value: 46000 },
        { name: '4月', value: 47000 },
        { name: '5月', value: 45200 }
      ]
    },
    {
      id: 'engagement',
      title: '用户参与度',
      value: '78.5%',
      change: 5.2,
      changeType: 'increase',
      icon: Heart,
      color: 'red',
      description: '用户互动参与度指标',
      trend: [
        { name: '1月', value: 72 },
        { name: '2月', value: 74 },
        { name: '3月', value: 76 },
        { name: '4月', value: 77 },
        { name: '5月', value: 78.5 }
      ]
    }
  ];

  const mockChartData = {
    smellCategories: [
      { name: '咖啡香', value: 450, color: '#8B4513' },
      { name: '花香', value: 380, color: '#FF69B4' },
      { name: '食物香', value: 320, color: '#FFA500' },
      { name: '自然香', value: 280, color: '#32CD32' },
      { name: '其他', value: 170, color: '#808080' }
    ],
    timeSeriesData: [
      { name: '1月', pins: 240, users: 180, views: 3200, engagement: 72 },
      { name: '2月', pins: 280, users: 220, views: 3800, engagement: 74 },
      { name: '3月', pins: 320, users: 250, views: 4200, engagement: 76 },
      { name: '4月', pins: 380, users: 290, views: 4600, engagement: 77 },
      { name: '5月', pins: 420, users: 320, views: 4800, engagement: 78.5 },
      { name: '6月', pins: 450, users: 340, views: 5000, engagement: 80 }
    ],
    deviceData: [
      { name: '移动端', value: 65, icon: Smartphone },
      { name: '桌面端', value: 28, icon: Monitor },
      { name: '平板端', value: 7, icon: Tablet }
    ],
    locationData: [
      { name: '北京', value: 850, lat: 39.9042, lng: 116.4074 },
      { name: '上海', value: 720, lat: 31.2304, lng: 121.4737 },
      { name: '广州', value: 580, lat: 23.1291, lng: 113.2644 },
      { name: '深圳', value: 520, lat: 22.3193, lng: 114.1694 },
      { name: '杭州', value: 380, lat: 30.2741, lng: 120.1551 }
    ],
    radarData: [
      {
        subject: '用户体验',
        A: 85,
        B: 78,
        fullMark: 100
      },
      {
        subject: '性能表现',
        A: 92,
        B: 85,
        fullMark: 100
      },
      {
        subject: '内容质量',
        A: 78,
        B: 82,
        fullMark: 100
      },
      {
        subject: '社区活跃',
        A: 88,
        B: 75,
        fullMark: 100
      },
      {
        subject: '功能完整',
        A: 90,
        B: 88,
        fullMark: 100
      },
      {
        subject: '易用性',
        A: 82,
        B: 79,
        fullMark: 100
      }
    ]
  };

  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);
      try {
        await new Promise(resolve => setTimeout(resolve, 1500));
      } catch (error) {
        console.error('数据加载失败:', error);
        alert('数据加载失败');
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
  }, [selectedTimeRange]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      console.log('数据已刷新');
      alert('数据已刷新');
    } catch (error) {
      console.error('刷新失败:', error);
      alert('刷新失败');
    } finally {
      setRefreshing(false);
    }
  };

  const handleExport = async (format: 'csv' | 'pdf' | 'png') => {
    try {
      console.log(`正在导出${format.toUpperCase()}格式...`);
      alert(`正在导出${format.toUpperCase()}格式...`);
      await new Promise(resolve => setTimeout(resolve, 2000));
      console.log('导出成功');
      alert('导出成功');
    } catch (error) {
      console.error('导出失败:', error);
      alert('导出失败');
    }
  };

  const getChangeIcon = (type: 'increase' | 'decrease' | 'neutral') => {
    switch (type) {
      case 'increase':
        return <TrendingUp className="w-4 h-4 text-green-500" />;
      case 'decrease':
        return <TrendingDown className="w-4 h-4 text-red-500" />;
      default:
        return <Activity className="w-4 h-4 text-gray-500" />;
    }
  };

  const getChangeColor = (type: 'increase' | 'decrease' | 'neutral') => {
    switch (type) {
      case 'increase':
        return 'text-green-600';
      case 'decrease':
        return 'text-red-600';
      default:
        return 'text-gray-600';
    }
  };

  const renderMetricCard = (metric: MetricCard) => {
    const IconComponent = metric.icon;
    const isExpanded = expandedCard === metric.id;

    return (
      <motion.div
        key={metric.id}
        layout
        className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden"
      >
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className={`p-3 rounded-lg bg-${metric.color}-100`}>
              <IconComponent className={`w-6 h-6 text-${metric.color}-600`} />
            </div>
            <button
              onClick={() => setExpandedCard(isExpanded ? null : metric.id)}
              className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
            >
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
          
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-600">{metric.title}</h3>
            <div className="flex items-end gap-2">
              <span className="text-2xl font-bold text-gray-900">{metric.value}</span>
              <div className={`flex items-center gap-1 ${getChangeColor(metric.changeType)}`}>
                {getChangeIcon(metric.changeType)}
                <span className="text-sm font-medium">
                  {Math.abs(metric.change)}%
                </span>
              </div>
            </div>
            {metric.description && (
              <p className="text-xs text-gray-500">{metric.description}</p>
            )}
          </div>
        </div>
        
        <AnimatePresence>
          {isExpanded && metric.trend && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="border-t border-gray-100 p-4"
            >
              <h4 className="text-sm font-medium text-gray-700 mb-3">趋势图</h4>
              <ResponsiveContainer width="100%" height={120}>
                <LineChart data={metric.trend}>
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke={`var(--color-${metric.color}-500)`}
                    strokeWidth={2}
                    dot={false}
                  />
                  <XAxis dataKey="name" hide />
                  <YAxis hide />
                  <Tooltip />
                </LineChart>
              </ResponsiveContainer>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    );
  };

  const renderChart = (type: string, data: unknown[], title: string) => {
    const chartId = `chart-${type}`;
    const isFullscreen = fullscreenChart === chartId;

    const chartContent = () => {
      switch (type) {
        case 'bar':
          return (
            <ResponsiveContainer width="100%" height={isFullscreen ? 500 : 300}>
              <BarChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          );
        
        case 'line':
          return (
            <ResponsiveContainer width="100%" height={isFullscreen ? 500 : 300}>
              <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="pins" stroke="#3B82F6" strokeWidth={2} />
                <Line type="monotone" dataKey="users" stroke="#10B981" strokeWidth={2} />
                <Line type="monotone" dataKey="views" stroke="#F59E0B" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          );
        
        case 'pie':
          return (
            <ResponsiveContainer width="100%" height={isFullscreen ? 500 : 300}>
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${percent ? (percent * 100).toFixed(0) : 0}%`}
                  outerRadius={isFullscreen ? 180 : 100}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {(data as Array<{ color: string }>).map((entry, index: number) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          );
        
        case 'area':
          return (
            <ResponsiveContainer width="100%" height={isFullscreen ? 500 : 300}>
              <AreaChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="engagement"
                  stackId="1"
                  stroke="#8B5CF6"
                  fill="#8B5CF6"
                  fillOpacity={0.6}
                />
              </AreaChart>
            </ResponsiveContainer>
          );
        
        case 'radar':
          return (
            <ResponsiveContainer width="100%" height={isFullscreen ? 500 : 300}>
              <RadarChart data={data}>
                <PolarGrid />
                <PolarAngleAxis dataKey="subject" />
                <PolarRadiusAxis angle={90} domain={[0, 100]} />
                <Radar
                  name="当前"
                  dataKey="A"
                  stroke="#3B82F6"
                  fill="#3B82F6"
                  fillOpacity={0.3}
                />
                <Radar
                  name="对比"
                  dataKey="B"
                  stroke="#10B981"
                  fill="#10B981"
                  fillOpacity={0.3}
                />
                <Legend />
                <Tooltip />
              </RadarChart>
            </ResponsiveContainer>
          );
        
        case 'scatter':
          return (
            <ResponsiveContainer width="100%" height={isFullscreen ? 500 : 300}>
              <ScatterChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="lat" name="纬度" />
                <YAxis dataKey="lng" name="经度" />
                <Tooltip />
                <Scatter name="位置" dataKey="value" fill="#3B82F6" />
              </ScatterChart>
            </ResponsiveContainer>
          );
        
        default:
          return null;
      }
    };

    return (
      <motion.div
        layout
        className={`bg-white rounded-lg shadow-sm border border-gray-200 ${
          isFullscreen ? 'fixed inset-4 z-50' : ''
        }`}
      >
        <div className="p-4 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-800">{title}</h3>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setFullscreenChart(isFullscreen ? null : chartId)}
                className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
              >
                {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
              </button>
              <button className="p-1 text-gray-400 hover:text-gray-600 transition-colors">
                <MoreVertical className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
        
        <div className="p-4">
          {chartContent()}
        </div>
        
        {isFullscreen && (
          <div className="absolute inset-0 bg-black bg-opacity-50 -z-10" 
               onClick={() => setFullscreenChart(null)} />
        )}
      </motion.div>
    );
  };

  if (isLoading) {
    return (
      <div className={`w-full ${className}`}>
        <div className="flex items-center justify-center p-8">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-600">加载数据分析中...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!isOnline) {
    return (
      <div className={`w-full ${className}`}>
        <div className="flex items-center justify-center p-8">
          <div className="text-center">
            <Globe className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">网络连接异常</h3>
            <p className="text-gray-600 mb-4">请检查网络连接后重试</p>
            <button onClick={handleRefresh} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
              重试
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`w-full space-y-6 ${className}`}>
      {/* 控制面板 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-800">数据分析</h2>
          <div className="flex items-center gap-2">
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="flex items-center gap-1 px-3 py-2 text-gray-600 hover:text-gray-800 transition-colors disabled:opacity-50 hover:scale-105 transition-transform"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              刷新
            </button>
            
            {showExport && (
              <div className="relative group">
                <button className="flex items-center gap-1 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                  <Download className="w-4 h-4" />
                  导出
                </button>
                <div className="absolute right-0 top-full mt-1 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                  <div className="hover:scale-105 transition-transform">
                    <button
                      onClick={() => handleExport('csv')}
                      className="flex items-center gap-1 px-3 py-2 text-blue-600 hover:text-blue-800 transition-colors"
                    >
                      <Download className="w-4 h-4" />
                      CSV
                    </button>
                  </div>
                  <div className="hover:scale-105 transition-transform">
                    <button
                      onClick={() => handleExport('pdf')}
                      className="flex items-center gap-1 px-3 py-2 text-red-600 hover:text-red-800 transition-colors"
                    >
                      <Download className="w-4 h-4" />
                      PDF
                    </button>
                  </div>
                  <div className="hover:scale-105 transition-transform">
                    <button
                      onClick={() => handleExport('png')}
                      className="flex items-center gap-1 px-3 py-2 text-green-600 hover:text-green-800 transition-colors"
                    >
                      <Download className="w-4 h-4" />
                      PNG
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <label className="text-sm font-medium text-gray-700">时间范围:</label>
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value as '7d' | '30d' | '90d' | '1y')}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="7d">最近7天</option>
              <option value="30d">最近30天</option>
              <option value="90d">最近90天</option>
              <option value="1y">最近1年</option>
            </select>
          </div>
          
          <div className="flex items-center gap-2">
            <label className="text-sm font-medium text-gray-700">图表类型:</label>
            <select
              value={selectedChart}
              onChange={(e) => setSelectedChart(e.target.value as 'bar' | 'line' | 'pie' | 'area' | 'radar' | 'scatter')}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="bar">柱状图</option>
              <option value="line">折线图</option>
              <option value="pie">饼图</option>
              <option value="area">面积图</option>
              <option value="radar">雷达图</option>
              <option value="scatter">散点图</option>
            </select>
          </div>
          
          <div className="flex items-center gap-2">
            <label className="text-sm font-medium text-gray-700">分类:</label>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">全部</option>
              <option value="users">用户</option>
              <option value="content">内容</option>
              <option value="engagement">互动</option>
            </select>
          </div>
        </div>
      </div>
      
      {/* 指标卡片 */}
      {showMetrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {mockMetrics.map((metric, index) => (
            <div key={`metric-${metric.title}-${index}`}>
              {renderMetricCard(metric)}
            </div>
          ))}
        </div>
      )}
      
      {/* 图表展示 */}
      {showCharts && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {renderChart('bar', mockChartData.smellCategories, '气味分类统计')}
          {renderChart('line', mockChartData.timeSeriesData, '时间序列分析')}
          {renderChart('pie', mockChartData.deviceData, '设备使用分布')}
          {renderChart('radar', mockChartData.radarData, '综合评估雷达图')}
        </div>
      )}
      
      {/* 详细数据表格 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-4 border-b border-gray-100">
          <h3 className="text-lg font-semibold text-gray-800">详细数据</h3>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  日期
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  标注数
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  用户数
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  浏览量
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  参与度
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {mockChartData.timeSeriesData.map((row, index) => (
                <tr key={`item-${index}`} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-sm text-gray-900">{row.name}</td>
                  <td className="px-4 py-3 text-sm text-gray-900">{row.pins}</td>
                  <td className="px-4 py-3 text-sm text-gray-900">{row.users}</td>
                  <td className="px-4 py-3 text-sm text-gray-900">{row.views}</td>
                  <td className="px-4 py-3 text-sm text-gray-900">{row.engagement}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      
      {/* 网络状态提示 */}
      {!isOnline && (
        <div className="fixed bottom-4 left-4 right-4 bg-yellow-100 border border-yellow-300 rounded-lg p-3 z-40">
          <p className="text-yellow-800 text-sm text-center">
            网络连接断开，数据可能不是最新的
          </p>
        </div>
      )}
    </div>
  );
};

export default DataVisualization;