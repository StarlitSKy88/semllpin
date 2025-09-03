'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { TrendingUp, TrendingDown, Users, MapPin, DollarSign } from 'lucide-react';

// 模拟数据
const userGrowthData = [
  { date: '01-01', newUsers: 12, totalUsers: 1200 },
  { date: '01-02', newUsers: 15, totalUsers: 1215 },
  { date: '01-03', newUsers: 8, totalUsers: 1223 },
  { date: '01-04', newUsers: 22, totalUsers: 1245 },
  { date: '01-05', newUsers: 18, totalUsers: 1263 },
  { date: '01-06', newUsers: 25, totalUsers: 1288 },
  { date: '01-07', newUsers: 30, totalUsers: 1318 },
];

const revenueData = [
  { date: '01-01', revenue: 1250, transactions: 45 },
  { date: '01-02', revenue: 1680, transactions: 52 },
  { date: '01-03', revenue: 890, transactions: 38 },
  { date: '01-04', revenue: 2100, transactions: 67 },
  { date: '01-05', revenue: 1950, transactions: 58 },
  { date: '01-06', revenue: 2350, transactions: 72 },
  { date: '01-07', revenue: 2800, transactions: 85 },
];

const annotationStatsData = [
  { date: '01-01', created: 25, approved: 20, rejected: 3 },
  { date: '01-02', created: 32, approved: 28, rejected: 2 },
  { date: '01-03', created: 18, approved: 15, rejected: 1 },
  { date: '01-04', created: 45, approved: 38, rejected: 5 },
  { date: '01-05', created: 38, approved: 32, rejected: 4 },
  { date: '01-06', created: 52, approved: 45, rejected: 3 },
  { date: '01-07', created: 60, approved: 52, rejected: 6 },
];

const locationStatsData = [
  { city: '北京', count: 156, revenue: 3200 },
  { city: '上海', count: 142, revenue: 2980 },
  { city: '广州', count: 98, revenue: 2100 },
  { city: '深圳', count: 87, revenue: 1850 },
  { city: '杭州', count: 76, revenue: 1620 },
  { city: '成都', count: 65, revenue: 1380 },
  { city: '武汉', count: 54, revenue: 1150 },
  { city: '西安', count: 43, revenue: 920 },
];

const statusDistributionData = [
  { name: '已通过', value: 68, color: '#10b981' },
  { name: '待审核', value: 23, color: '#f59e0b' },
  { name: '已拒绝', value: 9, color: '#ef4444' },
];

interface AnalyticsChartsProps {
  className?: string;
}

export function AnalyticsCharts({ className }: AnalyticsChartsProps) {
  return (
    <div className={`grid grid-cols-1 lg:grid-cols-2 gap-6 ${className}`}>
      {/* 用户增长趋势 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>用户增长趋势</span>
          </CardTitle>
          <CardDescription>最近7天新用户注册情况</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={userGrowthData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Area
                type="monotone"
                dataKey="newUsers"
                stackId="1"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.6}
                name="新用户"
              />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-between mt-4 text-sm">
            <div className="flex items-center space-x-1 text-green-600">
              <TrendingUp className="h-4 w-4" />
              <span>+12% 较上周</span>
            </div>
            <div className="text-gray-500">
              总用户: {userGrowthData[userGrowthData.length - 1]?.totalUsers.toLocaleString()}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 收入统计 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <DollarSign className="h-5 w-5" />
            <span>收入统计</span>
          </CardTitle>
          <CardDescription>最近7天平台收入情况</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={revenueData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip formatter={(value, name) => [`¥${value}`, name]} />
              <Legend />
              <Line
                type="monotone"
                dataKey="revenue"
                stroke="#10b981"
                strokeWidth={2}
                name="收入 (¥)"
              />
            </LineChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-between mt-4 text-sm">
            <div className="flex items-center space-x-1 text-green-600">
              <TrendingUp className="h-4 w-4" />
              <span>+15% 较上周</span>
            </div>
            <div className="text-gray-500">
              总交易: {revenueData.reduce((sum, item) => sum + item.transactions, 0)} 笔
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 标注统计 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <MapPin className="h-5 w-5" />
            <span>标注统计</span>
          </CardTitle>
          <CardDescription>最近7天标注创建和审核情况</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={annotationStatsData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="created" fill="#3b82f6" name="创建" />
              <Bar dataKey="approved" fill="#10b981" name="通过" />
              <Bar dataKey="rejected" fill="#ef4444" name="拒绝" />
            </BarChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-between mt-4 text-sm">
            <div className="flex items-center space-x-1 text-green-600">
              <TrendingUp className="h-4 w-4" />
              <span>通过率: 85%</span>
            </div>
            <div className="text-gray-500">
              总标注: {annotationStatsData.reduce((sum, item) => sum + item.created, 0)}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 标注状态分布 */}
      <Card>
        <CardHeader>
          <CardTitle>标注状态分布</CardTitle>
          <CardDescription>当前所有标注的状态分布</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={statusDistributionData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {statusDistributionData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-3 gap-4 mt-4">
            {statusDistributionData.map((item) => (
              <div key={item.name} className="text-center">
                <div className="flex items-center justify-center space-x-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-sm font-medium">{item.name}</span>
                </div>
                <div className="text-lg font-bold mt-1">{item.value}%</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* 地域分布 */}
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>地域分布统计</CardTitle>
          <CardDescription>各城市标注数量和收入情况</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={locationStatsData} layout="horizontal">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="city" type="category" width={60} />
              <Tooltip
                formatter={(value, name) => [
                  name === 'count' ? `${value} 个` : `¥${value}`,
                  name === 'count' ? '标注数量' : '收入'
                ]}
              />
              <Legend />
              <Bar dataKey="count" fill="#3b82f6" name="标注数量" />
              <Bar dataKey="revenue" fill="#10b981" name="收入 (¥)" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}

export default AnalyticsCharts;