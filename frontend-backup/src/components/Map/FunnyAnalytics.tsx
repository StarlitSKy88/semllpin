import React, { useMemo } from 'react';
import { Avatar, Card, Col, Progress, Row, Space, Statistic, Timeline, Typography } from 'antd'; // Tag and Tooltip removed as unused
import { Eye, Heart, MapPin, Smile } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Tooltip as RechartsTooltip } from 'recharts';

const { Text } = Typography;

interface Annotation {
  id: string;
  latitude: number;
  longitude: number;
  smell_intensity: number;
  description?: string;
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
  likes_count: number;
  views_count: number;
  created_at: string;
  media_files?: string[];
  category?: string;
}

interface UserStat {
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
  count: number;
  totalLikes: number;
  totalViews: number;
}

interface HotspotData {
  location: string;
  count: number;
  totalLikes: number;
  avgIntensity: number;
}

interface FunnyAnalyticsProps {
  annotations: Annotation[];
  visible?: boolean;
}

const COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8'];

const FunnyAnalytics: React.FC<FunnyAnalyticsProps> = ({ annotations, visible = true }) => {
  const analytics = useMemo(() => {
    if (!annotations.length) {
      return {
        totalAnnotations: 0,
        totalViews: 0,
        totalLikes: 0,
        avgSmellIntensity: 0,
        topUsers: [],
        smellDistribution: [],
        timelineData: [],
        categoryData: [],
        hotspots: [],
        engagementRate: 0,
        recentActivity: []
      };
    }

    // 基础统计
    const totalAnnotations = annotations.length;
    const totalViews = annotations.reduce((sum, ann) => sum + ann.views_count, 0);
    const totalLikes = annotations.reduce((sum, ann) => sum + ann.likes_count, 0);
    const avgSmellIntensity = annotations.reduce((sum, ann) => sum + ann.smell_intensity, 0) / totalAnnotations;
    const engagementRate = totalViews > 0 ? (totalLikes / totalViews) * 100 : 0;

    // 用户排行榜
    const userStats = annotations.reduce((acc, ann) => {
      const userId = ann.user.id;
      if (!acc[userId]) {
        acc[userId] = {
          user: ann.user,
          count: 0,
          totalLikes: 0,
          totalViews: 0
        };
      }
      acc[userId].count++;
      acc[userId].totalLikes += ann.likes_count;
      acc[userId].totalViews += ann.views_count;
      return acc;
    }, {} as Record<string, UserStat>);

    const topUsers = Object.values(userStats)
      .sort((a: UserStat, b: UserStat) => b.totalLikes - a.totalLikes)
      .slice(0, 5);

    // 臭味强度分布
    const smellDistribution = Array.from({ length: 10 }, (_, i) => {
      const intensity = i + 1;
      const count = annotations.filter(ann => ann.smell_intensity === intensity).length;
      return {
        intensity,
        count,
        percentage: (count / totalAnnotations) * 100
      };
    }).filter(item => item.count > 0);

    // 时间线数据（按小时统计）
    const hourlyData = Array.from({ length: 24 }, (_, hour) => {
      const count = annotations.filter(ann => {
        const date = new Date(ann.created_at);
        return date.getHours() === hour;
      }).length;
      return {
        hour: `${hour}:00`,
        count
      };
    });

    // 分类统计
    const categoryStats = annotations.reduce((acc, ann) => {
      const category = ann.category || '未分类';
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const categoryData = Object.entries(categoryStats).map(([name, value]) => ({
      name,
      value,
      percentage: (value / totalAnnotations) * 100
    }));

    // 热点区域（简化版）
    const hotspotsData = annotations
      .reduce((acc, ann) => {
        const key = `${Math.round(ann.latitude * 100) / 100},${Math.round(ann.longitude * 100) / 100}`;
        if (!acc[key]) {
          acc[key] = {
            location: key,
            count: 0,
            totalLikes: 0,
            avgIntensity: 0
          };
        }
        acc[key].count++;
        acc[key].totalLikes += ann.likes_count;
        acc[key].avgIntensity += ann.smell_intensity;
        return acc;
      }, {} as Record<string, HotspotData>);
    
    const hotspots = Object.values(hotspotsData)
      .map((item: HotspotData) => ({
        ...item,
        avgIntensity: item.avgIntensity / item.count
      }))
      .sort((a: HotspotData, b: HotspotData) => b.totalLikes - a.totalLikes)
      .slice(0, 5);

    // 最近活动
    const recentActivity = annotations
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      .slice(0, 10)
      .map(ann => ({
        ...ann,
        timeAgo: getTimeAgo(ann.created_at)
      }));

    return {
      totalAnnotations,
      totalViews,
      totalLikes,
      avgSmellIntensity,
      topUsers,
      smellDistribution,
      timelineData: hourlyData,
      categoryData,
      hotspots,
      engagementRate,
      recentActivity
    };
  }, [annotations]);

  const getTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return '刚刚';
    if (diffInHours < 24) return `${diffInHours}小时前`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}天前`;
    return date.toLocaleDateString('zh-CN');
  };

  if (!visible) return null;

  return (
    <div className="space-y-6">
      {/* 总体统计 */}
      <Card title="📊 搞笑数据总览" className="mb-6">
        <Row gutter={16}>
          <Col span={6}>
            <Statistic
              title="总标注数"
              value={analytics.totalAnnotations}
              prefix={<MapPin size={16} />}
              valueStyle={{ color: '#3f8600' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="总浏览量"
              value={analytics.totalViews}
              prefix={<Eye size={16} />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="总点赞数"
              value={analytics.totalLikes}
              prefix={<Heart size={16} />}
              valueStyle={{ color: '#cf1322' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="平均臭味强度"
              value={analytics.avgSmellIntensity}
              precision={1}
              suffix="/ 10"
              prefix={<Smile size={16} />}
              valueStyle={{ color: '#722ed1' }}
            />
          </Col>
        </Row>
        
        <div className="mt-4">
          <Text strong>互动率: </Text>
          <Progress 
            percent={analytics.engagementRate} 
            size="small" 
            format={(percent) => `${percent?.toFixed(1)}%`}
            strokeColor={{
              '0%': '#108ee9',
              '100%': '#87d068' }}
          />
        </div>
      </Card>

      <Row gutter={16}>
        {/* 用户排行榜 */}
        <Col span={12}>
          <Card title="🏆 搞笑达人榜" size="small">
            <div className="space-y-3">
              {analytics.topUsers.map((userStat: UserStat, index) => (
                <div key={userStat.user.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                  <div className="flex items-center space-x-2">
                    <div className="flex items-center justify-center w-6 h-6 rounded-full bg-primary-500 text-white text-xs font-bold">
                      {index + 1}
                    </div>
                    <Avatar 
                      size="small" 
                      src={userStat.user.avatar}
                      className="bg-primary-500"
                    >
                      {userStat.user.username[0]?.toUpperCase()}
                    </Avatar>
                    <div>
                      <Text strong className="text-sm">{userStat.user.username}</Text>
                      <div className="text-xs text-gray-500">
                        {userStat.count} 个标注
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-bold text-red-500">
                      {userStat.totalLikes} ❤️
                    </div>
                    <div className="text-xs text-gray-500">
                      {userStat.totalViews} 👁️
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </Col>

        {/* 臭味强度分布 */}
        <Col span={12}>
          <Card title="🌡️ 臭味强度分布" size="small">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={analytics.smellDistribution}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="intensity" />
                <YAxis />
                <RechartsTooltip 
                  formatter={(value: number, _name: string) => [value, '数量']}
                  labelFormatter={(label: number) => `强度: ${label}`}
                />
                <Bar dataKey="count" fill="#8884d8" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        {/* 时间分布 */}
        <Col span={12}>
          <Card title="⏰ 发布时间分布" size="small">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={analytics.timelineData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" />
                <YAxis />
                <RechartsTooltip />
                <Line 
                  type="monotone" 
                  dataKey="count" 
                  stroke="#8884d8" 
                  strokeWidth={2}
                  dot={{ fill: '#8884d8' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </Col>

        {/* 分类分布 */}
        <Col span={12}>
          <Card title="📂 分类分布" size="small">
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={analytics.categoryData}
                  cx="50%"
                  cy="50%"
                  outerRadius={60}
                  fill="#8884d8"
                  dataKey="value"
                  label={(entry: { name: string; percent?: number }) => `${entry.name} (${entry.percent?.toFixed(1)}%)`}
                >
                  {analytics.categoryData.map((_entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      {/* 最近活动 */}
      <Card title="🕒 最近活动" size="small">
        <Timeline mode="left" className="mt-4">
          {analytics.recentActivity.slice(0, 5).map((activity: Annotation & { timeAgo: string }) => (
            <Timeline.Item 
              key={activity.id}
              dot={<Avatar size="small" src={activity.user.avatar}>{activity.user.username[0]?.toUpperCase()}</Avatar>}
            >
              <div className="flex items-center justify-between">
                <div>
                  <Text strong>{activity.user.username}</Text>
                  <Text className="ml-2">添加了新标注</Text>
                  <div className="text-sm text-gray-500 mt-1">
                    臭味强度: {activity.smell_intensity}/10
                    {activity.description && (
                      <span className="ml-2">- {activity.description.slice(0, 30)}...</span>
                    )}
                  </div>
                </div>
                <div className="text-right text-sm text-gray-500">
                  <div>{activity.timeAgo}</div>
                  <Space size={8}>
                    <span>👁️ {activity.views_count}</span>
                    <span>❤️ {activity.likes_count}</span>
                  </Space>
                </div>
              </div>
            </Timeline.Item>
          ))}
        </Timeline>
      </Card>
    </div>
  );
};

export default FunnyAnalytics;