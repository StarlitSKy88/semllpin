'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { 
  MapPin, 
  Search, 
  Navigation, 
  Star, 
  Zap, 
  CreditCard, 
  Users, 
  Target,
  Filter,
  Image,
  MessageCircle
} from 'lucide-react'

const features = [
  {
    icon: MapPin,
    title: 'OSM地图集成',
    description: '使用OpenStreetMap提供高质量的地图服务，支持实时交互和标注显示',
    color: 'from-blue-500 to-cyan-500'
  },
  {
    icon: Search,
    title: '智能地址搜索',
    description: '支持地址搜索和地理编码，快速定位到任意地点',
    color: 'from-green-500 to-emerald-500'
  },
  {
    icon: Star,
    title: '气味分类标注',
    description: '9种气味类型分类，5级强度评估，专业的气味标注系统',
    color: 'from-purple-500 to-pink-500'
  },
  {
    icon: Navigation,
    title: '位置服务',
    description: '自动获取用户当前位置，支持位置跟踪和导航',
    color: 'from-orange-500 to-red-500'
  },
  {
    icon: Users,
    title: '附近标注',
    description: '实时显示附近的气味标注，查看其他用户分享的内容',
    color: 'from-teal-500 to-blue-500'
  },
  {
    icon: Filter,
    title: '高级筛选',
    description: '按气味类型、强度、时间等多维度筛选标注',
    color: 'from-indigo-500 to-purple-500'
  },
  {
    icon: CreditCard,
    title: 'PayPal支付',
    description: '安全的在线支付系统，支持创建付费标注',
    color: 'from-yellow-500 to-orange-500'
  },
  {
    icon: Zap,
    title: 'LBS奖励系统',
    description: '基于位置的奖励机制，发现标注可获得奖励',
    color: 'from-pink-500 to-rose-500'
  },
  {
    icon: Image,
    title: '图片上传',
    description: '支持多图片上传，首次标注需要提供图片证据',
    color: 'from-cyan-500 to-blue-500'
  },
  {
    icon: MessageCircle,
    title: '评论互动',
    description: '用户可以对标注进行评论和互动，分享更多信息',
    color: 'from-emerald-500 to-teal-500'
  },
  {
    icon: Target,
    title: '热力图视图',
    description: '以热力图形式可视化气味分布密度和强度',
    color: 'from-red-500 to-pink-500'
  }
]

export const MapFeaturesDemo: React.FC = () => {
  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="text-center mb-12">
        <h2 className="text-4xl font-bold bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 bg-clip-text text-transparent mb-4">
          SmellPin 地图功能展示
        </h2>
        <p className="text-white/70 text-lg max-w-2xl mx-auto">
          完整的气味标注地图系统，集成了现代化的交互功能和专业的气味分类体系
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {features.map((feature, index) => {
          const Icon = feature.icon
          return (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="relative group"
            >
              {/* 背景效果 */}
              <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-2xl border border-white/10 group-hover:bg-white/10 transition-all duration-300"></div>
              
              {/* 内容 */}
              <div className="relative p-6">
                {/* 图标 */}
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-r ${feature.color} p-3 mb-4 group-hover:scale-110 transition-transform duration-300`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                
                {/* 标题和描述 */}
                <h3 className="text-white font-semibold text-lg mb-2 group-hover:text-white/90 transition-colors">
                  {feature.title}
                </h3>
                <p className="text-white/70 text-sm leading-relaxed group-hover:text-white/80 transition-colors">
                  {feature.description}
                </p>
              </div>
              
              {/* 悬停效果 */}
              <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                <div className={`absolute inset-0 bg-gradient-to-r ${feature.color} opacity-10 rounded-2xl blur-xl`}></div>
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* 技术栈说明 */}
      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 1.0 }}
        className="mt-16 p-8 bg-white/5 backdrop-blur-xl rounded-3xl border border-white/10"
      >
        <h3 className="text-2xl font-bold text-white mb-6 text-center">技术实现</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div>
            <h4 className="text-lg font-semibold text-white mb-3">前端技术</h4>
            <ul className="space-y-2 text-white/70 text-sm">
              <li>• Next.js 15 + React 18 + TypeScript</li>
              <li>• Tailwind CSS + Framer Motion</li>
              <li>• React Leaflet (OSM地图)</li>
              <li>• Zustand 状态管理</li>
              <li>• React Query 数据获取</li>
            </ul>
          </div>
          <div>
            <h4 className="text-lg font-semibold text-white mb-3">后端集成</h4>
            <ul className="space-y-2 text-white/70 text-sm">
              <li>• Node.js + Express.js API</li>
              <li>• PostgreSQL + PostGIS</li>
              <li>• PayPal 支付集成</li>
              <li>• JWT 认证系统</li>
              <li>• 地理编码服务</li>
            </ul>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

export default MapFeaturesDemo