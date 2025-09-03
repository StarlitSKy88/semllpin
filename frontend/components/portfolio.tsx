"use client"

import Image from "next/image"
import { motion } from "framer-motion"
import TransitionLink from "./transition-link"
import { MapPin, Gift, Compass, Users, Zap, Trophy } from "lucide-react"

const features = [
  {
    title: "创建恶搞标注",
    description: "在地图上任意位置创建搞笑恶搞标注，分享你的创意和幽默。",
    price: "¥1起",
    users: 12400,
    rewards: 8900,
    imgSrc: "/map-pin-creation.png",
    href: "/create",
    category: "创建",
    icon: MapPin,
  },
  {
    title: "LBS定位奖励",
    description: "通过GPS定位发现附近的恶搞标注，获得现金奖励。",
    price: "¥0.5-50",
    users: 8900,
    rewards: 15600,
    imgSrc: "/lbs-rewards.png",
    href: "/discover",
    category: "奖励",
    icon: Gift,
  },
  {
    title: "地图探索",
    description: "探索全球恶搞地图，发现有趣的地点和故事。",
    price: "免费",
    users: 6500,
    rewards: 3200,
    imgSrc: "/map-exploration.png",
    href: "/explore",
    category: "探索",
    icon: Compass,
  },
  {
    title: "社区互动",
    description: "与其他用户互动，点赞评论，建立恶搞社区。",
    price: "免费",
    users: 4200,
    rewards: 2100,
    imgSrc: "/community-interaction.png",
    href: "/community",
    category: "社区",
    icon: Users,
  },
  {
    title: "实时通知",
    description: "接收附近新标注的实时推送，第一时间获得奖励。",
    price: "免费",
    users: 7800,
    rewards: 5400,
    imgSrc: "/real-time-notifications.png",
    href: "/notifications",
    category: "通知",
    icon: Zap,
  },
  {
    title: "排行榜",
    description: "查看创建者和发现者排行榜，争夺恶搞之王称号。",
    price: "免费",
    users: 3200,
    rewards: 1800,
    imgSrc: "/leaderboard.png",
    href: "/leaderboard",
    category: "排行",
    icon: Trophy,
  },
]

export function Portfolio() {
  return (
    <div id="marketplace" className="relative py-20 px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-16">
        <h2 className="text-4xl md:text-5xl font-bold tracking-tight">核心功能</h2>
        <p className="mt-4 max-w-2xl mx-auto text-lg text-neutral-400">
          探索SmellPin的强大功能，创建标注、发现奖励、探索世界，让每个地点都有故事。
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-7xl mx-auto">
        {features.map((feature, index) => (
          <motion.div
            key={feature.title}
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            viewport={{ once: true }}
          >
            <TransitionLink href={feature.href}>
              <div className="group relative block w-full bg-neutral-900/50 backdrop-blur-sm rounded-xl overflow-hidden border border-neutral-800 hover:border-blue-500/50 transition-all duration-300">
                <div className="relative h-48 overflow-hidden">
                  <div className="w-full h-full bg-gradient-to-br from-blue-500/20 to-purple-600/20 flex items-center justify-center">
                    <feature.icon size={48} className="text-white/80" />
                  </div>
                  <div className="absolute top-3 left-3">
                    <span className="bg-blue-500/90 text-white text-xs font-medium px-2 py-1 rounded-full">
                      {feature.category}
                    </span>
                  </div>
                  <div className="absolute top-3 right-3">
                    <span className="bg-black/70 text-white text-sm font-bold px-2 py-1 rounded-full">{feature.price}</span>
                  </div>
                </div>

                <div className="p-6">
                  <h3 className="text-xl font-bold mb-2 group-hover:text-blue-400 transition-colors">{feature.title}</h3>
                  <p className="text-neutral-400 text-sm mb-4 line-clamp-2">{feature.description}</p>

                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-1 text-blue-400">
                        <Users size={14} />
                        <span>{feature.users}</span>
                      </div>
                      <div className="flex items-center gap-1 text-green-400">
                        <Gift size={14} />
                        <span>{feature.rewards}</span>
                      </div>
                    </div>
                    <div className="text-orange-400 font-medium text-xs">
                      {feature.category}
                    </div>
                  </div>
                </div>
              </div>
            </TransitionLink>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
