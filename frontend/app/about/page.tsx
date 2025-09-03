import { Button } from "@/components/ui/button"
import { TransitionLink } from "@/components/transition-link"
import { MapPin, Users, Zap, Globe } from "lucide-react"

const features = [
  {
    icon: MapPin,
    title: "地理位置恶搞",
    description: "在真实世界的任何地点创建有趣的恶搞标注，让每个角落都充满惊喜和欢乐。"
  },
  {
    icon: Zap,
    title: "LBS奖励机制",
    description: "通过先进的定位技术，用户在发现标注时获得真实奖励，让探索变得更有价值。"
  },
  {
    icon: Users,
    title: "全球社区",
    description: "连接世界各地的用户，分享有趣的故事和创意，建立独特的地理社交网络。"
  },
  {
    icon: Globe,
    title: "无界探索",
    description: "打破地理界限，让用户在任何地方都能发现新奇有趣的内容和意外惊喜。"
  }
]

const teamMembers = [
  {
    name: "张伟",
    role: "创始人 & CEO",
    description: "前腾讯地图技术专家，专注于LBS技术和用户体验设计。"
  },
  {
    name: "李小明",
    role: "技术总监",
    description: "全栈工程师，负责平台架构设计和核心功能开发。"
  },
  {
    name: "王丽",
    role: "产品经理",
    description: "用户体验专家，致力于打造最有趣的地理社交产品。"
  },
  {
    name: "陈浩",
    role: "运营总监",
    description: "社区运营专家，负责用户增长和内容生态建设。"
  }
]

export default function AboutPage() {
  return (
    <div className="min-h-screen pt-32 pb-20">
      <div className="container mx-auto px-4">
        {/* Hero Section */}
        <div className="text-center mb-20">
          <h1 className="text-5xl md:text-7xl font-bold mb-6">关于SmellPin</h1>
          <p className="text-xl text-neutral-300 max-w-3xl mx-auto mb-8">
            SmellPin是全球首个基于地理位置的恶搞标注平台。我们相信每个地点都有自己的故事，
            每个角落都值得被发现。通过创新的LBS技术和有趣的社交机制，
            我们让现实世界变得更加有趣和充满惊喜。
          </p>
          <TransitionLink href="/contact">
            <Button size="lg" className="bg-white text-black hover:bg-neutral-200 font-bold text-lg px-8 py-6">
              联系我们
            </Button>
          </TransitionLink>
        </div>

        {/* Mission Section */}
        <div className="mb-20">
          <h2 className="text-4xl font-bold text-center mb-12">我们的使命</h2>
          <div className="max-w-4xl mx-auto text-center">
            <p className="text-lg text-neutral-300 mb-8">
              让每个地理位置都充满故事和惊喜，通过技术连接现实世界与数字体验，
              创造一个全新的地理社交生态系统。
            </p>
            <p className="text-lg text-neutral-300">
              我们致力于打造一个安全、有趣、包容的平台，让用户在探索世界的同时，
              也能创造价值、获得收益、结交朋友。
            </p>
          </div>
        </div>

        {/* Features Section */}
        <div className="mb-20">
          <h2 className="text-4xl font-bold text-center mb-12">核心特色</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => {
              const IconComponent = feature.icon
              return (
                <div key={index} className="bg-[#1a1a1a] p-6 rounded-lg text-center">
                  <div className="flex justify-center mb-4">
                    <IconComponent size={48} className="text-white" />
                  </div>
                  <h3 className="text-xl font-bold mb-3">{feature.title}</h3>
                  <p className="text-neutral-400">{feature.description}</p>
                </div>
              )
            })}
          </div>
        </div>

        {/* Team Section */}
        <div className="mb-20">
          <h2 className="text-4xl font-bold text-center mb-12">核心团队</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {teamMembers.map((member, index) => (
              <div key={index} className="bg-[#1a1a1a] p-6 rounded-lg text-center">
                <div className="w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full mx-auto mb-4 flex items-center justify-center">
                  <span className="text-2xl font-bold text-white">
                    {member.name.charAt(0)}
                  </span>
                </div>
                <h3 className="text-xl font-bold mb-2">{member.name}</h3>
                <p className="text-blue-400 mb-3">{member.role}</p>
                <p className="text-neutral-400 text-sm">{member.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Values Section */}
        <div className="text-center">
          <h2 className="text-4xl font-bold mb-8">我们的价值观</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="bg-[#1a1a1a] p-6 rounded-lg">
              <h3 className="text-xl font-bold mb-3">创新驱动</h3>
              <p className="text-neutral-400">
                持续探索新技术，用创新思维解决用户需求，让产品始终保持领先优势。
              </p>
            </div>
            <div className="bg-[#1a1a1a] p-6 rounded-lg">
              <h3 className="text-xl font-bold mb-3">用户至上</h3>
              <p className="text-neutral-400">
                以用户体验为核心，倾听用户声音，不断优化产品功能和服务质量。
              </p>
            </div>
            <div className="bg-[#1a1a1a] p-6 rounded-lg">
              <h3 className="text-xl font-bold mb-3">开放包容</h3>
              <p className="text-neutral-400">
                建设多元化、包容性的社区环境，尊重不同文化背景的用户和创意。
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}