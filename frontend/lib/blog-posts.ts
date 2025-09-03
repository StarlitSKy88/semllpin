export interface BlogPost {
  title: string
  excerpt: string
  slug: string
  date: string
  author: string
  category: string
}

export const allPosts: BlogPost[] = [
  {
    title: "用户故事：我在咖啡店发现了¥50奖励",
    excerpt: "一位用户分享如何通过SmellPin在日常生活中发现有趣标注并获得意外收入的真实经历。从下载应用到第一次获得奖励，这个故事告诉我们SmellPin如何让平凡的生活变得更有趣。",
    slug: "user-story-coffee-shop",
    date: "2024-12-15",
    author: "SmellPin用户",
    category: "用户故事"
  },
  {
    title: "平台动态：全球用户突破10万大关",
    excerpt: "SmellPin平台用户数量快速增长，恶搞标注遍布全球，社区活跃度持续攀升。我们回顾了平台发展的重要里程碑，并展望未来的发展方向。",
    slug: "platform-milestone-100k",
    date: "2024-12-10",
    author: "SmellPin团队",
    category: "平台动态"
  },
  {
    title: "使用指南：如何创建高质量恶搞标注",
    excerpt: "掌握创建吸引人恶搞标注的技巧，提高标注被发现的概率，获得更多用户互动。本指南将教你从选择位置到编写内容的完整流程。",
    slug: "guide-quality-annotations",
    date: "2024-12-05",
    author: "SmellPin团队",
    category: "使用指南"
  },
  {
    title: "技术分享：LBS定位技术如何保证奖励公平性",
    excerpt: "深入了解SmellPin如何使用先进的LBS技术确保用户只能在真实位置获得奖励，防止作弊行为，维护平台公平性。",
    slug: "tech-lbs-fairness",
    date: "2024-11-28",
    author: "技术团队",
    category: "技术分享"
  },
  {
    title: "社区规范：创建友好的恶搞环境",
    excerpt: "了解SmellPin社区规范，学习如何创建既有趣又不伤害他人的恶搞内容。我们致力于建设一个包容、有趣、安全的社区环境。",
    slug: "community-guidelines",
    date: "2024-11-20",
    author: "社区团队",
    category: "社区规范"
  }
]