"use client"

import { useRef } from "react"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { TransitionLink } from "./transition-link"
import { ArrowRight } from "lucide-react"

const posts = [
  {
    title: "用户故事：我在咖啡店发现了¥50奖励",
    excerpt: "一位用户分享如何通过SmellPin在日常生活中发现有趣标注并获得意外收入的真实经历。",
    slug: "/blog/user-story-coffee-shop",
  },
  {
    title: "平台动态：全球用户突破10万大关",
    excerpt: "SmellPin平台用户数量快速增长，恶搞标注遍布全球，社区活跃度持续攀升。",
    slug: "/blog/platform-milestone-100k",
  },
  {
    title: "使用指南：如何创建高质量恶搞标注",
    excerpt: "掌握创建吸引人恶搞标注的技巧，提高标注被发现的概率，获得更多用户互动。",
    slug: "/blog/guide-quality-annotations",
  },
]

export function BlogPreview() {
  const container = useRef(null)

  useGSAP(
    () => {
      gsap.from(".blog-title", {
        scrollTrigger: {
          trigger: container.current,
          start: "top 80%",
        },
        y: 100,
        opacity: 0,
        duration: 1,
        ease: "power3.out",
      })

      gsap.from(".blog-post", {
        scrollTrigger: {
          trigger: ".blog-grid",
          start: "top 80%",
        },
        y: 100,
        opacity: 0,
        stagger: 0.2,
        duration: 0.8,
        ease: "power3.out",
      })
    },
    { scope: container },
  )

  return (
    <section ref={container} className="py-20 md:py-32 bg-black">
      <div className="container mx-auto px-4">
        <div className="text-center mb-8 md:mb-16 px-4">
          <h2 className="blog-title text-2xl sm:text-3xl md:text-4xl lg:text-6xl font-bold text-white mb-4">社区动态</h2>
          <p className="text-gray-300 text-sm sm:text-base md:text-lg max-w-2xl mx-auto">
            发现最新的社区动态，分享你的精彩时刻
          </p>
        </div>
        <div className="blog-grid grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6 lg:gap-8 items-stretch px-4">
          {posts.map((post, index) => (
            <div key={index} className="blog-post bg-white/10 backdrop-blur-md border border-white/20 shadow-lg p-4 md:p-6 lg:p-8 rounded-lg flex flex-col justify-between hover:bg-white/15 transition-all duration-300 h-full">
              <div className="flex-grow">
                <h3 className="text-base sm:text-lg md:text-xl lg:text-2xl font-bold mb-3 md:mb-4 text-white leading-tight">{post.title}</h3>
                <p className="text-gray-300 mb-4 md:mb-6 text-sm sm:text-base">{post.excerpt}</p>
              </div>
              <TransitionLink href={post.slug} className="group text-white font-semibold flex items-center gap-2 hover:text-blue-300 transition-colors mt-auto text-sm sm:text-base">
                <span className="hidden sm:inline">Read </span>More <ArrowRight className="transition-transform group-hover:translate-x-1" size={16} />
              </TransitionLink>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
