import { useRef } from "react"
import { motion } from "framer-motion"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { ArrowRight, MapPin, Coins, Users } from "lucide-react"
import { useNavigate } from "react-router-dom"
import { useAuthStore } from "@/stores/authStore"

export function Hero() {
  const container = useRef(null)
  const navigate = useNavigate()
  const { user } = useAuthStore()

  useGSAP(
    () => {
      // 确保元素始终可见
      gsap.set(".hero-title, .hero-subtitle, .hero-button, .hero-features", { 
        opacity: 1, 
        visibility: "visible" 
      })
      
      // 简化动画，避免影响可见性
      const tl = gsap.timeline()
      tl.from(".hero-title", {
        y: 30,
        opacity: 0.5,
        duration: 0.8,
        ease: "power2.out"
      })
      .from(".hero-subtitle", {
        y: 20,
        opacity: 0.5,
        duration: 0.6,
        ease: "power2.out"
      }, "-=0.4")
      .from(".hero-features", {
        y: 20,
        opacity: 0.5,
        duration: 0.6,
        ease: "power2.out"
      }, "-=0.3")
      .from(".hero-button", {
        y: 20,
        opacity: 0.5,
        duration: 0.6,
        ease: "power2.out"
      }, "-=0.3")
    },
    { scope: container },
  )

  const title = "SmellPin 搞笑恶搞地图平台"
  const splitTitle = title.split(" ").map((word, i) => (
    <span key={i} className="inline-block overflow-hidden">
      <span className="inline-block">{word}&nbsp;</span>
    </span>
  ))

  const handleExplore = () => {
    if (user) {
      navigate('/map')
    } else {
      navigate('/login')
    }
  }

  const handleAuth = () => {
    if (user) {
      navigate('/dashboard')
    } else {
      navigate('/register')
    }
  }

  return (
    <div ref={container} className="relative w-full h-screen overflow-hidden">
      {/* 动态渐变背景 */}
      <div className="absolute inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-purple-900 via-blue-900 to-indigo-900" />
        <div className="absolute inset-0 bg-gradient-to-tl from-pink-800/30 via-transparent to-cyan-800/30 animate-pulse" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-purple-600/20 via-transparent to-transparent" />
      </div>
      <div className="relative z-10 flex flex-col items-center justify-center h-full text-white text-center px-4">
        <h1 className="hero-title font-bold text-4xl md:text-6xl lg:text-7xl mb-6">{splitTitle}</h1>

        <motion.p
          className="hero-subtitle text-lg md:text-xl lg:text-2xl max-w-4xl mb-8 text-neutral-300"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.5, duration: 1 }}
        >
          在地图上创建付费恶搞标注，通过LBS获得奖励。全球最大的搞笑恶搞地图平台，连接有趣的人和地点。
        </motion.p>

        <motion.div
          className="hero-features flex items-center gap-8 mb-8 text-sm text-white"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 2, duration: 0.8 }}
        >
          <div className="flex items-center gap-2 px-4 py-2 border border-white/30 rounded-full bg-transparent backdrop-blur-sm">
            <MapPin size={16} />
            <span>地理标注</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 border border-white/30 rounded-full bg-transparent backdrop-blur-sm">
            <Coins size={16} />
            <span>付费奖励</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 border border-white/30 rounded-full bg-transparent backdrop-blur-sm">
            <Users size={16} />
            <span>社交互动</span>
          </div>
        </motion.div>

        <div className="flex gap-4">
          <motion.button
            onClick={handleExplore}
            className="hero-button flex items-center gap-2 border-2 border-white/50 bg-transparent backdrop-blur-sm text-white font-semibold py-4 px-8 rounded-full transition-all duration-300 hover:border-white hover:bg-white/10"
            whileHover={{ scale: 1.05, transition: { type: "spring", stiffness: 300 } }}
            whileTap={{ scale: 0.95 }}
          >
            开始探索 <ArrowRight size={20} />
          </motion.button>
          
          <motion.button
            onClick={handleAuth}
            className="hero-button flex items-center gap-2 bg-white/20 backdrop-blur-sm text-white font-semibold py-4 px-8 rounded-full transition-all duration-300 hover:bg-white/30"
            whileHover={{ scale: 1.05, transition: { type: "spring", stiffness: 300 } }}
            whileTap={{ scale: 0.95 }}
          >
            {user ? '进入控制台' : '立即注册'}
          </motion.button>
        </div>
      </div>
    </div>
  )
}