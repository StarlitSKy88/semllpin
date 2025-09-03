"use client"

import { Suspense, useRef } from "react"
import { Canvas } from "@react-three/fiber"
import { motion } from "framer-motion"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { Scene } from "@/components/scene"
import { TransitionLink } from "@/components/transition-link"
import { ArrowRight, Upload, Download, Zap } from "lucide-react"

export function Hero() {
  const container = useRef(null)

  useGSAP(
    () => {
      const tl = gsap.timeline()
      tl.fromTo(
        ".hero-title span",
        { y: 100, opacity: 0 },
        { y: 0, opacity: 1, stagger: 0.1, duration: 1, ease: "power3.out" },
      )
        .fromTo(
          ".hero-subtitle",
          { y: 50, opacity: 0 },
          { y: 0, opacity: 1, duration: 0.8, ease: "power3.out" },
          "-=0.6",
        )
        .fromTo(
          ".hero-button",
          { scale: 0.8, opacity: 0 },
          { scale: 1, opacity: 1, duration: 0.8, ease: "elastic.out(1, 0.5)" },
          "-=0.5",
        )
    },
    { scope: container },
  )

  const title = "AI Agent Documentation Marketplace"
  const splitTitle = title.split(" ").map((word, i) => (
    <span key={i} className="inline-block overflow-hidden">
      <span className="inline-block">{word}&nbsp;</span>
    </span>
  ))

  return (
    <div ref={container} className="relative w-full h-screen overflow-hidden">
      <div className="absolute inset-0 z-0">
        <Canvas>
          <Suspense fallback={null}>
            <Scene />
          </Suspense>
        </Canvas>
      </div>
      <div className="relative z-10 flex flex-col items-center justify-center h-full text-white text-center px-4">
        <h1 className="hero-title font-bold text-4xl md:text-6xl lg:text-7xl mb-6 text-balance">{splitTitle}</h1>

        <motion.p
          className="hero-subtitle text-lg md:text-xl lg:text-2xl max-w-4xl mb-8 text-neutral-300 text-balance"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.5, duration: 1 }}
        >
          Upload, discover, and monetize AI agent documentation. The premier marketplace for AI workflows, prompts, and
          implementation guides.
        </motion.p>

        <motion.div
          className="flex items-center gap-8 mb-8 text-sm text-white"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 2, duration: 0.8 }}
        >
          <div className="flex items-center gap-2 px-4 py-2 border border-white/30 rounded-full bg-transparent backdrop-blur-sm">
            <Upload size={16} />
            <span>Upload Docs</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 border border-white/30 rounded-full bg-transparent backdrop-blur-sm">
            <Download size={16} />
            <span>Buy & Download</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 border border-white/30 rounded-full bg-transparent backdrop-blur-sm">
            <Zap size={16} />
            <span>AI Powered</span>
          </div>
        </motion.div>

        <TransitionLink href="/#marketplace">
          <motion.button
            className="hero-button flex items-center gap-2 border-2 border-white/50 bg-transparent backdrop-blur-sm text-white font-semibold py-4 px-8 rounded-full transition-all duration-300 hover:border-white hover:bg-white/10"
            whileHover={{ scale: 1.05, transition: { type: "spring", stiffness: 300 } }}
            whileTap={{ scale: 0.95 }}
          >
            Explore Marketplace <ArrowRight size={20} />
          </motion.button>
        </TransitionLink>
      </div>
    </div>
  )
}
