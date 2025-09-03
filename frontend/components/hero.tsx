"use client"

import { Suspense, useRef, useState, useEffect } from "react"
// import { Canvas } from "@react-three/fiber"
import { motion } from "framer-motion"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
// import { Scene } from "@/components/scene"
import { TransitionLink } from "@/components/transition-link"
import { ArrowRight, Upload, Download, Zap, MapPin } from "lucide-react"
import { useLanguage } from "@/context/language-context"
import { Button } from "@/components/ui/button"

export function Hero() {
  const { t } = useLanguage()
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
      <div className="absolute inset-0 z-0 bg-gradient-to-br from-blue-900 via-purple-900 to-black">
        {/* Canvas temporarily disabled due to React compatibility issues */}
        {/* <Canvas>
          <Suspense fallback={null}>
            <Scene />
          </Suspense>
        </Canvas> */}
      </div>
      <div className="relative z-10 flex flex-col items-center justify-center h-full text-white text-center px-4">
        <div className="bg-black/30 backdrop-blur-sm rounded-2xl md:rounded-3xl p-4 sm:p-6 md:p-8 border border-white/10 shadow-2xl max-w-5xl w-full">
          <h1 className="text-3xl sm:text-4xl md:text-6xl lg:text-8xl font-bold mb-6 md:mb-8 leading-tight text-white drop-shadow-2xl">
            {t('hero.title')}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-600 drop-shadow-lg">
              {t('hero.subtitle')}
            </span>
          </h1>

          <p className="text-base sm:text-lg md:text-xl lg:text-2xl text-white mb-8 md:mb-12 max-w-3xl drop-shadow-lg px-4">
            {t('hero.description')}
          </p>
        </div>

        <div className="flex justify-center mt-6 md:mt-8">
          <TransitionLink href="/map">
            <Button
              variant="gradient"
              size="lg"
              className="px-8 sm:px-12 md:px-16 py-3 md:py-4 font-semibold text-base md:text-lg shadow-lg hover:shadow-xl w-full max-w-xs sm:max-w-md"
              style={{ letterSpacing: '0.2em' }}
            >
              <span>开始</span>
              <MapPin className="mx-2" size={20} />
              <span>标注</span>
            </Button>
          </TransitionLink>
        </div>
      </div>
    </div>
  )
}
