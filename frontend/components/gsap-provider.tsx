"use client"

import type React from "react"
import { useEffect, useState } from "react"

export function GsapProvider({ children }: { children: React.ReactNode }) {
  const [isLoaded, setIsLoaded] = useState(false)

  useEffect(() => {
    const loadGsap = async () => {
      try {
        const { gsap } = await import("gsap")
        const { ScrollTrigger } = await import("gsap/ScrollTrigger")
        const { ScrollToPlugin } = await import("gsap/ScrollToPlugin")
        
        gsap.registerPlugin(ScrollTrigger, ScrollToPlugin)
        setIsLoaded(true)
      } catch (error) {
        console.error("Failed to load GSAP:", error)
        setIsLoaded(true) // 即使失败也继续渲染
      }
    }

    loadGsap()
  }, [])

  return <>{children}</>
}
