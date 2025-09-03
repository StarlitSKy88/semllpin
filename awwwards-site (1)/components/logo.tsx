"use client"

import { motion } from "framer-motion"

interface LogoProps {
  className?: string
  size?: "sm" | "md" | "lg"
}

export function Logo({ className = "", size = "md" }: LogoProps) {
  const sizeClasses = {
    sm: "w-8 h-8",
    md: "w-10 h-10",
    lg: "w-12 h-12",
  }

  const textSizes = {
    sm: "text-lg",
    md: "text-xl",
    lg: "text-2xl",
  }

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <motion.div
        className={`${sizeClasses[size]} relative flex items-center justify-center`}
        whileHover={{ scale: 1.05 }}
        transition={{ type: "spring", stiffness: 300 }}
      >
        {/* AI Brain Icon */}
        <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
          {/* Brain outline */}
          <path
            d="M20 4C24.4183 4 28 7.58172 28 12C30.2091 12 32 13.7909 32 16C34.2091 16 36 17.7909 36 20C36 22.2091 34.2091 24 32 24C32 26.2091 30.2091 28 28 28C28 32.4183 24.4183 36 20 36C15.5817 36 12 32.4183 12 28C9.79086 28 8 26.2091 8 24C5.79086 24 4 22.2091 4 20C4 17.7909 5.79086 16 8 16C8 13.7909 9.79086 12 12 12C12 7.58172 15.5817 4 20 4Z"
            stroke="currentColor"
            strokeWidth="2"
            fill="none"
          />
          {/* Neural network nodes */}
          <circle cx="16" cy="16" r="1.5" fill="currentColor" />
          <circle cx="24" cy="16" r="1.5" fill="currentColor" />
          <circle cx="20" cy="20" r="1.5" fill="currentColor" />
          <circle cx="16" cy="24" r="1.5" fill="currentColor" />
          <circle cx="24" cy="24" r="1.5" fill="currentColor" />
          {/* Neural connections */}
          <path
            d="M16 16L20 20M24 16L20 20M20 20L16 24M20 20L24 24"
            stroke="currentColor"
            strokeWidth="1"
            opacity="0.6"
          />
        </svg>

        {/* Glow effect */}
        <div className="absolute inset-0 bg-blue-500/20 rounded-full blur-md animate-pulse" />
      </motion.div>

      <div className="flex flex-col">
        <span className={`font-bold ${textSizes[size]} text-white leading-none`}>AI WORKER</span>
        <span className="text-xs text-blue-400 font-medium tracking-wider">DOCS MARKET</span>
      </div>
    </div>
  )
}
