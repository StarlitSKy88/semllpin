"use client"

import { TransitionLink } from "./transition-link"
import { Logo } from "./logo"
import { motion } from "framer-motion"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { useRef } from "react"

export function Header() {
  const headerRef = useRef(null)

  useGSAP(() => {
    gsap.from(headerRef.current, {
      y: -100,
      opacity: 0,
      duration: 1,
      ease: "power3.out",
      delay: 2,
    })
  }, [])

  return (
    <motion.header ref={headerRef} className="fixed top-0 left-0 right-0 z-50 p-4">
      <div className="container mx-auto flex justify-between items-center bg-black/20 backdrop-blur-md p-4 rounded-full">
        <TransitionLink href="/" className="text-white">
          <Logo size="sm" />
        </TransitionLink>

        <nav className="hidden md:flex items-center gap-6 text-white">
          <TransitionLink href="/#marketplace" className="hover:text-blue-400 transition-colors">
            Marketplace
          </TransitionLink>
          <TransitionLink href="/upload" className="hover:text-blue-400 transition-colors">
            Upload Docs
          </TransitionLink>
          <TransitionLink href="/my-docs" className="hover:text-blue-400 transition-colors">
            My Docs
          </TransitionLink>
        </nav>

        <TransitionLink href="/get-started">
          <motion.button
            className="bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold py-2 px-5 rounded-full"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Get Started
          </motion.button>
        </TransitionLink>
      </div>
    </motion.header>
  )
}
