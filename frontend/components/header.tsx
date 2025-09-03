"use client"

import { TransitionLink } from "./transition-link"
import { Logo } from "./logo"
import { LanguageSwitcher } from "./language-switcher"
import { useLanguage } from "@/context/language-context"
import { motion } from "framer-motion"
import { useState } from "react"
import { Menu, X } from "lucide-react"
import NotificationCenter from "./notifications/notification-center"

export function Header() {
  const { t } = useLanguage()
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  return (
    <motion.header
      className="fixed top-0 left-0 right-0 z-50 bg-white/5 backdrop-blur-xl border-b border-white/10 shadow-lg shadow-black/5 p-4"
      initial={{ y: -100, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.8, ease: "easeOut" }}
    >
      <div className="container mx-auto flex justify-between items-center bg-black/20 backdrop-blur-md p-4 rounded-full">
        <TransitionLink href="/" className="text-white">
          <Logo size="sm" />
        </TransitionLink>

        {/* Desktop Navigation Links */}
        <nav className="hidden md:flex items-center space-x-8">
          <motion.a
            href="/map"
            className="text-white/80 hover:text-white transition-colors duration-200 font-medium"
            whileHover={{ y: -2 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            {t('nav.map')}
          </motion.a>
          <motion.a
            href="#annotation"
            className="text-white/80 hover:text-white transition-colors duration-200 font-medium"
            whileHover={{ y: -2 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            {t('nav.mark')}
          </motion.a>
          <motion.a
            href="#my-annotations"
            className="text-white/80 hover:text-white transition-colors duration-200 font-medium"
            whileHover={{ y: -2 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            {t('nav.myMarks')}
          </motion.a>
        </nav>

        {/* Mobile Menu Button */}
        <button
          className="md:hidden text-white p-2"
          onClick={() => setIsMenuOpen(!isMenuOpen)}
        >
          {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>

        {/* Desktop CTA Button */}
        <div className="hidden md:flex items-center gap-4">
          <NotificationCenter />
          <LanguageSwitcher />
          <motion.button
            className="bg-white/10 backdrop-blur-md border border-white/20 text-white px-6 py-2 rounded-full font-medium hover:bg-white/20 transition-all duration-200 shadow-lg hover:shadow-xl"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            {t('nav.getStarted')}
          </motion.button>
        </div>
      </div>

      {/* Mobile Menu */}
      {isMenuOpen && (
        <motion.div
          className="md:hidden absolute top-full left-0 right-0 bg-black/90 backdrop-blur-xl border-b border-white/10 p-4"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.2 }}
        >
          <nav className="flex flex-col space-y-4">
            <a
              href="/map"
              className="text-white/80 hover:text-white transition-colors duration-200 font-medium py-2"
              onClick={() => setIsMenuOpen(false)}
            >
              {t('nav.map')}
            </a>
            <a
              href="#annotation"
              className="text-white/80 hover:text-white transition-colors duration-200 font-medium py-2"
              onClick={() => setIsMenuOpen(false)}
            >
              {t('nav.mark')}
            </a>
            <a
              href="#my-annotations"
              className="text-white/80 hover:text-white transition-colors duration-200 font-medium py-2"
              onClick={() => setIsMenuOpen(false)}
            >
              {t('nav.myMarks')}
            </a>
            <div className="flex items-center gap-4 pt-4 border-t border-white/10">
              <NotificationCenter />
              <LanguageSwitcher />
              <button className="bg-white/10 backdrop-blur-md border border-white/20 text-white px-6 py-2 rounded-full font-medium hover:bg-white/20 transition-all duration-200">
                {t('nav.getStarted')}
              </button>
            </div>
          </nav>
        </motion.div>
      )}
    </motion.header>
  )
}
