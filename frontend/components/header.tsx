"use client"

import { TransitionLink } from "./transition-link"
import { Logo } from "./logo"
import { LanguageSwitcher } from "./language-switcher"
import { useLanguage } from "@/context/language-context"
import { motion } from "framer-motion"
import { useState } from "react"
import { Menu, X, LogIn, UserPlus } from "lucide-react"
import NotificationCenter from "./notifications/notification-center"
import { useAuthStore } from "@/store/auth"

export function Header() {
  const { t } = useLanguage()
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const { isAuthenticated, user, logout } = useAuthStore()

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

        {/* Desktop Auth Buttons */}
        <div className="hidden md:flex items-center gap-4">
          <NotificationCenter />
          <LanguageSwitcher />
          
          {isAuthenticated ? (
            <div className="flex items-center gap-4">
              <span className="text-white/80 text-sm">
                欢迎, {user?.username || user?.email}
              </span>
              <motion.button
                onClick={logout}
                className="bg-red-500/20 backdrop-blur-md border border-red-400/30 text-red-200 px-4 py-2 rounded-full font-medium hover:bg-red-500/30 transition-all duration-200"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                登出
              </motion.button>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <TransitionLink href="/login">
                <motion.button
                  className="bg-blue-500/20 backdrop-blur-md border border-blue-400/30 text-blue-200 px-4 py-2 rounded-full font-medium hover:bg-blue-500/30 transition-all duration-200 flex items-center gap-2"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <LogIn size={16} />
                  登录
                </motion.button>
              </TransitionLink>
              
              <TransitionLink href="/register">
                <motion.button
                  className="bg-green-500/20 backdrop-blur-md border border-green-400/30 text-green-200 px-4 py-2 rounded-full font-medium hover:bg-green-500/30 transition-all duration-200 flex items-center gap-2"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <UserPlus size={16} />
                  注册
                </motion.button>
              </TransitionLink>
            </div>
          )}
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
            <div className="pt-4 border-t border-white/10">
              <div className="flex items-center gap-4 mb-4">
                <NotificationCenter />
                <LanguageSwitcher />
              </div>
              
              {isAuthenticated ? (
                <div className="space-y-3">
                  <div className="text-white/80 text-sm">
                    欢迎, {user?.username || user?.email}
                  </div>
                  <button
                    onClick={logout}
                    className="w-full bg-red-500/20 backdrop-blur-md border border-red-400/30 text-red-200 px-4 py-2 rounded-full font-medium hover:bg-red-500/30 transition-all duration-200"
                  >
                    登出
                  </button>
                </div>
              ) : (
                <div className="flex gap-3">
                  <TransitionLink href="/login" className="flex-1">
                    <button 
                      className="w-full bg-blue-500/20 backdrop-blur-md border border-blue-400/30 text-blue-200 px-4 py-2 rounded-full font-medium hover:bg-blue-500/30 transition-all duration-200 flex items-center justify-center gap-2"
                      onClick={() => setIsMenuOpen(false)}
                    >
                      <LogIn size={16} />
                      登录
                    </button>
                  </TransitionLink>
                  
                  <TransitionLink href="/register" className="flex-1">
                    <button 
                      className="w-full bg-green-500/20 backdrop-blur-md border border-green-400/30 text-green-200 px-4 py-2 rounded-full font-medium hover:bg-green-500/30 transition-all duration-200 flex items-center justify-center gap-2"
                      onClick={() => setIsMenuOpen(false)}
                    >
                      <UserPlus size={16} />
                      注册
                    </button>
                  </TransitionLink>
                </div>
              )}
            </div>
          </nav>
        </motion.div>
      )}
    </motion.header>
  )
}
