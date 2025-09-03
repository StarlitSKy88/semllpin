"use client"

import { useLanguage } from '@/context/language-context'
import { Globe } from 'lucide-react'
import { motion } from 'framer-motion'

export function LanguageSwitcher() {
  const { language, setLanguage } = useLanguage()

  return (
    <div className="relative flex items-center gap-2">
      <Globe className="w-4 h-4 text-white/70" />
      <div className="flex bg-white/10 backdrop-blur-md rounded-full p-1 border border-white/20">
        <motion.button
          onClick={() => setLanguage('zh')}
          className={`px-3 py-1 text-sm font-medium rounded-full transition-all duration-200 ${
            language === 'zh'
              ? 'bg-white/20 text-white shadow-lg'
              : 'text-white/70 hover:text-white hover:bg-white/10'
          }`}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          中文
        </motion.button>
        <motion.button
          onClick={() => setLanguage('en')}
          className={`px-3 py-1 text-sm font-medium rounded-full transition-all duration-200 ${
            language === 'en'
              ? 'bg-white/20 text-white shadow-lg'
              : 'text-white/70 hover:text-white hover:bg-white/10'
          }`}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          EN
        </motion.button>
      </div>
    </div>
  )
}