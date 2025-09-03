"use client"

import React, { createContext, useContext, useState, useEffect } from 'react'

type Language = 'zh' | 'en'

interface LanguageContextType {
  language: Language
  setLanguage: (lang: Language) => void
  t: (key: string) => string
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined)

// 翻译字典
const translations = {
  zh: {
    // Header
    nav: {
      map: '地图',
      mark: '标注',
      myMarks: '我的标注',
      getStarted: '开始探索'
    },
    
    // Hero
    hero: {
      title: 'SmellPin',
      subtitle: '恶搞地图',
      description: '在地图上创建搞笑恶搞标注，通过LBS定位发现奖励，全球最大的地理位置恶搞平台，让每个地点都有故事',
      features: {
        createMarks: '创建标注',
        lbsRewards: 'LBS定位',
        exploreMap: '景观美景',
        earnMoney: '地理探索'
      },
      cta: {
        primary: '探索地图',
        secondary: '开始标注'
      }
    },
    map: {
      title: 'SmellPin 恶搞地图',
      subtitle: '发现身边的有趣标注，创造属于你的地理故事',
      searchPlaceholder: '搜索地点...',
      createMarker: '创建新标注',
      markerDetails: {
        creator: '创建者',
        claimReward: '领取奖励'
      },
      createModal: {
        title: '创建新标注',
        titleLabel: '标题',
        titlePlaceholder: '输入标注标题',
        descriptionLabel: '描述',
        descriptionPlaceholder: '输入标注描述',
        rewardLabel: '奖励金额 (¥)',
        cancel: '取消',
        create: '创建'
      }
    },
    title: 'SmellPin恶搞地图',
    subtitle: '在地图上创建搞笑恶搞标注，通过LBS定位现实奖励',
    description: '全球最大的地理位置恶搞平台，让每个地点都有故事',
    feature1: '创建标注',
    feature2: 'LBS定位',
    feature3: '实时奖励',
    feature4: '地理围栏',
    exploreMap: '探索地图',
    createAnnotation: '开始标注',
    
    // Map Page
    searchLocation: '搜索地点...',
    activeUsers: '活跃用户',
    comments: '评论',
    checkIn: '签到',
    addComment: '添加评论',
    createMarker: '创建标记',
    location: '位置',
    searchOrClickMap: '搜索或点击地图选择位置',
    markerTitle: '标题',
    enterTitle: '输入标题',
    markerDescription: '描述',
    enterDescription: '输入描述（至少100字）',
    amount: '金额',
    cancel: '取消',
    create: '创建'
  },
  en: {
    // Header
    nav: {
      map: 'Map',
      mark: 'Annotations',
      myMarks: 'My Annotations',
      getStarted: 'Start Exploring'
    },
    
    // Hero
    hero: {
      title: 'SmellPin',
      subtitle: 'Prank Map',
      description: 'Create funny prank annotations on the map, earn real rewards through LBS positioning. The world\'s largest location-based prank platform, where every place has a story',
      features: {
        createMarks: 'Create Annotations',
        lbsRewards: 'LBS Positioning',
        exploreMap: 'Explore Map',
        earnMoney: 'Earn Money'
      },
      cta: {
        primary: 'Explore Map',
        secondary: 'Start Annotating'
      }
    },
    map: {
      title: 'SmellPin Prank Map',
      subtitle: 'Discover interesting annotations around you, create your own geographic stories',
      searchPlaceholder: 'Search locations...',
      createMarker: 'Create New Marker',
      markerDetails: {
        creator: 'Creator',
        claimReward: 'Claim Reward'
      },
      createModal: {
        title: 'Create New Marker',
        titleLabel: 'Title',
        titlePlaceholder: 'Enter marker title',
        descriptionLabel: 'Description',
        descriptionPlaceholder: 'Enter marker description',
        rewardLabel: 'Reward Amount ($)',
        cancel: 'Cancel',
        create: 'Create'
      }
    },
    title: 'SmellPin Prank Map',
    subtitle: 'Create funny prank annotations on the map, earn real rewards through LBS positioning',
    description: 'The world\'s largest location-based prank platform, where every place has a story',
    feature1: 'Create Annotations',
    feature2: 'LBS Positioning',
    feature3: 'Real-time Rewards',
    feature4: 'Geofencing',
    exploreMap: 'Explore Map',
    createAnnotation: 'Start Annotating',
    
    // Map Page
    searchLocation: 'Search location...',
    activeUsers: 'active users',
    comments: 'comments',
    checkIn: 'Check In',
    addComment: 'Add Comment',
    createMarker: 'Create Marker',
    location: 'Location',
    searchOrClickMap: 'Search or click map to select location',
    markerTitle: 'Title',
    enterTitle: 'Enter title',
    markerDescription: 'Description',
    enterDescription: 'Enter description (at least 100 words)',
    amount: 'Amount',
    cancel: 'Cancel',
    create: 'Create'
  }
}

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [language, setLanguage] = useState<Language>('zh')

  // 从localStorage读取语言设置
  useEffect(() => {
    const savedLanguage = localStorage.getItem('language') as Language
    if (savedLanguage && (savedLanguage === 'zh' || savedLanguage === 'en')) {
      setLanguage(savedLanguage)
    }
  }, [])

  // 保存语言设置到localStorage
  const handleSetLanguage = (lang: Language) => {
    setLanguage(lang)
    localStorage.setItem('language', lang)
  }

  // 翻译函数
  const t = (key: string): string => {
    const keys = key.split('.')
    let value: any = translations[language]
    
    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k]
      } else {
        return key // 如果找不到翻译，返回原始键
      }
    }
    
    return typeof value === 'string' ? value : key
  }

  return (
    <LanguageContext.Provider value={{ language, setLanguage: handleSetLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useLanguage() {
  const context = useContext(LanguageContext)
  if (context === undefined) {
    throw new Error('useLanguage must be used within a LanguageProvider')
  }
  return context
}