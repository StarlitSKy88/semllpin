"use client"

import { useState, useEffect, useRef } from 'react'
import dynamic from 'next/dynamic'
import { motion, AnimatePresence } from 'framer-motion'
import { MapPin, Search, Plus, X, Navigation, Zap, User, Wallet, MessageCircle, Filter, Star, Clock, Users, Target } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Slider } from '@/components/ui/slider'
import { useLanguage } from '@/context/language-context'
import { useMapStore } from '@/lib/stores/map-store'
import { useAuthStore } from '@/lib/stores/auth-store'
import { useMapAnnotations, useNearbyAnnotations, useCreateAnnotation } from '@/lib/hooks/use-api'
import { UserMenu } from '@/components/auth/user-menu'
import { PaymentButton } from '@/components/payment/payment-button'
import { WalletPage } from '@/components/wallet/wallet-page'
import { LocationTracker } from '@/components/lbs/location-tracker'
import { NearbyAnnotations } from '@/components/lbs/nearby-annotations'
import { CommentDetail } from '@/components/comments/comment-detail'
import { useGlobalNotifications } from '@/lib/stores'
import { AdvancedFilter, FilterOptions } from '@/components/search/advanced-filter'
import { SearchResults, SearchResult } from '@/components/search/search-results'
import { geocodingApi } from '@/lib/services/api'

// 动态导入OSM地图组件以避免SSR问题
const OSMMap = dynamic(() => import('@/components/map/osm-map'), { 
  ssr: false,
  loading: () => (
    <div className="h-full bg-gray-900/50 backdrop-blur-xl rounded-2xl sm:rounded-3xl border border-white/10 flex items-center justify-center">
      <div className="text-center">
        <div className="w-8 h-8 border-2 border-white/30 border-t-white rounded-full animate-spin mx-auto mb-3"></div>
        <p className="text-white/70 text-sm">地图加载中...</p>
      </div>
    </div>
  )
})

interface UserLocation {
  lat: number
  lng: number
}

// 气味类型选项
const SMELL_TYPES = [
  { value: 'food', label: '食物味道', emoji: '🍕' },
  { value: 'chemical', label: '化学味道', emoji: '🧪' },
  { value: 'nature', label: '自然味道', emoji: '🌿' },
  { value: 'smoke', label: '烟雾味道', emoji: '🚬' },
  { value: 'perfume', label: '香水味道', emoji: '💐' },
  { value: 'garbage', label: '垃圾味道', emoji: '🗑️' },
  { value: 'gas', label: '燃气味道', emoji: '⛽' },
  { value: 'sewage', label: '下水道味道', emoji: '🚰' },
  { value: 'other', label: '其他味道', emoji: '❓' },
]

// 气味强度标签
const INTENSITY_LABELS = [
  { value: 1, label: '几乎察觉不到', color: 'bg-green-500' },
  { value: 2, label: '轻微', color: 'bg-green-400' },
  { value: 3, label: '明显', color: 'bg-yellow-500' },
  { value: 4, label: '强烈', color: 'bg-orange-500' },
  { value: 5, label: '非常强烈', color: 'bg-red-500' },
]

export default function MapPage() {
  const { t } = useLanguage()
  const { isAuthenticated } = useAuthStore()
  const { addNotification } = useGlobalNotifications()
  const {
    annotations,
    selectedAnnotation,
    userLocation,
    center,
    zoom,
    bounds,
    mapViewMode,
    isLoading,
    error,
    showCreateModal,
    showPaymentModal,
    showAnnotationDetail,
    selectAnnotation,
    setUserLocation,
    setCenter,
    setZoom,
    setBounds,
    setMapViewMode,
    openCreateModal,
    closeCreateModal,
    openPaymentModal,
    closePaymentModal,
    openAnnotationDetail,
    closeAnnotationDetail,
    loadAnnotations,
    clearError
  } = useMapStore()
  
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedLocation, setSelectedLocation] = useState<{lat: number, lng: number} | null>(null)
  const [showWallet, setShowWallet] = useState(false)
  const [showLocationTracker, setShowLocationTracker] = useState(false)
  const [showNearbyAnnotations, setShowNearbyAnnotations] = useState(false)
  const [selectedAnnotationId, setSelectedAnnotationId] = useState<string | null>(null)
  
  // API hooks - 提供默认bounds避免API调用失败
  const defaultBounds = {
    north: 40.0,
    south: 39.8,
    east: 116.5,
    west: 116.3
  }
  const { data: annotationsData, isLoading: annotationsLoading } = useMapAnnotations(bounds || defaultBounds)
  
  const { data: nearbyData } = useNearbyAnnotations(
    userLocation?.[0] || 0,
    userLocation?.[1] || 0,
    1000
  )
  
  const createAnnotationMutation = useCreateAnnotation()
  
  // 状态管理
  const [newAnnotation, setNewAnnotation] = useState<{
    title: string;
    content: string;
    reward_amount: number;
    smell_type: string;
    smell_intensity: number;
    images: File[];
  }>({
    title: '',
    content: '',
    reward_amount: 1,
    smell_type: '',
    smell_intensity: 3,
    images: []
  })
  const [isFirstTimeUser, setIsFirstTimeUser] = useState(true)
  const [isCreating, setIsCreating] = useState(false)
  const [searchAddress, setSearchAddress] = useState('')
  const [isSearchingLocation, setIsSearchingLocation] = useState(false)
  const [showAnnotationsSidebar, setShowAnnotationsSidebar] = useState(false)
  
  // 筛选相关状态
  const [showAdvancedFilter, setShowAdvancedFilter] = useState(false)
  const [showSearchResults, setShowSearchResults] = useState(false)
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [filters, setFilters] = useState<FilterOptions>({
    keyword: '',
    location: '',
    dateRange: { from: null, to: null },
    rewardRange: [0, 1000],
    smellRating: [1, 5],
    category: 'all',
    tags: [],
    sortBy: 'time',
    sortOrder: 'desc'
  })
  
  // 模拟搜索结果数据
  const mockSearchResults: SearchResult[] = [
    {
      id: '1',
      type: 'annotation',
      title: '这里有奇怪的味道',
      content: '刚路过这里闻到一股很奇怪的味道，像是腐烂的鸡蛋混合着汽油的味道...',
      location: '北京市朝阳区三里屯',
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      author: '路过的小明',
      imageUrl: '/api/placeholder/300/200',
      rewardAmount: 50,
      smellRating: 4,
      tags: ['恶臭', '化学味', '三里屯'],
      likes: 23,
      replies: 8,
      distance: 150
    },
    {
      id: '2',
      type: 'news',
      title: '环保部门调查异味源头',
      content: '针对市民反映的异味问题，环保部门已派遣专业团队进行实地调查...',
      location: '北京市朝阳区',
      timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
      source: '北京日报',
      url: 'https://example.com/news/1',
      tags: ['环保', '调查', '异味'],
      likes: 156,
      replies: 42,
      distance: 500
    },
    {
      id: '3',
      type: 'comment',
      title: '我也闻到了！',
      content: '昨天晚上路过那里也闻到了，确实很难闻，希望相关部门能尽快处理',
      location: '北京市朝阳区工体北路',
      timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
      author: '热心市民',
      avatar: '/api/placeholder/32/32',
      smellRating: 3,
      tags: ['异味', '工体'],
      likes: 12,
      distance: 300
    }
  ]



  // 获取用户位置
  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const location: [number, number] = [
            position.coords.latitude,
            position.coords.longitude
          ]
          setUserLocation(location)
          setCenter(location)
        },
        (error) => {
          console.error('获取位置失败:', error)
          addNotification({
            type: 'error',
            title: '位置获取失败',
            message: '无法获取位置信息，使用默认位置'
          })
          // 默认位置设为北京
          const defaultLocation: [number, number] = [39.9042, 116.4074]
          setUserLocation(defaultLocation)
          setCenter(defaultLocation)
        }
      )
    }
  }, [setUserLocation, setCenter])
  
  // 加载标注数据
  useEffect(() => {
    if (bounds) {
      loadAnnotations(bounds)
    }
  }, [bounds, loadAnnotations])
  
  // 错误处理
  useEffect(() => {
    if (error) {
      addNotification({
        type: 'error',
        title: '位置错误',
        message: error
      })
      clearError()
    }
  }, [error, clearError])

  // 根据奖励金额确定标记颜色
  const getMarkerColor = (reward: number) => {
    if (reward >= 15) return 'red'
    if (reward >= 10) return 'blue'
    return 'green'
  }

  // 检查位置是否已有标记
  const checkLocationForExistingAnnotations = (lat: number, lng: number) => {
    const threshold = 0.001 // 约100米范围
    return annotations.some(annotation => 
      Math.abs(annotation.latitude - lat) < threshold && 
      Math.abs(annotation.longitude - lng) < threshold
    )
  }

  // 处理地址搜索
  const handleAddressSearch = async () => {
    if (!searchAddress.trim()) return
    
    setIsSearchingLocation(true)
    try {
      const response = await geocodingApi.geocode(searchAddress)
      const { latitude, longitude } = response.data?.data || response.data || {}
      setCenter([latitude, longitude])
      setZoom(16)
      addNotification({
        type: 'success',
        title: '位置找到',
        message: `已定位到：${searchAddress}`
      })
    } catch (error) {
      addNotification({
        type: 'error',
        title: '搜索失败',
        message: '无法找到指定地址，请重新输入'
      })
    } finally {
      setIsSearchingLocation(false)
    }
  }

  // 处理地图点击
  const handleMapClick = (lat: number, lng: number) => {
    if (!isAuthenticated) {
      addNotification({
        type: 'error',
        title: '需要登录',
        message: '请先登录后再创建标注'
      })
      return
    }
    
    setSelectedLocation({ lat, lng })
    const hasExistingAnnotations = checkLocationForExistingAnnotations(lat, lng)
    
    if (hasExistingAnnotations) {
      openPaymentModal()
    } else {
      openCreateModal([lat, lng])
    }
  }
  
  // 处理标注点击
  const handleAnnotationClick = (annotation: any) => {
    selectAnnotation(annotation)
    openAnnotationDetail()
  }

  // 创建新标注
  const handleCreateAnnotation = async () => {
    if (!selectedLocation || !newAnnotation.title.trim()) {
      addNotification({
        type: 'error',
        title: '信息不完整',
        message: '请填写标注标题'
      })
      return
    }

    // 验证气味类型
    if (!newAnnotation.smell_type) {
      addNotification({
        type: 'error',
        title: '气味类型缺失',
        message: '请选择气味类型'
      })
      return
    }

    // 验证气味强度
    if (newAnnotation.smell_intensity < 1 || newAnnotation.smell_intensity > 5) {
      addNotification({
        type: 'error',
        title: '气味强度无效',
        message: '请选择有效的气味强度(1-5)'
      })
      return
    }

    // 首次标注验证
    if (isFirstTimeUser) {
      if (newAnnotation.content.length < 50) {
        addNotification({
          type: 'error',
          title: '描述不足',
          message: '首次标注需要至少50字的描述说明'
        })
        return
      }
      if (!newAnnotation.images || newAnnotation.images.length === 0) {
        addNotification({
          type: 'error',
          title: '图片缺失',
          message: '首次标注需要上传至少一张图片'
        })
        return
      }
    } else {
      if (newAnnotation.reward_amount < 1) {
        addNotification({
          type: 'error',
          title: '金额不足',
          message: '非首次标注需要支付至少1美金'
        })
        return
      }
    }

    setIsCreating(true)
    try {
      const annotationData = {
        title: newAnnotation.title,
        description: newAnnotation.content,
        latitude: selectedLocation.lat,
        longitude: selectedLocation.lng,
        smell_type: newAnnotation.smell_type,
        smell_intensity: newAnnotation.smell_intensity,
        rewardAmount: isFirstTimeUser ? 0 : newAnnotation.reward_amount,
        images: newAnnotation.images.map(file => URL.createObjectURL(file))
      }
      
      await createAnnotationMutation.mutateAsync(annotationData)
      
      addNotification({
        type: 'success',
        title: '创建成功',
        message: '标注创建成功！'
      })
      setNewAnnotation({ title: '', content: '', reward_amount: 1, smell_type: '', smell_intensity: 3, images: [] })
      closeCreateModal()
      setSelectedLocation(null)
      setIsFirstTimeUser(false)
    } catch (error) {
      addNotification({
        type: 'error',
        title: '创建失败',
        message: '创建标注失败，请重试'
      })
    } finally {
      setIsCreating(false)
    }
  }

  // 处理图片上传
  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    setNewAnnotation({...newAnnotation, images: [...(newAnnotation.images || []), ...files]})
  }

  // 移除图片
  const removeImage = (index: number) => {
    const newImages = (newAnnotation.images || []).filter((_, i) => i !== index)
    setNewAnnotation({...newAnnotation, images: newImages})
  }

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* 三维背景动画 */}
      <div className="fixed inset-0 z-0 bg-gradient-to-br from-blue-900 via-purple-900 to-black">
        {/* Canvas temporarily disabled due to React compatibility issues */}
        {/* <Canvas
          camera={{ position: [0, 0, 5], fov: 75 }}
          style={{ background: 'linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%)' }}
        >
          <Scene />
        </Canvas> */}
      </div>

      {/* 主要内容 */}
      <div className="relative z-10">
        {/* 页面标题 */}
        <motion.div 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="pt-20 sm:pt-24 pb-6 sm:pb-8 text-center"
        >
          <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-6xl font-bold mb-3 sm:mb-4">
            <span className="bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
              {t('map.title')}
            </span>
          </h1>
          <p className="text-sm sm:text-base lg:text-lg text-white/70 max-w-2xl mx-auto px-4">
             {t('map.subtitle')}
            </p>
        </motion.div>

        {/* 搜索栏 */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="px-3 sm:px-4 mb-6 sm:mb-8"
        >
          <div className="max-w-2xl mx-auto">
            <div className="relative">
              <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl sm:rounded-2xl border border-white/10"></div>
              <div className="relative flex items-center">
                <Search className="absolute left-3 sm:left-4 text-white/60 w-4 h-4 sm:w-5 sm:h-5" />
                <Input
                  type="text"
                  placeholder={t('map.searchPlaceholder')}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 sm:pl-12 pr-3 sm:pr-4 py-3 sm:py-4 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm sm:text-base"
                />
              </div>
            </div>
          </div>
        </motion.div>

        {/* 顶部导航栏 */}
        <motion.div 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="fixed top-0 left-0 right-0 z-50 bg-black/20 backdrop-blur-xl border-b border-white/10"
        >
          <div className="max-w-7xl mx-auto px-3 sm:px-4 py-2 sm:py-3 flex items-center justify-between">
            <div className="flex items-center space-x-2 sm:space-x-4">
              <h1 className="text-lg sm:text-xl font-bold text-white">SmellPin</h1>
            </div>
            <div className="flex items-center space-x-1 sm:space-x-2">
              <Button 
                size="sm" 
                variant="ghost"
                onClick={() => setShowWallet(true)}
                className="text-white/60 hover:text-white p-1 sm:p-2"
              >
                <Wallet className="h-3 w-3 sm:h-4 sm:w-4" />
                <span className="hidden sm:inline ml-1">钱包</span>
              </Button>
              <Button 
                size="sm" 
                variant="ghost"
                onClick={() => setShowLocationTracker(true)}
                className="text-white/60 hover:text-white p-1 sm:p-2"
              >
                <Navigation className="h-3 w-3 sm:h-4 sm:w-4" />
                <span className="hidden sm:inline ml-1">定位</span>
              </Button>
              <Button 
                size="sm" 
                variant="ghost"
                onClick={() => setShowNearbyAnnotations(true)}
                className="text-white/60 hover:text-white p-1 sm:p-2"
              >
                <MapPin className="h-3 w-3 sm:h-4 sm:w-4" />
                <span className="hidden sm:inline ml-1">附近</span>
              </Button>
              <Button 
                size="sm" 
                variant="ghost"
                onClick={() => setSelectedAnnotationId('demo-annotation-1')}
                className="text-white/60 hover:text-white p-1 sm:p-2"
              >
                <MessageCircle className="h-3 w-3 sm:h-4 sm:w-4" />
                <span className="hidden sm:inline ml-1">评论</span>
              </Button>
              <UserMenu />
            </div>
          </div>
        </motion.div>

        {/* 地图控制按钮 */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.3 }}
          className="px-3 sm:px-4 mb-3 sm:mb-4 mt-16 sm:mt-20"
        >
          <div className="max-w-6xl mx-auto flex justify-center space-x-1 sm:space-x-2">
            <Button
              onClick={() => setMapViewMode('markers')}
              variant={mapViewMode === 'markers' ? 'default' : 'outline'}
              className={`px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg sm:rounded-xl transition-all text-xs sm:text-sm ${
                mapViewMode === 'markers'
                  ? 'bg-blue-500/80 text-white shadow-lg backdrop-blur-xl border border-blue-400/30'
                  : 'bg-white/10 text-white/70 hover:bg-white/20 backdrop-blur-xl border border-white/10'
              }`}
            >
              <span className="hidden sm:inline">标记模式</span>
              <span className="sm:hidden">标记</span>
            </Button>
            <Button
              onClick={() => setMapViewMode('heatmap')}
              variant={mapViewMode === 'heatmap' ? 'default' : 'outline'}
              className={`px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg sm:rounded-xl transition-all text-xs sm:text-sm ${
                mapViewMode === 'heatmap'
                  ? 'bg-orange-500/80 text-white shadow-lg backdrop-blur-xl border border-orange-400/30'
                  : 'bg-white/10 text-white/70 hover:bg-white/20 backdrop-blur-xl border border-white/10'
              }`}
            >
              <span className="hidden sm:inline">热力图模式</span>
              <span className="sm:hidden">热力图</span>
            </Button>
            <Button
              onClick={() => setMapViewMode('hybrid')}
              variant={mapViewMode === 'hybrid' ? 'default' : 'outline'}
              className={`px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg sm:rounded-xl transition-all text-xs sm:text-sm ${
                mapViewMode === 'hybrid'
                  ? 'bg-purple-500/80 text-white shadow-lg backdrop-blur-xl border border-purple-400/30'
                  : 'bg-white/10 text-white/70 hover:bg-white/20 backdrop-blur-xl border border-white/10'
              }`}
            >
              <span className="hidden sm:inline">混合模式</span>
              <span className="sm:hidden">混合</span>
            </Button>
          </div>
        </motion.div>

        {/* 地图容器 */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mx-2 sm:mx-4 mb-4 sm:mb-8"
        >
          <div className="max-w-6xl mx-auto">
            <div className="relative h-[50vh] sm:h-[60vh] rounded-2xl sm:rounded-3xl overflow-hidden">
              {/* 液体玻璃效果背景 */}
              <div className="absolute inset-0 bg-white/5 backdrop-blur-xl border border-white/10"></div>
              
              {/* 地图内容 */}
              <div 
                className="relative h-full p-3 sm:p-6 cursor-crosshair"
                onClick={(e) => {
                  const rect = e.currentTarget.getBoundingClientRect()
                  const x = e.clientX - rect.left
                  const y = e.clientY - rect.top
                  const lat = 39.9042 + (0.5 - y / rect.height) * 0.1
                  const lng = 116.4074 + (x / rect.width - 0.5) * 0.1
                  handleMapClick(lat, lng)
                }}
              >
                {/* 地图网格背景 */}
                <div className="absolute inset-3 sm:inset-6 opacity-20">
                  <div className="w-full h-full" style={{
                    backgroundImage: `url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23ffffff' fill-opacity='0.1'%3E%3Cpath d='M0 0h40v40H0V0zm20 20h20v20H20V20z'/%3E%3C/g%3E%3C/svg%3E")`
                  }}></div>
                </div>

                {/* 热力图层 */}
                {(mapViewMode === 'heatmap' || mapViewMode === 'hybrid') && (
                  <div className="absolute inset-3 sm:inset-6">
                    {/* Heatmap visualization would go here */}
                  </div>
                )}

                {/* 地图标记 */}
                {(mapViewMode === 'markers' || mapViewMode === 'hybrid') && annotations.map((annotation, index) => {
                  const markerColor = getMarkerColor(annotation.rewardAmount || 0)
                  return (
                    <motion.div
                      key={annotation.id}
                      initial={{ opacity: 0, scale: 0 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ duration: 0.5, delay: 0.6 + index * 0.1 }}
                      className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group z-10"
                      style={{
                        left: `${50 + (annotation.longitude - center[1]) * 800}%`,
                        top: `${50 - (annotation.latitude - center[0]) * 800}%`
                      }}
                      onClick={() => handleAnnotationClick(annotation)}
                      whileHover={{ scale: 1.2 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <div className={`relative w-6 h-6 sm:w-8 sm:h-8 rounded-full border-2 border-white shadow-lg flex items-center justify-center transition-all duration-300 ${
                        markerColor === 'red' ? 'bg-gradient-to-r from-red-500 to-pink-500' :
                        markerColor === 'blue' ? 'bg-gradient-to-r from-blue-500 to-cyan-500' : 
                        'bg-gradient-to-r from-green-500 to-emerald-500'
                      }`}>
                        <MapPin className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                        <div className="absolute -inset-2 bg-white/20 rounded-full animate-ping opacity-0 group-hover:opacity-100"></div>
                      </div>
                      
                      {/* 标记信息提示 */}
                      <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                        <div className="bg-black/80 backdrop-blur-sm text-white text-xs px-2 py-1 rounded-lg whitespace-nowrap max-w-32 sm:max-w-none truncate sm:whitespace-nowrap">
                          {annotation.title} - ¥{annotation.rewardAmount || 0}
                        </div>
                      </div>
                    </motion.div>
                  )
                })}

                {/* 用户位置标记 */}
                {userLocation && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.5, delay: 1 }}
                    className="absolute transform -translate-x-1/2 -translate-y-1/2"
                    style={{
                      left: `${50 + (userLocation[1] - center[1]) * 800}%`,
                      top: `${50 - (userLocation[0] - center[0]) * 800}%`
                    }}
                  >
                    <div className="relative">
                      <div className="w-5 h-5 sm:w-6 sm:h-6 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full border-2 border-white shadow-lg">
                        <div className="absolute inset-0 bg-blue-400 rounded-full animate-ping opacity-75"></div>
                      </div>
                      <Navigation className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-2.5 h-2.5 sm:w-3 sm:h-3 text-white" />
                    </div>
                  </motion.div>
                )}
              </div>
            </div>
          </div>
        </motion.div>

        {/* 创建标记按钮 */}
        {isAuthenticated && (
          <motion.div
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.8 }}
            className="fixed bottom-4 right-4 sm:bottom-8 sm:right-8 z-20"
          >
            <PaymentButton
              size="icon"
              className="relative group p-3 sm:p-4 rounded-full bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 shadow-lg"
              annotationData={{
                location: '当前位置',
                description: '新的标注',
                coordinates: center
              }}
              onPaymentSuccess={(paymentId) => {
                console.log('Payment successful:', paymentId);
                openCreateModal(center);
              }}
            >
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full blur-lg opacity-75 group-hover:opacity-100 transition-opacity"></div>
              <Plus className="w-5 h-5 sm:w-6 sm:h-6 text-white relative z-10" />
            </PaymentButton>
          </motion.div>
        )}
      </div>

      {/* 标注详情弹窗 */}
      <AnimatePresence>
        {showAnnotationDetail && selectedAnnotation && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={() => closeAnnotationDetail()}
          >
            <motion.div 
              initial={{ opacity: 0, scale: 0.8, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8, y: 20 }}
              className="relative max-w-md w-full mx-2 sm:mx-0"
              onClick={(e) => e.stopPropagation()}
            >
              {/* 液体玻璃效果背景 */}
              <div className="absolute inset-0 bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20"></div>
              
              <div className="relative p-4 sm:p-6">
                <div className="flex justify-between items-start mb-4">
                  <h3 className="text-xl sm:text-2xl font-bold text-white pr-2">{selectedAnnotation.title}</h3>
                  <Button
                      onClick={() => closeAnnotationDetail()}
                      variant="ghost"
                      size="icon"
                      className="text-white/60 hover:text-white transition-colors flex-shrink-0"
                    >
                      <X className="w-5 h-5 sm:w-6 sm:h-6" />
                    </Button>
                </div>
                
                <p className="text-white/80 mb-4 sm:mb-6 leading-relaxed text-sm sm:text-base">{selectedAnnotation.description}</p>
                
                <div className="flex justify-between items-center text-xs sm:text-sm text-white/60 mb-4 sm:mb-6">
                  <span className="truncate">创建者: 匿名用户</span>
                  <div className="flex items-center space-x-1 flex-shrink-0">
                    <Zap className="w-3 h-3 sm:w-4 sm:h-4 text-yellow-400" />
                    <span className="font-semibold text-yellow-400">¥{selectedAnnotation.rewardAmount || 0}</span>
                  </div>
                </div>
                
                {selectedAnnotation.rewardAmount > 0 && (
                  <Button 
                    className="w-full relative group bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white py-2.5 sm:py-3 px-4 sm:px-6 rounded-xl font-semibold text-sm sm:text-base"
                    onClick={() => {
                      // TODO: 实现领取奖励逻辑
                      addNotification({
                        type: 'success',
                        title: '功能提示',
                        message: '奖励领取功能即将上线！'
                      })
                    }}
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-green-500 to-emerald-500 rounded-xl blur-lg opacity-75 group-hover:opacity-100 transition-opacity"></div>
                    <span className="relative z-10">领取奖励</span>
                  </Button>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 创建标注弹窗 */}
      <AnimatePresence>
        {showCreateModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={closeCreateModal}
          >
            <motion.div 
              initial={{ opacity: 0, scale: 0.8, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8, y: 20 }}
              className="relative max-w-md w-full max-h-[90vh] overflow-y-auto mx-2 sm:mx-0"
              onClick={(e) => e.stopPropagation()}
            >
              {/* 液体玻璃效果背景 */}
              <div className="absolute inset-0 bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20"></div>
              
              <div className="relative p-4 sm:p-6">
                <div className="flex justify-between items-center mb-4 sm:mb-6">
                  <h3 className="text-lg sm:text-2xl font-bold text-white pr-2">
                    {isFirstTimeUser ? '创建你的第一个标注' : '创建新标注'}
                  </h3>
                  <Button
                    onClick={closeCreateModal}
                    variant="ghost"
                    size="icon"
                    className="text-white/60 hover:text-white transition-colors flex-shrink-0"
                  >
                    <X className="w-5 h-5 sm:w-6 sm:h-6" />
                  </Button>
                </div>
                
                {isFirstTimeUser && (
                  <div className="mb-4 sm:mb-6 p-3 sm:p-4 bg-blue-500/20 border border-blue-500/30 rounded-lg">
                    <p className="text-xs sm:text-sm text-blue-300">
                      🎉 恭喜！你的第一个标注是免费的。请添加详细描述和至少一张图片。
                    </p>
                  </div>
                )}
                
                <div className="space-y-3 sm:space-y-4">
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">标题</label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <Input
                        type="text"
                        value={newAnnotation.title}
                        onChange={(e) => setNewAnnotation({...newAnnotation, title: e.target.value})}
                        className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm sm:text-base"
                        placeholder="输入标注标题"
                      />
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">气味类型</label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <Select value={newAnnotation.smell_type} onValueChange={(value) => setNewAnnotation({...newAnnotation, smell_type: value})}>
                        <SelectTrigger className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white border-none">
                          <SelectValue placeholder="选择气味类型" />
                        </SelectTrigger>
                        <SelectContent className="bg-gray-900/95 backdrop-blur-xl border-white/20">
                          {SMELL_TYPES.map((type) => (
                            <SelectItem key={type.value} value={type.value} className="text-white hover:bg-white/10">
                              <span className="flex items-center gap-2">
                                <span>{type.emoji}</span>
                                <span>{type.label}</span>
                              </span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">
                      气味强度: {newAnnotation.smell_intensity} - {INTENSITY_LABELS.find(l => l.value === newAnnotation.smell_intensity)?.label}
                    </label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <div className="relative px-4 py-3">
                        <Slider
                          value={[newAnnotation.smell_intensity]}
                          onValueChange={(value) => setNewAnnotation({...newAnnotation, smell_intensity: value[0]})}
                          min={1}
                          max={5}
                          step={1}
                          className="w-full"
                        />
                        <div className="flex justify-between text-xs text-white/60 mt-2">
                          {INTENSITY_LABELS.map((label, index) => (
                            <div key={label.value} className="text-center">
                              <div className={`w-2 h-2 rounded-full mx-auto mb-1 ${label.color}`}></div>
                              <span>{label.value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">
                      {isFirstTimeUser ? '描述 (至少50字)' : '描述（可选）'}
                    </label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <textarea
                        value={newAnnotation.content}
                        onChange={(e) => setNewAnnotation({...newAnnotation, content: e.target.value})}
                        className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none resize-none text-sm sm:text-base border-none"
                        rows={3}
                        placeholder={isFirstTimeUser ? "详细描述这个位置的气味特征（至少50字）" : "输入对这个气味的详细描述（可选）"}
                      />
                    </div>
                    {isFirstTimeUser && (
                      <p className="text-xs text-white/60 mt-1">
                        {newAnnotation.content.length}/50 字
                      </p>
                    )}
                  </div>
                  
                  {isFirstTimeUser && (
                    <div>
                      <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">
                        图片上传 (至少1张)
                      </label>
                      <div className="relative">
                        <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                        <Input
                        type="file"
                        multiple
                        accept="image/*"
                        onChange={handleImageUpload}
                        className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm sm:text-base"
                      />
                      </div>
                      {newAnnotation.images && newAnnotation.images.length > 0 && (
                        <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-2">
                          {newAnnotation.images.map((image, index) => (
                            <div key={index} className="relative">
                              <img
                                src={URL.createObjectURL(image)}
                                alt={`Upload ${index + 1}`}
                                className="w-full h-16 sm:h-20 object-cover rounded-lg"
                              />
                              <Button
                                onClick={() => removeImage(index)}
                                size="icon"
                                className="absolute -top-1 -right-1 sm:-top-2 sm:-right-2 bg-red-500 hover:bg-red-600 text-white rounded-full w-5 h-5 sm:w-6 sm:h-6 text-xs"
                              >
                                ×
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  
                  {!isFirstTimeUser && (
                    <div>
                      <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">奖励金额 ($)</label>
                      <div className="relative">
                        <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                        <Input
                          type="number"
                          min="1"
                          max="100"
                          value={newAnnotation.reward_amount}
                          onChange={(e) => setNewAnnotation({...newAnnotation, reward_amount: parseInt(e.target.value) || 1})}
                          className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm sm:text-base"
                        />
                      </div>
                    </div>
                  )}
                  
                  <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3 pt-3 sm:pt-4">
                    <Button
                      onClick={closeCreateModal}
                      variant="outline"
                      className="w-full sm:flex-1 relative group bg-white/10 backdrop-blur-xl border border-white/20 text-white hover:bg-white/20 py-2.5 sm:py-3 text-sm sm:text-base"
                    >
                      取消
                    </Button>
                    
                    <Button
                      onClick={handleCreateAnnotation}
                      disabled={isCreating}
                      className="w-full sm:flex-1 relative group bg-gradient-to-r from-blue-500 to-purple-500 text-white hover:from-blue-600 hover:to-purple-600 py-2.5 sm:py-3 text-sm sm:text-base"
                    >
                      {isCreating ? '创建中...' : (isFirstTimeUser ? '免费创建' : '付费创建')}
                    </Button>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 付费标注弹窗 */}
      <AnimatePresence>
        {showPaymentModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={closePaymentModal}
          >
            <motion.div 
              initial={{ opacity: 0, scale: 0.8, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8, y: 20 }}
              className="relative max-w-md w-full mx-2 sm:mx-0"
              onClick={(e) => e.stopPropagation()}
            >
              {/* 液体玻璃效果背景 */}
              <div className="absolute inset-0 bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20"></div>
              
              <div className="relative p-4 sm:p-6">
                <div className="flex justify-between items-center mb-4 sm:mb-6">
                  <h3 className="text-lg sm:text-2xl font-bold text-white pr-2">该位置已有标注</h3>
                  <Button
                    onClick={closePaymentModal}
                    variant="ghost"
                    size="icon"
                    className="text-white/60 hover:text-white transition-colors flex-shrink-0"
                  >
                    <X className="w-5 h-5 sm:w-6 sm:h-6" />
                  </Button>
                </div>
                
                <div className="mb-4 sm:mb-6 p-3 sm:p-4 bg-yellow-500/20 border border-yellow-500/30 rounded-lg">
                  <p className="text-xs sm:text-sm text-yellow-300">
                    💰 该位置已有其他用户的标注，需要支付至少1美金才能添加新标注。
                  </p>
                </div>
                
                <div className="space-y-3 sm:space-y-4">
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">标题</label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <Input
                        type="text"
                        value={newAnnotation.title}
                        onChange={(e) => setNewAnnotation({...newAnnotation, title: e.target.value})}
                        className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm sm:text-base"
                        placeholder="输入标注标题"
                      />
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">描述（可选）</label>
                    <div className="relative">
                         <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                         <Textarea
                           value={newAnnotation.content}
                           onChange={(e) => setNewAnnotation({...newAnnotation, content: e.target.value})}
                           className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none resize-none border-none text-sm sm:text-base"
                           rows={3}
                           placeholder="输入标注描述（可选）"
                         />
                       </div>
                  </div>
                  
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-white/80 mb-2">支付金额 ($)</label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <Input
                        type="number"
                        min="1"
                        value={newAnnotation.reward_amount}
                        onChange={(e) => setNewAnnotation({...newAnnotation, reward_amount: parseInt(e.target.value) || 1})}
                        className="relative w-full px-3 sm:px-4 py-2.5 sm:py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm sm:text-base"
                      />
                    </div>
                  </div>
                  
                  <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3 pt-3 sm:pt-4">
                    <Button
                      onClick={closePaymentModal}
                      variant="outline"
                      className="w-full sm:flex-1 relative group bg-white/10 backdrop-blur-xl border border-white/20 text-white hover:bg-white/20 py-2.5 sm:py-3 text-sm sm:text-base"
                    >
                      取消
                    </Button>
                    
                    <Button
                      onClick={handleCreateAnnotation}
                      disabled={isCreating}
                      className="w-full sm:flex-1 relative group bg-gradient-to-r from-green-500 to-emerald-500 text-white hover:from-green-600 hover:to-emerald-600 py-2.5 sm:py-3 text-sm sm:text-base"
                    >
                      {isCreating ? '创建中...' : '支付并创建'}
                    </Button>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 钱包页面 */}
      {showWallet && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-sm z-50">
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between p-3 sm:p-4 border-b border-white/10">
              <h1 className="text-lg sm:text-xl font-semibold text-white">我的钱包</h1>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={() => setShowWallet(false)}
                className="text-white/60 hover:text-white"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-hidden">
              <WalletPage />
            </div>
          </div>
        </div>
      )}
      
      {/* 位置跟踪页面 */}
      {showLocationTracker && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-sm z-50">
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between p-3 sm:p-4 border-b border-white/10">
              <h1 className="text-lg sm:text-xl font-semibold text-white">位置跟踪</h1>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={() => setShowLocationTracker(false)}
                className="text-white/60 hover:text-white"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-hidden">
              <LocationTracker />
            </div>
          </div>
        </div>
      )}
      
      {/* 附近标注页面 */}
      {showNearbyAnnotations && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-sm z-50">
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between p-3 sm:p-4 border-b border-white/10">
              <h1 className="text-lg sm:text-xl font-semibold text-white">附近标注</h1>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={() => setShowNearbyAnnotations(false)}
                className="text-white/60 hover:text-white"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-hidden">
              <NearbyAnnotations />
            </div>
          </div>
        </div>
      )}
      
      {/* 评论详情页面 */}
      {selectedAnnotationId && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-sm z-50">
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-white/10">
              <h1 className="text-xl font-semibold text-white">评论详情</h1>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={() => setSelectedAnnotationId(null)}
                className="text-white/60 hover:text-white"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-hidden">
              <CommentDetail 
                annotationId={selectedAnnotationId}
                onBack={() => setSelectedAnnotationId(null)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}