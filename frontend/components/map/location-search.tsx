'use client'

import React, { useState, useCallback } from 'react'
import { Search, Target, Navigation, MapPin, Clock, Star } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { motion, AnimatePresence } from 'framer-motion'
import { geocodingApi } from '@/lib/services/api'
import { useGlobalNotifications } from '@/lib/stores'

interface LocationSuggestion {
  id: string
  name: string
  address: string
  coordinates: [number, number]
  type: 'poi' | 'address' | 'business'
  distance?: number
}

interface LocationSearchProps {
  onLocationSelect: (coordinates: [number, number], address: string) => void
  onCurrentLocation: () => void
  className?: string
  placeholder?: string
}

export const LocationSearch: React.FC<LocationSearchProps> = ({
  onLocationSelect,
  onCurrentLocation,
  className = '',
  placeholder = '搜索地址或地点...'
}) => {
  const [searchQuery, setSearchQuery] = useState('')
  const [suggestions, setSuggestions] = useState<LocationSuggestion[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [recentSearches, setRecentSearches] = useState<LocationSuggestion[]>([])
  const { addNotification } = useGlobalNotifications()

  // 模拟的建议数据（实际项目中应该从地图服务API获取）
  const mockSuggestions: LocationSuggestion[] = [
    {
      id: '1',
      name: '三里屯太古里',
      address: '北京市朝阳区三里屯路19号',
      coordinates: [39.9368, 116.4477],
      type: 'poi'
    },
    {
      id: '2',
      name: '王府井大街',
      address: '北京市东城区王府井大街',
      coordinates: [39.9149, 116.4074],
      type: 'business'
    },
    {
      id: '3',
      name: '天安门广场',
      address: '北京市东城区东长安街',
      coordinates: [39.9042, 116.4074],
      type: 'poi'
    },
    {
      id: '4',
      name: '故宫博物院',
      address: '北京市东城区景山前街4号',
      coordinates: [39.9163, 116.4026],
      type: 'poi'
    }
  ]

  // 搜索地址
  const handleSearch = useCallback(async () => {
    if (!searchQuery.trim()) return

    setIsSearching(true)
    try {
      // 首先尝试使用真实的地理编码API
      const response = await geocodingApi.geocode(searchQuery)
      const { latitude, longitude, address } = response.data
      
      onLocationSelect([latitude, longitude], address)
      addNotification({
        type: 'success',
        title: '位置找到',
        message: `已定位到：${address}`
      })

      // 添加到最近搜索
      const newSearch: LocationSuggestion = {
        id: Date.now().toString(),
        name: searchQuery,
        address: address,
        coordinates: [latitude, longitude],
        type: 'address'
      }
      setRecentSearches(prev => [newSearch, ...prev.slice(0, 4)])
      setShowSuggestions(false)
      setSearchQuery('')
    } catch (error) {
      // 如果API失败，使用模拟数据作为后备
      const filteredSuggestions = mockSuggestions.filter(suggestion =>
        suggestion.name.includes(searchQuery) || 
        suggestion.address.includes(searchQuery)
      )
      setSuggestions(filteredSuggestions)
      setShowSuggestions(true)
    } finally {
      setIsSearching(false)
    }
  }, [searchQuery, onLocationSelect, addNotification])

  // 处理输入变化
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setSearchQuery(value)
    
    if (value.trim()) {
      // 过滤建议
      const filtered = mockSuggestions.filter(suggestion =>
        suggestion.name.includes(value) || 
        suggestion.address.includes(value)
      )
      setSuggestions(filtered)
      setShowSuggestions(true)
    } else {
      setShowSuggestions(false)
    }
  }

  // 选择建议
  const handleSuggestionClick = (suggestion: LocationSuggestion) => {
    onLocationSelect(suggestion.coordinates, suggestion.address)
    setSearchQuery(suggestion.name)
    setShowSuggestions(false)
    
    // 添加到最近搜索
    setRecentSearches(prev => [suggestion, ...prev.filter(item => item.id !== suggestion.id).slice(0, 4)])
    
    addNotification({
      type: 'success',
      title: '位置已选择',
      message: suggestion.name
    })
  }

  // 获取当前位置
  const handleCurrentLocation = () => {
    if (!navigator.geolocation) {
      addNotification({
        type: 'error',
        title: '不支持定位',
        message: '您的浏览器不支持地理定位功能'
      })
      return
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords
        onLocationSelect([latitude, longitude], '当前位置')
        onCurrentLocation()
        addNotification({
          type: 'success',
          title: '定位成功',
          message: '已获取您的当前位置'
        })
      },
      (error) => {
        addNotification({
          type: 'error',
          title: '定位失败',
          message: '无法获取您的位置信息，请手动搜索'
        })
      },
      { enableHighAccuracy: true, timeout: 10000 }
    )
  }

  // 获取图标
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'poi': return <Star className="w-4 h-4" />
      case 'business': return <MapPin className="w-4 h-4" />
      default: return <Search className="w-4 h-4" />
    }
  }

  return (
    <div className={`relative ${className}`}>
      <div className="relative">
        <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
        <div className="relative flex items-center space-x-2 p-2">
          {/* 搜索输入框 */}
          <div className="flex-1 flex items-center">
            <Search className="absolute left-3 text-white/60 w-4 h-4 z-10" />
            <Input
              type="text"
              placeholder={placeholder}
              value={searchQuery}
              onChange={handleInputChange}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              onFocus={() => setShowSuggestions(searchQuery.trim() ? suggestions.length > 0 : recentSearches.length > 0)}
              className="w-full pl-10 pr-3 py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none text-sm"
            />
          </div>
          
          {/* 搜索按钮 */}
          <Button
            onClick={handleSearch}
            disabled={isSearching || !searchQuery.trim()}
            className="px-4 py-3 bg-blue-500/80 hover:bg-blue-600/80 text-white rounded-xl transition-all"
          >
            {isSearching ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <Target className="w-4 h-4" />
            )}
          </Button>
          
          {/* 当前位置按钮 */}
          <Button
            onClick={handleCurrentLocation}
            className="px-4 py-3 bg-green-500/80 hover:bg-green-600/80 text-white rounded-xl transition-all"
          >
            <Navigation className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* 建议列表 */}
      <AnimatePresence>
        {showSuggestions && (
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full left-0 right-0 mt-2 bg-white/10 backdrop-blur-xl rounded-xl border border-white/20 overflow-hidden z-50"
          >
            {/* 建议标题 */}
            <div className="px-4 py-2 bg-white/5 border-b border-white/10">
              <p className="text-white/80 text-sm font-medium">
                {searchQuery.trim() ? '搜索结果' : '最近搜索'}
              </p>
            </div>

            {/* 建议列表 */}
            <div className="max-h-64 overflow-y-auto">
              {(searchQuery.trim() ? suggestions : recentSearches).map((suggestion, index) => (
                <motion.div
                  key={suggestion.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="px-4 py-3 hover:bg-white/10 cursor-pointer transition-colors"
                  onClick={() => handleSuggestionClick(suggestion)}
                >
                  <div className="flex items-center space-x-3">
                    <div className="text-white/60">
                      {getTypeIcon(suggestion.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium text-sm truncate">
                        {suggestion.name}
                      </p>
                      <p className="text-white/60 text-xs truncate">
                        {suggestion.address}
                      </p>
                    </div>
                    {suggestion.distance && (
                      <div className="text-white/40 text-xs">
                        {suggestion.distance}m
                      </div>
                    )}
                  </div>
                </motion.div>
              ))}
              
              {searchQuery.trim() && suggestions.length === 0 && (
                <div className="px-4 py-8 text-center">
                  <Search className="w-8 h-8 mx-auto text-white/30 mb-2" />
                  <p className="text-white/60 text-sm">未找到相关位置</p>
                  <p className="text-white/40 text-xs mt-1">
                    请尝试其他关键词或使用当前位置
                  </p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default LocationSearch