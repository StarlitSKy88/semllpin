'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { 
  MapPin, 
  Clock, 
  Star, 
  DollarSign, 
  MessageCircle, 
  Heart, 
  ExternalLink,
  User,
  TrendingUp
} from 'lucide-react'
import Image from 'next/image'
import { FilterOptions } from './advanced-filter'

export interface SearchResult {
  id: string
  type: 'news' | 'comment' | 'annotation'
  title: string
  content: string
  location: string
  timestamp: string
  author?: string
  avatar?: string
  imageUrl?: string
  rewardAmount?: number
  smellRating?: number
  tags: string[]
  likes?: number
  replies?: number
  source?: string
  url?: string
  distance?: number
}

interface SearchResultsProps {
  results: SearchResult[]
  filters: FilterOptions
  isLoading: boolean
  onResultClick: (result: SearchResult) => void
  className?: string
}

export function SearchResults({
  results,
  filters,
  isLoading,
  onResultClick,
  className = ''
}: SearchResultsProps) {
  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60))
    
    if (diffInHours < 1) return '刚刚'
    if (diffInHours < 24) return `${diffInHours}小时前`
    const diffInDays = Math.floor(diffInHours / 24)
    if (diffInDays < 7) return `${diffInDays}天前`
    return date.toLocaleDateString('zh-CN')
  }

  const formatDistance = (distance?: number) => {
    if (!distance) return ''
    if (distance < 1000) return `${Math.round(distance)}m`
    return `${(distance / 1000).toFixed(1)}km`
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'news':
        return <ExternalLink className="w-3 h-3" />
      case 'comment':
        return <MessageCircle className="w-3 h-3" />
      case 'annotation':
        return <MapPin className="w-3 h-3" />
      default:
        return <TrendingUp className="w-3 h-3" />
    }
  }

  const getTypeBadge = (type: string) => {
    const configs = {
      news: { label: '新闻', color: 'bg-blue-500/20 text-blue-300 border-blue-500/30' },
      comment: { label: '评论', color: 'bg-green-500/20 text-green-300 border-green-500/30' },
      annotation: { label: '标注', color: 'bg-purple-500/20 text-purple-300 border-purple-500/30' }
    }
    const config = configs[type as keyof typeof configs] || configs.news
    return (
      <Badge className={`${config.color} text-xs border`}>
        {getTypeIcon(type)}
        <span className="ml-1">{config.label}</span>
      </Badge>
    )
  }

  const renderSmellRating = (rating?: number) => {
    if (!rating) return null
    return (
      <div className="flex items-center space-x-1">
        {[1, 2, 3, 4, 5].map((star) => (
          <Star
            key={star}
            className={`w-3 h-3 ${
              star <= rating ? 'text-yellow-400 fill-current' : 'text-gray-400'
            }`}
          />
        ))}
        <span className="text-xs text-gray-400 ml-1">{rating}/5</span>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className={`space-y-4 ${className}`}>
        {[1, 2, 3].map((i) => (
          <div key={i} className="animate-pulse">
            <Card className="bg-white/10 backdrop-blur-md border-white/20">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between mb-2">
                  <div className="h-5 bg-white/20 rounded w-16"></div>
                  <div className="h-4 bg-white/20 rounded w-20"></div>
                </div>
                <div className="h-6 bg-white/20 rounded w-3/4"></div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="h-4 bg-white/20 rounded w-full"></div>
                  <div className="h-4 bg-white/20 rounded w-2/3"></div>
                  <div className="flex justify-between mt-4">
                    <div className="h-4 bg-white/20 rounded w-24"></div>
                    <div className="h-4 bg-white/20 rounded w-16"></div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        ))}
      </div>
    )
  }

  if (results.length === 0) {
    return (
      <div className={`text-center py-12 ${className}`}>
        <div className="text-white/60 text-lg mb-2">没有找到匹配的结果</div>
        <div className="text-white/40 text-sm">尝试调整筛选条件或搜索关键词</div>
      </div>
    )
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {/* 结果统计 */}
      <div className="flex items-center justify-between text-white/60 text-sm mb-4">
        <span>找到 {results.length} 个结果</span>
        <span>按{filters.sortBy === 'time' ? '时间' : filters.sortBy === 'reward' ? '奖励' : filters.sortBy === 'rating' ? '评级' : '距离'}排序</span>
      </div>

      {/* 搜索结果列表 */}
      {results.map((result, index) => (
        <motion.div
          key={result.id}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: index * 0.1 }}
        >
          <Card 
            className="overflow-hidden hover:shadow-2xl transition-all duration-300 bg-white/10 backdrop-blur-md border border-white/20 shadow-lg cursor-pointer hover:bg-white/15"
            onClick={() => onResultClick(result)}
          >
            <div className="flex">
              {/* 图片区域 */}
              {result.imageUrl && (
                <div className="relative w-24 h-24 sm:w-32 sm:h-32 flex-shrink-0">
                  <Image
                    src={result.imageUrl}
                    alt={result.title}
                    fill
                    className="object-cover"
                    onError={(e) => {
                      e.currentTarget.style.display = 'none'
                    }}
                  />
                </div>
              )}

              {/* 内容区域 */}
              <div className="flex-1 min-w-0">
                <CardHeader className="pb-2 p-3 sm:p-4">
                  <div className="flex items-center justify-between mb-2">
                    {getTypeBadge(result.type)}
                    <div className="flex items-center space-x-2 text-xs text-gray-400">
                      {result.distance && (
                        <span className="flex items-center">
                          <MapPin className="w-3 h-3 mr-1" />
                          {formatDistance(result.distance)}
                        </span>
                      )}
                      {result.source && (
                        <span className="truncate max-w-20">{result.source}</span>
                      )}
                    </div>
                  </div>
                  <CardTitle className="text-sm sm:text-base leading-tight text-white line-clamp-2">
                    {result.title}
                  </CardTitle>
                </CardHeader>

                <CardContent className="pt-0 p-3 sm:p-4">
                  <p className="text-gray-300 text-xs sm:text-sm mb-3 line-clamp-2">
                    {result.content}
                  </p>

                  {/* 标签 */}
                  {result.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-3">
                      {result.tags.slice(0, 3).map((tag) => (
                        <Badge
                          key={tag}
                          variant="outline"
                          className="text-xs bg-white/5 text-white/70 border-white/20"
                        >
                          {tag}
                        </Badge>
                      ))}
                      {result.tags.length > 3 && (
                        <Badge
                          variant="outline"
                          className="text-xs bg-white/5 text-white/70 border-white/20"
                        >
                          +{result.tags.length - 3}
                        </Badge>
                      )}
                    </div>
                  )}

                  {/* 底部信息 */}
                  <div className="flex items-center justify-between text-xs text-gray-400">
                    <div className="flex items-center space-x-3 min-w-0 flex-1">
                      {/* 位置 */}
                      <div className="flex items-center min-w-0">
                        <MapPin className="w-3 h-3 mr-1 flex-shrink-0" />
                        <span className="truncate">{result.location}</span>
                      </div>
                      
                      {/* 时间 */}
                      <div className="flex items-center flex-shrink-0">
                        <Clock className="w-3 h-3 mr-1" />
                        <span className="whitespace-nowrap">{formatTimeAgo(result.timestamp)}</span>
                      </div>
                    </div>

                    {/* 右侧信息 */}
                    <div className="flex items-center space-x-3 flex-shrink-0">
                      {/* 臭味等级 */}
                      {result.smellRating && renderSmellRating(result.smellRating)}
                      
                      {/* 奖励金额 */}
                      {result.rewardAmount && result.rewardAmount > 0 && (
                        <div className="flex items-center text-yellow-400">
                          <DollarSign className="w-3 h-3 mr-1" />
                          <span>¥{result.rewardAmount}</span>
                        </div>
                      )}
                      
                      {/* 互动数据 */}
                      {(result.likes || result.replies) && (
                        <div className="flex items-center space-x-2">
                          {result.likes && (
                            <div className="flex items-center">
                              <Heart className="w-3 h-3 mr-1" />
                              <span>{result.likes}</span>
                            </div>
                          )}
                          {result.replies && (
                            <div className="flex items-center">
                              <MessageCircle className="w-3 h-3 mr-1" />
                              <span>{result.replies}</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* 作者信息 */}
                  {result.author && (
                    <div className="flex items-center mt-2 pt-2 border-t border-white/10">
                      {result.avatar ? (
                        <Image
                          src={result.avatar}
                          alt={result.author}
                          width={16}
                          height={16}
                          className="rounded-full mr-2"
                        />
                      ) : (
                        <User className="w-4 h-4 mr-2 text-white/60" />
                      )}
                      <span className="text-xs text-white/60">{result.author}</span>
                    </div>
                  )}
                </CardContent>
              </div>
            </div>
          </Card>
        </motion.div>
      ))}
    </div>
  )
}