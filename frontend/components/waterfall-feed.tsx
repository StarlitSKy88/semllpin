'use client';

import React, { useState, useEffect } from 'react';
import { motion } from "framer-motion"
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Clock, MapPin, MessageCircle, Heart, Share2, TrendingUp, Globe, RefreshCw, ExternalLink } from 'lucide-react';
import { useNewsStore } from '@/lib/stores/news-store';
import { NewsArticle } from '@/lib/services/news-api';
import Image from "next/image"

// 用户评论类型定义
interface UserComment {
  id: string;
  userId: string;
  username: string;
  avatar: string;
  content: string;
  location: string;
  timestamp: string;
  likes: number;
  replies: number;
  images?: string[];
  smellRating: number; // 1-5 臭味等级
  tags: string[];
  category: 'comment';
  isHot?: boolean;
}

type FeedItem = NewsArticle | UserComment

// 模拟用户评论数据
const mockUserComments: UserComment[] = [
  {
    id: '1',
    userId: 'user1',
    username: '环保小卫士',
    avatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=40&h=40&fit=crop&crop=face',
    content: '刚路过这里，确实有很重的化学味道，希望相关部门能尽快处理！',
    location: '北京市朝阳区CBD',
    timestamp: '2024-01-15T14:20:00Z',
    likes: 23,
    replies: 5,
    images: ['https://images.unsplash.com/photo-1573160813959-df05c1b2e5d1?w=300&h=200&fit=crop'],
    smellRating: 4,
    tags: ['化学味', '刺鼻', '环保'],
    category: 'comment'
  },
  {
    id: '2',
    userId: 'user2',
    username: '市民张三',
    avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=40&h=40&fit=crop&crop=face',
    content: '我家就在附近，最近几天晚上都能闻到异味，影响睡眠质量。已经向12345热线投诉了。',
    location: '北京市朝阳区',
    timestamp: '2024-01-15T16:45:00Z',
    likes: 45,
    replies: 12,
    smellRating: 3,
    tags: ['异味', '投诉', '影响生活'],
    category: 'comment'
  }
]

export function WaterfallFeed() {
  const { 
    articles, 
    isLoading: newsLoading, 
    searchNews, 
    getTrendingNews,
    refreshNews,
    error 
  } = useNewsStore()
  const [feedItems, setFeedItems] = useState<FeedItem[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'news' | 'comments'>('all')

  useEffect(() => {
    // 加载新闻和评论数据
    const loadFeedData = async () => {
      setLoading(true)
      
      try {
        // 获取臭味相关新闻数据
        await searchNews({
          query: '臭味 OR 异味 OR 恶臭 OR 污染 OR 气味',
          pageSize: 10
        })
        
        // 获取热门新闻
        await getTrendingNews()
      } catch (error) {
        console.error('Failed to load news:', error)
      }
      
      setLoading(false)
    }

    loadFeedData()
  }, [])
  
  // 当articles更新时，重新合并数据
  useEffect(() => {
    if (articles.length > 0) {
      // 合并新闻和评论数据，按时间排序
      const allItems = [...articles, ...mockUserComments]
        .sort((a, b) => {
          const timeA = new Date(
            'publishedAt' in a ? a.publishedAt : a.timestamp
          ).getTime()
          const timeB = new Date(
            'publishedAt' in b ? b.publishedAt : b.timestamp
          ).getTime()
          return timeB - timeA
        })
      
      setFeedItems(allItems)
    }
  }, [articles])

  const filteredItems = feedItems.filter(item => {
    if (filter === 'all') return true
    if (filter === 'news') return item.category === 'news'
    if (filter === 'comments') return item.category === 'comment'
    return true
  })

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

  const renderNewsCard = (news: NewsArticle) => (
    <motion.div
      key={news.id}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="mb-6"
    >
      <Card className="overflow-hidden hover:shadow-2xl transition-all duration-300 bg-white/10 backdrop-blur-md border border-white/20 shadow-lg">
        {news.imageUrl && (
          <div className="relative h-28 sm:h-32 md:h-40 lg:h-48 w-full">
            <Image
              src={news.imageUrl}
              alt={news.title}
              fill
              className="object-cover"
              onError={(e) => {
                e.currentTarget.style.display = 'none'
              }}
            />
          </div>
        )}
        <CardHeader className="pb-2 sm:pb-3 p-3 sm:p-4 md:p-6">
          <div className="flex items-center justify-between mb-2">
            <Badge variant="secondary" className="bg-blue-500/20 text-blue-300 border border-blue-500/30 text-xs">
              <ExternalLink className="w-2 h-2 sm:w-3 sm:h-3 mr-1" />
              新闻
            </Badge>
            <span className="text-xs text-gray-400 truncate ml-2">{news.source}</span>
          </div>
          <CardTitle className="text-sm sm:text-base md:text-lg leading-tight text-white line-clamp-2">{news.title}</CardTitle>
        </CardHeader>
        <CardContent className="pt-0 p-3 sm:p-4 md:p-6">
          <p className="text-gray-300 text-xs sm:text-sm mb-3 line-clamp-2 sm:line-clamp-3">{news.summary}</p>
          <div className="flex items-center justify-between text-xs text-gray-400 mb-3">
            <div className="flex items-center min-w-0 flex-1 mr-2">
              <MapPin className="w-3 h-3 mr-1 flex-shrink-0" />
              <span className="truncate">{news.location}</span>
            </div>
            <div className="flex items-center flex-shrink-0">
              <Clock className="w-3 h-3 mr-1" />
              <span className="whitespace-nowrap">{formatTimeAgo(news.publishedAt)}</span>
            </div>
          </div>
          <Button 
            variant="outline" 
            size="sm" 
            className="w-full h-8 sm:h-9 text-gray-300 border-gray-500/50 hover:text-white hover:border-gray-400 hover:bg-white/10 text-xs sm:text-sm px-2 sm:px-3"
            onClick={() => window.open(news.url, '_blank')}
          >
            <span className="hidden sm:inline">阅读</span>全文
          </Button>
        </CardContent>
      </Card>
    </motion.div>
  )

  const renderCommentCard = (comment: UserComment) => (
    <motion.div
      key={comment.id}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="mb-6"
    >
      <Card className="overflow-hidden hover:shadow-2xl transition-all duration-300 bg-white/10 backdrop-blur-md border border-white/20 shadow-lg">
        <CardHeader className="pb-2 sm:pb-3 p-3 sm:p-4 md:p-6">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center">
              <Badge 
                variant="secondary"
                className="bg-green-500/20 text-green-300 border border-green-500/30 text-xs"
              >
                <MessageCircle className="w-2 h-2 sm:w-3 sm:h-3 mr-1" />用户评论
              </Badge>
            </div>
            <div className="flex items-center space-x-2">
              {comment.smellRating && (
                <div className="flex items-center">
                  <span className="text-xs text-gray-400 mr-1 hidden sm:inline">臭味等级:</span>
                  <div className="flex">
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                                        className={`w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full mr-0.5 sm:mr-1 ${
                          i < comment.smellRating ? 'bg-red-400' : 'bg-gray-200'
                        }`}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center">
            <div className="w-6 h-6 sm:w-8 sm:h-8 rounded-full bg-gray-200 flex items-center justify-center mr-2 sm:mr-3 flex-shrink-0">
              {comment.avatar ? (
                <Image
                  src={comment.avatar}
                  alt={comment.username}
                  width={32}
                  height={32}
                  className="rounded-full w-full h-full object-cover"
                  onError={(e) => {
                    e.currentTarget.style.display = 'none'
                  }}
                />
              ) : (
                <span className="text-xs sm:text-sm font-medium text-white">{comment.username?.[0] || '?'}</span>
              )}
            </div>
            <span className="font-medium text-white text-sm sm:text-base truncate">{comment.username}</span>
          </div>
        </CardHeader>
        <CardContent className="pt-0 p-3 sm:p-4 md:p-6">
          <p className="text-gray-200 mb-3 leading-relaxed text-xs sm:text-sm line-clamp-3 sm:line-clamp-4">{comment.content}</p>
          
          {comment.images && comment.images.length > 0 && (
            <div className="grid grid-cols-2 gap-1.5 sm:gap-2 mb-3">
              {comment.images.map((img, index) => (
                <div key={index} className="relative h-16 sm:h-20 md:h-24 rounded-lg overflow-hidden">
                  <Image
                    src={img}
                    alt={`评论图片 ${index + 1}`}
                    fill
                    className="object-cover"
                    onError={(e) => {
                      e.currentTarget.style.display = 'none'
                    }}
                  />
                </div>
              ))}
            </div>
          )}
          
          {comment.tags && comment.tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mb-3">
              {comment.tags.slice(0, 3).map((tag, index) => (
                <Badge key={index} variant="outline" className="text-xs text-gray-300 border-gray-500/50 hover:border-gray-400 px-1.5 py-0.5">
                  {tag}
                </Badge>
              ))}
              {comment.tags.length > 3 && (
                <Badge variant="outline" className="text-xs text-gray-300 border-gray-500/50 px-1.5 py-0.5">
                  +{comment.tags.length - 3}
                </Badge>
              )}
            </div>
          )}
          
          <div className="flex items-center justify-between text-xs text-gray-400 mb-3">
            <div className="flex items-center min-w-0 flex-1 mr-2">
              <MapPin className="w-3 h-3 mr-1 flex-shrink-0" />
              <span className="truncate">{comment.location}</span>
            </div>
            <div className="flex items-center flex-shrink-0">
              <Clock className="w-3 h-3 mr-1" />
              <span className="whitespace-nowrap">{formatTimeAgo(comment.timestamp)}</span>
            </div>
          </div>
          
          <div className="flex items-center justify-between pt-2 border-t border-white/20">
            <div className="flex items-center space-x-3 sm:space-x-4">
              <button className="flex items-center text-gray-400 hover:text-red-400 transition-colors">
                <Heart className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
                <span className="text-xs sm:text-sm">{comment.likes}</span>
              </button>
              <button className="flex items-center text-gray-400 hover:text-blue-400 transition-colors">
                <MessageCircle className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
                <span className="text-xs sm:text-sm">{comment.replies}</span>
              </button>
            </div>
            <Button variant="ghost" size="sm" className="text-gray-300 hover:text-white hover:bg-white/10 text-xs sm:text-sm px-2 sm:px-3 h-7 sm:h-8">
              <span className="hidden sm:inline">查看</span>详情
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )

  const handleRefresh = async () => {
    setLoading(true)
    try {
      await refreshNews()
    } catch (error) {
      console.error('Failed to refresh news:', error)
    }
    setLoading(false)
  }

  return (
    <section className="py-16 bg-black min-h-screen">
      <div className="container mx-auto px-4">
        <div className="text-center mb-8 sm:mb-12">
          <motion.h2 
            className="text-xl sm:text-2xl md:text-3xl font-bold mb-3 sm:mb-4 text-white px-4"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            全球臭味动态
          </motion.h2>
          <motion.p 
            className="text-gray-300 max-w-2xl mx-auto text-sm sm:text-base px-4"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
          >
            实时追踪全球臭味相关新闻和用户分享，发现身边的环境问题
          </motion.p>
        </div>

        {/* 错误提示 */}
        {error && (
          <motion.div 
            className="max-w-4xl mx-auto mb-6"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="bg-red-900/20 backdrop-blur-md border border-red-500/30 rounded-lg p-4">
              <p className="text-red-300 text-sm">
                <span className="font-medium">加载失败：</span>{error}
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={handleRefresh}
                className="mt-2"
              >
                重试
              </Button>
            </div>
          </motion.div>
        )}

        {/* 筛选器和刷新按钮 */}
        <motion.div 
          className="flex flex-col sm:flex-row justify-center items-center gap-3 sm:gap-4 mb-6 sm:mb-8 px-4"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={loading || newsLoading}
            className="w-full sm:w-auto h-8 sm:h-9 text-xs sm:text-sm px-3 sm:px-4"
          >
            <RefreshCw className={`w-3 h-3 sm:w-4 sm:h-4 mr-1 ${(loading || newsLoading) ? 'animate-spin' : ''}`} />
            刷新
          </Button>
          <div className="flex flex-wrap justify-center gap-1 bg-white/10 backdrop-blur-md rounded-lg p-1 shadow-lg border border-white/20">
            <Button
              variant={filter === 'all' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setFilter('all')}
              className="text-xs sm:text-sm h-7 sm:h-8 px-2 sm:px-3"
            >
              全部
            </Button>
            <Button
              variant={filter === 'news' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setFilter('news')}
              className="text-xs sm:text-sm h-7 sm:h-8 px-2 sm:px-3"
            >
              <Globe className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
              <span className="hidden sm:inline">新闻</span>资讯
            </Button>
            <Button
              variant={filter === 'comments' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setFilter('comments')}
              className="text-xs sm:text-sm h-7 sm:h-8 px-2 sm:px-3"
            >
              <MessageCircle className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
              <span className="hidden sm:inline">用户</span>评论
            </Button>
          </div>
        </motion.div>

        {/* 瀑布流内容 */}
        <div className="max-w-6xl mx-auto px-3 sm:px-4">
          {loading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6">
              {[...Array(6)].map((_, index) => (
                <div key={index} className="animate-pulse">
                  <Card className="bg-white/10 backdrop-blur-md border border-white/20">
                    <div className="h-28 sm:h-32 md:h-40 lg:h-48 bg-gray-700/50"></div>
                    <CardHeader className="p-3 sm:p-4 md:p-6">
                      <div className="h-3 sm:h-4 bg-gray-600/50 rounded w-3/4 mb-2"></div>
                      <div className="h-4 sm:h-5 md:h-6 bg-gray-600/50 rounded"></div>
                    </CardHeader>
                    <CardContent className="p-3 sm:p-4 md:p-6">
                      <div className="space-y-2">
                        <div className="h-3 sm:h-4 bg-gray-600/50 rounded"></div>
                        <div className="h-3 sm:h-4 bg-gray-600/50 rounded w-5/6"></div>
                        <div className="h-3 sm:h-4 bg-gray-600/50 rounded w-4/5"></div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6">
              {filteredItems.map((item) => (
                item.category === 'news' 
                  ? renderNewsCard(item as NewsArticle)
                  : renderCommentCard(item as UserComment)
              ))}
            </div>
          )}
        </div>

        {filteredItems.length === 0 && !loading && (
          <div className="text-center py-8 sm:py-12 px-4">
            <p className="text-gray-400 text-sm sm:text-base">暂无相关内容</p>
          </div>
        )}
      </div>
    </section>
  )
}