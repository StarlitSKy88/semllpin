'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  ArrowLeft, 
  MapPin, 
  Calendar, 
  User, 
  DollarSign,
  Eye,
  Heart,
  Share2,
  Flag,
  MoreHorizontal
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Skeleton } from '@/components/ui/skeleton'
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import CommentList from './comment-list'
import { useAnnotationStore } from '@/lib/stores/annotation-store'
import { useGlobalNotifications } from '@/lib/stores'

interface CommentDetailProps {
  annotationId: string
  onBack?: () => void
  className?: string
}

interface AnnotationInfo {
  id: string
  title: string
  description: string
  location: {
    latitude: number
    longitude: number
    address: string
  }
  rewardAmount: number
  images: string[]
  creator: {
    id: string
    name: string
    avatar?: string
  }
  createdAt: string
  status: 'active' | 'claimed' | 'expired'
  views: number
  likes: number
  isLiked: boolean
  tags: string[]
}

// 模拟获取标注详情的函数
const getAnnotationDetail = async (id: string): Promise<AnnotationInfo> => {
  // 模拟API延迟
  await new Promise(resolve => setTimeout(resolve, 1000))
  
  return {
    id,
    title: '神秘的臭豆腐摊',
    description: '这里有一个超级臭的豆腐摊，但是味道出奇的好！每天下午3点开始营业，经常排长队。老板是个很有趣的人，会跟客人聊天。推荐尝试他们的招牌臭豆腐配辣椒酱！',
    location: {
      latitude: 39.9042,
      longitude: 116.4074,
      address: '北京市朝阳区三里屯太古里'
    },
    rewardAmount: 50,
    images: [
      'https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?w=400',
      'https://images.unsplash.com/photo-1551782450-a2132b4ba21d?w=400'
    ],
    creator: {
      id: 'user1',
      name: '美食探索者',
      avatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100'
    },
    createdAt: '2024-01-15T10:30:00Z',
    status: 'active',
    views: 1234,
    likes: 89,
    isLiked: false,
    tags: ['美食', '臭豆腐', '小吃', '排队']
  }
}

export function CommentDetail({ annotationId, onBack, className = '' }: CommentDetailProps) {
  const [annotation, setAnnotation] = useState<AnnotationInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isLiked, setIsLiked] = useState(false)
  const [likes, setLikes] = useState(0)
  const { addNotification } = useGlobalNotifications()
  
  useEffect(() => {
    const loadAnnotation = async () => {
      try {
        setLoading(true)
        setError(null)
        const data = await getAnnotationDetail(annotationId)
        setAnnotation(data)
        setIsLiked(data.isLiked)
        setLikes(data.likes)
      } catch (err) {
        setError('加载标注详情失败')
        console.error('Error loading annotation:', err)
      } finally {
        setLoading(false)
      }
    }
    
    loadAnnotation()
  }, [annotationId])
  
  const handleLike = async () => {
    try {
      // 模拟API调用
      await new Promise(resolve => setTimeout(resolve, 500))
      
      if (isLiked) {
        setLikes(prev => prev - 1)
        setIsLiked(false)
        addNotification({
          type: 'success',
          title: '已取消点赞',
          message: '您已取消对此标注的点赞'
        })
      } else {
        setLikes(prev => prev + 1)
        setIsLiked(true)
        addNotification({
          type: 'success',
          title: '点赞成功',
          message: '感谢您的点赞支持'
        })
      }
    } catch (error) {
      addNotification({
        type: 'error',
        title: '操作失败',
        message: '点赞操作失败，请重试'
      })
    }
  }
  
  const handleShare = async () => {
    try {
      if (navigator.share) {
        await navigator.share({
          title: annotation?.title,
          text: annotation?.description,
          url: window.location.href
        })
      } else {
        // 复制到剪贴板
        await navigator.clipboard.writeText(window.location.href)
        addNotification({
          type: 'success',
          title: '链接已复制',
          message: '链接已复制到剪贴板，可以分享给朋友了'
        })
      }
    } catch (error) {
      addNotification({
        type: 'error',
        title: '分享失败',
        message: '分享操作失败，请重试'
      })
    }
  }
  
  const handleReport = () => {
    addNotification({
      type: 'success',
      title: '举报已提交',
      message: '感谢您的举报，我们会尽快处理'
    })
  }
  
  const formatTime = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    
    const minutes = Math.floor(diff / (1000 * 60))
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    
    if (minutes < 60) {
      return `${minutes}分钟前`
    } else if (hours < 24) {
      return `${hours}小时前`
    } else if (days < 30) {
      return `${days}天前`
    } else {
      return date.toLocaleDateString('zh-CN')
    }
  }
  
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge className="bg-green-100 text-green-800">活跃</Badge>
      case 'claimed':
        return <Badge className="bg-blue-100 text-blue-800">已领取</Badge>
      case 'expired':
        return <Badge className="bg-gray-100 text-gray-800">已过期</Badge>
      default:
        return null
    }
  }
  
  if (loading) {
    return (
      <div className={`max-w-4xl mx-auto ${className}`}>
        {/* 头部骨架屏 */}
        <div className="flex items-center gap-3 sm:gap-4 p-3 sm:p-4 border-b border-gray-100">
          <Skeleton className="w-6 h-6 sm:w-8 sm:h-8 rounded" />
          <Skeleton className="h-5 sm:h-6 w-24 sm:w-32" />
        </div>
        
        {/* 内容骨架屏 */}
        <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
          <div className="space-y-3 sm:space-y-4">
            <Skeleton className="h-6 sm:h-8 w-3/4" />
            <Skeleton className="h-3 sm:h-4 w-full" />
            <Skeleton className="h-3 sm:h-4 w-2/3" />
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
            <Skeleton className="h-32 sm:h-48 rounded-lg" />
            <Skeleton className="h-32 sm:h-48 rounded-lg" />
          </div>
          
          <div className="flex items-center gap-3 sm:gap-4">
            <Skeleton className="w-8 h-8 sm:w-10 sm:h-10 rounded-full" />
            <div className="space-y-1 sm:space-y-2">
              <Skeleton className="h-3 sm:h-4 w-20 sm:w-24" />
              <Skeleton className="h-2 sm:h-3 w-12 sm:w-16" />
            </div>
          </div>
        </div>
      </div>
    )
  }
  
  if (error || !annotation) {
    return (
      <div className={`max-w-4xl mx-auto ${className}`}>
        <div className="text-center py-12">
          <p className="text-red-600 mb-4">{error || '标注不存在'}</p>
          <Button onClick={() => window.location.reload()}>
            重试
          </Button>
        </div>
      </div>
    )
  }
  
  return (
    <div className={`max-w-4xl mx-auto bg-white ${className}`}>
      {/* 头部导航 */}
      <div className="flex items-center justify-between p-3 sm:p-4 border-b border-gray-100 sticky top-0 bg-white z-10">
        <div className="flex items-center gap-2 sm:gap-3">
          {onBack && (
            <Button variant="ghost" size="sm" onClick={onBack} className="h-8 w-8 sm:h-9 sm:w-auto sm:px-3">
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline ml-1">返回</span>
            </Button>
          )}
          <h1 className="font-semibold text-base sm:text-lg truncate">标注详情</h1>
        </div>
        
        <div className="flex items-center gap-1 sm:gap-2">
          <Button variant="ghost" size="sm" onClick={handleShare} className="h-8 w-8 sm:h-9 sm:w-auto sm:px-3">
            <Share2 className="w-4 h-4" />
            <span className="hidden sm:inline ml-1">分享</span>
          </Button>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-8 w-8 sm:h-9 sm:w-9">
                <MoreHorizontal className="w-4 h-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={handleReport}>
                <Flag className="w-4 h-4 mr-2" />
                举报
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      
      {/* 标注详情 */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="p-4 sm:p-6"
      >
        {/* 标题和状态 */}
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 sm:gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <h2 className="text-xl sm:text-2xl font-bold text-gray-900 mb-2 line-clamp-2">
              {annotation.title}
            </h2>
            <div className="flex flex-wrap items-center gap-2 mb-3">
              {getStatusBadge(annotation.status)}
              <div className="flex items-center gap-3 sm:gap-4 text-sm text-gray-500">
                <span className="flex items-center gap-1">
                  <Eye className="w-3 h-3 sm:w-4 sm:h-4" />
                  <span className="text-xs sm:text-sm">{annotation.views}</span>
                </span>
                <span className="flex items-center gap-1">
                  <Heart className="w-3 h-3 sm:w-4 sm:h-4" />
                  <span className="text-xs sm:text-sm">{likes}</span>
                </span>
              </div>
            </div>
          </div>
          
          <div className="text-left sm:text-right flex-shrink-0">
            <div className="flex items-center gap-1 text-lg sm:text-xl font-semibold text-green-600">
              <DollarSign className="w-4 h-4 sm:w-5 sm:h-5" />
              {annotation.rewardAmount}
            </div>
            <span className="text-xs sm:text-sm text-gray-500">奖励金额</span>
          </div>
        </div>
        
        {/* 描述 */}
        <p className="text-sm sm:text-base text-gray-700 leading-relaxed mb-4 sm:mb-6">
          {annotation.description}
        </p>
        
        {/* 标签 */}
        {annotation.tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 sm:gap-2 mb-4 sm:mb-6">
            {annotation.tags.slice(0, 6).map((tag, index) => (
              <Badge key={index} variant="secondary" className="text-xs">
                #{tag}
              </Badge>
            ))}
            {annotation.tags.length > 6 && (
              <Badge variant="outline" className="text-xs">
                +{annotation.tags.length - 6}
              </Badge>
            )}
          </div>
        )}
        
        {/* 图片 */}
        {annotation.images.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4 mb-4 sm:mb-6">
            {annotation.images.map((image, index) => (
              <motion.img
                key={index}
                src={image}
                alt={`标注图片 ${index + 1}`}
                className="w-full h-48 sm:h-64 object-cover rounded-lg cursor-pointer hover:opacity-90 transition-opacity"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              />
            ))}
          </div>
        )}
        
        {/* 位置信息 */}
        <div className="bg-gray-50 rounded-lg p-3 sm:p-4 mb-4 sm:mb-6">
          <div className="flex items-center gap-2 mb-2">
            <MapPin className="w-4 h-4 sm:w-5 sm:h-5 text-gray-600" />
            <span className="font-medium text-sm sm:text-base">位置信息</span>
          </div>
          <p className="text-sm sm:text-base text-gray-700 line-clamp-2">{annotation.location.address}</p>
          <p className="text-xs sm:text-sm text-gray-500 mt-1 font-mono">
            {annotation.location.latitude.toFixed(4)}, {annotation.location.longitude.toFixed(4)}
          </p>
        </div>
        
        {/* 创建者信息 */}
        <div className="flex items-center justify-between p-3 sm:p-4 bg-gray-50 rounded-lg mb-4 sm:mb-6">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
            <Avatar className="w-10 h-10 sm:w-12 sm:h-12 flex-shrink-0">
              <AvatarImage src={annotation.creator.avatar} alt={annotation.creator.name} />
              <AvatarFallback>
                <User className="w-5 h-5 sm:w-6 sm:h-6" />
              </AvatarFallback>
            </Avatar>
            <div className="min-w-0 flex-1">
              <p className="font-medium text-sm sm:text-base truncate">{annotation.creator.name}</p>
              <div className="flex items-center gap-1 text-xs sm:text-sm text-gray-500">
                <Calendar className="w-3 h-3 sm:w-4 sm:h-4 flex-shrink-0" />
                <span className="truncate">{formatTime(annotation.createdAt)}</span>
              </div>
            </div>
          </div>
          
          <Button
            variant={isLiked ? "default" : "outline"}
            size="sm"
            onClick={handleLike}
            className={`h-8 sm:h-9 flex-shrink-0 ${isLiked ? "bg-red-500 hover:bg-red-600" : ""}`}
          >
            <Heart className={`w-3 h-3 sm:w-4 sm:h-4 ${isLiked ? 'fill-current' : ''}`} />
            <span className="ml-1 text-xs sm:text-sm">{isLiked ? '已赞' : '点赞'}</span>
          </Button>
        </div>
      </motion.div>
      
      {/* 评论区域 */}
      <div className="border-t border-gray-100">
        <CommentList annotationId={annotationId} />
      </div>
    </div>
  )
}

export default CommentDetail