'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  MessageCircle, 
  ThumbsUp, 
  ThumbsDown, 
  Reply as ReplyIcon, 
  MoreHorizontal,
  Trash2,
  Flag,
  Image as ImageIcon,
  Send,
  SortAsc
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useCommentStore } from '@/lib/stores/comment-store'
import { CommentService, COMMENT_SORT_OPTIONS, Comment, Reply } from '@/lib/services/comment-service'
import { useGlobalNotifications } from '@/lib/stores'

interface CommentListProps {
  annotationId: string
  className?: string
}

interface CommentItemProps {
  comment: Comment
  onReply: (commentId: string, replyToUserId?: string, replyToUserName?: string) => void
}

interface ReplyItemProps {
  reply: Reply
  commentId: string
  onReply: (commentId: string, replyToUserId: string, replyToUserName: string) => void
}

// 回复组件
function ReplyItem({ reply, commentId, onReply }: ReplyItemProps) {
  const {
    likeReply,
    dislikeReply,
    deleteReply,
    likingReplies,
    deletingReplies
  } = useCommentStore()
  const { addNotification } = useGlobalNotifications()
  
  const replyKey = `${commentId}-${reply.id}`
  const isLiking = likingReplies.has(replyKey)
  const isDeleting = deletingReplies.has(replyKey)
  
  const handleLike = () => {
    if (!isLiking) {
      likeReply(commentId, reply.id)
    }
  }
  
  const handleDislike = () => {
    if (!isLiking) {
      dislikeReply(commentId, reply.id)
    }
  }
  
  const handleDelete = () => {
    if (!isDeleting) {
      deleteReply(commentId, reply.id)
      addNotification({
        type: 'success',
        title: '回复已删除',
        message: '您的回复已成功删除'
      })
    }
  }
  
  const handleReply = () => {
    onReply(commentId, reply.userId, reply.userName)
  }
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="flex gap-2 sm:gap-3 p-2 sm:p-3 bg-gray-50 rounded-lg ml-6 sm:ml-12"
    >
      <Avatar className="w-6 h-6 sm:w-8 sm:h-8 flex-shrink-0">
        <AvatarImage src={reply.userAvatar} alt={reply.userName} className="object-cover" />
        <AvatarFallback className="text-xs">{reply.userName.charAt(0)}</AvatarFallback>
      </Avatar>
      
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1 sm:gap-2 mb-1 flex-wrap">
          <span className="font-medium text-xs sm:text-sm truncate max-w-20 sm:max-w-none">{reply.userName}</span>
          <span className="text-xs text-gray-500 flex-shrink-0">
            {CommentService.formatTime(reply.createdAt)}
          </span>
          {reply.replyToUserName && (
            <span className="text-xs text-blue-600 truncate max-w-16 sm:max-w-none">
              回复 @{reply.replyToUserName}
            </span>
          )}
        </div>
        
        <p className="text-xs sm:text-sm text-gray-700 mb-2 line-clamp-3">{reply.content}</p>
        
        <div className="flex items-center gap-1 sm:gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLike}
            disabled={isLiking}
            className={`h-5 sm:h-6 px-1 sm:px-2 text-xs ${
              reply.isLiked ? 'text-blue-600 bg-blue-50' : 'text-gray-500'
            }`}
          >
            <ThumbsUp className="w-2.5 h-2.5 sm:w-3 sm:h-3 mr-0.5 sm:mr-1" />
            <span className="hidden sm:inline">{reply.likes}</span>
          </Button>
          
          <Button
            variant="ghost"
            size="sm"
            onClick={handleDislike}
            disabled={isLiking}
            className={`h-5 sm:h-6 px-1 sm:px-2 text-xs ${
              reply.isDisliked ? 'text-red-600 bg-red-50' : 'text-gray-500'
            }`}
          >
            <ThumbsDown className="w-2.5 h-2.5 sm:w-3 sm:h-3 mr-0.5 sm:mr-1" />
            <span className="hidden sm:inline">{reply.dislikes}</span>
          </Button>
          
          <Button
            variant="ghost"
            size="sm"
            onClick={handleReply}
            className="h-5 sm:h-6 px-1 sm:px-2 text-xs text-gray-500"
          >
            <ReplyIcon className="w-2.5 h-2.5 sm:w-3 sm:h-3 mr-0.5 sm:mr-1" />
            <span className="hidden sm:inline">回复</span>
          </Button>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-5 sm:h-6 w-5 sm:w-6 p-0">
                <MoreHorizontal className="w-2.5 h-2.5 sm:w-3 sm:h-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={handleDelete} disabled={isDeleting}>
                <Trash2 className="w-4 h-4 mr-2" />
                删除
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Flag className="w-4 h-4 mr-2" />
                举报
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </motion.div>
  )
}

// 评论组件
function CommentItem({ comment, onReply }: CommentItemProps) {
  const [showReplies, setShowReplies] = useState(false)
  const {
    likeComment,
    dislikeComment,
    deleteComment,
    likingComments,
    deletingComments
  } = useCommentStore()
  const { addNotification } = useGlobalNotifications()
  
  const isLiking = likingComments.has(comment.id)
  const isDeleting = deletingComments.has(comment.id)
  
  const handleLike = () => {
    if (!isLiking) {
      likeComment(comment.id)
    }
  }
  
  const handleDislike = () => {
    if (!isLiking) {
      dislikeComment(comment.id)
    }
  }
  
  const handleDelete = () => {
    if (!isDeleting) {
      deleteComment(comment.id)
      addNotification({
        type: 'success',
        title: '评论已删除',
        message: '您的评论已成功删除'
      })
    }
  }
  
  const handleReply = () => {
    onReply(comment.id)
  }
  
  const handleReplyToReply = (commentId: string, replyToUserId: string, replyToUserName: string) => {
    onReply(commentId, replyToUserId, replyToUserName)
  }
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="border-b border-gray-100 pb-4 last:border-b-0"
    >
      <div className="flex gap-2 sm:gap-3">
        <Avatar className="w-8 h-8 sm:w-10 sm:h-10 flex-shrink-0">
          <AvatarImage src={comment.userAvatar} alt={comment.userName} className="object-cover" />
          <AvatarFallback className="text-sm">{comment.userName.charAt(0)}</AvatarFallback>
        </Avatar>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1 sm:gap-2 mb-2 flex-wrap">
            <span className="font-medium text-sm sm:text-base truncate max-w-24 sm:max-w-none">{comment.userName}</span>
            <span className="text-xs sm:text-sm text-gray-500 flex-shrink-0">
              {CommentService.formatTime(comment.createdAt)}
            </span>
          </div>
          
          <p className="text-sm sm:text-base text-gray-700 mb-3 line-clamp-6">{comment.content}</p>
          
          {comment.images && comment.images.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1 sm:gap-2 mb-3">
              {comment.images.map((image, index) => (
                <img
                  key={index}
                  src={image}
                  alt={`评论图片 ${index + 1}`}
                  className="rounded-lg object-cover w-full h-20 sm:h-32"
                />
              ))}
            </div>
          )}
          
          <div className="flex items-center gap-1 sm:gap-4 mb-3 flex-wrap">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLike}
              disabled={isLiking}
              className={`h-6 sm:h-8 px-2 sm:px-3 text-xs sm:text-sm ${
                comment.isLiked ? 'text-blue-600 bg-blue-50' : 'text-gray-500'
              }`}
            >
              <ThumbsUp className="w-3 h-3 sm:w-4 sm:h-4 mr-0.5 sm:mr-1" />
              <span className="hidden sm:inline">{comment.likes}</span>
            </Button>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={handleDislike}
              disabled={isLiking}
              className={`h-6 sm:h-8 px-2 sm:px-3 text-xs sm:text-sm ${
                comment.isDisliked ? 'text-red-600 bg-red-50' : 'text-gray-500'
              }`}
            >
              <ThumbsDown className="w-3 h-3 sm:w-4 sm:h-4 mr-0.5 sm:mr-1" />
              <span className="hidden sm:inline">{comment.dislikes}</span>
            </Button>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={handleReply}
              className="h-6 sm:h-8 px-2 sm:px-3 text-xs sm:text-sm text-gray-500"
            >
              <ReplyIcon className="w-3 h-3 sm:w-4 sm:h-4 mr-0.5 sm:mr-1" />
              <span className="hidden sm:inline">回复</span>
            </Button>
            
            {comment.replies.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowReplies(!showReplies)}
                className="h-6 sm:h-8 px-2 sm:px-3 text-xs sm:text-sm text-gray-500"
              >
                <MessageCircle className="w-3 h-3 sm:w-4 sm:h-4 mr-0.5 sm:mr-1" />
                <span className="hidden sm:inline">{comment.replies.length} 条回复</span>
                <span className="sm:hidden">{comment.replies.length}</span>
              </Button>
            )}
            
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-6 sm:h-8 w-6 sm:w-8 p-0">
                  <MoreHorizontal className="w-3 h-3 sm:w-4 sm:h-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={handleDelete} disabled={isDeleting}>
                  <Trash2 className="w-4 h-4 mr-2" />
                  删除
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <Flag className="w-4 h-4 mr-2" />
                  举报
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          
          {/* 回复列表 */}
          <AnimatePresence>
            {showReplies && comment.replies.length > 0 && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="space-y-2"
              >
                {comment.replies.map((reply) => (
                  <ReplyItem
                    key={reply.id}
                    reply={reply}
                    commentId={comment.id}
                    onReply={handleReplyToReply}
                  />
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  )
}

// 评论输入框组件
function CommentInput({ 
  annotationId, 
  replyTo 
}: { 
  annotationId: string
  replyTo?: { commentId: string, userId?: string, userName?: string } 
}) {
  const [content, setContent] = useState('')
  const [images, setImages] = useState<File[]>([])
  const { createComment, createReply, creatingComment, creatingReply } = useCommentStore()
  const { addNotification } = useGlobalNotifications()
  
  const isLoading = creatingComment || creatingReply
  
  const handleSubmit = async () => {
    if (!content.trim()) {
      addNotification({
        type: 'error',
        title: '内容不能为空',
        message: '请输入评论内容'
      })
      return
    }
    
    try {
      if (replyTo) {
        await createReply({
          commentId: replyTo.commentId,
          content: content.trim(),
          replyToUserId: replyTo.userId,
          replyToUserName: replyTo.userName
        })
        addNotification({
          type: 'success',
          title: '回复发布成功',
          message: '您的回复已成功发布'
        })
      } else {
        await createComment({
          annotationId,
          content: content.trim(),
          images
        })
        addNotification({
          type: 'success',
          title: '评论发布成功',
          message: '您的评论已成功发布'
        })
      }
      
      setContent('')
      setImages([])
    } catch (error) {
      addNotification({
        type: 'error',
        title: '发布失败',
        message: '发布失败，请重试'
      })
    }
  }
  
  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    if (files.length + images.length > 4) {
      addNotification({
        type: 'error',
        title: '图片数量超限',
        message: '最多只能上传4张图片'
      })
      return
    }
    setImages([...images, ...files])
  }
  
  const removeImage = (index: number) => {
    setImages(images.filter((_, i) => i !== index))
  }
  
  return (
    <div className="border-t border-gray-100 pt-4">
      {replyTo && (
        <div className="mb-2 text-xs sm:text-sm text-gray-600">
          回复 @{replyTo.userName || '评论'}
        </div>
      )}
      
      <div className="flex gap-2 sm:gap-3">
        <Avatar className="w-6 h-6 sm:w-8 sm:h-8 flex-shrink-0">
          <AvatarFallback className="text-xs">我</AvatarFallback>
        </Avatar>
        
        <div className="flex-1">
          <Textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={replyTo ? '写下你的回复...' : '写下你的评论...'}
            className="min-h-[60px] sm:min-h-[80px] resize-none text-sm"
            disabled={isLoading}
          />
          
          {images.length > 0 && (
            <div className="grid grid-cols-3 sm:grid-cols-4 gap-1 sm:gap-2 mt-2">
              {images.map((image, index) => (
                <div key={index} className="relative">
                  <img
                    src={URL.createObjectURL(image)}
                    alt={`预览 ${index + 1}`}
                    className="w-full h-12 sm:h-16 object-cover rounded"
                  />
                  <button
                    onClick={() => removeImage(index)}
                    className="absolute -top-1 -right-1 w-4 h-4 sm:w-5 sm:h-5 bg-red-500 text-white rounded-full text-xs"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
          
          <div className="flex items-center justify-between mt-2 sm:mt-3">
            <div className="flex items-center gap-1 sm:gap-2">
              <input
                type="file"
                accept="image/*"
                multiple
                onChange={handleImageUpload}
                className="hidden"
                id="comment-image-upload"
                disabled={isLoading}
              />
              <label
                htmlFor="comment-image-upload"
                className="cursor-pointer p-1.5 sm:p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded"
              >
                <ImageIcon className="w-3 h-3 sm:w-4 sm:h-4" />
              </label>
            </div>
            
            <Button
              onClick={handleSubmit}
              disabled={isLoading || !content.trim()}
              size="sm"
              className="h-7 sm:h-8 px-2 sm:px-3 text-xs sm:text-sm"
            >
              {isLoading ? (
                <div className="w-3 h-3 sm:w-4 sm:h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Send className="w-3 h-3 sm:w-4 sm:h-4" />
              )}
              <span className="ml-1">{replyTo ? '回复' : '发布'}</span>
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}

// 主评论列表组件
export function CommentList({ annotationId, className = '' }: CommentListProps) {
  const [replyTo, setReplyTo] = useState<{
    commentId: string
    userId?: string
    userName?: string
  } | null>(null)
  
  const {
    comments,
    loading,
    error,
    hasMore,
    total,
    sortBy,
    loadComments,
    loadMoreComments,
    setSortBy,
    clearError
  } = useCommentStore()
  
  useEffect(() => {
    loadComments(annotationId)
  }, [annotationId, loadComments])
  
  const handleSortChange = (newSortBy: string) => {
    setSortBy(newSortBy)
    loadComments(annotationId, 1, newSortBy)
  }
  
  const handleReply = (commentId: string, userId?: string, userName?: string) => {
    setReplyTo({ commentId, userId, userName })
  }
  
  const handleLoadMore = () => {
    if (hasMore && !loading) {
      loadMoreComments(annotationId)
    }
  }
  
  if (error) {
    return (
      <div className={`p-4 ${className}`}>
        <div className="text-center py-8">
          <p className="text-red-600 mb-4">{error}</p>
          <Button onClick={() => {
            clearError()
            loadComments(annotationId)
          }}>
            重试
          </Button>
        </div>
      </div>
    )
  }
  
  return (
    <div className={`${className}`}>
      {/* 头部 */}
      <div className="flex items-center justify-between p-3 sm:p-4 border-b border-gray-100">
        <div className="flex items-center gap-1 sm:gap-2">
          <MessageCircle className="w-4 h-4 sm:w-5 sm:h-5 text-gray-600" />
          <span className="font-medium text-sm sm:text-base">评论 ({total})</span>
        </div>
        
        <Select value={sortBy} onValueChange={handleSortChange}>
          <SelectTrigger className="w-24 sm:w-32 h-7 sm:h-9 text-xs sm:text-sm">
            <SortAsc className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {COMMENT_SORT_OPTIONS.map((option) => (
              <SelectItem key={option.value} value={option.value} className="text-xs sm:text-sm">
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      
      {/* 评论输入框 */}
      <div className="p-3 sm:p-4">
        <CommentInput annotationId={annotationId} replyTo={replyTo} />
        {replyTo && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setReplyTo(null)}
            className="mt-2 h-6 sm:h-8 px-2 sm:px-3 text-xs sm:text-sm"
          >
            取消回复
          </Button>
        )}
      </div>
      
      {/* 评论列表 */}
      <div className="px-3 sm:px-4">
        {loading && comments.length === 0 ? (
          <div className="space-y-3 sm:space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="flex gap-2 sm:gap-3">
                <Skeleton className="w-8 h-8 sm:w-10 sm:h-10 rounded-full flex-shrink-0" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-3 sm:h-4 w-1/4" />
                  <Skeleton className="h-3 sm:h-4 w-full" />
                  <Skeleton className="h-3 sm:h-4 w-3/4" />
                  <div className="flex gap-1 sm:gap-2">
                    <Skeleton className="h-5 sm:h-6 w-12 sm:w-16" />
                    <Skeleton className="h-5 sm:h-6 w-12 sm:w-16" />
                    <Skeleton className="h-5 sm:h-6 w-12 sm:w-16" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : comments.length === 0 ? (
          <div className="text-center py-8 sm:py-12">
            <MessageCircle className="w-8 h-8 sm:w-12 sm:h-12 text-gray-300 mx-auto mb-3 sm:mb-4" />
            <p className="text-sm sm:text-base text-gray-500">还没有评论，来发表第一条评论吧！</p>
          </div>
        ) : (
          <div className="space-y-4 sm:space-y-6">
            <AnimatePresence>
              {comments.map((comment) => (
                <CommentItem
                  key={comment.id}
                  comment={comment}
                  onReply={handleReply}
                />
              ))}
            </AnimatePresence>
            
            {hasMore && (
              <div className="text-center py-3 sm:py-4">
                <Button
                  variant="outline"
                  onClick={handleLoadMore}
                  disabled={loading}
                  size="sm"
                  className="h-7 sm:h-9 px-3 sm:px-4 text-xs sm:text-sm"
                >
                  {loading ? (
                    <div className="w-3 h-3 sm:w-4 sm:h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin mr-1 sm:mr-2" />
                  ) : null}
                  加载更多评论
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default CommentList