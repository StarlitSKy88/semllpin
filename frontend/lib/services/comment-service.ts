import { apiClient } from '../api'

// 评论接口定义
export interface Comment {
  id: string
  annotationId: string
  userId: string
  userName: string
  userAvatar?: string
  content: string
  images?: string[]
  likes: number
  dislikes: number
  isLiked: boolean
  isDisliked: boolean
  replies: Reply[]
  createdAt: string
  updatedAt: string
}

export interface Reply {
  id: string
  commentId: string
  userId: string
  userName: string
  userAvatar?: string
  content: string
  likes: number
  dislikes: number
  isLiked: boolean
  isDisliked: boolean
  replyToUserId?: string
  replyToUserName?: string
  createdAt: string
  updatedAt: string
}

export interface CreateCommentRequest {
  annotationId: string
  content: string
  images?: File[]
}

export interface CreateReplyRequest {
  commentId: string
  content: string
  replyToUserId?: string
  replyToUserName?: string
}

export interface CommentListResponse {
  comments: Comment[]
  total: number
  page: number
  pageSize: number
  hasMore: boolean
}

export interface CommentSortOption {
  value: 'newest' | 'oldest' | 'likes' | 'replies'
  label: string
}

// 评论排序选项
export const COMMENT_SORT_OPTIONS: CommentSortOption[] = [
  { value: 'newest', label: '最新' },
  { value: 'oldest', label: '最早' },
  { value: 'likes', label: '最多赞' },
  { value: 'replies', label: '最多回复' }
]

// 模拟数据
const mockComments: Comment[] = [
  {
    id: '1',
    annotationId: 'ann1',
    userId: 'user1',
    userName: '臭味探测员',
    userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=user1',
    content: '这里确实很臭，刚路过的时候差点被熏晕了！建议大家绕道而行。',
    images: ['https://picsum.photos/400/300?random=1'],
    likes: 15,
    dislikes: 2,
    isLiked: false,
    isDisliked: false,
    replies: [
      {
        id: 'r1',
        commentId: '1',
        userId: 'user2',
        userName: '路人甲',
        userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=user2',
        content: '同感！我昨天也路过这里，味道真的很重。',
        likes: 5,
        dislikes: 0,
        isLiked: true,
        isDisliked: false,
        createdAt: '2024-01-15T10:30:00Z',
        updatedAt: '2024-01-15T10:30:00Z'
      }
    ],
    createdAt: '2024-01-15T09:15:00Z',
    updatedAt: '2024-01-15T09:15:00Z'
  },
  {
    id: '2',
    annotationId: 'ann1',
    userId: 'user3',
    userName: '环保志愿者',
    userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=user3',
    content: '已经向相关部门举报了，希望能尽快处理这个问题。大家也可以通过官方渠道反映情况。',
    likes: 23,
    dislikes: 1,
    isLiked: true,
    isDisliked: false,
    replies: [],
    createdAt: '2024-01-15T11:20:00Z',
    updatedAt: '2024-01-15T11:20:00Z'
  },
  {
    id: '3',
    annotationId: 'ann1',
    userId: 'user4',
    userName: '本地居民',
    userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=user4',
    content: '这个问题已经存在很久了，附近的居民都深受其害。感谢大家的关注！',
    likes: 18,
    dislikes: 0,
    isLiked: false,
    isDisliked: false,
    replies: [
      {
        id: 'r2',
        commentId: '3',
        userId: 'user5',
        userName: '热心市民',
        userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=user5',
        content: '我们可以联合起来向政府部门施压，这样效果会更好。',
        likes: 8,
        dislikes: 0,
        isLiked: false,
        isDisliked: false,
        createdAt: '2024-01-15T12:45:00Z',
        updatedAt: '2024-01-15T12:45:00Z'
      },
      {
        id: 'r3',
        commentId: '3',
        userId: 'user6',
        userName: '环境专家',
        userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=user6',
        content: '@热心市民 同意你的建议，集体行动确实更有效果。',
        likes: 3,
        dislikes: 0,
        isLiked: false,
        isDisliked: false,
        replyToUserId: 'user5',
        replyToUserName: '热心市民',
        createdAt: '2024-01-15T13:10:00Z',
        updatedAt: '2024-01-15T13:10:00Z'
      }
    ],
    createdAt: '2024-01-15T12:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z'
  }
]

// 评论服务类
export class CommentService {
  // 获取标注的评论列表
  static async getComments(
    annotationId: string,
    page: number = 1,
    pageSize: number = 10,
    sortBy: string = 'newest'
  ): Promise<CommentListResponse> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 500))
      
      // 过滤指定标注的评论
      let filteredComments = mockComments.filter(comment => comment.annotationId === annotationId)
      
      // 排序
      switch (sortBy) {
        case 'newest':
          filteredComments.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
          break
        case 'oldest':
          filteredComments.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
          break
        case 'likes':
          filteredComments.sort((a, b) => b.likes - a.likes)
          break
        case 'replies':
          filteredComments.sort((a, b) => b.replies.length - a.replies.length)
          break
      }
      
      // 分页
      const startIndex = (page - 1) * pageSize
      const endIndex = startIndex + pageSize
      const paginatedComments = filteredComments.slice(startIndex, endIndex)
      
      return {
        comments: paginatedComments,
        total: filteredComments.length,
        page,
        pageSize,
        hasMore: endIndex < filteredComments.length
      }
    } catch (error) {
      console.error('获取评论失败:', error)
      throw new Error('获取评论失败')
    }
  }
  
  // 创建评论
  static async createComment(request: CreateCommentRequest): Promise<Comment> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 800))
      
      const newComment: Comment = {
        id: `comment_${Date.now()}`,
        annotationId: request.annotationId,
        userId: 'current_user',
        userName: '当前用户',
        userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=current',
        content: request.content,
        images: request.images ? request.images.map((_, index) => `https://picsum.photos/400/300?random=${Date.now() + index}`) : [],
        likes: 0,
        dislikes: 0,
        isLiked: false,
        isDisliked: false,
        replies: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
      
      // 添加到模拟数据中
      mockComments.unshift(newComment)
      
      return newComment
    } catch (error) {
      console.error('创建评论失败:', error)
      throw new Error('创建评论失败')
    }
  }
  
  // 创建回复
  static async createReply(request: CreateReplyRequest): Promise<Reply> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 600))
      
      const newReply: Reply = {
        id: `reply_${Date.now()}`,
        commentId: request.commentId,
        userId: 'current_user',
        userName: '当前用户',
        userAvatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=current',
        content: request.content,
        likes: 0,
        dislikes: 0,
        isLiked: false,
        isDisliked: false,
        replyToUserId: request.replyToUserId,
        replyToUserName: request.replyToUserName,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
      
      // 添加到对应评论的回复列表中
      const comment = mockComments.find(c => c.id === request.commentId)
      if (comment) {
        comment.replies.push(newReply)
      }
      
      return newReply
    } catch (error) {
      console.error('创建回复失败:', error)
      throw new Error('创建回复失败')
    }
  }
  
  // 点赞评论
  static async likeComment(commentId: string): Promise<void> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 300))
      
      const comment = mockComments.find(c => c.id === commentId)
      if (comment) {
        if (comment.isLiked) {
          comment.likes--
          comment.isLiked = false
        } else {
          comment.likes++
          comment.isLiked = true
          if (comment.isDisliked) {
            comment.dislikes--
            comment.isDisliked = false
          }
        }
      }
    } catch (error) {
      console.error('点赞评论失败:', error)
      throw new Error('点赞评论失败')
    }
  }
  
  // 踩评论
  static async dislikeComment(commentId: string): Promise<void> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 300))
      
      const comment = mockComments.find(c => c.id === commentId)
      if (comment) {
        if (comment.isDisliked) {
          comment.dislikes--
          comment.isDisliked = false
        } else {
          comment.dislikes++
          comment.isDisliked = true
          if (comment.isLiked) {
            comment.likes--
            comment.isLiked = false
          }
        }
      }
    } catch (error) {
      console.error('踩评论失败:', error)
      throw new Error('踩评论失败')
    }
  }
  
  // 点赞回复
  static async likeReply(commentId: string, replyId: string): Promise<void> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 300))
      
      const comment = mockComments.find(c => c.id === commentId)
      if (comment) {
        const reply = comment.replies.find(r => r.id === replyId)
        if (reply) {
          if (reply.isLiked) {
            reply.likes--
            reply.isLiked = false
          } else {
            reply.likes++
            reply.isLiked = true
            if (reply.isDisliked) {
              reply.dislikes--
              reply.isDisliked = false
            }
          }
        }
      }
    } catch (error) {
      console.error('点赞回复失败:', error)
      throw new Error('点赞回复失败')
    }
  }
  
  // 踩回复
  static async dislikeReply(commentId: string, replyId: string): Promise<void> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 300))
      
      const comment = mockComments.find(c => c.id === commentId)
      if (comment) {
        const reply = comment.replies.find(r => r.id === replyId)
        if (reply) {
          if (reply.isDisliked) {
            reply.dislikes--
            reply.isDisliked = false
          } else {
            reply.dislikes++
            reply.isDisliked = true
            if (reply.isLiked) {
              reply.likes--
              reply.isLiked = false
            }
          }
        }
      }
    } catch (error) {
      console.error('踩回复失败:', error)
      throw new Error('踩回复失败')
    }
  }
  
  // 删除评论
  static async deleteComment(commentId: string): Promise<void> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 400))
      
      const index = mockComments.findIndex(c => c.id === commentId)
      if (index !== -1) {
        mockComments.splice(index, 1)
      }
    } catch (error) {
      console.error('删除评论失败:', error)
      throw new Error('删除评论失败')
    }
  }
  
  // 删除回复
  static async deleteReply(commentId: string, replyId: string): Promise<void> {
    try {
      // 模拟API延迟
      await new Promise(resolve => setTimeout(resolve, 400))
      
      const comment = mockComments.find(c => c.id === commentId)
      if (comment) {
        const index = comment.replies.findIndex(r => r.id === replyId)
        if (index !== -1) {
          comment.replies.splice(index, 1)
        }
      }
    } catch (error) {
      console.error('删除回复失败:', error)
      throw new Error('删除回复失败')
    }
  }
  
  // 格式化时间
  static formatTime(dateString: string): string {
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / (1000 * 60))
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
    
    if (diffMins < 1) {
      return '刚刚'
    } else if (diffMins < 60) {
      return `${diffMins}分钟前`
    } else if (diffHours < 24) {
      return `${diffHours}小时前`
    } else if (diffDays < 7) {
      return `${diffDays}天前`
    } else {
      return date.toLocaleDateString('zh-CN', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      })
    }
  }
}

export default CommentService