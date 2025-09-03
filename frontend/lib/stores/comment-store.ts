import { create } from 'zustand'
import { CommentService, Comment, Reply, CommentListResponse, CreateCommentRequest, CreateReplyRequest } from '../services/comment-service'

interface CommentState {
  // 状态
  comments: Comment[]
  loading: boolean
  error: string | null
  currentPage: number
  hasMore: boolean
  total: number
  sortBy: string
  
  // 创建评论状态
  creatingComment: boolean
  creatingReply: boolean
  
  // 操作状态
  likingComments: Set<string>
  likingReplies: Set<string>
  deletingComments: Set<string>
  deletingReplies: Set<string>
  
  // Actions
  loadComments: (annotationId: string, page?: number, sortBy?: string) => Promise<void>
  loadMoreComments: (annotationId: string) => Promise<void>
  createComment: (request: CreateCommentRequest) => Promise<void>
  createReply: (request: CreateReplyRequest) => Promise<void>
  likeComment: (commentId: string) => Promise<void>
  dislikeComment: (commentId: string) => Promise<void>
  likeReply: (commentId: string, replyId: string) => Promise<void>
  dislikeReply: (commentId: string, replyId: string) => Promise<void>
  deleteComment: (commentId: string) => Promise<void>
  deleteReply: (commentId: string, replyId: string) => Promise<void>
  setSortBy: (sortBy: string) => void
  clearError: () => void
  reset: () => void
}

export const useCommentStore = create<CommentState>((set, get) => ({
  // 初始状态
  comments: [],
  loading: false,
  error: null,
  currentPage: 1,
  hasMore: true,
  total: 0,
  sortBy: 'newest',
  
  creatingComment: false,
  creatingReply: false,
  
  likingComments: new Set(),
  likingReplies: new Set(),
  deletingComments: new Set(),
  deletingReplies: new Set(),
  
  // 加载评论列表
  loadComments: async (annotationId: string, page = 1, sortBy?: string) => {
    const state = get()
    const currentSortBy = sortBy || state.sortBy
    
    set({ 
      loading: true, 
      error: null,
      sortBy: currentSortBy,
      currentPage: page
    })
    
    try {
      const response: CommentListResponse = await CommentService.getComments(
        annotationId,
        page,
        10,
        currentSortBy
      )
      
      set({
        comments: page === 1 ? response.comments : [...state.comments, ...response.comments],
        hasMore: response.hasMore,
        total: response.total,
        currentPage: response.page,
        loading: false
      })
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : '加载评论失败',
        loading: false
      })
    }
  },
  
  // 加载更多评论
  loadMoreComments: async (annotationId: string) => {
    const state = get()
    if (!state.hasMore || state.loading) return
    
    await state.loadComments(annotationId, state.currentPage + 1, state.sortBy)
  },
  
  // 创建评论
  createComment: async (request: CreateCommentRequest) => {
    set({ creatingComment: true, error: null })
    
    try {
      const newComment = await CommentService.createComment(request)
      const state = get()
      
      set({
        comments: [newComment, ...state.comments],
        total: state.total + 1,
        creatingComment: false
      })
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : '创建评论失败',
        creatingComment: false
      })
    }
  },
  
  // 创建回复
  createReply: async (request: CreateReplyRequest) => {
    set({ creatingReply: true, error: null })
    
    try {
      const newReply = await CommentService.createReply(request)
      const state = get()
      
      // 更新对应评论的回复列表
      const updatedComments = state.comments.map(comment => {
        if (comment.id === request.commentId) {
          return {
            ...comment,
            replies: [...comment.replies, newReply]
          }
        }
        return comment
      })
      
      set({
        comments: updatedComments,
        creatingReply: false
      })
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : '创建回复失败',
        creatingReply: false
      })
    }
  },
  
  // 点赞评论
  likeComment: async (commentId: string) => {
    const state = get()
    if (state.likingComments.has(commentId)) return
    
    const newLikingComments = new Set(state.likingComments)
    newLikingComments.add(commentId)
    set({ likingComments: newLikingComments })
    
    try {
      await CommentService.likeComment(commentId)
      
      // 重新加载评论以获取最新状态
      const updatedComments = state.comments.map(comment => {
        if (comment.id === commentId) {
          return {
            ...comment,
            likes: comment.isLiked ? comment.likes - 1 : comment.likes + 1,
            isLiked: !comment.isLiked,
            dislikes: comment.isDisliked ? comment.dislikes - 1 : comment.dislikes,
            isDisliked: false
          }
        }
        return comment
      })
      
      const finalLikingComments = new Set(state.likingComments)
      finalLikingComments.delete(commentId)
      
      set({
        comments: updatedComments,
        likingComments: finalLikingComments
      })
    } catch (error) {
      const finalLikingComments = new Set(state.likingComments)
      finalLikingComments.delete(commentId)
      
      set({
        error: error instanceof Error ? error.message : '操作失败',
        likingComments: finalLikingComments
      })
    }
  },
  
  // 踩评论
  dislikeComment: async (commentId: string) => {
    const state = get()
    if (state.likingComments.has(commentId)) return
    
    const newLikingComments = new Set(state.likingComments)
    newLikingComments.add(commentId)
    set({ likingComments: newLikingComments })
    
    try {
      await CommentService.dislikeComment(commentId)
      
      const updatedComments = state.comments.map(comment => {
        if (comment.id === commentId) {
          return {
            ...comment,
            dislikes: comment.isDisliked ? comment.dislikes - 1 : comment.dislikes + 1,
            isDisliked: !comment.isDisliked,
            likes: comment.isLiked ? comment.likes - 1 : comment.likes,
            isLiked: false
          }
        }
        return comment
      })
      
      const finalLikingComments = new Set(state.likingComments)
      finalLikingComments.delete(commentId)
      
      set({
        comments: updatedComments,
        likingComments: finalLikingComments
      })
    } catch (error) {
      const finalLikingComments = new Set(state.likingComments)
      finalLikingComments.delete(commentId)
      
      set({
        error: error instanceof Error ? error.message : '操作失败',
        likingComments: finalLikingComments
      })
    }
  },
  
  // 点赞回复
  likeReply: async (commentId: string, replyId: string) => {
    const state = get()
    const replyKey = `${commentId}-${replyId}`
    if (state.likingReplies.has(replyKey)) return
    
    const newLikingReplies = new Set(state.likingReplies)
    newLikingReplies.add(replyKey)
    set({ likingReplies: newLikingReplies })
    
    try {
      await CommentService.likeReply(commentId, replyId)
      
      const updatedComments = state.comments.map(comment => {
        if (comment.id === commentId) {
          const updatedReplies = comment.replies.map(reply => {
            if (reply.id === replyId) {
              return {
                ...reply,
                likes: reply.isLiked ? reply.likes - 1 : reply.likes + 1,
                isLiked: !reply.isLiked,
                dislikes: reply.isDisliked ? reply.dislikes - 1 : reply.dislikes,
                isDisliked: false
              }
            }
            return reply
          })
          return { ...comment, replies: updatedReplies }
        }
        return comment
      })
      
      const finalLikingReplies = new Set(state.likingReplies)
      finalLikingReplies.delete(replyKey)
      
      set({
        comments: updatedComments,
        likingReplies: finalLikingReplies
      })
    } catch (error) {
      const finalLikingReplies = new Set(state.likingReplies)
      finalLikingReplies.delete(replyKey)
      
      set({
        error: error instanceof Error ? error.message : '操作失败',
        likingReplies: finalLikingReplies
      })
    }
  },
  
  // 踩回复
  dislikeReply: async (commentId: string, replyId: string) => {
    const state = get()
    const replyKey = `${commentId}-${replyId}`
    if (state.likingReplies.has(replyKey)) return
    
    const newLikingReplies = new Set(state.likingReplies)
    newLikingReplies.add(replyKey)
    set({ likingReplies: newLikingReplies })
    
    try {
      await CommentService.dislikeReply(commentId, replyId)
      
      const updatedComments = state.comments.map(comment => {
        if (comment.id === commentId) {
          const updatedReplies = comment.replies.map(reply => {
            if (reply.id === replyId) {
              return {
                ...reply,
                dislikes: reply.isDisliked ? reply.dislikes - 1 : reply.dislikes + 1,
                isDisliked: !reply.isDisliked,
                likes: reply.isLiked ? reply.likes - 1 : reply.likes,
                isLiked: false
              }
            }
            return reply
          })
          return { ...comment, replies: updatedReplies }
        }
        return comment
      })
      
      const finalLikingReplies = new Set(state.likingReplies)
      finalLikingReplies.delete(replyKey)
      
      set({
        comments: updatedComments,
        likingReplies: finalLikingReplies
      })
    } catch (error) {
      const finalLikingReplies = new Set(state.likingReplies)
      finalLikingReplies.delete(replyKey)
      
      set({
        error: error instanceof Error ? error.message : '操作失败',
        likingReplies: finalLikingReplies
      })
    }
  },
  
  // 删除评论
  deleteComment: async (commentId: string) => {
    const state = get()
    if (state.deletingComments.has(commentId)) return
    
    const newDeletingComments = new Set(state.deletingComments)
    newDeletingComments.add(commentId)
    set({ deletingComments: newDeletingComments })
    
    try {
      await CommentService.deleteComment(commentId)
      
      const updatedComments = state.comments.filter(comment => comment.id !== commentId)
      const finalDeletingComments = new Set(state.deletingComments)
      finalDeletingComments.delete(commentId)
      
      set({
        comments: updatedComments,
        total: state.total - 1,
        deletingComments: finalDeletingComments
      })
    } catch (error) {
      const finalDeletingComments = new Set(state.deletingComments)
      finalDeletingComments.delete(commentId)
      
      set({
        error: error instanceof Error ? error.message : '删除失败',
        deletingComments: finalDeletingComments
      })
    }
  },
  
  // 删除回复
  deleteReply: async (commentId: string, replyId: string) => {
    const state = get()
    const replyKey = `${commentId}-${replyId}`
    if (state.deletingReplies.has(replyKey)) return
    
    const newDeletingReplies = new Set(state.deletingReplies)
    newDeletingReplies.add(replyKey)
    set({ deletingReplies: newDeletingReplies })
    
    try {
      await CommentService.deleteReply(commentId, replyId)
      
      const updatedComments = state.comments.map(comment => {
        if (comment.id === commentId) {
          const updatedReplies = comment.replies.filter(reply => reply.id !== replyId)
          return { ...comment, replies: updatedReplies }
        }
        return comment
      })
      
      const finalDeletingReplies = new Set(state.deletingReplies)
      finalDeletingReplies.delete(replyKey)
      
      set({
        comments: updatedComments,
        deletingReplies: finalDeletingReplies
      })
    } catch (error) {
      const finalDeletingReplies = new Set(state.deletingReplies)
      finalDeletingReplies.delete(replyKey)
      
      set({
        error: error instanceof Error ? error.message : '删除失败',
        deletingReplies: finalDeletingReplies
      })
    }
  },
  
  // 设置排序方式
  setSortBy: (sortBy: string) => {
    set({ sortBy })
  },
  
  // 清除错误
  clearError: () => {
    set({ error: null })
  },
  
  // 重置状态
  reset: () => {
    set({
      comments: [],
      loading: false,
      error: null,
      currentPage: 1,
      hasMore: true,
      total: 0,
      sortBy: 'newest',
      creatingComment: false,
      creatingReply: false,
      likingComments: new Set(),
      likingReplies: new Set(),
      deletingComments: new Set(),
      deletingReplies: new Set()
    })
  }
}))

export default useCommentStore