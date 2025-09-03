import React, { useState, useEffect, useCallback } from 'react';
import { Avatar, Button, Empty, List, Spin, Tooltip, message } from 'antd';; // Input removed as unused
import { Heart, MessageCircle, Trash2 } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

import { getAnnotationComments, getCommentReplies, likeComment, unlikeComment, deleteComment } from '../../utils/api';
import CommentEditor from './CommentEditor';

// const { TextArea } = Input; // removed as unused

interface Comment {
  id: string;
  content: string;
  user: {
    id: string;
    username: string;
    avatar?: string;
  };
  likes_count: number;
  replies_count: number;
  is_liked: boolean;
  created_at: string;
  updated_at: string;
  parent_id?: string;
}

interface CommentListProps {
  annotationId: string;
  onCommentCreate?: () => void;
}

const CommentList: React.FC<CommentListProps> = ({ annotationId, onCommentCreate }) => {
  const [comments, setComments] = useState<Comment[]>([]);
  const [loading, setLoading] = useState(false);
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  // const [editingComment, setEditingComment] = useState<string | null>(null); // removed as unused
  const [expandedReplies, setExpandedReplies] = useState<Set<string>>(new Set());
  const [replies, setReplies] = useState<Record<string, Comment[]>>({});
  const [loadingReplies, setLoadingReplies] = useState<Set<string>>(new Set());
  
  const { user: currentUser } = useAuthStore();

  // 加载评论列表
  const loadComments = useCallback(async () => {
    try {
      setLoading(true);
      const response = await getAnnotationComments(annotationId);
      setComments(response.data.comments || []);
    } catch (error) {
      console.error('加载评论失败:', error);
      message.error('加载评论失败');
    } finally {
      setLoading(false);
    }
  }, [annotationId]);

  // 加载回复
  const loadReplies = async (commentId: string) => {
    try {
      setLoadingReplies(prev => new Set([...prev, commentId]));
      const response = await getCommentReplies(commentId);
      setReplies(prev => ({
        ...prev,
        [commentId]: response.data.replies || []
      }));
      setExpandedReplies(prev => new Set([...prev, commentId]));
    } catch (error) {
      console.error('加载回复失败:', error);
      message.error('加载回复失败');
    } finally {
      setLoadingReplies(prev => {
        const newSet = new Set(prev);
        newSet.delete(commentId);
        return newSet;
      });
    }
  };

  // 点赞/取消点赞
  const handleLike = async (commentId: string, isLiked: boolean) => {
    try {
      if (isLiked) {
        await unlikeComment(commentId);
      } else {
        await likeComment(commentId);
      }
      
      // 更新评论列表中的点赞状态
      setComments(prev => prev.map(comment => 
        comment.id === commentId 
          ? { 
              ...comment, 
              is_liked: !isLiked,
              likes_count: isLiked ? comment.likes_count - 1 : comment.likes_count + 1
            }
          : comment
      ));
      
      // 更新回复列表中的点赞状态
      setReplies(prev => {
        const newReplies = { ...prev };
        Object.keys(newReplies).forEach(parentId => {
          newReplies[parentId] = newReplies[parentId].map(reply => 
            reply.id === commentId
              ? {
                  ...reply,
                  is_liked: !isLiked,
                  likes_count: isLiked ? reply.likes_count - 1 : reply.likes_count + 1
                }
              : reply
          );
        });
        return newReplies;
      });
    } catch (error) {
      console.error('点赞操作失败:', error);
      message.error('操作失败');
    }
  };

  // 删除评论
  const handleDelete = async (commentId: string) => {
    try {
      await deleteComment(commentId);
      message.success('删除成功');
      loadComments(); // 重新加载评论列表
    } catch (error) {
      console.error('删除评论失败:', error);
      message.error('删除失败');
    }
  };

  // 评论创建成功回调
  const handleCommentSuccess = () => {
    setReplyingTo(null);
    // setEditingComment(null); // removed as unused
    loadComments();
    onCommentCreate?.();
  };

  // 回复创建成功回调
  const handleReplySuccess = (parentId: string) => {
    setReplyingTo(null);
    // 重新加载该评论的回复
    if (expandedReplies.has(parentId)) {
      loadReplies(parentId);
    }
  };

  // 切换回复展开状态
  const toggleReplies = (commentId: string) => {
    if (expandedReplies.has(commentId)) {
      setExpandedReplies(prev => {
        const newSet = new Set(prev);
        newSet.delete(commentId);
        return newSet;
      });
    } else {
      loadReplies(commentId);
    }
  };

  useEffect(() => {
    loadComments();
  }, [loadComments]);

  const renderCommentActions = (comment: Comment) => [
    <Button
      key="like"
      type="text"
      size="small"
      icon={comment.is_liked ? <Heart style={{ color: '#ff4d4f' }} fill="#ff4d4f" size={16} /> : <Heart size={16} />}
      onClick={() => handleLike(comment.id, comment.is_liked)}
    >
      {comment.likes_count || 0}
    </Button>,
    <Button
      key="reply"
      type="text"
      size="small"
      icon={<MessageCircle size={16} />}
      onClick={() => setReplyingTo(replyingTo === comment.id ? null : comment.id)}
    >
      回复
    </Button>,
    comment.replies_count > 0 && (
      <Button
        key="replies"
        type="text"
        size="small"
        onClick={() => toggleReplies(comment.id)}
        loading={loadingReplies.has(comment.id)}
      >
        {expandedReplies.has(comment.id) ? '收起' : `查看回复 (${comment.replies_count})`}
      </Button>
    ),
    currentUser?.id === comment.user.id && (
      <Tooltip key="delete" title="删除评论">
        <Button
          type="text"
          size="small"
          danger
          icon={<Trash2 size={16} />}
          onClick={() => handleDelete(comment.id)}
        />
      </Tooltip>
    )
  ].filter(Boolean);

  const renderComment = (comment: Comment, isReply = false) => (
    <div key={comment.id} style={{ marginLeft: isReply ? 40 : 0 }}>
      <List.Item
        actions={renderCommentActions(comment)}
      >
        <List.Item.Meta
          avatar={
            <Avatar 
              src={comment.user.avatar} 
              size={isReply ? 'small' : 'default'}
            >
              {comment.user.username.charAt(0).toUpperCase()}
            </Avatar>
          }
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>{comment.user.username}</span>
              <span style={{ fontSize: '12px', color: '#999' }}>
                {new Date(comment.created_at).toLocaleString()}
              </span>
            </div>
          }
          description={
            <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {comment.content}
            </div>
          }
        />
      </List.Item>
      
      {/* 回复编辑器 */}
      {replyingTo === comment.id && (
        <div style={{ marginLeft: isReply ? 0 : 40, marginTop: 8, marginBottom: 16 }}>
          <CommentEditor
            annotationId={annotationId}
            parentId={comment.id}
            placeholder={`回复 @${comment.user.username}`}
            onSuccess={() => handleReplySuccess(comment.id)}
            onCancel={() => setReplyingTo(null)}
          />
        </div>
      )}
      
      {/* 回复列表 */}
      {expandedReplies.has(comment.id) && replies[comment.id] && (
        <div style={{ marginLeft: isReply ? 0 : 40, marginTop: 8 }}>
          {replies[comment.id].map(reply => (
            <div key={reply.id}>
              {renderComment(reply, true)}
            </div>
          ))}
        </div>
      )}
    </div>
  );

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '20px' }}>
        <Spin size="large" />
      </div>
    );
  }

  return (
    <div>
      {/* 主评论编辑器 */}
      <div style={{ marginBottom: 16 }}>
        <CommentEditor
          annotationId={annotationId}
          placeholder="写下你的搞笑评论..."
          onSuccess={handleCommentSuccess}
        />
      </div>
      
      {/* 评论列表 */}
      {comments.length === 0 ? (
        <Empty 
          description="还没有评论，快来抢沙发吧！" 
          style={{ padding: '40px 0' }}
        />
      ) : (
        <List
          itemLayout="vertical"
          dataSource={comments}
          renderItem={comment => renderComment(comment)}
        />
      )}
    </div>
  );
};

export default CommentList;