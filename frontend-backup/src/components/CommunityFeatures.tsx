// import { Comment } from 'antd'; // Comment组件在新版本antd中已移除
import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Users,
  MessageCircle,
  Heart,
  Share2,

  Reply,
  Flag,
  MoreVertical,
  Send,
  Image,
  Smile,

  TrendingUp,

  Zap,
  Eye,
  Bookmark,

  Search,

  UserPlus,


  X,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
// import { LazyImage } from './LazyLoad';
// import { MicroInteraction, LoadingButton, showToast } from './InteractionFeedback';
// import { useMobile } from './MobileOptimization';
// import { useNetworkStatus } from './NetworkStatus';
// import EmptyState, { LoadingState } from './EmptyState';
// import { useFormValidation, InputField, TextAreaField } from './FormValidation';

interface User {
  id: string;
  name: string;
  username: string;
  avatar: string;
  level: number;
  badges: string[];
  isFollowing?: boolean;
  isVerified?: boolean;
  joinDate: Date;
  stats: {
    followers: number;
    following: number;
    posts: number;
    likes: number;
  };
}

interface Comment {
  id: string;
  content: string;
  author: User;
  timestamp: Date;
  likes: number;
  dislikes: number;
  isLiked: boolean;
  isDisliked: boolean;
  replies: Comment[];
  parentId?: string;
  mentions: string[];
  hashtags: string[];
  images?: string[];
}

interface Post {
  id: string;
  title: string;
  content: string;
  author: User;
  timestamp: Date;
  likes: number;
  comments: number;
  shares: number;
  views: number;
  isLiked: boolean;
  isBookmarked: boolean;
  category: string;
  tags: string[];
  images?: string[];
  location?: {
    name: string;
    coordinates: [number, number];
  };
}

interface CommunityFeaturesProps {
  postId?: string;
  showComments?: boolean;
  showSocialFeed?: boolean;
  className?: string;
}

const CommunityFeatures: React.FC<CommunityFeaturesProps> = ({
  // postId,
  showComments = true,
  showSocialFeed = true,
  className = ''
}) => {
  const [posts, setPosts] = useState<Post[]>([]);
  const [comments, setComments] = useState<Comment[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'feed' | 'trending' | 'following'>('feed');
  const [sortBy, setSortBy] = useState<'latest' | 'popular' | 'trending'>('latest');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [newComment, setNewComment] = useState('');
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [expandedComments, setExpandedComments] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  
  const commentInputRef = useRef<HTMLTextAreaElement>(null);
  // const { isMobile } = useMobile();
  // const { isOnline } = useNetworkStatus();
  // const isMobile = false;
  const isOnline = true;
  
  // const { values, errors, handleChange, handleSubmit, isSubmitting } = useFormValidation({
  //   initialValues: { comment: '' },
  //   validationRules: {
  //     comment: { required: true, minLength: 1, maxLength: 500 }
  //   },
  //   onSubmit: async (values) => {
  //     await handleAddComment(values.comment);
  //   }
  // });

  // 模拟数据
  const mockUsers: User[] = useMemo(() => [
    {
      id: '1',
      name: '咖啡爱好者',
      username: 'coffee_lover',
      avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=coffee%20enthusiast%20avatar%20friendly&image_size=square',
      level: 15,
      badges: ['☕', '🏆'],
      isVerified: true,
      joinDate: new Date('2023-01-15'),
      stats: { followers: 1250, following: 340, posts: 89, likes: 2340 }
    },
    {
      id: '2',
      name: '花香追寻者',
      username: 'flower_seeker',
      avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=nature%20lover%20avatar%20with%20flowers&image_size=square',
      level: 12,
      badges: ['🌸', '🌿'],
      joinDate: new Date('2023-03-20'),
      stats: { followers: 890, following: 210, posts: 67, likes: 1890 }
    }
  ], []);

  const mockPosts: Post[] = useMemo(() => [
    {
      id: '1',
      title: '今天在星巴克发现了新的咖啡香味',
      content: '这家新开的星巴克有着独特的烘焙香味，混合了焦糖和坚果的味道，非常值得一试！位置就在市中心，推荐大家去体验一下。',
      author: mockUsers[0],
      timestamp: new Date(Date.now() - 3600000),
      likes: 45,
      comments: 12,
      shares: 8,
      views: 234,
      isLiked: false,
      isBookmarked: true,
      category: 'coffee',
      tags: ['星巴克', '咖啡', '香味'],
      images: ['https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=cozy%20starbucks%20coffee%20shop%20interior&image_size=landscape_4_3'],
      location: {
        name: '星巴克市中心店',
        coordinates: [116.4074, 39.9042]
      }
    },
    {
      id: '2',
      title: '春天的樱花香气记录',
      content: '今年的樱花开得特别好，走在樱花大道上能闻到淡淡的花香，清新怡人。配合着春风，这种感觉真的太美好了。',
      author: mockUsers[1],
      timestamp: new Date(Date.now() - 7200000),
      likes: 78,
      comments: 23,
      shares: 15,
      views: 456,
      isLiked: true,
      isBookmarked: false,
      category: 'flower',
      tags: ['樱花', '春天', '花香'],
      images: ['https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=beautiful%20cherry%20blossoms%20spring%20scene&image_size=landscape_4_3']
    }
  ], [mockUsers]);

  const mockComments: Comment[] = useMemo(() => [
    {
      id: '1',
      content: '我也去过这家店！确实香味很特别，特别是他们的招牌拿铁 ☕',
      author: mockUsers[1],
      timestamp: new Date(Date.now() - 1800000),
      likes: 8,
      dislikes: 0,
      isLiked: false,
      isDisliked: false,
      replies: [
        {
          id: '1-1',
          content: '是的！他们的拿铁真的很香，奶泡也很细腻 @flower_seeker',
          author: mockUsers[0],
          timestamp: new Date(Date.now() - 1200000),
          likes: 3,
          dislikes: 0,
          isLiked: true,
          isDisliked: false,
          replies: [],
          parentId: '1',
          mentions: ['flower_seeker'],
          hashtags: []
        }
      ],
      mentions: [],
      hashtags: []
    },
    {
      id: '2',
      content: '这个位置我知道！就在地铁站附近，交通很方便 #星巴克 #咖啡',
      author: {
        id: '3',
        name: '城市探索者',
        username: 'city_explorer',
        avatar: 'https://trae-api-us.mchost.guru/api/ide/v1/text_to_image?prompt=urban%20explorer%20avatar%20modern&image_size=square',
        level: 8,
        badges: ['🗺️'],
        joinDate: new Date('2023-05-10'),
        stats: { followers: 450, following: 120, posts: 34, likes: 890 }
      },
      timestamp: new Date(Date.now() - 3600000),
      likes: 5,
      dislikes: 0,
      isLiked: false,
      isDisliked: false,
      replies: [],
      mentions: [],
      hashtags: ['星巴克', '咖啡']
    }
  ], [mockUsers]);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setPosts(mockPosts);
      setComments(mockComments);
    } catch (error) {
      console.error('加载数据失败', error);
    } finally {
      setIsLoading(false);
    }
  }, [mockPosts, mockComments]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleLikePost = async (postId: string) => {
    setPosts(prev => prev.map(post => {
      if (post.id === postId) {
        return {
          ...post,
          isLiked: !post.isLiked,
          likes: post.isLiked ? post.likes - 1 : post.likes + 1
        };
      }
      return post;
    }));
  };

  const handleBookmarkPost = async (postId: string) => {
    setPosts(prev => prev.map(post => {
      if (post.id === postId) {
        return { ...post, isBookmarked: !post.isBookmarked };
      }
      return post;
    }));
    console.log('已更新收藏状态');
  };

  const handleSharePost = async (post: Post) => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: post.title,
          text: post.content,
          url: window.location.href
        });
      } catch {
        console.log('分享取消');
      }
    } else {
      await navigator.clipboard.writeText(window.location.href);
      console.log('链接已复制到剪贴板');
    }
  };

  const handleFollowUser = async (/* userId: string */) => {
    console.log('关注功能开发中');
  };

  const handleLikeComment = async (commentId: string) => {
    const updateCommentLikes = (comments: Comment[]): Comment[] => {
      return comments.map(comment => {
        if (comment.id === commentId) {
          return {
            ...comment,
            isLiked: !comment.isLiked,
            likes: comment.isLiked ? comment.likes - 1 : comment.likes + 1,
            isDisliked: false
          };
        }
        if (comment.replies.length > 0) {
          return { ...comment, replies: updateCommentLikes(comment.replies) };
        }
        return comment;
      });
    };

    setComments(prev => updateCommentLikes(prev));
  };

  const handleAddComment = async (content: string) => {
    if (!content.trim()) return;

    const newCommentObj: Comment = {
      id: Date.now().toString(),
      content: content.trim(),
      author: mockUsers[0], // 当前用户
      timestamp: new Date(),
      likes: 0,
      dislikes: 0,
      isLiked: false,
      isDisliked: false,
      replies: [],
      parentId: replyingTo || undefined,
      mentions: content.match(/@\w+/g) || [],
      hashtags: content.match(/#\w+/g) || []
    };

    if (replyingTo) {
      // 添加回复
      const updateReplies = (comments: Comment[]): Comment[] => {
        return comments.map(comment => {
          if (comment.id === replyingTo) {
            return { ...comment, replies: [...comment.replies, newCommentObj] };
          }
          if (comment.replies.length > 0) {
            return { ...comment, replies: updateReplies(comment.replies) };
          }
          return comment;
        });
      };
      setComments(prev => updateReplies(prev));
      setReplyingTo(null);
    } else {
      // 添加新评论
      setComments(prev => [newCommentObj, ...prev]);
    }

    setNewComment('');
    console.log('评论发布成功');
  };

  const handleReply = (commentId: string) => {
    setReplyingTo(commentId);
    commentInputRef.current?.focus();
  };

  const toggleCommentExpansion = (commentId: string) => {
    setExpandedComments(prev => {
      const newSet = new Set(prev);
      if (newSet.has(commentId)) {
        newSet.delete(commentId);
      } else {
        newSet.add(commentId);
      }
      return newSet;
    });
  };

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) return '刚刚';
    if (hours < 24) return `${hours}小时前`;
    return `${Math.floor(hours / 24)}天前`;
  };

  const renderComment = (comment: Comment, depth = 0) => (
    <motion.div
      key={comment.id}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`${depth > 0 ? 'ml-8 border-l-2 border-gray-100 pl-4' : ''}`}
    >
      <div className="flex gap-3 p-4 hover:bg-gray-50 transition-colors">
        <img
          src={comment.author.avatar}
          alt={comment.author.name}
          className="w-8 h-8 rounded-full flex-shrink-0"
        />
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-medium text-gray-800">{comment.author.name}</span>
            <span className="text-gray-500 text-sm">@{comment.author.username}</span>
            {comment.author.isVerified && (
              <div className="w-4 h-4 bg-blue-500 rounded-full flex items-center justify-center">
                <span className="text-white text-xs">✓</span>
              </div>
            )}
            <span className="text-gray-400 text-xs">{formatTimeAgo(comment.timestamp)}</span>
          </div>
          
          <div className="text-gray-700 text-sm mb-2">
            {comment.content.split(' ').map((word, index) => {
              if (word.startsWith('@')) {
                return (
                  <span key={`item-${index}`} className="text-blue-600 hover:underline cursor-pointer">
                    {word}{' '}
                  </span>
                );
              }
              if (word.startsWith('#')) {
                return (
                  <span key={`item-${index}`} className="text-blue-600 hover:underline cursor-pointer">
                    {word}{' '}
                  </span>
                );
              }
              return word + ' ';
            })}
          </div>
          
          {comment.images && comment.images.length > 0 && (
            <div className="flex gap-2 mb-2">
              {comment.images.map((image, index) => (
                <img
                  key={`item-${index}`}
                  src={image}
                  alt={`评论图片 ${index + 1}`}
                  className="w-16 h-16 rounded-lg object-cover"
                />
              ))}
            </div>
          )}
          
          <div className="flex items-center gap-4 text-gray-500">
            <button
              onClick={() => handleLikeComment(comment.id)}
              className={`flex items-center gap-1 text-xs hover:text-red-500 transition-colors ${
                comment.isLiked ? 'text-red-500' : ''
              }`}
            >
              <Heart className={`w-3 h-3 ${comment.isLiked ? 'fill-current' : ''}`} />
              <span>{comment.likes}</span>
            </button>
            
            <button
              onClick={() => handleReply(comment.id)}
              className="flex items-center gap-1 text-xs hover:text-blue-500 transition-colors"
            >
              <Reply className="w-3 h-3" />
              <span>回复</span>
            </button>
            
            <button className="flex items-center gap-1 text-xs hover:text-gray-700 transition-colors">
              <Flag className="w-3 h-3" />
              <span>举报</span>
            </button>
          </div>
          
          {comment.replies.length > 0 && (
            <div className="mt-3">
              <button
                onClick={() => toggleCommentExpansion(comment.id)}
                className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700 transition-colors mb-2"
              >
                {expandedComments.has(comment.id) ? (
                  <ChevronUp className="w-3 h-3" />
                ) : (
                  <ChevronDown className="w-3 h-3" />
                )}
                <span>
                  {expandedComments.has(comment.id) ? '收起' : '展开'} {comment.replies.length} 条回复
                </span>
              </button>
              
              <AnimatePresence>
                {expandedComments.has(comment.id) && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="space-y-2"
                  >
                    {comment.replies.map(reply => (
                      <div key={reply.id}>
                        {renderComment(reply, depth + 1)}
                      </div>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );

  const renderPost = (post: Post) => (
    <motion.div
      key={post.id}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden"
    >
      {/* 帖子头部 */}
      <div className="p-4 border-b border-gray-100">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <img
              src={post.author.avatar}
              alt={post.author.name}
              className="w-10 h-10 rounded-full"
            />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-medium text-gray-800">{post.author.name}</span>
                {post.author.isVerified && (
                  <div className="w-4 h-4 bg-blue-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs">✓</span>
                  </div>
                )}
                <div className="flex items-center gap-1">
                  {post.author.badges.map((badge, index) => (
                    <span key={`item-${index}`} className="text-sm">{badge}</span>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <span>@{post.author.username}</span>
                <span>•</span>
                <span>{formatTimeAgo(post.timestamp)}</span>
                {post.location && (
                  <>
                    <span>•</span>
                    <span className="flex items-center gap-1">
                      📍 {post.location.name}
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleFollowUser()}
              className="px-3 py-1 text-sm bg-blue-600 text-white rounded-full hover:bg-blue-700 transition-colors"
            >
              <UserPlus className="w-3 h-3 inline mr-1" />
              关注
            </button>
            
            <button className="p-1 text-gray-500 hover:text-gray-700 transition-colors">
              <MoreVertical className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
      
      {/* 帖子内容 */}
      <div className="p-4">
        <h3 className="text-lg font-semibold text-gray-800 mb-2">{post.title}</h3>
        <p className="text-gray-700 mb-3">{post.content}</p>
        
        {/* 标签 */}
        {post.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-3">
            {post.tags.map((tag, index) => (
              <span
                key={`item-${index}`}
                className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded-full hover:bg-blue-200 cursor-pointer transition-colors"
              >
                #{tag}
              </span>
            ))}
          </div>
        )}
        
        {/* 图片 */}
        {post.images && post.images.length > 0 && (
          <div className="grid grid-cols-2 gap-2 mb-3">
            {post.images.map((image, index) => (
              <img
                key={`item-${index}`}
                src={image}
                alt={`帖子图片 ${index + 1}`}
                className="w-full h-40 rounded-lg object-cover"
              />
            ))}
          </div>
        )}
      </div>
      
      {/* 帖子统计 */}
      <div className="px-4 py-2 border-t border-gray-100 bg-gray-50">
        <div className="flex items-center justify-between text-sm text-gray-600">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <Eye className="w-4 h-4" />
              {post.views}
            </span>
            <span className="flex items-center gap-1">
              <Heart className="w-4 h-4" />
              {post.likes}
            </span>
            <span className="flex items-center gap-1">
              <MessageCircle className="w-4 h-4" />
              {post.comments}
            </span>
            <span className="flex items-center gap-1">
              <Share2 className="w-4 h-4" />
              {post.shares}
            </span>
          </div>
        </div>
      </div>
      
      {/* 操作按钮 */}
      <div className="px-4 py-3 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1">
            <button
              onClick={() => handleLikePost(post.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors ${
                post.isLiked 
                  ? 'bg-red-100 text-red-600' 
                  : 'hover:bg-gray-100 text-gray-600'
              }`}
            >
              <Heart className={`w-4 h-4 ${post.isLiked ? 'fill-current' : ''}`} />
              <span className="text-sm">赞</span>
            </button>
            
            <button className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-100 text-gray-600 transition-colors">
              <MessageCircle className="w-4 h-4" />
              <span className="text-sm">评论</span>
            </button>
            
            <button
              onClick={() => handleSharePost(post)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-100 text-gray-600 transition-colors"
            >
              <Share2 className="w-4 h-4" />
              <span className="text-sm">分享</span>
            </button>
          </div>
          
          <button
            onClick={() => handleBookmarkPost(post.id)}
            className={`p-2 rounded-lg transition-colors ${
              post.isBookmarked 
                ? 'bg-yellow-100 text-yellow-600' 
                : 'hover:bg-gray-100 text-gray-600'
            }`}
          >
            <Bookmark className={`w-4 h-4 ${post.isBookmarked ? 'fill-current' : ''}`} />
          </button>
        </div>
      </div>
    </motion.div>
  );

  if (isLoading) {
    return (
      <div className={`w-full ${className}`}>
        <div className="flex items-center justify-center p-8">
          <div className="text-gray-500">加载社区内容中...</div>
        </div>
      </div>
    );
  }

  return (
    <div className={`w-full space-y-6 ${className}`}>
      {showSocialFeed && (
        <div className="space-y-6">
          {/* 社区导航 */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <h2 className="text-xl font-bold text-gray-800">社区动态</h2>
                <div className="flex items-center gap-2">
                  {[
                    { key: 'feed', label: '推荐', icon: TrendingUp },
                    { key: 'trending', label: '热门', icon: Zap },
                    { key: 'following', label: '关注', icon: Users }
                  ].map((tab) => (
                    <button
                      key={tab.key}
                      onClick={() => setActiveTab(tab.key as 'feed' | 'trending' | 'following')}
                      className={`flex items-center gap-1 px-3 py-1 rounded-full text-sm transition-colors ${
                        activeTab === tab.key
                          ? 'bg-blue-100 text-blue-600'
                          : 'text-gray-600 hover:bg-gray-100'
                      }`}
                    >
                      <tab.icon className="w-3 h-3" />
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>
              
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="搜索帖子..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as 'latest' | 'popular' | 'trending')}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="latest">最新</option>
                  <option value="popular">最热</option>
                  <option value="trending">趋势</option>
                </select>
                
                <select
                  value={filterCategory}
                  onChange={(e) => setFilterCategory(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">全部分类</option>
                  <option value="coffee">咖啡</option>
                  <option value="flower">花香</option>
                  <option value="food">美食</option>
                  <option value="nature">自然</option>
                </select>
              </div>
            </div>
          </div>
          
          {/* 帖子列表 */}
          <div className="space-y-4">
            {posts.length > 0 ? (
              posts.map(post => (
                <div key={post.id}>
                  {renderPost(post)}
                </div>
              ))
            ) : (
              <div className="text-center p-8">
                <div className="text-gray-500 text-lg font-medium">暂无帖子</div>
                <div className="text-gray-400 text-sm mt-2">成为第一个分享气味体验的人吧！</div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {showComments && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          {/* 评论头部 */}
          <div className="p-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-800">
                评论 ({comments.length})
              </h3>
              <select className="text-sm border border-gray-300 rounded-md px-2 py-1">
                <option value="latest">最新</option>
                <option value="popular">最热</option>
                <option value="oldest">最早</option>
              </select>
            </div>
          </div>
          
          {/* 评论输入框 */}
          <div className="p-4 border-b border-gray-200">
            <div className="flex gap-3">
              <img
                src={mockUsers[0].avatar}
                alt="当前用户"
                className="w-8 h-8 rounded-full flex-shrink-0"
              />
              <div className="flex-1">
                {replyingTo && (
                  <div className="mb-2 p-2 bg-blue-50 rounded-lg text-sm text-blue-700">
                    <span>回复评论</span>
                    <button
                      onClick={() => setReplyingTo(null)}
                      className="ml-2 text-blue-500 hover:text-blue-700"
                    >
                      <X className="w-3 h-3 inline" />
                    </button>
                  </div>
                )}
                
                <div className="relative">
                  <textarea
                    ref={commentInputRef}
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    placeholder={replyingTo ? '写下你的回复...' : '写下你的评论...'}
                    className="w-full p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    rows={3}
                    maxLength={500}
                  />
                  
                  <div className="absolute bottom-3 right-3 flex items-center gap-2">
                    <button
                      onClick={() => setShowEmojiPicker(!showEmojiPicker)}
                      className="p-1 text-gray-500 hover:text-gray-700 transition-colors"
                    >
                      <Smile className="w-4 h-4" />
                    </button>
                    
                    <button className="p-1 text-gray-500 hover:text-gray-700 transition-colors">
                      <Image className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                <div className="flex items-center justify-between mt-2">
                  <div className="text-xs text-gray-500">
                    {newComment.length}/500 字符
                  </div>
                  
                  <button
                    onClick={() => handleAddComment(newComment)}
                    disabled={!newComment.trim()}
                    className="flex items-center gap-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <Send className="w-3 h-3" />
                    {replyingTo ? '回复' : '发布'}
                  </button>
                </div>
              </div>
            </div>
          </div>
          
          {/* 评论列表 */}
          <div className="divide-y divide-gray-100">
            {comments.length > 0 ? (
              comments.map(comment => (
                <div key={comment.id}>
                  {renderComment(comment)}
                </div>
              ))
            ) : (
              <div className="p-8">
                <div className="text-center">
                  <div className="text-gray-500 text-lg font-medium">暂无评论</div>
                  <div className="text-gray-400 text-sm mt-2">成为第一个评论的人吧！</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {/* 网络状态提示 */}
      {!isOnline && (
        <div className="fixed bottom-4 left-4 right-4 bg-yellow-100 border border-yellow-300 rounded-lg p-3 z-40">
          <p className="text-yellow-800 text-sm text-center">
            网络连接断开，部分功能可能受限
          </p>
        </div>
      )}
    </div>
  );
};

export default CommunityFeatures;