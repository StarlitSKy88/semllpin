// import { Form } from 'antd';
import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  HelpCircle,
  Search,
  Book,
  MessageCircle,
  Mail,
  Phone,
  FileText,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Star,
  ThumbsUp,
  ThumbsDown,
  Send,
  Clock,
  AlertCircle,
  Info,
  Users,
  Globe,
  Shield,
  Zap,
  User,
  FileQuestion,
  Wrench,
  Bug,
  Sparkles
} from 'lucide-react';

import { MicroInteraction, LoadingButton } from './InteractionFeedback';
import { toast } from 'sonner';
// import { useMobile } from './MobileOptimization';
import { useNetworkStatus } from '../hooks/useNetworkStatus';
import EmptyState, { LoadingState } from './EmptyState';
import { useFormValidation } from '../hooks/useFormValidation';
import { InputField, TextAreaField } from './FormValidation';

interface FAQItem {
  id: string;
  question: string;
  answer: string;
  category: string;
  helpful: number;
  notHelpful: number;
  tags: string[];
  lastUpdated: string;
}

interface GuideSection {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<any>;
  articles: GuideArticle[];
}

interface GuideArticle {
  id: string;
  title: string;
  description: string;
  readTime: number;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  views: number;
  rating: number;
  lastUpdated: string;
}

interface SupportTicket {
  id: string;
  subject: string;
  status: 'open' | 'pending' | 'resolved' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  category: string;
  createdAt: string;
  lastReply: string;
}

interface HelpSupportProps {
  className?: string;
}

const HelpSupport: React.FC<HelpSupportProps> = ({ className = '' }) => {
  const [activeTab, setActiveTab] = useState<'faq' | 'guides' | 'contact' | 'tickets'>('faq');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedFAQ, setExpandedFAQ] = useState<Set<string>>(new Set());
  const [isLoading, setIsLoading] = useState(true);
  const [faqs, setFaqs] = useState<FAQItem[]>([]);
  const [guides, setGuides] = useState<GuideSection[]>([]);
  const [tickets, setTickets] = useState<SupportTicket[]>([]);
  const [contactForm, setContactForm] = useState({
    name: '',
    email: '',
    subject: '',
    category: 'general',
    priority: 'medium',
    message: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  // const { isMobile } = useMobile();
  const { isOnline } = useNetworkStatus();
  const validationRules = {
    name: [{ required: true, message: '姓名不能为空' }, { minLength: 2, message: '姓名至少2个字符' }],
    email: [{ required: true, message: '邮箱不能为空' }, { pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, message: '邮箱格式不正确' }],
    subject: [{ required: true, message: '主题不能为空' }, { minLength: 5, message: '主题至少5个字符' }],
    message: [{ required: true, message: '消息不能为空' }, { minLength: 10, message: '消息至少10个字符' }]
  };
  const { errors, validateForm } = useFormValidation(validationRules);

  // FAQ 数据
  const faqData: FAQItem[] = useMemo(() => [
    {
      id: '1',
      question: '如何创建我的第一个气味标注？',
      answer: '创建气味标注很简单！首先确保您已登录账户，然后在地图上点击您想要标注的位置。选择气味类型、强度等级，添加描述和照片（可选），最后点击"发布标注"即可。',
      category: 'getting-started',
      helpful: 45,
      notHelpful: 2,
      tags: ['标注', '新手', '地图'],
      lastUpdated: '2024-01-15'
    },
    {
      id: '2',
      question: '为什么我的标注没有显示在地图上？',
      answer: '标注可能需要几分钟时间才能显示。请检查：1) 网络连接是否正常；2) 是否已完成所有必填字段；3) 标注是否违反了社区准则。如果问题持续存在，请联系客服。',
      category: 'troubleshooting',
      helpful: 32,
      notHelpful: 5,
      tags: ['标注', '地图', '故障排除'],
      lastUpdated: '2024-01-14'
    },
    {
      id: '3',
      question: '如何提升我的用户等级？',
      answer: '用户等级通过积分系统提升。您可以通过以下方式获得积分：创建高质量标注（+10分）、获得点赞（+2分）、评论互动（+1分）、连续签到（+5分）、完成每日任务（+15分）。',
      category: 'account',
      helpful: 67,
      notHelpful: 1,
      tags: ['等级', '积分', '成就'],
      lastUpdated: '2024-01-13'
    },
    {
      id: '4',
      question: '如何设置隐私保护？',
      answer: '在设置页面中，您可以控制：1) 谁可以查看您的资料；2) 是否显示位置信息；3) 是否接收通知；4) 数据共享偏好。我们建议定期检查隐私设置以确保符合您的需求。',
      category: 'privacy',
      helpful: 28,
      notHelpful: 3,
      tags: ['隐私', '安全', '设置'],
      lastUpdated: '2024-01-12'
    },
    {
      id: '5',
      question: '应用支持哪些设备和浏览器？',
      answer: 'SmellPin 支持现代浏览器（Chrome 90+、Firefox 88+、Safari 14+、Edge 90+）和移动设备（iOS 13+、Android 8+）。建议使用最新版本以获得最佳体验。',
      category: 'technical',
      helpful: 19,
      notHelpful: 0,
      tags: ['兼容性', '浏览器', '移动端'],
      lastUpdated: '2024-01-11'
    }
  ], []);

  // 指南数据
  const guideData: GuideSection[] = useMemo(() => [
    {
      id: 'getting-started',
      title: '快速入门',
      description: '了解 SmellPin 的基本功能和使用方法',
      icon: Sparkles,
      articles: [
        {
          id: 'welcome',
          title: '欢迎使用 SmellPin',
          description: '了解 SmellPin 的核心概念和主要功能',
          readTime: 3,
          difficulty: 'beginner',
          views: 1250,
          rating: 4.8,
          lastUpdated: '2024-01-15'
        },
        {
          id: 'first-annotation',
          title: '创建您的第一个标注',
          description: '逐步指导如何创建高质量的气味标注',
          readTime: 5,
          difficulty: 'beginner',
          views: 980,
          rating: 4.9,
          lastUpdated: '2024-01-14'
        },
        {
          id: 'explore-map',
          title: '探索气味地图',
          description: '学习如何有效浏览和搜索气味标注',
          readTime: 4,
          difficulty: 'beginner',
          views: 756,
          rating: 4.7,
          lastUpdated: '2024-01-13'
        }
      ]
    },
    {
      id: 'advanced-features',
      title: '高级功能',
      description: '掌握 SmellPin 的进阶功能和技巧',
      icon: Zap,
      articles: [
        {
          id: 'data-analysis',
          title: '数据分析和可视化',
          description: '使用内置工具分析气味数据趋势',
          readTime: 8,
          difficulty: 'advanced',
          views: 432,
          rating: 4.6,
          lastUpdated: '2024-01-12'
        },
        {
          id: 'api-integration',
          title: 'API 集成指南',
          description: '将 SmellPin 数据集成到您的应用中',
          readTime: 12,
          difficulty: 'advanced',
          views: 298,
          rating: 4.5,
          lastUpdated: '2024-01-11'
        }
      ]
    },
    {
      id: 'community',
      title: '社区互动',
      description: '参与社区讨论和协作',
      icon: Users,
      articles: [
        {
          id: 'community-guidelines',
          title: '社区准则',
          description: '了解社区规则和最佳实践',
          readTime: 6,
          difficulty: 'beginner',
          views: 654,
          rating: 4.8,
          lastUpdated: '2024-01-10'
        },
        {
          id: 'collaboration',
          title: '协作和分享',
          description: '与其他用户协作创建更好的内容',
          readTime: 7,
          difficulty: 'intermediate',
          views: 387,
          rating: 4.7,
          lastUpdated: '2024-01-09'
        }
      ]
    }
  ], []);

  // 工单数据
  const ticketData: SupportTicket[] = useMemo(() => [
    {
      id: 'T001',
      subject: '标注无法保存',
      status: 'open',
      priority: 'high',
      category: 'technical',
      createdAt: '2024-01-15T10:30:00Z',
      lastReply: '2024-01-15T14:20:00Z'
    },
    {
      id: 'T002',
      subject: '账户升级问题',
      status: 'resolved',
      priority: 'medium',
      category: 'account',
      createdAt: '2024-01-14T09:15:00Z',
      lastReply: '2024-01-14T16:45:00Z'
    }
  ], []);

  const categories = [
    { id: 'all', label: '全部', icon: Globe },
    { id: 'getting-started', label: '快速入门', icon: Sparkles },
    { id: 'account', label: '账户管理', icon: User },
    { id: 'privacy', label: '隐私安全', icon: Shield },
    { id: 'technical', label: '技术问题', icon: Wrench },
    { id: 'troubleshooting', label: '故障排除', icon: Bug }
  ];

  const contactCategories = [
    { id: 'general', label: '一般咨询' },
    { id: 'technical', label: '技术支持' },
    { id: 'account', label: '账户问题' },
    { id: 'billing', label: '计费问题' },
    { id: 'feature', label: '功能建议' },
    { id: 'bug', label: '错误报告' }
  ];

  const priorities = [
    { id: 'low', label: '低', color: 'text-green-600' },
    { id: 'medium', label: '中', color: 'text-yellow-600' },
    { id: 'high', label: '高', color: 'text-orange-600' },
    { id: 'urgent', label: '紧急', color: 'text-red-600' }
  ];

  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);
      try {
        await new Promise(resolve => setTimeout(resolve, 1000));
        setFaqs(faqData);
        setGuides(guideData);
        setTickets(ticketData);
      } catch (_error) {
        toast.error('加载数据失败');
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
  }, [faqData, guideData, ticketData]);

  const toggleFAQ = (id: string) => {
    setExpandedFAQ(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const handleFAQFeedback = (id: string, helpful: boolean) => {
    setFaqs(prev => prev.map(faq => {
      if (faq.id === id) {
        return {
          ...faq,
          helpful: helpful ? faq.helpful + 1 : faq.helpful,
          notHelpful: !helpful ? faq.notHelpful + 1 : faq.notHelpful
        };
      }
      return faq;
    }));
    
    toast.success(helpful ? '感谢您的反馈！' : '我们会改进这个答案');
  };

  const handleContactSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    

    
    if (!validateForm(contactForm).isValid) {
      toast.error('请填写所有必填字段');
      return;
    }
    
    setIsSubmitting(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const newTicket: SupportTicket = {
        id: `T${String(tickets.length + 1).padStart(3, '0')}`,
        subject: contactForm.subject,
        status: 'open',
        priority: contactForm.priority as 'low' | 'medium' | 'high',
        category: contactForm.category,
        createdAt: new Date().toISOString(),
        lastReply: new Date().toISOString()
      };
      
      setTickets(prev => [newTicket, ...prev]);
      setContactForm({
        name: '',
        email: '',
        subject: '',
        category: 'general',
        priority: 'medium',
        message: ''
      });
      
      toast.success(`工单 ${newTicket.id} 已创建，我们会尽快回复`);
      setActiveTab('tickets');
    } catch (_error) {
      toast.error('提交失败，请稍后重试');
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredFAQs = faqs.filter(faq => {
    const matchesSearch = !searchQuery || 
      faq.question.toLowerCase().includes(searchQuery.toLowerCase()) ||
      faq.answer.toLowerCase().includes(searchQuery.toLowerCase()) ||
      faq.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesCategory = selectedCategory === 'all' || faq.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'text-green-600 bg-green-100';
      case 'intermediate': return 'text-yellow-600 bg-yellow-100';
      case 'advanced': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-blue-600 bg-blue-100';
      case 'pending': return 'text-yellow-600 bg-yellow-100';
      case 'resolved': return 'text-green-600 bg-green-100';
      case 'closed': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('zh-CN', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (isLoading) {
    return (
      <div className={`w-full ${className}`}>
        <LoadingState message="加载帮助内容中..." />
      </div>
    );
  }

  return (
    <div className={`w-full max-w-6xl mx-auto space-y-6 ${className}`}>
      {/* 头部 */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
              <HelpCircle className="w-8 h-8 text-blue-600" />
              帮助与支持
            </h1>
            <p className="text-gray-600 mt-1">找到您需要的答案和支持</p>
          </div>
          
          <div className="flex items-center gap-2">
            {!isOnline && (
              <div className="flex items-center gap-1 text-amber-600 text-sm">
                <AlertCircle className="w-4 h-4" />
                <span>离线模式</span>
              </div>
            )}
          </div>
        </div>
        
        {/* 标签导航 */}
        <div className="flex flex-wrap gap-2 mb-6">
          {[
            { id: 'faq', label: '常见问题', icon: FileQuestion },
            { id: 'guides', label: '使用指南', icon: Book },
            { id: 'contact', label: '联系支持', icon: MessageCircle },
            { id: 'tickets', label: '我的工单', icon: FileText }
          ].map(tab => {
            const IconComponent = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'faq' | 'guides' | 'contact' | 'tickets')}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                <IconComponent className="w-4 h-4" />
                {tab.label}
                {tab.id === 'tickets' && tickets.length > 0 && (
                  <span className="ml-1 px-2 py-0.5 bg-blue-600 text-white text-xs rounded-full">
                    {tickets.filter(t => t.status === 'open').length}
                  </span>
                )}
              </button>
            );
          })}
        </div>
        
        {/* 搜索 */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="搜索帮助内容..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
      </div>
      
      {/* 内容区域 */}
      <AnimatePresence mode="wait">
        {activeTab === 'faq' && (
          <motion.div
            key="faq"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* 分类筛选 */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
              <div className="flex flex-wrap gap-2">
                {categories.map(category => {
                  const IconComponent = category.icon;
                  return (
                    <button
                      key={category.id}
                      onClick={() => setSelectedCategory(category.id)}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                        selectedCategory === category.id
                          ? 'bg-blue-100 text-blue-700'
                          : 'text-gray-600 hover:bg-gray-100'
                      }`}
                    >
                      <IconComponent className="w-4 h-4" />
                      {category.label}
                    </button>
                  );
                })}
              </div>
            </div>
            
            {/* FAQ 列表 */}
            <div className="space-y-4">
              {filteredFAQs.length === 0 ? (
                <EmptyState
                  type="search"
                  title="未找到相关问题"
                  description="尝试使用不同的关键词或浏览其他分类"
                />
              ) : (
                filteredFAQs.map(faq => {
                  const isExpanded = expandedFAQ.has(faq.id);
                  return (
                    <motion.div
                      key={faq.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden"
                    >
                      <button
                        onClick={() => toggleFAQ(faq.id)}
                        className="w-full p-4 text-left hover:bg-gray-50 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex-1 min-w-0">
                            <h3 className="text-lg font-medium text-gray-800 mb-2">
                              {faq.question}
                            </h3>
                            <div className="flex items-center gap-2 text-sm text-gray-500">
                              <div className="flex items-center gap-1">
                                <ThumbsUp className="w-3 h-3" />
                                <span>{faq.helpful}</span>
                              </div>
                              <span>•</span>
                              <span>更新于 {faq.lastUpdated}</span>
                              <span>•</span>
                              <div className="flex gap-1">
                                {faq.tags.map(tag => (
                                  <span
                                    key={tag}
                                    className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full text-xs"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                          
                          {isExpanded ? (
                            <ChevronUp className="w-5 h-5 text-gray-400 flex-shrink-0" />
                          ) : (
                            <ChevronDown className="w-5 h-5 text-gray-400 flex-shrink-0" />
                          )}
                        </div>
                      </button>
                      
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="border-t border-gray-100"
                          >
                            <div className="p-4">
                              <div className="prose prose-sm max-w-none text-gray-700 mb-4">
                                {faq.answer}
                              </div>
                              
                              <div className="flex items-center justify-between pt-4 border-t border-gray-100">
                                <div className="text-sm text-gray-500">
                                  这个答案对您有帮助吗？
                                </div>
                                <div className="flex items-center gap-2">
                                  <MicroInteraction>
                                    <button
                                      onClick={() => handleFAQFeedback(faq.id, true)}
                                      className="flex items-center gap-1 px-3 py-1 text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                                    >
                                      <ThumbsUp className="w-4 h-4" />
                                      <span>有帮助</span>
                                    </button>
                                  </MicroInteraction>
                                  
                                  <MicroInteraction>
                                    <button
                                      onClick={() => handleFAQFeedback(faq.id, false)}
                                      className="flex items-center gap-1 px-3 py-1 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                                    >
                                      <ThumbsDown className="w-4 h-4" />
                                      <span>没帮助</span>
                                    </button>
                                  </MicroInteraction>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })
              )}
            </div>
          </motion.div>
        )}
        
        {activeTab === 'guides' && (
          <motion.div
            key="guides"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {guides.map(section => {
              const IconComponent = section.icon;
              return (
                <div
                  key={section.id}
                  className="bg-white rounded-lg shadow-sm border border-gray-200 p-6"
                >
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <IconComponent className="w-6 h-6 text-blue-600" />
                    </div>
                    <div>
                      <h2 className="text-xl font-semibold text-gray-800">{section.title}</h2>
                      <p className="text-gray-600">{section.description}</p>
                    </div>
                  </div>
                  
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                    {section.articles.map(article => (
                      <motion.div
                        key={article.id}
                        whileHover={{ y: -2 }}
                        className="p-4 border border-gray-200 rounded-lg hover:shadow-md transition-all cursor-pointer"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <h3 className="font-medium text-gray-800 line-clamp-2">
                            {article.title}
                          </h3>
                          <ExternalLink className="w-4 h-4 text-gray-400 flex-shrink-0 ml-2" />
                        </div>
                        
                        <p className="text-sm text-gray-600 mb-3 line-clamp-2">
                          {article.description}
                        </p>
                        
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-1 rounded-full ${getDifficultyColor(article.difficulty)}`}>
                              {article.difficulty === 'beginner' ? '初级' : 
                               article.difficulty === 'intermediate' ? '中级' : '高级'}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {article.readTime}分钟
                            </span>
                          </div>
                          
                          <div className="flex items-center gap-2">
                            <span className="flex items-center gap-1">
                              <Star className="w-3 h-3 text-yellow-500" />
                              {article.rating}
                            </span>
                            <span>{article.views} 次阅读</span>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              );
            })}
          </motion.div>
        )}
        
        {activeTab === 'contact' && (
          <motion.div
            key="contact"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="grid gap-6 lg:grid-cols-3"
          >
            {/* 联系方式 */}
            <div className="lg:col-span-1 space-y-4">
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h2 className="text-lg font-semibold text-gray-800 mb-4">联系方式</h2>
                
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <Mail className="w-5 h-5 text-blue-600" />
                    </div>
                    <div>
                      <div className="font-medium text-gray-800">邮箱支持</div>
                      <div className="text-sm text-gray-600">support@smellpin.com</div>
                      <div className="text-xs text-gray-500">24小时内回复</div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-green-100 rounded-lg">
                      <MessageCircle className="w-5 h-5 text-green-600" />
                    </div>
                    <div>
                      <div className="font-medium text-gray-800">在线客服</div>
                      <div className="text-sm text-gray-600">即时聊天支持</div>
                      <div className="text-xs text-gray-500">工作日 9:00-18:00</div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-purple-100 rounded-lg">
                      <Phone className="w-5 h-5 text-purple-600" />
                    </div>
                    <div>
                      <div className="font-medium text-gray-800">电话支持</div>
                      <div className="text-sm text-gray-600">400-123-4567</div>
                      <div className="text-xs text-gray-500">紧急问题专线</div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="bg-blue-50 rounded-lg p-4">
                <div className="flex items-start gap-2">
                  <Info className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="font-medium text-blue-800 mb-1">提示</div>
                    <div className="text-sm text-blue-700">
                      为了更快解决您的问题，请在描述中包含详细的错误信息和重现步骤。
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            {/* 联系表单 */}
            <div className="lg:col-span-2">
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h2 className="text-lg font-semibold text-gray-800 mb-4">提交支持请求</h2>
                
                <form onSubmit={handleContactSubmit} className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <InputField
                      label="姓名"
                      name="name"
                      value={contactForm.name}
                      onChange={(value) => setContactForm(prev => ({ ...prev, name: value }))}
                      errors={errors.name || []}
                      required
                    />
                    
                    <InputField
                      label="邮箱"
                      name="email"
                      type="email"
                      value={contactForm.email}
                      onChange={(value) => setContactForm(prev => ({ ...prev, email: value }))}
                      errors={errors.email || []}
                      required
                    />
                  </div>
                  
                  <InputField
                    label="主题"
                    name="subject"
                    value={contactForm.subject}
                    onChange={(value) => setContactForm(prev => ({ ...prev, subject: value }))}
                    errors={errors.subject || []}
                    required
                  />
                  
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        问题类型
                      </label>
                      <select
                        value={contactForm.category}
                        onChange={(e) => setContactForm(prev => ({ ...prev, category: e.target.value }))}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        {contactCategories.map(category => (
                          <option key={category.id} value={category.id}>
                            {category.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        优先级
                      </label>
                      <select
                        value={contactForm.priority}
                        onChange={(e) => setContactForm(prev => ({ ...prev, priority: e.target.value }))}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        {priorities.map(priority => (
                          <option key={priority.id} value={priority.id}>
                            {priority.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  
                  <TextAreaField
                    label="详细描述"
                    name="message"
                    value={contactForm.message}
                    onChange={(value) => setContactForm(prev => ({ ...prev, message: value }))}
                    errors={errors.message || []}
                    rows={6}
                    placeholder="请详细描述您遇到的问题，包括错误信息、重现步骤等..."
                    required
                  />
                  
                  <LoadingButton
                    loading={isSubmitting}
                    disabled={!isOnline}
                    onClick={() => {}}
                    className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                  >
                    <Send className="w-4 h-4" />
                    提交请求
                  </LoadingButton>
                </form>
              </div>
            </div>
          </motion.div>
        )}
        
        {activeTab === 'tickets' && (
          <motion.div
            key="tickets"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="bg-white rounded-lg shadow-sm border border-gray-200"
          >
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-800">我的支持工单</h2>
              <p className="text-gray-600 mt-1">查看和管理您的支持请求</p>
            </div>
            
            <div className="p-6">
              {tickets.length === 0 ? (
                <EmptyState
                  type="no-data"
                  title="暂无支持工单"
                  description="您还没有提交过支持请求"
                  action={{
                    label: "提交新请求",
                    onClick: () => setActiveTab('contact')
                  }}
                />
              ) : (
                <div className="space-y-4">
                  {tickets.map(ticket => (
                    <motion.div
                      key={ticket.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="p-4 border border-gray-200 rounded-lg hover:shadow-md transition-all"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-gray-800">#{ticket.id}</span>
                            <span className={`px-2 py-1 rounded-full text-xs ${getStatusColor(ticket.status)}`}>
                              {ticket.status === 'open' ? '处理中' :
                               ticket.status === 'pending' ? '等待回复' :
                               ticket.status === 'resolved' ? '已解决' : '已关闭'}
                            </span>
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              priorities.find(p => p.id === ticket.priority)?.color || 'text-gray-600'
                            } bg-gray-100`}>
                              {priorities.find(p => p.id === ticket.priority)?.label || ticket.priority}
                            </span>
                          </div>
                          <h3 className="font-medium text-gray-800 mb-1">{ticket.subject}</h3>
                          <div className="text-sm text-gray-500">
                            创建于 {formatDate(ticket.createdAt)} • 最后回复 {formatDate(ticket.lastReply)}
                          </div>
                        </div>
                        
                        <button className="flex items-center gap-1 px-3 py-1 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors">
                          <ExternalLink className="w-4 h-4" />
                          查看详情
                        </button>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default HelpSupport;