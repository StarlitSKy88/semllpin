'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence, PanInfo } from 'framer-motion';
import { 
  MapPin, Camera, DollarSign, Tag, User, CheckCircle, 
  AlertCircle, Upload, X, ArrowLeft, ArrowRight, 
  Sparkles, Target, Lightbulb, Star, Heart, Laugh,
  Zap, Coffee, TreePine, Building
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';

interface SmartCreationFlowProps {
  isVisible: boolean;
  location: { latitude: number; longitude: number };
  onClose: () => void;
  onSubmit: (annotation: AnnotationData) => void;
  isFirstTimeUser?: boolean;
  nearbyAnnotationsCount?: number;
}

interface AnnotationData {
  title: string;
  description: string;
  category: string;
  rewardAmount: number;
  images: File[];
  tags: string[];
  isPublic: boolean;
  scheduledTime?: Date;
}

type CreationStep = 'location' | 'category' | 'content' | 'media' | 'reward' | 'preview' | 'payment';

const categories = [
  { id: 'funny', label: '搞笑有趣', icon: Laugh, color: 'from-pink-500 to-rose-500', description: '让人捧腹大笑的有趣发现' },
  { id: 'weird', label: '奇闻异事', icon: Zap, color: 'from-purple-500 to-indigo-500', description: '不可思议的奇异现象' },
  { id: 'historical', label: '历史文化', icon: Star, color: 'from-amber-500 to-orange-500', description: '承载历史记忆的文化遗迹' },
  { id: 'nature', label: '自然景观', icon: TreePine, color: 'from-green-500 to-emerald-500', description: '美丽的自然风光和生态' },
  { id: 'urban', label: '城市生活', icon: Building, color: 'from-blue-500 to-cyan-500', description: '现代城市的独特风貌' },
  { id: 'food', label: '美食推荐', icon: Coffee, color: 'from-yellow-500 to-orange-500', description: '值得品尝的美食体验' },
];

const SmartCreationFlow: React.FC<SmartCreationFlowProps> = ({
  isVisible,
  location,
  onClose,
  onSubmit,
  isFirstTimeUser = false,
  nearbyAnnotationsCount = 0
}) => {
  const [currentStep, setCurrentStep] = useState<CreationStep>('category');
  const [formData, setFormData] = useState<AnnotationData>({
    title: '',
    description: '',
    category: '',
    rewardAmount: isFirstTimeUser ? 0 : 5,
    images: [],
    tags: [],
    isPublic: true,
  });
  
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Smart suggestions based on location and category
  const generateSuggestions = useCallback((category: string) => {
    const categoryData = categories.find(c => c.id === category);
    if (!categoryData) return;

    const baseSuggestions = {
      funny: ['搞笑瞬间', '有趣发现', '意外惊喜', '萌宠出没'],
      weird: ['神秘现象', '奇异景象', '不解之谜', '超自然'],
      historical: ['历史遗迹', '文化传承', '古建筑', '纪念地'],
      nature: ['自然美景', '生态观察', '季节变化', '野生动物'],
      urban: ['城市印记', '建筑特色', '街头艺术', '现代风光'],
      food: ['美食推荐', '特色小吃', '网红店', '传统味道']
    };

    setSuggestions(baseSuggestions[category as keyof typeof baseSuggestions] || []);
  }, []);

  // Validate current step
  const validateStep = (step: CreationStep): boolean => {
    const newErrors: Record<string, string> = {};

    switch (step) {
      case 'category':
        if (!formData.category) {
          newErrors.category = '请选择标注类别';
        }
        break;
      case 'content':
        if (!formData.title.trim()) {
          newErrors.title = '请输入标注标题';
        }
        if (isFirstTimeUser && formData.description.length < 50) {
          newErrors.description = '首次标注需要至少50字的描述';
        }
        break;
      case 'media':
        if (isFirstTimeUser && formData.images.length === 0) {
          newErrors.images = '首次标注需要上传至少一张图片';
        }
        break;
      case 'reward':
        if (!isFirstTimeUser && formData.rewardAmount < 1) {
          newErrors.rewardAmount = '奖励金额至少1元';
        }
        break;
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle step navigation
  const nextStep = () => {
    if (!validateStep(currentStep)) return;

    const steps: CreationStep[] = ['category', 'content', 'media', 'reward', 'preview'];
    if (!isFirstTimeUser && nearbyAnnotationsCount > 0) {
      steps.push('payment');
    }

    const currentIndex = steps.indexOf(currentStep);
    if (currentIndex < steps.length - 1) {
      setCurrentStep(steps[currentIndex + 1]);
    }
  };

  const previousStep = () => {
    const steps: CreationStep[] = ['category', 'content', 'media', 'reward', 'preview'];
    if (!isFirstTimeUser && nearbyAnnotationsCount > 0) {
      steps.push('payment');
    }

    const currentIndex = steps.indexOf(currentStep);
    if (currentIndex > 0) {
      setCurrentStep(steps[currentIndex - 1]);
    }
  };

  // Handle image upload
  const handleImageUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    setFormData(prev => ({
      ...prev,
      images: [...prev.images, ...files].slice(0, 5) // Max 5 images
    }));
  };

  // Remove image
  const removeImage = (index: number) => {
    setFormData(prev => ({
      ...prev,
      images: prev.images.filter((_, i) => i !== index)
    }));
  };

  // Add tag
  const addTag = (tag: string) => {
    if (!formData.tags.includes(tag) && formData.tags.length < 5) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, tag]
      }));
    }
  };

  // Remove tag
  const removeTag = (tagToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove)
    }));
  };

  // Handle form submission
  const handleSubmit = async () => {
    if (!validateStep('preview')) return;

    setIsSubmitting(true);
    try {
      await onSubmit(formData);
      onClose();
    } catch (error) {
      console.error('Failed to submit annotation:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Update suggestions when category changes
  useEffect(() => {
    if (formData.category) {
      generateSuggestions(formData.category);
    }
  }, [formData.category, generateSuggestions]);

  const stepProgress = () => {
    const steps = ['category', 'content', 'media', 'reward', 'preview'];
    const currentIndex = steps.indexOf(currentStep);
    return ((currentIndex + 1) / steps.length) * 100;
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-3xl max-w-lg w-full max-h-[90vh] overflow-hidden shadow-2xl"
            transition={{ type: "spring", stiffness: 300, damping: 25 }}
          >
            {/* Header */}
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-white">
                  {isFirstTimeUser ? '创建你的第一个标注' : '创建新标注'}
                </h2>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={onClose}
                  className="text-white/60 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </Button>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-white/20 rounded-full h-2 mb-2">
                <motion.div
                  className="h-full bg-gradient-to-r from-blue-400 to-cyan-400 rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${stepProgress()}%` }}
                  transition={{ duration: 0.3 }}
                />
              </div>
              <p className="text-sm text-white/70">
                步骤 {['category', 'content', 'media', 'reward', 'preview'].indexOf(currentStep) + 1} / 5
              </p>

              {isFirstTimeUser && (
                <div className="mt-4 p-3 bg-blue-500/20 border border-blue-500/30 rounded-xl">
                  <p className="text-sm text-blue-300 flex items-center gap-2">
                    <Sparkles className="w-4 h-4" />
                    首次标注免费！请添加详细描述和图片。
                  </p>
                </div>
              )}
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto flex-1">
              <AnimatePresence mode="wait">
                {/* Category Selection */}
                {currentStep === 'category' && (
                  <motion.div
                    key="category"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-4"
                  >
                    <div className="text-center mb-6">
                      <Target className="w-12 h-12 text-blue-400 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-white mb-2">选择标注类别</h3>
                      <p className="text-sm text-white/70">选择最符合你发现的类别</p>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      {categories.map((category) => {
                        const IconComponent = category.icon;
                        return (
                          <motion.button
                            key={category.id}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            onClick={() => {
                              setFormData(prev => ({ ...prev, category: category.id }));
                              setErrors(prev => ({ ...prev, category: '' }));
                            }}
                            className={`p-4 rounded-xl border transition-all ${
                              formData.category === category.id
                                ? 'bg-white/20 border-white/30 shadow-lg'
                                : 'bg-white/5 border-white/10 hover:bg-white/10'
                            }`}
                          >
                            <div className={`w-10 h-10 rounded-full bg-gradient-to-r ${category.color} flex items-center justify-center mb-3 mx-auto`}>
                              <IconComponent className="w-5 h-5 text-white" />
                            </div>
                            <h4 className="font-semibold text-white text-sm mb-1">{category.label}</h4>
                            <p className="text-xs text-white/60 leading-tight">{category.description}</p>
                          </motion.button>
                        );
                      })}
                    </div>

                    {errors.category && (
                      <p className="text-red-400 text-sm flex items-center gap-2">
                        <AlertCircle className="w-4 h-4" />
                        {errors.category}
                      </p>
                    )}
                  </motion.div>
                )}

                {/* Content Creation */}
                {currentStep === 'content' && (
                  <motion.div
                    key="content"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-4"
                  >
                    <div className="text-center mb-6">
                      <Lightbulb className="w-12 h-12 text-yellow-400 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-white mb-2">描述你的发现</h3>
                      <p className="text-sm text-white/70">让其他人了解这个有趣的地方</p>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <Label className="text-white text-sm mb-2 block">标注标题</Label>
                        <Input
                          value={formData.title}
                          onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                          placeholder="给你的发现取个有趣的标题"
                          className="bg-white/10 border-white/20 text-white placeholder-white/50"
                        />
                        {errors.title && (
                          <p className="text-red-400 text-sm mt-1">{errors.title}</p>
                        )}
                      </div>

                      <div>
                        <Label className="text-white text-sm mb-2 block">
                          详细描述 {isFirstTimeUser && '(至少50字)'}
                        </Label>
                        <Textarea
                          value={formData.description}
                          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                          placeholder="详细描述这个地方的特色，让其他人也能感受到你的发现..."
                          rows={4}
                          className="bg-white/10 border-white/20 text-white placeholder-white/50 resize-none"
                        />
                        <div className="flex justify-between text-xs text-white/60 mt-1">
                          <span>{formData.description.length} 字</span>
                          {isFirstTimeUser && formData.description.length < 50 && (
                            <span className="text-orange-400">还需要 {50 - formData.description.length} 字</span>
                          )}
                        </div>
                        {errors.description && (
                          <p className="text-red-400 text-sm mt-1">{errors.description}</p>
                        )}
                      </div>

                      {/* Smart suggestions */}
                      {suggestions.length > 0 && (
                        <div>
                          <Label className="text-white text-sm mb-2 block">智能标签建议</Label>
                          <div className="flex flex-wrap gap-2">
                            {suggestions.map((suggestion) => (
                              <motion.button
                                key={suggestion}
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                onClick={() => addTag(suggestion)}
                                className="px-3 py-1 bg-white/10 hover:bg-white/20 border border-white/20 rounded-full text-xs text-white transition-colors"
                              >
                                + {suggestion}
                              </motion.button>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Added tags */}
                      {formData.tags.length > 0 && (
                        <div>
                          <Label className="text-white text-sm mb-2 block">已添加标签</Label>
                          <div className="flex flex-wrap gap-2">
                            {formData.tags.map((tag) => (
                              <Badge
                                key={tag}
                                variant="outline"
                                className="bg-white/10 border-white/20 text-white"
                              >
                                {tag}
                                <button
                                  onClick={() => removeTag(tag)}
                                  className="ml-2 hover:text-red-400"
                                >
                                  <X className="w-3 h-3" />
                                </button>
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}

                {/* Media Upload */}
                {currentStep === 'media' && (
                  <motion.div
                    key="media"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-4"
                  >
                    <div className="text-center mb-6">
                      <Camera className="w-12 h-12 text-purple-400 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-white mb-2">添加图片</h3>
                      <p className="text-sm text-white/70">
                        {isFirstTimeUser ? '首次标注需要至少一张图片' : '图片能让你的标注更生动'}
                      </p>
                    </div>

                    <div className="space-y-4">
                      {/* Upload button */}
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="w-full p-6 border-2 border-dashed border-white/30 rounded-xl hover:border-white/50 transition-colors bg-white/5 hover:bg-white/10"
                      >
                        <Upload className="w-8 h-8 text-white/60 mx-auto mb-2" />
                        <p className="text-white/80 text-sm">点击上传图片</p>
                        <p className="text-white/50 text-xs mt-1">支持 JPG、PNG，最多5张</p>
                      </button>

                      <input
                        ref={fileInputRef}
                        type="file"
                        multiple
                        accept="image/*"
                        onChange={handleImageUpload}
                        className="hidden"
                      />

                      {/* Image preview */}
                      {formData.images.length > 0 && (
                        <div className="grid grid-cols-2 gap-3">
                          {formData.images.map((image, index) => (
                            <div key={index} className="relative group">
                              <img
                                src={URL.createObjectURL(image)}
                                alt={`Upload ${index + 1}`}
                                className="w-full h-24 object-cover rounded-lg"
                              />
                              <button
                                onClick={() => removeImage(index)}
                                className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full w-6 h-6 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                              >
                                <X className="w-4 h-4" />
                              </button>
                            </div>
                          ))}
                        </div>
                      )}

                      {errors.images && (
                        <p className="text-red-400 text-sm flex items-center gap-2">
                          <AlertCircle className="w-4 h-4" />
                          {errors.images}
                        </p>
                      )}
                    </div>
                  </motion.div>
                )}

                {/* Reward Setting */}
                {currentStep === 'reward' && (
                  <motion.div
                    key="reward"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-4"
                  >
                    <div className="text-center mb-6">
                      <DollarSign className="w-12 h-12 text-green-400 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-white mb-2">设置奖励</h3>
                      <p className="text-sm text-white/70">
                        {isFirstTimeUser ? '你的首次标注免费创建！' : '设置发现者可获得的奖励金额'}
                      </p>
                    </div>

                    {isFirstTimeUser ? (
                      <div className="text-center p-6 bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/30 rounded-xl">
                        <Sparkles className="w-8 h-8 text-green-400 mx-auto mb-3" />
                        <h4 className="text-lg font-semibold text-white mb-2">恭喜！</h4>
                        <p className="text-green-300 text-sm">
                          作为首次用户，你可以免费创建这个标注。其他用户发现后会获得系统奖励！
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <div>
                          <Label className="text-white text-sm mb-4 block">奖励金额: ¥{formData.rewardAmount}</Label>
                          <Slider
                            value={[formData.rewardAmount]}
                            onValueChange={(value) => setFormData(prev => ({ ...prev, rewardAmount: value[0] }))}
                            max={100}
                            min={1}
                            step={1}
                            className="w-full"
                          />
                          <div className="flex justify-between text-xs text-white/60 mt-2">
                            <span>¥1</span>
                            <span>¥100</span>
                          </div>
                        </div>

                        <div className="p-4 bg-white/10 rounded-xl">
                          <h4 className="text-white font-medium mb-2">费用说明</h4>
                          <div className="space-y-1 text-sm text-white/70">
                            <div className="flex justify-between">
                              <span>奖励金额</span>
                              <span>¥{formData.rewardAmount}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>平台费用 (10%)</span>
                              <span>¥{(formData.rewardAmount * 0.1).toFixed(1)}</span>
                            </div>
                            <div className="flex justify-between font-medium text-white border-t border-white/20 pt-1 mt-2">
                              <span>总计</span>
                              <span>¥{(formData.rewardAmount * 1.1).toFixed(1)}</span>
                            </div>
                          </div>
                        </div>

                        {errors.rewardAmount && (
                          <p className="text-red-400 text-sm flex items-center gap-2">
                            <AlertCircle className="w-4 h-4" />
                            {errors.rewardAmount}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Additional settings */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label className="text-white text-sm">公开标注</Label>
                        <Switch
                          checked={formData.isPublic}
                          onCheckedChange={(checked) => setFormData(prev => ({ ...prev, isPublic: checked }))}
                        />
                      </div>
                      <p className="text-xs text-white/60">
                        公开标注会显示在地图上供其他用户发现
                      </p>
                    </div>
                  </motion.div>
                )}

                {/* Preview */}
                {currentStep === 'preview' && (
                  <motion.div
                    key="preview"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-4"
                  >
                    <div className="text-center mb-6">
                      <CheckCircle className="w-12 h-12 text-blue-400 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-white mb-2">预览标注</h3>
                      <p className="text-sm text-white/70">确认信息后即可创建</p>
                    </div>

                    <div className="bg-white/10 rounded-xl p-4 space-y-3">
                      <div className="flex items-start gap-3">
                        <div className={`w-10 h-10 rounded-full bg-gradient-to-r ${categories.find(c => c.id === formData.category)?.color} flex items-center justify-center flex-shrink-0`}>
                          {React.createElement(categories.find(c => c.id === formData.category)?.icon || MapPin, { 
                            className: "w-5 h-5 text-white" 
                          })}
                        </div>
                        <div className="flex-1">
                          <h4 className="font-semibold text-white">{formData.title}</h4>
                          <p className="text-sm text-white/70 mt-1">{formData.description}</p>
                          
                          {formData.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {formData.tags.map((tag) => (
                                <Badge key={tag} variant="outline" className="bg-white/10 border-white/20 text-white text-xs">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                          
                          <div className="flex items-center justify-between mt-3">
                            <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
                              ¥{formData.rewardAmount} 奖励
                            </Badge>
                            <div className="text-xs text-white/60">
                              {formData.images.length} 张图片
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Footer */}
            <div className="p-6 border-t border-white/10 flex gap-3">
              {currentStep !== 'category' && (
                <Button
                  variant="outline"
                  onClick={previousStep}
                  className="bg-white/10 border-white/20 text-white hover:bg-white/20"
                >
                  <ArrowLeft className="w-4 h-4 mr-2" />
                  上一步
                </Button>
              )}
              
              <Button
                onClick={currentStep === 'preview' ? handleSubmit : nextStep}
                disabled={isSubmitting}
                className="flex-1 bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-white"
              >
                {isSubmitting ? (
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-4 h-4 mr-2"
                  >
                    <Sparkles className="w-4 h-4" />
                  </motion.div>
                ) : currentStep === 'preview' ? (
                  <CheckCircle className="w-4 h-4 mr-2" />
                ) : (
                  <ArrowRight className="w-4 h-4 mr-2" />
                )}
                {isSubmitting ? '创建中...' : currentStep === 'preview' ? '创建标注' : '下一步'}
              </Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default SmartCreationFlow;