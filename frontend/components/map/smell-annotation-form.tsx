'use client'

import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Upload, AlertCircle, CheckCircle, Star } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Slider } from '@/components/ui/slider'
import { useGlobalNotifications } from '@/lib/stores'

// 气味类型选项
const SMELL_TYPES = [
  { value: 'food', label: '食物味道', emoji: '🍕', color: 'bg-orange-500' },
  { value: 'chemical', label: '化学味道', emoji: '🧪', color: 'bg-purple-500' },
  { value: 'nature', label: '自然味道', emoji: '🌿', color: 'bg-green-500' },
  { value: 'smoke', label: '烟雾味道', emoji: '🚬', color: 'bg-gray-500' },
  { value: 'perfume', label: '香水味道', emoji: '💐', color: 'bg-pink-500' },
  { value: 'garbage', label: '垃圾味道', emoji: '🗑️', color: 'bg-red-500' },
  { value: 'gas', label: '燃气味道', emoji: '⛽', color: 'bg-yellow-500' },
  { value: 'sewage', label: '下水道味道', emoji: '🚰', color: 'bg-blue-500' },
  { value: 'other', label: '其他味道', emoji: '❓', color: 'bg-slate-500' },
]

// 气味强度标签
const INTENSITY_LABELS = [
  { value: 1, label: '几乎察觉不到', color: 'bg-green-500', description: '需要仔细闻才能察觉' },
  { value: 2, label: '轻微', color: 'bg-green-400', description: '能够清楚闻到但不强烈' },
  { value: 3, label: '明显', color: 'bg-yellow-500', description: '容易闻到，比较明显' },
  { value: 4, label: '强烈', color: 'bg-orange-500', description: '非常明显，有些刺鼻' },
  { value: 5, label: '非常强烈', color: 'bg-red-500', description: '极其强烈，难以忍受' },
]

interface AnnotationData {
  title: string
  content: string
  smell_type: string
  smell_intensity: number
  reward_amount: number
  images: File[]
}

interface SmellAnnotationFormProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: AnnotationData) => Promise<void>
  isFirstTimeUser?: boolean
  isCreating?: boolean
  location?: { lat: number; lng: number }
}

export const SmellAnnotationForm: React.FC<SmellAnnotationFormProps> = ({
  isOpen,
  onClose,
  onSubmit,
  isFirstTimeUser = false,
  isCreating = false,
  location
}) => {
  const [formData, setFormData] = useState<AnnotationData>({
    title: '',
    content: '',
    smell_type: '',
    smell_intensity: 3,
    reward_amount: 1,
    images: []
  })

  const [errors, setErrors] = useState<Record<string, string>>({})
  const { addNotification } = useGlobalNotifications()

  // 验证表单
  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {}

    if (!formData.title.trim()) {
      newErrors.title = '请输入标注标题'
    }

    if (!formData.smell_type) {
      newErrors.smell_type = '请选择气味类型'
    }

    if (formData.smell_intensity < 1 || formData.smell_intensity > 5) {
      newErrors.smell_intensity = '请选择有效的气味强度'
    }

    if (isFirstTimeUser) {
      if (formData.content.length < 50) {
        newErrors.content = '首次标注需要至少50字的描述说明'
      }
      if (formData.images.length === 0) {
        newErrors.images = '首次标注需要上传至少一张图片'
      }
    } else {
      if (formData.reward_amount < 1) {
        newErrors.reward_amount = '非首次标注需要支付至少1美金'
      }
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  // 提交表单
  const handleSubmit = async () => {
    if (!validateForm()) {
      addNotification({
        type: 'error',
        title: '表单验证失败',
        message: '请检查并填写必要信息'
      })
      return
    }

    try {
      await onSubmit(formData)
      // 重置表单
      setFormData({
        title: '',
        content: '',
        smell_type: '',
        smell_intensity: 3,
        reward_amount: 1,
        images: []
      })
      setErrors({})
    } catch (error) {
      console.error('Form submission error:', error)
    }
  }

  // 处理图片上传
  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    setFormData(prev => ({
      ...prev,
      images: [...prev.images, ...files]
    }))
    if (errors.images) {
      setErrors(prev => ({ ...prev, images: '' }))
    }
  }

  // 移除图片
  const removeImage = (index: number) => {
    setFormData(prev => ({
      ...prev,
      images: prev.images.filter((_, i) => i !== index)
    }))
  }

  // 获取选中的气味类型信息
  const selectedSmellType = SMELL_TYPES.find(type => type.value === formData.smell_type)
  const selectedIntensity = INTENSITY_LABELS.find(label => label.value === formData.smell_intensity)

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={onClose}
        >
          <motion.div 
            initial={{ opacity: 0, scale: 0.8, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.8, y: 20 }}
            className="relative max-w-md w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* 液体玻璃效果背景 */}
            <div className="absolute inset-0 bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20"></div>
            
            <div className="relative p-6">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-2xl font-bold text-white">
                  {isFirstTimeUser ? '🎉 创建你的第一个气味标注' : '🌟 创建新的气味标注'}
                </h3>
                <Button
                  onClick={onClose}
                  variant="ghost"
                  size="icon"
                  className="text-white/60 hover:text-white transition-colors"
                >
                  <X className="w-6 h-6" />
                </Button>
              </div>

              {/* 首次用户提示 */}
              {isFirstTimeUser && (
                <motion.div 
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-6 p-4 bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30 rounded-xl"
                >
                  <div className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-blue-400 mt-0.5" />
                    <div>
                      <p className="text-blue-300 font-medium text-sm">恭喜！你的第一个标注是免费的</p>
                      <p className="text-blue-300/80 text-xs mt-1">
                        请添加详细的气味描述和至少一张图片，帮助其他用户了解这个位置的气味特征
                      </p>
                    </div>
                  </div>
                </motion.div>
              )}

              <div className="space-y-4">
                {/* 标题输入 */}
                <div>
                  <label className="block text-sm font-medium text-white/80 mb-2">
                    标注标题 <span className="text-red-400">*</span>
                  </label>
                  <div className="relative">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                    <Input
                      type="text"
                      value={formData.title}
                      onChange={(e) => {
                        setFormData(prev => ({ ...prev, title: e.target.value }))
                        if (errors.title) setErrors(prev => ({ ...prev, title: '' }))
                      }}
                      className="relative w-full px-4 py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none"
                      placeholder="输入一个简洁的标题，如：奇怪的化学味"
                    />
                  </div>
                  {errors.title && (
                    <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3" />
                      {errors.title}
                    </p>
                  )}
                </div>

                {/* 气味类型选择 */}
                <div>
                  <label className="block text-sm font-medium text-white/80 mb-2">
                    气味类型 <span className="text-red-400">*</span>
                  </label>
                  <div className="relative">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                    <Select 
                      value={formData.smell_type} 
                      onValueChange={(value) => {
                        setFormData(prev => ({ ...prev, smell_type: value }))
                        if (errors.smell_type) setErrors(prev => ({ ...prev, smell_type: '' }))
                      }}
                    >
                      <SelectTrigger className="relative w-full px-4 py-3 bg-transparent text-white border-none">
                        <SelectValue placeholder="选择最符合的气味类型" />
                      </SelectTrigger>
                      <SelectContent className="bg-gray-900/95 backdrop-blur-xl border-white/20">
                        {SMELL_TYPES.map((type) => (
                          <SelectItem key={type.value} value={type.value} className="text-white hover:bg-white/10">
                            <div className="flex items-center gap-3">
                              <span className="text-lg">{type.emoji}</span>
                              <span>{type.label}</span>
                              <div className={`w-3 h-3 rounded-full ${type.color}`}></div>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  {selectedSmellType && (
                    <div className="mt-2">
                      <div className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 text-white rounded-full text-sm">
                        <span>{selectedSmellType.emoji}</span>
                        <span>已选择：{selectedSmellType.label}</span>
                      </div>
                    </div>
                  )}
                  {errors.smell_type && (
                    <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3" />
                      {errors.smell_type}
                    </p>
                  )}
                </div>

                {/* 气味强度滑块 */}
                <div>
                  <label className="block text-sm font-medium text-white/80 mb-2">
                    气味强度: {formData.smell_intensity} - {selectedIntensity?.label}
                  </label>
                  <div className="relative">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                    <div className="relative px-4 py-4">
                      <Slider
                        value={[formData.smell_intensity]}
                        onValueChange={(value) => setFormData(prev => ({ ...prev, smell_intensity: value[0] }))}
                        min={1}
                        max={5}
                        step={1}
                        className="w-full"
                      />
                      <div className="flex justify-between text-xs text-white/60 mt-3">
                        {INTENSITY_LABELS.map((label) => (
                          <div key={label.value} className="text-center flex-1">
                            <div className={`w-2 h-2 rounded-full mx-auto mb-1 ${label.color}`}></div>
                            <span>{label.value}</span>
                          </div>
                        ))}
                      </div>
                      {selectedIntensity && (
                        <div className="mt-3 p-2 bg-white/5 rounded-lg">
                          <p className="text-white/80 text-xs">{selectedIntensity.description}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* 详细描述 */}
                <div>
                  <label className="block text-sm font-medium text-white/80 mb-2">
                    详细描述 {isFirstTimeUser && <span className="text-red-400">*</span>}
                    {isFirstTimeUser && <span className="text-white/60">(至少50字)</span>}
                  </label>
                  <div className="relative">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                    <textarea
                      value={formData.content}
                      onChange={(e) => {
                        setFormData(prev => ({ ...prev, content: e.target.value }))
                        if (errors.content) setErrors(prev => ({ ...prev, content: '' }))
                      }}
                      className="relative w-full px-4 py-3 bg-transparent text-white placeholder-white/60 focus:outline-none resize-none border-none"
                      rows={4}
                      placeholder={isFirstTimeUser 
                        ? "请详细描述这个位置的气味特征，比如：闻起来像什么、强度如何、持续时间等..." 
                        : "输入对这个气味的详细描述（可选）"
                      }
                    />
                  </div>
                  {isFirstTimeUser && (
                    <p className="text-xs text-white/60 mt-1">
                      已输入 {formData.content.length}/50 字
                    </p>
                  )}
                  {errors.content && (
                    <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3" />
                      {errors.content}
                    </p>
                  )}
                </div>

                {/* 图片上传 */}
                {isFirstTimeUser && (
                  <div>
                    <label className="block text-sm font-medium text-white/80 mb-2">
                      图片上传 <span className="text-red-400">*</span>
                      <span className="text-white/60">(至少1张)</span>
                    </label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <div className="relative p-4">
                        <Input
                          type="file"
                          multiple
                          accept="image/*"
                          onChange={handleImageUpload}
                          className="relative w-full px-4 py-3 bg-transparent text-white border-none"
                        />
                        <div className="flex items-center gap-2 mt-2 text-white/60 text-xs">
                          <Upload className="w-4 h-4" />
                          <span>支持 JPG、PNG、GIF 格式，最大 5MB</span>
                        </div>
                      </div>
                    </div>
                    {formData.images.length > 0 && (
                      <div className="mt-3 grid grid-cols-3 gap-2">
                        {formData.images.map((image, index) => (
                          <div key={index} className="relative">
                            <img
                              src={URL.createObjectURL(image)}
                              alt={`Upload ${index + 1}`}
                              className="w-full h-20 object-cover rounded-lg"
                            />
                            <Button
                              onClick={() => removeImage(index)}
                              size="icon"
                              className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full w-6 h-6"
                            >
                              <X className="w-3 h-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                    {errors.images && (
                      <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                        <AlertCircle className="w-3 h-3" />
                        {errors.images}
                      </p>
                    )}
                  </div>
                )}

                {/* 奖励金额设置 */}
                {!isFirstTimeUser && (
                  <div>
                    <label className="block text-sm font-medium text-white/80 mb-2">奖励金额 ($)</label>
                    <div className="relative">
                      <div className="absolute inset-0 bg-white/5 backdrop-blur-xl rounded-xl border border-white/10"></div>
                      <Input
                        type="number"
                        min="1"
                        max="100"
                        value={formData.reward_amount}
                        onChange={(e) => setFormData(prev => ({ ...prev, reward_amount: parseInt(e.target.value) || 1 }))}
                        className="relative w-full px-4 py-3 bg-transparent text-white placeholder-white/60 focus:outline-none border-none"
                      />
                    </div>
                  </div>
                )}

                {/* 提交按钮 */}
                <div className="flex space-x-3 pt-4">
                  <Button
                    onClick={onClose}
                    variant="outline"
                    className="flex-1 bg-white/10 backdrop-blur-xl border-white/20 text-white hover:bg-white/20 py-3"
                  >
                    取消
                  </Button>
                  
                  <Button
                    onClick={handleSubmit}
                    disabled={isCreating}
                    className="flex-1 bg-gradient-to-r from-blue-500 to-purple-500 text-white hover:from-blue-600 hover:to-purple-600 py-3"
                  >
                    {isCreating ? (
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        <span>创建中...</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <Star className="w-4 h-4" />
                        <span>{isFirstTimeUser ? '免费创建' : '付费创建'}</span>
                      </div>
                    )}
                  </Button>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default SmellAnnotationForm