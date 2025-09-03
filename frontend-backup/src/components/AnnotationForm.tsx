import React, { useState } from 'react';
import { X, MapPin, Camera, Tag, Send, AlertCircle } from 'lucide-react';
import type { Location } from '../services/locationService';
import { createAnnotation } from '../services/annotationService';
import type { CreateAnnotationRequest } from '../services/annotationService';
import type { Pin } from '../types/map';

interface AnnotationData {
  title: string;
  description: string;
  category: string;
  intensity: number;
  tags: string[];
  images?: File[];
}

interface AnnotationFormProps {
  location: Location;
  isVisible: boolean;
  onSubmit: (annotation: Pin) => void;
  onClose: () => void;
}

const AnnotationForm: React.FC<AnnotationFormProps> = ({
  location,
  isVisible,
  onSubmit,
  onClose
}) => {
  const [formData, setFormData] = useState<AnnotationData>({
    title: '',
    description: '',
    category: location.category || 'other',
    intensity: 3,
    tags: [],
    images: []
  });
  
  const [newTag, setNewTag] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [imagePreview, setImagePreview] = useState<string[]>([]);

  // 分类选项
  const categories = [
    { value: 'food', label: '美食', icon: '🍽️' },
    { value: 'coffee', label: '咖啡', icon: '☕' },
    { value: 'flower', label: '花香', icon: '🌸' },
    { value: 'nature', label: '自然', icon: '🌳' },
    { value: 'pollution', label: '污染', icon: '🏭' },
    { value: 'other', label: '其他', icon: '📍' }
  ];

  // 强度选项
  const intensityOptions = [
    { value: 1, label: '很轻微', color: 'bg-green-100 text-green-800' },
    { value: 2, label: '轻微', color: 'bg-green-200 text-green-800' },
    { value: 3, label: '中等', color: 'bg-yellow-200 text-yellow-800' },
    { value: 4, label: '强烈', color: 'bg-orange-200 text-orange-800' },
    { value: 5, label: '非常强烈', color: 'bg-red-200 text-red-800' }
  ];

  // 处理表单输入
  const handleInputChange = (field: keyof AnnotationData, value: string | number | string[] | File[]) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    setError(null);
  };

  // 添加标签
  const handleAddTag = () => {
    const tag = newTag.trim();
    if (tag && !formData.tags.includes(tag)) {
      handleInputChange('tags', [...formData.tags, tag]);
      setNewTag('');
    }
  };

  // 删除标签
  const handleRemoveTag = (tagToRemove: string) => {
    handleInputChange('tags', formData.tags.filter(tag => tag !== tagToRemove));
  };

  // 处理图片上传
  const handleImageUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    if (files.length === 0) return;

    // 限制图片数量
    const maxImages = 3;
    const currentImages = formData.images || [];
    const newImages = files.slice(0, maxImages - currentImages.length);
    
    if (newImages.length > 0) {
      handleInputChange('images', [...currentImages, ...newImages]);
      
      // 生成预览
      newImages.forEach(file => {
        const reader = new FileReader();
        reader.onload = (e) => {
          setImagePreview(prev => [...prev, e.target?.result as string]);
        };
        reader.readAsDataURL(file);
      });
    }
  };

  // 删除图片
  const handleRemoveImage = (index: number) => {
    const newImages = (formData.images || []).filter((_, i) => i !== index);
    const newPreviews = imagePreview.filter((_, i) => i !== index);
    
    handleInputChange('images', newImages);
    setImagePreview(newPreviews);
  };

  // 验证表单
  const validateForm = (): boolean => {
    if (!formData.title.trim()) {
      setError('请输入标注标题');
      return false;
    }
    
    if (!formData.description.trim()) {
      setError('请输入标注描述');
      return false;
    }
    
    return true;
  };

  // 上传图片到服务器（模拟实现）
  const uploadImages = async (images: File[]): Promise<string[]> => {
    // 在实际项目中，这里应该调用图片上传API
    // 现在返回模拟的URL
    return images.map((_, index) => `https://example.com/image_${Date.now()}_${index}.jpg`);
  };

  // 提交表单
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      // 上传图片
      let mediaUrls: string[] = [];
      if (formData.images && formData.images.length > 0) {
        mediaUrls = await uploadImages(formData.images);
      }

      // 构建API请求数据
      const requestData: CreateAnnotationRequest = {
        content: `${formData.title}\n\n${formData.description}`,
        location: {
          latitude: location.coordinates[1],
          longitude: location.coordinates[0],
          address: location.address,
          place_name: location.name
        },
        media_urls: mediaUrls,
        tags: formData.tags,
        visibility: 'public',
        smell_intensity: formData.intensity,
        smell_category: formData.category
      };

      // 调用API创建标注
      const response = await createAnnotation(requestData);
      
      if (response.success && response.data) {
        onSubmit(response.data);
        onClose();
      } else {
        throw new Error(response.error || '创建标注失败');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '创建标注失败');
    } finally {
      setIsSubmitting(false);
    }
  };

  // 处理键盘事件
  const handleKeyPress = (e: React.KeyboardEvent, action: () => void) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      action();
    }
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl w-full max-w-lg max-h-[90vh] flex flex-col">
        {/* 头部 */}
        <div className="flex items-center justify-between p-6 border-b">
          <h3 className="text-xl font-semibold text-gray-900">创建标注</h3>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* 地点信息 */}
        <div className="p-6 bg-gray-50 border-b">
          <div className="flex items-start space-x-3">
            <MapPin className="w-5 h-5 text-blue-600 mt-1" />
            <div>
              <h4 className="font-medium text-gray-900">{location.name}</h4>
              <p className="text-sm text-gray-600 mt-1">{location.address}</p>
            </div>
          </div>
        </div>

        {/* 表单内容 */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto">
          <div className="p-6 space-y-6">
            {/* 错误提示 */}
            {error && (
              <div className="flex items-center space-x-2 p-3 bg-red-50 border border-red-200 rounded-lg">
                <AlertCircle className="w-5 h-5 text-red-500" />
                <span className="text-red-700 text-sm">{error}</span>
              </div>
            )}

            {/* 标题 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                标注标题 *
              </label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => handleInputChange('title', e.target.value)}
                placeholder="给这个地点起个标题..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                maxLength={50}
              />
            </div>

            {/* 描述 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                详细描述 *
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                placeholder="描述一下这个地点的气味、感受或其他特点..."
                rows={4}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                maxLength={500}
              />
              <div className="text-xs text-gray-500 mt-1 text-right">
                {formData.description.length}/500
              </div>
            </div>

            {/* 分类 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                分类
              </label>
              <div className="grid grid-cols-3 gap-2">
                {categories.map((category) => (
                  <button
                    key={category.value}
                    type="button"
                    onClick={() => handleInputChange('category', category.value)}
                    className={`p-3 rounded-lg border text-center transition-colors ${
                      formData.category === category.value
                        ? 'border-blue-500 bg-blue-50 text-blue-700'
                        : 'border-gray-300 hover:border-gray-400'
                    }`}
                  >
                    <div className="text-lg mb-1">{category.icon}</div>
                    <div className="text-xs">{category.label}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* 强度 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                强度等级
              </label>
              <div className="space-y-2">
                {intensityOptions.map((option) => (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => handleInputChange('intensity', option.value)}
                    className={`w-full p-3 rounded-lg border text-left transition-colors ${
                      formData.intensity === option.value
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-300 hover:border-gray-400'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{option.label}</span>
                      <span className={`px-2 py-1 rounded-full text-xs ${option.color}`}>
                        {option.value}/5
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* 标签 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                标签
              </label>
              <div className="flex space-x-2 mb-2">
                <input
                  type="text"
                  value={newTag}
                  onChange={(e) => setNewTag(e.target.value)}
                  onKeyPress={(e) => handleKeyPress(e, handleAddTag)}
                  placeholder="添加标签..."
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  maxLength={20}
                />
                <button
                  type="button"
                  onClick={handleAddTag}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Tag className="w-4 h-4" />
                </button>
              </div>
              {formData.tags.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {formData.tags.map((tag, index) => (
                    <span
                      key={index}
                      className="inline-flex items-center px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm"
                    >
                      {tag}
                      <button
                        type="button"
                        onClick={() => handleRemoveTag(tag)}
                        className="ml-2 text-gray-400 hover:text-gray-600"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* 图片上传 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                图片 (最多3张)
              </label>
              <div className="space-y-3">
                {imagePreview.length > 0 && (
                  <div className="grid grid-cols-3 gap-2">
                    {imagePreview.map((preview, index) => (
                      <div key={index} className="relative">
                        <img
                          src={preview}
                          alt={`预览 ${index + 1}`}
                          className="w-full h-20 object-cover rounded-lg"
                        />
                        <button
                          type="button"
                          onClick={() => handleRemoveImage(index)}
                          className="absolute -top-2 -right-2 w-6 h-6 bg-red-500 text-white rounded-full flex items-center justify-center hover:bg-red-600 transition-colors"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                
                {(formData.images?.length || 0) < 3 && (
                  <label className="block">
                    <input
                      type="file"
                      accept="image/*"
                      multiple
                      onChange={handleImageUpload}
                      className="hidden"
                    />
                    <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 text-center hover:border-gray-400 transition-colors cursor-pointer">
                      <Camera className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                      <p className="text-sm text-gray-600">点击上传图片</p>
                    </div>
                  </label>
                )}
              </div>
            </div>
          </div>

          {/* 底部按钮 */}
          <div className="p-6 border-t bg-gray-50">
            <div className="flex space-x-3">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
              >
                {isSubmitting ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    创建中...
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4 mr-2" />
                    创建标注
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AnnotationForm;
export type { AnnotationData };