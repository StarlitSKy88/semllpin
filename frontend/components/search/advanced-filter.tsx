'use client'

import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Filter, 
  MapPin, 
  Calendar, 
  Tag, 
  DollarSign, 
  Star, 
  X, 
  ChevronDown,
  Search,
  RotateCcw
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Slider } from '@/components/ui/slider'
import { Badge } from '@/components/ui/badge'
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { Calendar as CalendarComponent } from '@/components/ui/calendar'
import { format } from 'date-fns'
import { zhCN } from 'date-fns/locale'

export interface FilterOptions {
  keyword: string
  location: string
  dateRange: {
    from: Date | null
    to: Date | null
  }
  rewardRange: [number, number]
  smellRating: [number, number]
  category: string
  tags: string[]
  sortBy: 'time' | 'reward' | 'rating' | 'distance'
  sortOrder: 'asc' | 'desc'
}

interface AdvancedFilterProps {
  filters: FilterOptions
  onFiltersChange: (filters: FilterOptions) => void
  onApplyFilters: () => void
  onResetFilters: () => void
  className?: string
}

const PREDEFINED_TAGS = [
  '化学味', '刺鼻', '环保', '异味', '投诉', '影响生活',
  '工厂排放', '垃圾处理', '下水道', '餐厅油烟', '汽车尾气',
  '装修味道', '农药味', '烧烤味', '臭豆腐', '榴莲'
]

const CATEGORIES = [
  { value: 'all', label: '全部' },
  { value: 'news', label: '新闻' },
  { value: 'comment', label: '用户评论' },
  { value: 'annotation', label: '地图标注' }
]

const SORT_OPTIONS = [
  { value: 'time', label: '时间' },
  { value: 'reward', label: '奖励金额' },
  { value: 'rating', label: '臭味等级' },
  { value: 'distance', label: '距离' }
]

export function AdvancedFilter({
  filters,
  onFiltersChange,
  onApplyFilters,
  onResetFilters,
  className = ''
}: AdvancedFilterProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [datePickerOpen, setDatePickerOpen] = useState<'from' | 'to' | null>(null)

  const updateFilters = (updates: Partial<FilterOptions>) => {
    onFiltersChange({ ...filters, ...updates })
  }

  const addTag = (tag: string) => {
    if (!filters.tags.includes(tag)) {
      updateFilters({ tags: [...filters.tags, tag] })
    }
  }

  const removeTag = (tag: string) => {
    updateFilters({ tags: filters.tags.filter(t => t !== tag) })
  }

  const hasActiveFilters = () => {
    return (
      filters.keyword !== '' ||
      filters.location !== '' ||
      filters.dateRange.from !== null ||
      filters.dateRange.to !== null ||
      filters.rewardRange[0] > 0 || filters.rewardRange[1] < 1000 ||
      filters.smellRating[0] > 1 || filters.smellRating[1] < 5 ||
      filters.category !== 'all' ||
      filters.tags.length > 0
    )
  }

  return (
    <div className={`relative ${className}`}>
      {/* 筛选按钮 */}
      <Button
        variant="outline"
        onClick={() => setIsOpen(!isOpen)}
        className="relative bg-white/10 backdrop-blur-md border-white/20 text-white hover:bg-white/20"
      >
        <Filter className="w-4 h-4 mr-2" />
        高级筛选
        {hasActiveFilters() && (
          <Badge className="ml-2 bg-blue-500 text-white text-xs px-1 py-0 h-4">
            {filters.tags.length + (hasActiveFilters() ? 1 : 0)}
          </Badge>
        )}
        <ChevronDown className={`w-4 h-4 ml-2 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </Button>

      {/* 筛选面板 */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full left-0 right-0 mt-2 z-50"
          >
            <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6 shadow-2xl">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* 关键词搜索 */}
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">关键词</Label>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-white/60 w-4 h-4" />
                    <Input
                      placeholder="搜索关键词..."
                      value={filters.keyword}
                      onChange={(e) => updateFilters({ keyword: e.target.value })}
                      className="pl-10 bg-white/5 border-white/20 text-white placeholder-white/60"
                    />
                  </div>
                </div>

                {/* 位置筛选 */}
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">位置</Label>
                  <div className="relative">
                    <MapPin className="absolute left-3 top-1/2 transform -translate-y-1/2 text-white/60 w-4 h-4" />
                    <Input
                      placeholder="输入位置..."
                      value={filters.location}
                      onChange={(e) => updateFilters({ location: e.target.value })}
                      className="pl-10 bg-white/5 border-white/20 text-white placeholder-white/60"
                    />
                  </div>
                </div>

                {/* 类别筛选 */}
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">类别</Label>
                  <Select value={filters.category} onValueChange={(value) => updateFilters({ category: value })}>
                    <SelectTrigger className="bg-white/5 border-white/20 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {CATEGORIES.map((category) => (
                        <SelectItem key={category.value} value={category.value}>
                          {category.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* 日期范围 */}
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">日期范围</Label>
                  <div className="flex space-x-2">
                    <Popover open={datePickerOpen === 'from'} onOpenChange={(open) => setDatePickerOpen(open ? 'from' : null)}>
                      <PopoverTrigger asChild>
                        <Button
                          variant="outline"
                          className="flex-1 justify-start bg-white/5 border-white/20 text-white hover:bg-white/10"
                        >
                          <Calendar className="w-4 h-4 mr-2" />
                          {filters.dateRange.from ? format(filters.dateRange.from, 'MM/dd', { locale: zhCN }) : '开始日期'}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0" align="start">
                        <CalendarComponent
                          mode="single"
                          selected={filters.dateRange.from || undefined}
                          onSelect={(date) => {
                            updateFilters({ dateRange: { ...filters.dateRange, from: date || null } })
                            setDatePickerOpen(null)
                          }}
                          initialFocus
                        />
                      </PopoverContent>
                    </Popover>
                    <Popover open={datePickerOpen === 'to'} onOpenChange={(open) => setDatePickerOpen(open ? 'to' : null)}>
                      <PopoverTrigger asChild>
                        <Button
                          variant="outline"
                          className="flex-1 justify-start bg-white/5 border-white/20 text-white hover:bg-white/10"
                        >
                          <Calendar className="w-4 h-4 mr-2" />
                          {filters.dateRange.to ? format(filters.dateRange.to, 'MM/dd', { locale: zhCN }) : '结束日期'}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0" align="start">
                        <CalendarComponent
                          mode="single"
                          selected={filters.dateRange.to || undefined}
                          onSelect={(date) => {
                            updateFilters({ dateRange: { ...filters.dateRange, to: date || null } })
                            setDatePickerOpen(null)
                          }}
                          initialFocus
                        />
                      </PopoverContent>
                    </Popover>
                  </div>
                </div>

                {/* 奖励金额范围 */}
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">
                    奖励金额: ¥{filters.rewardRange[0]} - ¥{filters.rewardRange[1]}
                  </Label>
                  <div className="px-2">
                    <Slider
                      value={filters.rewardRange}
                      onValueChange={(value) => updateFilters({ rewardRange: value as [number, number] })}
                      max={1000}
                      min={0}
                      step={10}
                      className="w-full"
                    />
                  </div>
                </div>

                {/* 臭味等级 */}
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">
                    臭味等级: {filters.smellRating[0]} - {filters.smellRating[1]} 星
                  </Label>
                  <div className="px-2">
                    <Slider
                      value={filters.smellRating}
                      onValueChange={(value) => updateFilters({ smellRating: value as [number, number] })}
                      max={5}
                      min={1}
                      step={1}
                      className="w-full"
                    />
                  </div>
                </div>
              </div>

              {/* 标签筛选 */}
              <div className="mt-6 space-y-3">
                <Label className="text-white text-sm font-medium">标签</Label>
                <div className="flex flex-wrap gap-2">
                  {PREDEFINED_TAGS.map((tag) => (
                    <Badge
                      key={tag}
                      variant={filters.tags.includes(tag) ? "default" : "outline"}
                      className={`cursor-pointer transition-colors ${
                        filters.tags.includes(tag)
                          ? 'bg-blue-500 text-white border-blue-500'
                          : 'bg-white/5 text-white/80 border-white/20 hover:bg-white/10'
                      }`}
                      onClick={() => {
                        if (filters.tags.includes(tag)) {
                          removeTag(tag)
                        } else {
                          addTag(tag)
                        }
                      }}
                    >
                      {tag}
                      {filters.tags.includes(tag) && (
                        <X className="w-3 h-3 ml-1" />
                      )}
                    </Badge>
                  ))}
                </div>
                {filters.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2 pt-2 border-t border-white/10">
                    <span className="text-white/60 text-sm">已选择:</span>
                    {filters.tags.map((tag) => (
                      <Badge
                        key={tag}
                        className="bg-blue-500 text-white"
                      >
                        {tag}
                        <X
                          className="w-3 h-3 ml-1 cursor-pointer"
                          onClick={() => removeTag(tag)}
                        />
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              {/* 排序选项 */}
              <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">排序方式</Label>
                  <Select value={filters.sortBy} onValueChange={(value) => updateFilters({ sortBy: value as any })}>
                    <SelectTrigger className="bg-white/5 border-white/20 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SORT_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label className="text-white text-sm font-medium">排序顺序</Label>
                  <Select value={filters.sortOrder} onValueChange={(value) => updateFilters({ sortOrder: value as any })}>
                    <SelectTrigger className="bg-white/5 border-white/20 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="desc">降序</SelectItem>
                      <SelectItem value="asc">升序</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* 操作按钮 */}
              <div className="mt-6 flex justify-between">
                <Button
                  variant="outline"
                  onClick={onResetFilters}
                  className="bg-white/5 border-white/20 text-white hover:bg-white/10"
                >
                  <RotateCcw className="w-4 h-4 mr-2" />
                  重置
                </Button>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    onClick={() => setIsOpen(false)}
                    className="bg-white/5 border-white/20 text-white hover:bg-white/10"
                  >
                    取消
                  </Button>
                  <Button
                    onClick={() => {
                      onApplyFilters()
                      setIsOpen(false)
                    }}
                    className="bg-blue-500 hover:bg-blue-600 text-white"
                  >
                    应用筛选
                  </Button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}