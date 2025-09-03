'use client';

import React, { useRef, useCallback, useMemo, useState, useEffect } from 'react';
import { motion, AnimatePresence, useSpring, useTransform, PanInfo, useMotionValue } from 'framer-motion';
import { MapPin, Navigation, Zap, Eye, Target, Layers, Plus, Gift, Star } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useLBSStore } from '@/lib/stores/lbs-store';
import { useMapStore } from '@/lib/stores/map-store';

interface Annotation {
  id: string;
  title: string;
  description: string;
  latitude: number;
  longitude: number;
  rewardAmount: number;
  isDiscovered?: boolean;
  category?: string;
  images?: string[];
  createdAt: string;
  author?: string;
}

const mockAnnotations: Annotation[] = [
  {
    id: "1",
    lat: 39.9042,
    lng: 116.4074,
    title: "天安门广场的秘密",
    content: "据说这里埋藏着一个巨大的宝藏，但只有在满月的夜晚才能看到！",
    reward: 50,
    author: "探险家小王",
    discovered: false
  },
  {
    id: "2",
    lat: 39.9163,
    lng: 116.3972,
    title: "故宫里的猫咪王国",
    content: "传说故宫里的猫咪们有自己的王国，每天晚上都会开会讨论如何统治紫禁城！",
    reward: 30,
    author: "猫奴小李",
    discovered: true
  },
  {
    id: "3",
    lat: 39.8848,
    lng: 116.4199,
    title: "天坛的回音壁真相",
    content: "回音壁其实是古代的微信群聊，皇帝用它来和大臣们开视频会议！",
    reward: 25,
    author: "历史达人",
    discovered: false
  }
]

export function InteractiveMap() {
  const mapRef = useRef<HTMLDivElement>(null)
  const [selectedAnnotation, setSelectedAnnotation] = useState<Annotation | null>(null)
  const [userLocation, setUserLocation] = useState<{lat: number, lng: number} | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)

  useEffect(() => {
    // 模拟获取用户位置
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setUserLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude
          })
        },
        () => {
          // 如果获取位置失败，使用北京作为默认位置
          setUserLocation({ lat: 39.9042, lng: 116.4074 })
        }
      )
    } else {
      setUserLocation({ lat: 39.9042, lng: 116.4074 })
    }
  }, [])

  const handleDiscoverAnnotation = (annotation: Annotation) => {
    if (!userLocation) return
    
    // 计算距离（简化版本）
    const distance = Math.sqrt(
      Math.pow(annotation.lat - userLocation.lat, 2) + 
      Math.pow(annotation.lng - userLocation.lng, 2)
    ) * 111000 // 转换为米

    if (distance < 100) { // 100米范围内
      setSelectedAnnotation({...annotation, discovered: true})
      alert(`恭喜！您发现了标注"${annotation.title}"并获得¥${annotation.reward}奖励！`)
    } else {
      alert(`您距离标注还有${Math.round(distance)}米，请靠近后再试！`)
    }
  }

  return (
    <div className="relative w-full h-[300px] sm:h-[400px] md:h-[500px] lg:h-[600px] bg-[#1a1a1a] rounded-lg overflow-hidden">
      {/* 地图容器 */}
      <div ref={mapRef} className="w-full h-full relative">
        {/* 简化的地图背景 */}
        <div className="w-full h-full bg-gradient-to-br from-blue-900 to-green-900 relative">
          {/* 网格线模拟地图 */}
          <div className="absolute inset-0 opacity-20">
            {Array.from({length: 20}).map((_, i) => (
              <div key={i} className="absolute border-white/10" style={{
                left: `${i * 5}%`,
                top: 0,
                width: '1px',
                height: '100%',
                borderLeft: '1px solid'
              }} />
            ))}
            {Array.from({length: 12}).map((_, i) => (
              <div key={i} className="absolute border-white/10" style={{
                top: `${i * 8.33}%`,
                left: 0,
                height: '1px',
                width: '100%',
                borderTop: '1px solid'
              }} />
            ))}
          </div>

          {/* 用户位置 */}
          {userLocation && (
            <div className="absolute transform -translate-x-1/2 -translate-y-1/2" style={{
              left: '50%',
              top: '50%'
            }}>
              <div className="w-3 h-3 sm:w-4 sm:h-4 bg-blue-500 rounded-full border-2 border-white shadow-lg animate-pulse" />
              <div className="absolute -top-6 sm:-top-8 left-1/2 transform -translate-x-1/2 text-xs text-white bg-black/50 px-1 sm:px-2 py-1 rounded whitespace-nowrap">
                您的位置
              </div>
            </div>
          )}

          {/* 标注点 */}
          {mockAnnotations.map((annotation, index) => (
            <div
              key={annotation.id}
              className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer"
              style={{
                left: `${30 + index * 20}%`,
                top: `${30 + index * 15}%`
              }}
              onClick={() => setSelectedAnnotation(annotation)}
            >
              <div className={`w-6 h-6 sm:w-8 sm:h-8 rounded-full border-2 border-white shadow-lg flex items-center justify-center ${
                annotation.discovered ? 'bg-green-500' : 'bg-red-500'
              }`}>
                {annotation.discovered ? <Gift size={12} className="text-white sm:w-4 sm:h-4" /> : <MapPin size={12} className="text-white sm:w-4 sm:h-4" />}
              </div>
              <div className="absolute -top-8 sm:-top-10 left-1/2 transform -translate-x-1/2 text-xs text-white bg-black/70 px-1 sm:px-2 py-1 rounded whitespace-nowrap">
                ¥{annotation.reward}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 控制按钮 */}
      <div className="absolute top-2 right-2 sm:top-4 sm:right-4 space-y-2">
        <Button
          onClick={() => setShowCreateForm(true)}
          className="bg-white text-black hover:bg-neutral-200 font-bold text-xs sm:text-sm h-8 sm:h-9 px-2 sm:px-3"
          size="sm"
        >
          <Plus size={12} className="mr-1 sm:mr-2 sm:w-4 sm:h-4" />
          <span className="hidden sm:inline">创建标注</span>
          <span className="sm:hidden">创建</span>
        </Button>
      </div>

      {/* 标注详情弹窗 */}
      {selectedAnnotation && (
        <div className="absolute inset-0 bg-black/50 flex items-center justify-center p-3 sm:p-4">
          <div className="bg-[#1a1a1a] p-4 sm:p-6 rounded-lg max-w-sm sm:max-w-md w-full mx-2">
            <h3 className="text-base sm:text-lg md:text-xl font-bold mb-2 sm:mb-3 line-clamp-2">{selectedAnnotation.title}</h3>
            <p className="text-neutral-300 mb-3 sm:mb-4 text-sm sm:text-base line-clamp-3">{selectedAnnotation.content}</p>
            <div className="flex items-center justify-between mb-3 sm:mb-4">
              <span className="text-xs sm:text-sm text-neutral-400 truncate mr-2">作者：{selectedAnnotation.author}</span>
              <span className="text-sm sm:text-base md:text-lg font-bold text-green-400 whitespace-nowrap">¥{selectedAnnotation.reward}</span>
            </div>
            <div className="flex gap-2">
              {!selectedAnnotation.discovered && (
                <Button
                  onClick={() => handleDiscoverAnnotation(selectedAnnotation)}
                  className="bg-green-600 hover:bg-green-700 text-white flex-1 text-xs sm:text-sm h-8 sm:h-9"
                  size="sm"
                >
                  <Gift size={12} className="mr-1 sm:mr-2 sm:w-4 sm:h-4" />
                  <span className="hidden sm:inline">发现奖励</span>
                  <span className="sm:hidden">发现</span>
                </Button>
              )}
              <Button
                onClick={() => setSelectedAnnotation(null)}
                variant="outline"
                className="flex-1 text-xs sm:text-sm h-8 sm:h-9"
                size="sm"
              >
                关闭
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* 创建标注表单 */}
      {showCreateForm && (
        <div className="absolute inset-0 bg-black/50 flex items-center justify-center p-3 sm:p-4">
          <div className="bg-[#1a1a1a] p-4 sm:p-6 rounded-lg max-w-sm sm:max-w-md w-full mx-2 max-h-[90vh] overflow-y-auto">
            <h3 className="text-base sm:text-lg md:text-xl font-bold mb-3 sm:mb-4">创建新标注</h3>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="标注标题"
                className="w-full p-2 sm:p-3 bg-[#2a2a2a] border border-neutral-700 rounded text-white text-sm sm:text-base h-9 sm:h-10"
              />
              <textarea
                placeholder="标注内容（请发挥您的创意！）"
                rows={3}
                className="w-full p-2 sm:p-3 bg-[#2a2a2a] border border-neutral-700 rounded text-white text-sm sm:text-base resize-none"
              />
              <input
                type="number"
                placeholder="奖励金额（¥）"
                className="w-full p-2 sm:p-3 bg-[#2a2a2a] border border-neutral-700 rounded text-white text-sm sm:text-base h-9 sm:h-10"
              />
            </div>
            <div className="flex gap-2 mt-4 sm:mt-6">
              <Button
                onClick={() => {
                  alert('标注创建成功！等待审核通过后将显示在地图上。')
                  setShowCreateForm(false)
                }}
                className="bg-blue-600 hover:bg-blue-700 text-white flex-1 text-xs sm:text-sm h-8 sm:h-9"
                size="sm"
              >
                <span className="hidden sm:inline">创建标注</span>
                <span className="sm:hidden">创建</span>
              </Button>
              <Button
                onClick={() => setShowCreateForm(false)}
                variant="outline"
                className="flex-1 text-xs sm:text-sm h-8 sm:h-9"
                size="sm"
              >
                取消
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* 地图说明 */}
      <div className="absolute bottom-2 left-2 sm:bottom-4 sm:left-4 bg-black/70 text-white p-2 sm:p-3 rounded text-xs max-w-[180px] sm:max-w-[200px] md:max-w-xs">
        <p className="mb-1 sm:mb-2 font-semibold">使用说明：</p>
        <p className="text-xs text-neutral-300 leading-relaxed">
          • 蓝点是您的位置<br/>
          • 红点是未发现的标注<br/>
          • 绿点是已发现的标注<br/>
          • 点击标注查看详情<br/>
          • 靠近标注可获得奖励
        </p>
      </div>
    </div>
  )
}