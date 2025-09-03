'use client'

import React, { useEffect, useState } from 'react'
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'

// 修复Leaflet图标问题
delete (L.Icon.Default.prototype as any)._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
})

// 自定义气味标注图标
const createSmellIcon = (intensity: number, type: string) => {
  const getColor = (intensity: number) => {
    if (intensity <= 3) return '#22c55e' // 绿色 - 轻微
    if (intensity <= 6) return '#f59e0b' // 黄色 - 中等
    return '#ef4444' // 红色 - 强烈
  }

  const color = getColor(intensity)
  
  return L.divIcon({
    html: `
      <div style="
        background-color: ${color};
        width: 20px;
        height: 20px;
        border-radius: 50%;
        border: 2px solid white;
        box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 12px;
        font-weight: bold;
      ">
        ${intensity}
      </div>
    `,
    className: 'custom-smell-marker',
    iconSize: [20, 20],
    iconAnchor: [10, 10],
  })
}

interface Annotation {
  id: string
  latitude: number
  longitude: number
  smell_intensity: number
  smell_type?: string
  description: string
  created_at: string
}

interface OSMMapProps {
  center?: [number, number]
  zoom?: number
  annotations?: Annotation[]
  onMapClick?: (lat: number, lng: number) => void
  showUserLocation?: boolean
  className?: string
}

// 用户位置组件
const UserLocationMarker: React.FC<{ position: [number, number] }> = ({ position }) => {
  const userIcon = L.divIcon({
    html: `
      <div style="
        background-color: #3b82f6;
        width: 16px;
        height: 16px;
        border-radius: 50%;
        border: 3px solid white;
        box-shadow: 0 2px 8px rgba(59, 130, 246, 0.4);
      "></div>
    `,
    className: 'user-location-marker',
    iconSize: [16, 16],
    iconAnchor: [8, 8],
  })

  return (
    <Marker position={position} icon={userIcon}>
      <Popup>
        <div className="text-center">
          <p className="font-semibold">你的位置</p>
          <p className="text-sm text-gray-600">
            {position[0].toFixed(4)}, {position[1].toFixed(4)}
          </p>
        </div>
      </Popup>
    </Marker>
  )
}

// 地图点击处理组件
const MapClickHandler: React.FC<{ onMapClick?: (lat: number, lng: number) => void }> = ({ onMapClick }) => {
  const map = useMap()

  useEffect(() => {
    if (!onMapClick) return

    const handleClick = (e: L.LeafletMouseEvent) => {
      onMapClick(e.latlng.lat, e.latlng.lng)
    }

    map.on('click', handleClick)
    return () => {
      map.off('click', handleClick)
    }
  }, [map, onMapClick])

  return null
}

export const OSMMap: React.FC<OSMMapProps> = ({
  center = [39.9042, 116.4074], // 默认北京
  zoom = 13,
  annotations = [],
  onMapClick,
  showUserLocation = true,
  className = ''
}) => {
  const [userLocation, setUserLocation] = useState<[number, number] | null>(null)
  const [mounted, setMounted] = useState(false)

  // 确保组件在客户端挂载
  useEffect(() => {
    setMounted(true)
    
    // 获取用户地理位置
    if (showUserLocation && navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords
          setUserLocation([latitude, longitude])
        },
        (error) => {
          console.warn('无法获取地理位置:', error.message)
        },
        { enableHighAccuracy: true, timeout: 10000 }
      )
    }
  }, [showUserLocation])

  if (!mounted) {
    return (
      <div className={`bg-gray-200 animate-pulse rounded-lg ${className}`}>
        <div className="h-full flex items-center justify-center">
          <p className="text-gray-500">地图加载中...</p>
        </div>
      </div>
    )
  }

  const mapCenter = userLocation || center

  return (
    <div className={`relative ${className}`}>
      <MapContainer
        center={mapCenter}
        zoom={zoom}
        className="h-full w-full rounded-lg"
        zoomControl={true}
      >
        {/* OpenStreetMap 瓦片层 */}
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          maxZoom={19}
        />
        
        {/* 地图点击事件处理 */}
        <MapClickHandler onMapClick={onMapClick} />
        
        {/* 用户位置标记 */}
        {userLocation && <UserLocationMarker position={userLocation} />}
        
        {/* 气味标注标记 */}
        {annotations.map((annotation) => (
          <Marker
            key={annotation.id}
            position={[annotation.latitude, annotation.longitude]}
            icon={createSmellIcon(annotation.smell_intensity, annotation.smell_type || 'unknown')}
          >
            <Popup maxWidth={300}>
              <div className="p-2">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold text-lg">
                    气味强度: {annotation.smell_intensity}/10
                  </span>
                  <span className="text-sm text-gray-500">
                    {annotation.smell_type || '未分类'}
                  </span>
                </div>
                <p className="text-sm mb-2">{annotation.description}</p>
                <div className="text-xs text-gray-400">
                  <p>位置: {annotation.latitude.toFixed(4)}, {annotation.longitude.toFixed(4)}</p>
                  <p>时间: {new Date(annotation.created_at).toLocaleString('zh-CN')}</p>
                </div>
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
      
      {/* 地图控制面板 */}
      <div className="absolute top-4 right-4 bg-white rounded-lg shadow-lg p-2 space-y-2 z-[1000]">
        <div className="text-xs text-gray-600">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span>轻微 (1-3)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <span>中等 (4-6)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span>强烈 (7-10)</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default OSMMap