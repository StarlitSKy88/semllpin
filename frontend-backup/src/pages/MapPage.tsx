import React from 'react';
import { MapPin, Navigation, Search, Filter } from 'lucide-react';

const MapPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* 页面头部 */}
      <div className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
              <MapPin className="h-6 w-6 text-blue-600" />
              SmellPin 地图
            </h1>
            <div className="flex items-center gap-4">
              <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                <Navigation className="h-4 w-4" />
                定位
              </button>
              <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                <Filter className="h-4 w-4" />
                筛选
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 搜索栏 */}
      <div className="bg-white border-b">
        <div className="container mx-auto px-4 py-3">
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="搜索地点或标注..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>
      </div>

      {/* 地图容器 */}
      <div className="flex-1 relative">
        <div className="absolute inset-0 bg-gray-200 flex items-center justify-center">
          <div className="text-center">
            <MapPin className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-600 mb-2">地图功能开发中</h3>
            <p className="text-gray-500 max-w-md">
              SmellPin 地图将展示所有用户创建的恶搞标注，您可以在这里探索附近的有趣内容，
              或者创建自己的标注与其他用户分享。
            </p>
            <div className="mt-6 space-y-2">
              <div className="flex items-center justify-center gap-2 text-sm text-gray-600">
                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                <span>恶搞标注</span>
              </div>
              <div className="flex items-center justify-center gap-2 text-sm text-gray-600">
                <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                <span>我的标注</span>
              </div>
              <div className="flex items-center justify-center gap-2 text-sm text-gray-600">
                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                <span>已发现标注</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 底部操作栏 */}
      <div className="bg-white border-t p-4">
        <div className="container mx-auto">
          <div className="flex justify-center">
            <button className="bg-gradient-to-r from-purple-600 to-blue-600 text-white px-8 py-3 rounded-full font-semibold hover:from-purple-700 hover:to-blue-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105">
              创建新标注
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MapPage;