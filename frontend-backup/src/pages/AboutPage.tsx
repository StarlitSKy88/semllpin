import React from 'react';
import { MapPin, Users, Zap, Shield, Heart, Globe } from 'lucide-react';

const AboutPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-indigo-100">
      {/* 英雄区域 */}
      <div className="relative overflow-hidden bg-gradient-to-r from-purple-600 to-blue-600 text-white">
        <div className="absolute inset-0 bg-black opacity-10"></div>
        <div className="relative container mx-auto px-4 py-20">
          <div className="text-center max-w-4xl mx-auto">
            <div className="flex justify-center mb-6">
              <div className="bg-white bg-opacity-20 p-4 rounded-full">
                <MapPin className="h-12 w-12" />
              </div>
            </div>
            <h1 className="text-5xl font-bold mb-6">关于 SmellPin</h1>
            <p className="text-xl opacity-90 leading-relaxed">
              SmellPin 是一个基于地理位置的搞笑恶搞标注平台，让用户通过创意和幽默连接世界各地的有趣故事。
            </p>
          </div>
        </div>
      </div>

      {/* 核心功能介绍 */}
      <div className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">我们的愿景</h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              通过地理位置连接用户，创造有趣的社交体验，建立可持续的用户激励机制。
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center group">
              <div className="bg-gradient-to-br from-purple-500 to-pink-500 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform duration-300">
                <MapPin className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-2xl font-semibold text-gray-900 mb-4">地理标注</h3>
              <p className="text-gray-600 leading-relaxed">
                在地图上创建付费恶搞标注，让其他用户通过LBS服务发现并获得奖励。
              </p>
            </div>

            <div className="text-center group">
              <div className="bg-gradient-to-br from-blue-500 to-cyan-500 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform duration-300">
                <Users className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-2xl font-semibold text-gray-900 mb-4">社交互动</h3>
              <p className="text-gray-600 leading-relaxed">
                与全球用户分享有趣的恶搞内容，通过幽默和创意建立社交连接。
              </p>
            </div>

            <div className="text-center group">
              <div className="bg-gradient-to-br from-green-500 to-emerald-500 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform duration-300">
                <Zap className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-2xl font-semibold text-gray-900 mb-4">奖励机制</h3>
              <p className="text-gray-600 leading-relaxed">
                发现标注即可获得奖励，创建优质内容还能获得更多收益。
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* 平台特色 */}
      <div className="bg-white py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">平台特色</h2>
            <p className="text-xl text-gray-600">
              为什么选择 SmellPin？
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <div className="bg-gradient-to-br from-purple-50 to-blue-50 p-8 rounded-2xl hover:shadow-lg transition-shadow duration-300">
              <Shield className="h-10 w-10 text-purple-600 mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-3">安全可靠</h3>
              <p className="text-gray-600">
                严格的内容审核机制，确保平台内容健康有趣，保护用户隐私和数据安全。
              </p>
            </div>

            <div className="bg-gradient-to-br from-blue-50 to-cyan-50 p-8 rounded-2xl hover:shadow-lg transition-shadow duration-300">
              <Heart className="h-10 w-10 text-blue-600 mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-3">用户友好</h3>
              <p className="text-gray-600">
                简洁直观的界面设计，让每个用户都能轻松上手，享受创作和发现的乐趣。
              </p>
            </div>

            <div className="bg-gradient-to-br from-green-50 to-emerald-50 p-8 rounded-2xl hover:shadow-lg transition-shadow duration-300">
              <Globe className="h-10 w-10 text-green-600 mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-3">全球覆盖</h3>
              <p className="text-gray-600">
                支持全球范围内的地理标注，让世界各地的用户都能参与这个有趣的社区。
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* 团队介绍 */}
      <div className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">我们的团队</h2>
            <p className="text-xl text-gray-600">
              由一群热爱创新和幽默的开发者组成
            </p>
          </div>

          <div className="bg-white rounded-3xl shadow-xl p-12 text-center">
            <div className="max-w-3xl mx-auto">
              <h3 className="text-2xl font-semibold text-gray-900 mb-6">致力于创新</h3>
              <p className="text-lg text-gray-600 leading-relaxed mb-8">
                我们相信技术应该让生活更有趣。SmellPin 团队致力于通过创新的地理位置服务，
                为用户创造独特的社交体验，让每个地方都有属于它的有趣故事。
              </p>
              <div className="flex justify-center space-x-8">
                <div className="text-center">
                  <div className="text-3xl font-bold text-purple-600">10K+</div>
                  <div className="text-gray-600">活跃用户</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-blue-600">50K+</div>
                  <div className="text-gray-600">创建标注</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-green-600">100+</div>
                  <div className="text-gray-600">覆盖城市</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 联系我们 */}
      <div className="bg-gradient-to-r from-purple-600 to-blue-600 text-white py-16">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-3xl font-bold mb-4">加入 SmellPin 社区</h2>
          <p className="text-xl opacity-90 mb-8">
            开始您的创意标注之旅，发现世界各地的有趣故事
          </p>
          <div className="flex justify-center gap-4">
            <button className="bg-white text-purple-600 px-8 py-3 rounded-full font-semibold hover:bg-gray-100 transition-colors">
              立即注册
            </button>
            <button className="border-2 border-white text-white px-8 py-3 rounded-full font-semibold hover:bg-white hover:text-purple-600 transition-colors">
              了解更多
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AboutPage;