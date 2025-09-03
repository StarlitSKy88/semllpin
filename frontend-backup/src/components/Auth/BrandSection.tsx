import React from 'react';
import clsx from 'clsx';
import { Smile } from 'lucide-react';
import { Typography } from 'antd';
import { FadeIn, SlideUp } from '../OptimizedMotion';

const { Title, Text } = Typography;

interface BrandSectionProps {
  className?: string;
}

/**
 * 认证页面左侧/顶部的品牌展示区域
 */
export const BrandSection: React.FC<BrandSectionProps> = ({ className }) => {
  return (
    <div
      className={clsx(
        'flex items-center justify-center bg-gradient-to-br from-orange-400 via-pink-500 to-purple-600 relative overflow-hidden',
        className,
      )}
    >
      {/* 背景装饰 */}
      <div className="absolute inset-0 bg-black/10" />
      <div className="absolute top-10 left-10 w-32 h-32 bg-white/10 rounded-full blur-xl" />
      <div className="absolute bottom-20 right-20 w-48 h-48 bg-white/5 rounded-full blur-2xl" />

      {/* 品牌内容 */}
      <div className="relative z-10 text-center text-white px-12 max-w-lg">
        <FadeIn className="inline-flex items-center justify-center w-28 h-28 sm:w-32 sm:h-32 bg-white/20 backdrop-blur-sm rounded-full mb-6 shadow-2xl">
          <Smile size={56} className="text-white" />
        </FadeIn>

        <SlideUp>
          <Title level={1} className="text-white mb-2 sm:mb-4 text-4xl sm:text-5xl font-bold">
            SmellPin
          </Title>
          <Text className="text-xl sm:text-2xl text-white/90 block mb-4">
            全球搞笑臭味恶搞标注平台
          </Text>
          <Text className="text-base sm:text-lg text-white/80 block leading-relaxed">
            发现身边的搞笑瞬间，分享你的创意恶搞，让世界充满欢声笑语！
          </Text>
        </SlideUp>

        {/* 特色功能列表 */}
        <FadeIn className="mt-8 grid grid-cols-1 gap-3 sm:gap-4">
          {[
            '🗺️ 实时地图标注',
            '😄 搞笑内容分享',
            '🏆 社区互动排行',
          ].map((text) => (
            <div key={text} className="flex items-center space-x-3 text-white/90">
              <div className="w-2 h-2 bg-white rounded-full" />
              <Text className="text-white/90">{text}</Text>
            </div>
          ))}
        </FadeIn>
      </div>
    </div>
  );
};