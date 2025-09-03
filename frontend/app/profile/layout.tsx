import { Metadata } from 'next';

export const metadata: Metadata = {
  title: '个人中心 - SmellPin',
  description: '管理您的个人资料、标注记录和收益统计',
};

export default function ProfileLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-cyan-50">
      {children}
    </div>
  );
}