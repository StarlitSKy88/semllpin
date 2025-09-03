import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"

export default function ContactPage() {
  return (
    <div className="min-h-screen flex items-center justify-center pt-24 pb-12">
      <div className="container mx-auto px-4 max-w-2xl text-center">
        <h1 className="text-5xl md:text-7xl font-bold mb-4">联系我们</h1>
        <p className="text-lg text-neutral-300 mb-12">有任何问题或建议？我们很乐意听到您的声音。无论是技术支持、合作咨询还是用户反馈，都欢迎与SmellPin团队联系。</p>
        <form className="space-y-6 text-left">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input type="text" placeholder="您的姓名" className="bg-[#1a1a1a] border-neutral-700 text-white" />
            <Input type="email" placeholder="您的邮箱" className="bg-[#1a1a1a] border-neutral-700 text-white" />
          </div>
          <Input type="text" placeholder="主题（如：技术支持、合作咨询、用户反馈）" className="bg-[#1a1a1a] border-neutral-700 text-white" />
          <Textarea placeholder="请详细描述您的问题或建议..." rows={6} className="bg-[#1a1a1a] border-neutral-700 text-white" />
          <div className="text-center">
            <Button
              type="submit"
              size="lg"
              className="bg-white text-black hover:bg-neutral-200 font-bold text-lg px-10 py-6"
            >
              发送消息
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
