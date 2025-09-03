import { Hero } from "@/components/hero"
import { WaterfallFeed } from "@/components/waterfall-feed"
import { BlogPreview } from "@/components/blog-preview"
import NotificationBanners from "@/components/notifications/notification-banner"

export default function Home() {
  return (
    <div className="bg-black min-h-screen">
      <div className="container mx-auto px-4 pt-24">
        <NotificationBanners />
      </div>
      <Hero />
      <WaterfallFeed />
      <BlogPreview />
    </div>
  )
}
