import { TransitionLink } from "@/components/transition-link"
import { ArrowRight } from "lucide-react"
import { allPosts } from "@/lib/blog-posts"

export default function BlogPage() {
  return (
    <div className="min-h-screen pt-32 pb-20">
      <div className="container mx-auto px-4">
        <h1 className="text-5xl md:text-7xl font-bold text-center mb-16">Our Blog</h1>
        <div className="max-w-3xl mx-auto space-y-12">
          {allPosts.map((post, index) => (
            <div key={index} className="border-b border-white/10 pb-8">
              <h2 className="text-3xl font-bold mb-4">{post.title}</h2>
              <p className="text-neutral-400 mb-6">{post.excerpt}</p>
              <TransitionLink
                href={`/blog/${post.slug}`}
                className="group text-white font-semibold flex items-center gap-2"
              >
                Read Full Article <ArrowRight className="transition-transform group-hover:translate-x-1" size={20} />
              </TransitionLink>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
