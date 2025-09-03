"use client"

import Image from "next/image"
import { motion } from "framer-motion"
import TransitionLink from "./transition-link"
import { Star, Download, DollarSign } from "lucide-react"

const documents = [
  {
    title: "ChatGPT Advanced Prompts",
    description: "Professional prompt engineering techniques for ChatGPT optimization.",
    price: "$29",
    rating: 4.9,
    downloads: 1240,
    imgSrc: "/ai-chatbot-interface-with-chat-bubbles.png",
    href: "/docs/chatgpt-prompts",
    category: "Prompts",
  },
  {
    title: "AI Agent Workflow Builder",
    description: "Complete guide to building autonomous AI agents with step-by-step workflows.",
    price: "$49",
    rating: 4.8,
    downloads: 890,
    imgSrc: "/ai-workflow-diagram-with-nodes-and-connections.png",
    href: "/docs/ai-agent-workflow",
    category: "Workflows",
  },
  {
    title: "LangChain Implementation Guide",
    description: "Comprehensive documentation for LangChain integration and best practices.",
    price: "$39",
    rating: 4.7,
    downloads: 650,
    imgSrc: "/programming-code-interface-with-ai-elements.png",
    href: "/docs/langchain-guide",
    category: "Implementation",
  },
  {
    title: "RAG System Architecture",
    description: "Advanced Retrieval-Augmented Generation system design and implementation.",
    price: "$59",
    rating: 4.9,
    downloads: 420,
    imgSrc: "/database-and-ai-brain-connection-diagram.png",
    href: "/docs/rag-architecture",
    category: "Architecture",
  },
  {
    title: "AI Customer Service Bot",
    description: "Ready-to-deploy customer service AI bot with training data and scripts.",
    price: "$35",
    rating: 4.6,
    downloads: 780,
    imgSrc: "/customer-service-chatbot.png",
    href: "/docs/customer-service-bot",
    category: "Bots",
  },
  {
    title: "Multi-Modal AI Pipeline",
    description: "Complete pipeline for processing text, image, and audio with AI models.",
    price: "$69",
    rating: 4.8,
    downloads: 320,
    imgSrc: "/multimedia-ai-processing-pipeline-diagram.png",
    href: "/docs/multimodal-pipeline",
    category: "Pipelines",
  },
]

export function Portfolio() {
  return (
    <div id="marketplace" className="relative py-20 px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-16">
        <h2 className="text-4xl md:text-5xl font-bold tracking-tight">Featured Documentation</h2>
        <p className="mt-4 max-w-2xl mx-auto text-lg text-neutral-400">
          Discover premium AI agent documentation, workflows, and implementation guides from expert developers.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-7xl mx-auto">
        {documents.map((doc, index) => (
          <motion.div
            key={doc.title}
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            viewport={{ once: true }}
          >
            <TransitionLink href={doc.href}>
              <div className="group relative block w-full bg-neutral-900/50 backdrop-blur-sm rounded-xl overflow-hidden border border-neutral-800 hover:border-blue-500/50 transition-all duration-300">
                <div className="relative h-48 overflow-hidden">
                  <Image
                    src={doc.imgSrc || "/placeholder.svg"}
                    fill
                    alt={doc.title}
                    className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110"
                  />
                  <div className="absolute top-3 left-3">
                    <span className="bg-blue-500/90 text-white text-xs font-medium px-2 py-1 rounded-full">
                      {doc.category}
                    </span>
                  </div>
                  <div className="absolute top-3 right-3">
                    <span className="bg-black/70 text-white text-sm font-bold px-2 py-1 rounded-full">{doc.price}</span>
                  </div>
                </div>

                <div className="p-6">
                  <h3 className="text-xl font-bold mb-2 group-hover:text-blue-400 transition-colors">{doc.title}</h3>
                  <p className="text-neutral-400 text-sm mb-4 line-clamp-2">{doc.description}</p>

                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-1 text-yellow-400">
                        <Star size={14} fill="currentColor" />
                        <span>{doc.rating}</span>
                      </div>
                      <div className="flex items-center gap-1 text-neutral-400">
                        <Download size={14} />
                        <span>{doc.downloads}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 text-green-400 font-medium">
                      <DollarSign size={14} />
                      <span>{doc.price.replace("$", "")}</span>
                    </div>
                  </div>
                </div>
              </div>
            </TransitionLink>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
