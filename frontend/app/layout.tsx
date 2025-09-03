import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import dynamic from "next/dynamic"
import "./globals.css"
import { Header } from "@/components/header"
import { LanguageProvider } from "@/context/language-context"
import { QueryProvider } from '@/components/providers/query-provider'
import { AuthProvider } from '@/components/providers/auth-provider'
import { GlobalProvider } from '@/components/providers/global-provider'

// Lazy load non-critical components for better performance
const Footer = dynamic(() => import("@/components/footer").then(mod => ({ default: mod.Footer })), {
  ssr: false,
  loading: () => null
})

const GsapProvider = dynamic(() => import("@/components/gsap-provider").then(mod => ({ default: mod.GsapProvider })), {
  ssr: false
})

const TransitionProvider = dynamic(() => import("@/components/transition-provider").then(mod => ({ default: mod.TransitionProvider })), {
  ssr: false
})

const NotificationProvider = dynamic(() => import('@/components/notifications/notification-provider'), {
  ssr: false
})

const Toaster = dynamic(() => import('sonner').then(mod => ({ default: mod.Toaster })), {
  ssr: false
})

const ServiceWorkerProvider = dynamic(() => import('@/components/service-worker-provider').then(mod => ({ default: mod.ServiceWorkerProvider })), {
  ssr: false
})

const inter = Inter({ 
  subsets: ["latin"],
  display: 'swap',
  preload: true,
  variable: '--font-inter'
})

export const metadata: Metadata = {
  title: "SmellPin - Global Smell Annotation Platform",
  description:
    "Share and discover smell experiences worldwide. The global platform for smell annotations, rewards, and community insights.",
  generator: 'SmellPin v1.0',
  robots: 'index, follow',
  viewport: 'width=device-width, initial-scale=1, viewport-fit=cover',
  themeColor: '#0a0a0a',
  category: 'Social Platform',
  keywords: 'smell, annotation, location, community, rewards, LBS',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://smellpin.com',
    siteName: 'SmellPin',
    title: 'SmellPin - Global Smell Annotation Platform',
    description: 'Share and discover smell experiences worldwide',
  },
  twitter: {
    card: 'summary_large_image',
    site: '@smellpin',
    creator: '@smellpin'
  },
  manifest: '/manifest.json',
  icons: {
    icon: '/favicon.ico',
    apple: '/apple-touch-icon.png'
  }
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${inter.variable} font-sans`}>
      <head>
        <link rel="dns-prefetch" href="//fonts.googleapis.com" />
        <link rel="dns-prefetch" href="//cdnjs.cloudflare.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <meta name="format-detection" content="telephone=no" />
      </head>
      <body className="bg-[#0a0a0a] text-white antialiased">
        <QueryProvider>
          <AuthProvider>
            <GlobalProvider>
              <NotificationProvider>
                <LanguageProvider>
                  <GsapProvider>
                    <TransitionProvider>
                      <Header />
                      <main className="min-h-screen">{children}</main>
                      <Footer />
                    </TransitionProvider>
                  </GsapProvider>
                </LanguageProvider>
              </NotificationProvider>
            </GlobalProvider>
          </AuthProvider>
        </QueryProvider>
        <ServiceWorkerProvider />
        <Toaster position="top-right" richColors />
      </body>
    </html>
  )
}
