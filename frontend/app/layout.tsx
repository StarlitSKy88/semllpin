import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"
import { Header } from "@/components/header"
import { LanguageProvider } from "@/context/language-context"
import { QueryProvider } from '@/components/providers/query-provider'
import { AuthProvider } from '@/components/providers/auth-provider'
import { GlobalProvider } from '@/components/providers/global-provider'
import { ClientLayout } from '@/components/client-layout'

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
              <LanguageProvider>
                <ClientLayout>
                  <Header />
                  <main className="min-h-screen">{children}</main>
                </ClientLayout>
              </LanguageProvider>
            </GlobalProvider>
          </AuthProvider>
        </QueryProvider>
      </body>
    </html>
  )
}
