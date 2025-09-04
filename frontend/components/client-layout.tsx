'use client';

import React from 'react';
import dynamic from 'next/dynamic';

// Client-side dynamic imports with ssr: false
const Footer = dynamic(() => import("@/components/footer").then(mod => ({ default: mod.Footer })), {
  ssr: false,
  loading: () => null
});

const GsapProvider = dynamic(() => import("@/components/gsap-provider").then(mod => ({ default: mod.GsapProvider })), {
  ssr: false
});

const TransitionProvider = dynamic(() => import("@/components/transition-provider").then(mod => ({ default: mod.TransitionProvider })), {
  ssr: false
});

const NotificationProvider = dynamic(() => import('@/components/notifications/notification-provider'), {
  ssr: false
});

const Toaster = dynamic(() => import('sonner').then(mod => ({ default: mod.Toaster })), {
  ssr: false
});

const ServiceWorkerProvider = dynamic(() => import('@/components/service-worker-provider').then(mod => ({ default: mod.ServiceWorkerProvider })), {
  ssr: false
});

interface ClientLayoutProps {
  children: React.ReactNode;
}

export function ClientLayout({ children }: ClientLayoutProps) {
  return (
    <NotificationProvider>
      <GsapProvider>
        <TransitionProvider>
          {children}
          <Footer />
        </TransitionProvider>
      </GsapProvider>
      <ServiceWorkerProvider />
      <Toaster position="top-right" richColors />
    </NotificationProvider>
  );
}