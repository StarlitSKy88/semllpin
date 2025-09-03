import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowUp } from 'lucide-react';

interface BackToTopProps {
  threshold?: number;
  className?: string;
  smooth?: boolean;
}

const BackToTop: React.FC<BackToTopProps> = ({ 
  threshold = 300, 
  className = '',
  smooth = true 
}) => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const toggleVisibility = () => {
      if (window.pageYOffset > threshold) {
        setIsVisible(true);
      } else {
        setIsVisible(false);
      }
    };

    window.addEventListener('scroll', toggleVisibility);
    return () => window.removeEventListener('scroll', toggleVisibility);
  }, [threshold]);

  const scrollToTop = () => {
    if (smooth) {
      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    } else {
      window.scrollTo(0, 0);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      scrollToTop();
    }
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.button
          initial={{ opacity: 0, scale: 0.8, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.8, y: 20 }}
          transition={{ duration: 0.3 }}
          onClick={scrollToTop}
          onKeyDown={handleKeyDown}
          className={`
            fixed bottom-6 right-6 z-50
            w-12 h-12 rounded-full
            bg-gradient-to-r from-purple-500 to-pink-500
            text-white shadow-lg
            flex items-center justify-center
            hover:shadow-xl hover:scale-110
            focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2
            transition-all duration-300
            ${className}
          `}
          aria-label="返回顶部"
          title="返回顶部"
          type="button"
        >
          <ArrowUp className="w-5 h-5" aria-hidden={true} />
        </motion.button>
      )}
    </AnimatePresence>
  );
};

// 快速导航组件
interface QuickNavigationProps {
  sections: Array<{
    id: string;
    label: string;
    icon?: React.ReactNode;
  }>;
  className?: string;
}

export const QuickNavigation: React.FC<QuickNavigationProps> = ({ 
  sections, 
  className = '' 
}) => {
  const [activeSection, setActiveSection] = useState<string>('');

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      {
        threshold: 0.5,
        rootMargin: '-20% 0px -20% 0px'
      }
    );

    sections.forEach(({ id }) => {
      const element = document.getElementById(id);
      if (element) {
        observer.observe(element);
      }
    });

    return () => observer.disconnect();
  }, [sections]);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    }
  };

  return (
    <nav 
      className={`
        fixed left-6 top-1/2 transform -translate-y-1/2 z-40
        hidden lg:block
        ${className}
      `}
      aria-label="页面导航"
    >
      <ul className="space-y-2">
        {sections.map(({ id, label, icon }) => (
          <li key={id}>
            <button
              onClick={() => scrollToSection(id)}
              className={`
                group relative flex items-center
                w-3 h-3 rounded-full
                transition-all duration-300
                focus:outline-none focus:ring-2 focus:ring-purple-500
                ${
                  activeSection === id
                    ? 'bg-purple-500 scale-150'
                    : 'bg-gray-300 hover:bg-purple-300'
                }
              `}
              aria-label={`跳转到${label}`}
              title={label}
            >
              {icon && (
                <span className="absolute left-6 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  {icon}
                </span>
              )}
              <span className="sr-only">{label}</span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
};

// 面包屑导航组件
interface BreadcrumbItem {
  label: string;
  href?: string;
  current?: boolean;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  separator?: React.ReactNode;
  className?: string;
}

export const Breadcrumb: React.FC<BreadcrumbProps> = ({ 
  items, 
  separator = '/', 
  className = '' 
}) => {
  return (
    <nav 
      aria-label="面包屑导航" 
      className={`text-sm ${className}`}
    >
      <ol className="flex items-center space-x-2">
        {items.map((item, index) => (
          <li key={`item-${index}`} className="flex items-center">
            {index > 0 && (
              <span className="mx-2 text-gray-400" aria-hidden={true}>
                {separator}
              </span>
            )}
            {item.current ? (
              <span 
                className="text-gray-900 font-medium"
                aria-current="page"
              >
                {item.label}
              </span>
            ) : (
              <a 
                href={item.href}
                className="text-purple-600 hover:text-purple-800 transition-colors duration-200"
              >
                {item.label}
              </a>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
};

export default BackToTop;