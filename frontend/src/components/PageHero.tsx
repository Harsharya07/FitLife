import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

interface PageHeroProps {
  title: string;
  subtitle: string;
  icon?: ReactNode;
  children?: ReactNode;
  image?: string;
}

export default function PageHero({ title, subtitle, icon, children, image }: PageHeroProps) {
  return (
    <motion.section
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="relative mx-4 mt-6 overflow-hidden rounded-3xl shadow-2xl shadow-primary/10 sm:mx-auto sm:max-w-6xl"
      style={
        image
          ? {
              backgroundImage: `linear-gradient(135deg, rgba(109,40,217,0.88) 0%, rgba(99,102,241,0.82) 45%, rgba(20,184,166,0.72) 100%), url(${image})`,
              backgroundSize: 'cover',
              backgroundPosition: 'center',
            }
          : undefined
      }
    >
      <div className={`relative px-6 py-12 text-center sm:px-10 sm:py-14 ${!image ? 'gradient-hero' : ''}`}>
        <div className="gradient-mesh-overlay pointer-events-none absolute inset-0" />
        <div className="relative z-10">
          <h1 className="font-display flex items-center justify-center gap-3 text-2xl font-extrabold tracking-tight text-white drop-shadow-sm sm:text-4xl">
            {icon}
            {title}
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-base font-medium leading-relaxed text-white/90 sm:text-lg">
            {subtitle}
          </p>
          {children && <div className="mt-8">{children}</div>}
        </div>
        <div className="pointer-events-none absolute inset-0 shimmer opacity-20" />
      </div>
    </motion.section>
  );
}
