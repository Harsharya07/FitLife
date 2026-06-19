import { Activity, Bookmark, Bot, Dumbbell, Home, MoreHorizontal } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

const mainItems = [
  { to: '/dashboard', label: 'Home', icon: Home },
  { to: '/exercises', label: 'Workouts', icon: Dumbbell },
  { to: '/ai-coach', label: 'Coach', icon: Bot },
  { to: '/my-plans', label: 'Plans', icon: Bookmark },
];

const moreItems = [
  { to: '/activity', label: 'Activity', icon: Activity },
  { to: '/articles', label: 'Articles' },
  { to: '/recipes', label: 'Recipes' },
  { to: '/blogs', label: 'Blogs' },
  { to: '/contact', label: 'Contact' },
  { to: '/settings', label: 'Settings' },
];

export default function BottomNav() {
  const location = useLocation();
  const [moreOpen, setMoreOpen] = useState(false);

  return (
    <>
      <nav
        className="fixed bottom-0 left-0 right-0 z-50 border-t border-border bg-card/95 backdrop-blur-lg lg:hidden"
        aria-label="Mobile navigation"
      >
        <ul className="flex items-center justify-around px-2 py-2 pb-[max(0.5rem,env(safe-area-inset-bottom))]">
          {mainItems.map(({ to, label, icon: Icon }) => {
            const active = location.pathname === to;
            return (
              <li key={to}>
                <Link
                  to={to}
                  className={`flex flex-col items-center gap-0.5 rounded-xl px-3 py-1.5 text-xs font-semibold transition focus-visible:ring-2 focus-visible:ring-primary ${
                    active ? 'text-primary' : 'text-muted'
                  }`}
                >
                  <Icon size={22} strokeWidth={active ? 2.5 : 2} />
                  {label}
                </Link>
              </li>
            );
          })}
          <li>
            <button
              onClick={() => setMoreOpen(true)}
              className="flex flex-col items-center gap-0.5 rounded-xl px-3 py-1.5 text-xs font-semibold text-muted"
              aria-label="More pages"
            >
              <MoreHorizontal size={22} />
              More
            </button>
          </li>
        </ul>
      </nav>

      <AnimatePresence>
        {moreOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] bg-black/40 lg:hidden"
              onClick={() => setMoreOpen(false)}
            />
            <motion.div
              initial={{ y: '100%' }}
              animate={{ y: 0 }}
              exit={{ y: '100%' }}
              className="fixed bottom-0 left-0 right-0 z-[70] rounded-t-2xl bg-card p-4 pb-8 lg:hidden"
            >
              <p className="font-display mb-3 font-bold text-ink">More</p>
              <div className="grid grid-cols-2 gap-2">
                {moreItems.map(({ to, label }) => (
                  <Link
                    key={to}
                    to={to}
                    onClick={() => setMoreOpen(false)}
                    className="rounded-xl bg-surface-2 px-4 py-3 text-sm font-semibold text-ink"
                  >
                    {label}
                  </Link>
                ))}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
