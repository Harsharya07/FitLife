import { Link, useLocation } from 'react-router-dom';
import { Activity, Bot, Dumbbell, Home, Menu, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import FitLifeLogo from './FitLifeLogo';
import UserMenu from './UserMenu';
import CommandPalette from './CommandPalette';
import NotificationBell from './NotificationBell';

const navItems = [
  { to: '/dashboard', label: 'Home', icon: Home },
  { to: '/exercises', label: 'Exercises', icon: Dumbbell },
  { to: '/ai-coach', label: 'AI Coach', icon: Bot },
  { to: '/activity', label: 'Activity', icon: Activity },
];

interface NavbarProps {
  streak?: number;
}

export default function Navbar({ streak = 0 }: NavbarProps) {
  const { user } = useAuth();
  const location = useLocation();
  const [open, setOpen] = useState(false);

  if (!user) return null;

  return (
    <nav className="gradient-nav sticky top-0 z-50 shadow-lg shadow-indigo-900/20">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3.5 sm:px-6 lg:px-8">
        <FitLifeLogo to="/dashboard" ring textClassName="text-white hidden sm:inline" className="group" />

        <ul className="hidden items-center gap-0.5 lg:flex">
          {navItems.map(({ to, label, icon: Icon }) => (
            <li key={to}>
              <Link
                to={to}
                className={`flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-sm font-semibold transition-all duration-200 focus-visible:ring-2 focus-visible:ring-white/50 ${
                  location.pathname === to
                    ? 'bg-white/20 text-white shadow-inner backdrop-blur-sm'
                    : 'text-white/85 hover:bg-white/10 hover:text-white'
                }`}
              >
                <Icon size={16} />
                {label}
              </Link>
            </li>
          ))}
        </ul>

        <div className="flex items-center gap-2">
          <CommandPalette />
          <NotificationBell />
          <UserMenu streak={streak} />
          <button
            className="rounded-xl p-2 text-white transition hover:bg-white/10 lg:hidden"
            onClick={() => setOpen(!open)}
            aria-label="Toggle menu"
          >
            {open ? <X size={26} /> : <Menu size={26} />}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden border-t border-white/10 bg-black/10 backdrop-blur-md lg:hidden"
          >
            <ul className="flex flex-col gap-1 px-4 py-3">
              {navItems.map(({ to, label, icon: Icon }) => (
                <li key={to}>
                  <Link
                    to={to}
                    onClick={() => setOpen(false)}
                    className={`flex items-center gap-2 rounded-xl px-4 py-3 font-semibold transition ${
                      location.pathname === to
                        ? 'bg-white/20 text-white'
                        : 'text-white/90 hover:bg-white/10'
                    }`}
                  >
                    <Icon size={18} />
                    {label}
                  </Link>
                </li>
              ))}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}
