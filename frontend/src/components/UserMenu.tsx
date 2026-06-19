import { AnimatePresence, motion } from 'framer-motion';
import {
  Bookmark,
  Bot,
  ChevronDown,
  Home,
  LogOut,
  Settings,
  Shield,
  User,
} from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface UserMenuProps {
  streak?: number;
}

export default function UserMenu({ streak = 0 }: UserMenuProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  if (!user) return null;

  const initial = user.username.charAt(0).toUpperCase();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 rounded-xl bg-white/15 px-2 py-1.5 text-white transition hover:bg-white/25 focus-visible:ring-2 focus-visible:ring-white/50"
        aria-expanded={open}
        aria-haspopup="menu"
      >
        <span className="gradient-accent flex h-8 w-8 items-center justify-center rounded-lg text-sm font-bold">
          {initial}
        </span>
        <span className="hidden max-w-[100px] truncate text-sm font-semibold lg:block">{user.username}</span>
        {streak > 0 && (
          <span className="hidden rounded-full bg-orange-400/90 px-2 py-0.5 text-xs font-bold lg:inline">
            🔥 {streak}
          </span>
        )}
        <ChevronDown size={16} className={`transition ${open ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {open && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} aria-hidden="true" />
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="absolute right-0 z-50 mt-2 w-52 overflow-hidden rounded-xl border border-border bg-card py-1 shadow-xl"
              role="menu"
            >
              <div className="border-b border-border px-4 py-3">
                <p className="font-display font-bold text-ink">{user.username}</p>
                {streak > 0 && <p className="text-xs text-muted">{streak}-day streak 🔥</p>}
              </div>
              {[
                { to: '/dashboard', icon: Home, label: 'Dashboard' },
                { to: '/my-plans', icon: Bookmark, label: 'My Plans' },
                { to: '/ai-coach', icon: Bot, label: 'AI Coach' },
                { to: '/activity', icon: User, label: 'Activity' },
                { to: '/settings', icon: Settings, label: 'Settings' },
              ].map(({ to, icon: Icon, label }) => (
                <Link
                  key={to}
                  to={to}
                  onClick={() => setOpen(false)}
                  className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-ink hover:bg-surface-2"
                  role="menuitem"
                >
                  <Icon size={16} className="text-primary" /> {label}
                </Link>
              ))}
              {user.is_admin && (
                <>
                  <Link
                    to="/admin/contacts"
                    onClick={() => setOpen(false)}
                    className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-ink hover:bg-surface-2"
                  >
                    <Shield size={16} className="text-primary" /> Admin Inbox
                  </Link>
                  <Link
                    to="/admin/analytics"
                    onClick={() => setOpen(false)}
                    className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-ink hover:bg-surface-2"
                  >
                    <Shield size={16} className="text-primary" /> Analytics
                  </Link>
                </>
              )}
              <button
                onClick={handleLogout}
                className="flex w-full items-center gap-2 border-t border-border px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50"
                role="menuitem"
              >
                <LogOut size={16} /> Logout
              </button>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
