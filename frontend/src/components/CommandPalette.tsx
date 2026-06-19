import { AnimatePresence, motion } from 'framer-motion';
import { Bookmark, Bot, Dumbbell, Home, Search, Settings } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { contentApi, plansApi } from '../lib/api';

interface SearchItem {
  id: string;
  label: string;
  sub?: string;
  to: string;
  icon?: React.ReactNode;
}

const STATIC: SearchItem[] = [
  { id: 'nav-dashboard', label: 'Dashboard', to: '/dashboard', icon: <Home size={16} /> },
  { id: 'nav-exercises', label: 'Exercises', to: '/exercises', icon: <Dumbbell size={16} /> },
  { id: 'nav-coach', label: 'AI Coach', to: '/ai-coach', icon: <Bot size={16} /> },
  { id: 'nav-plans', label: 'My Plans', to: '/my-plans', icon: <Bookmark size={16} /> },
  { id: 'nav-activity', label: 'Activity & Progress', to: '/activity' },
  { id: 'nav-articles', label: 'Articles', to: '/articles' },
  { id: 'nav-recipes', label: 'Recipes', to: '/recipes' },
  { id: 'nav-settings', label: 'Settings', to: '/settings', icon: <Settings size={16} /> },
];

export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [dynamic, setDynamic] = useState<SearchItem[]>([]);
  const navigate = useNavigate();

  const loadDynamic = useCallback(async () => {
    try {
      const [exercises, plans] = await Promise.all([
        contentApi.exercises(),
        plansApi.list(),
      ]);
      const exItems: SearchItem[] = exercises.flatMap((cat) =>
        cat.exercises.map((ex) => ({
          id: `ex-${ex.id}`,
          label: ex.name,
          sub: cat.name,
          to: '/exercises',
        })),
      );
      const planItems: SearchItem[] = plans.map((p) => ({
        id: `plan-${p.id}`,
        label: p.title,
        sub: p.plan_type,
        to: '/my-plans',
      }));
      setDynamic([...exItems, ...planItems]);
    } catch {
      setDynamic([]);
    }
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (open) loadDynamic();
  }, [open, loadDynamic]);

  const all = [...STATIC, ...dynamic];
  const q = query.toLowerCase();
  const filtered = q
    ? all.filter((item) => item.label.toLowerCase().includes(q) || item.sub?.toLowerCase().includes(q))
    : all.slice(0, 12);

  const go = (to: string) => {
    navigate(to);
    setOpen(false);
    setQuery('');
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="hidden items-center gap-2 rounded-xl bg-white/10 px-3 py-1.5 text-sm text-white/80 transition hover:bg-white/20 md:flex"
        aria-label="Open search"
      >
        <Search size={16} />
        <span>Search</span>
        <kbd className="rounded bg-white/15 px-1.5 py-0.5 text-xs">⌘K</kbd>
      </button>

      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[100] bg-black/50 backdrop-blur-sm"
              onClick={() => setOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: -20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: -20 }}
              className="fixed left-1/2 top-[15%] z-[101] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 overflow-hidden rounded-2xl border border-border bg-card shadow-2xl"
              role="dialog"
              aria-label="Command palette"
            >
              <div className="flex items-center gap-2 border-b border-border px-4">
                <Search size={18} className="text-muted" />
                <input
                  autoFocus
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search pages, exercises, plans..."
                  className="flex-1 border-0 bg-transparent py-4 text-ink outline-none"
                />
              </div>
              <ul className="max-h-72 overflow-y-auto py-2">
                {filtered.length === 0 ? (
                  <li className="px-4 py-6 text-center text-muted">No results</li>
                ) : (
                  filtered.map((item) => (
                    <li key={item.id}>
                      <button
                        onClick={() => go(item.to)}
                        className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-2"
                      >
                        <span className="text-primary">{item.icon || <Dumbbell size={16} />}</span>
                        <span className="flex-1">
                          <span className="block font-medium text-ink">{item.label}</span>
                          {item.sub && <span className="text-xs text-muted">{item.sub}</span>}
                        </span>
                      </button>
                    </li>
                  ))
                )}
              </ul>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
