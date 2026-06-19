import { useEffect, useRef, useState } from 'react';
import { Bell } from 'lucide-react';
import { extrasApi } from '../lib/api';
import type { AppNotification } from '../types';

export default function NotificationBell() {
  const [items, setItems] = useState<AppNotification[]>([]);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const unread = items.filter((n) => !n.read).length;

  const load = () => {
    extrasApi.notifications().then(setItems).catch(() => null);
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const markAll = async () => {
    await extrasApi.markAllRead();
    setItems((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="relative rounded-xl p-2 text-white transition hover:bg-white/10"
        aria-label="Notifications"
      >
        <Bell size={20} />
        {unread > 0 && (
          <span className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-2 w-80 max-h-96 overflow-y-auto rounded-2xl bg-card shadow-xl ring-1 ring-border">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="font-display font-bold text-ink">Notifications</span>
            {unread > 0 && (
              <button onClick={markAll} className="text-xs font-bold text-primary hover:text-accent">
                Mark all read
              </button>
            )}
          </div>
          {items.length === 0 ? (
            <p className="p-4 text-sm text-muted">No notifications yet.</p>
          ) : (
            items.map((n) => (
              <div
                key={n.id}
                className={`border-b border-border px-4 py-3 last:border-0 ${n.read ? 'opacity-70' : 'bg-primary/5'}`}
              >
                <p className="text-sm font-bold text-ink">{n.title}</p>
                <p className="mt-0.5 text-xs text-muted">{n.body}</p>
                <time className="mt-1 block text-[10px] text-muted">
                  {new Date(n.created_at).toLocaleString()}
                </time>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
