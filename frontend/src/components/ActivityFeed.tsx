import { Bookmark, Dumbbell } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { ActivityFeedItem } from '../types';

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins || 1}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function ActivityFeed({ items }: { items: ActivityFeedItem[] }) {
  if (items.length === 0) {
    return (
      <div className="card-modern rounded-2xl p-6 text-center text-muted">
        No activity yet. Log a workout or generate an AI plan!
      </div>
    );
  }

  return (
    <div className="card-modern rounded-2xl p-5">
      <h3 className="font-display mb-4 font-bold text-ink">Recent Activity</h3>
      <ul className="space-y-3">
        {items.map((item) => (
          <li key={`${item.type}-${item.id}`} className="flex items-start gap-3 rounded-xl bg-surface-2 p-3">
            <div
              className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-white ${
                item.type === 'workout' ? 'gradient-accent' : 'gradient-primary'
              }`}
            >
              {item.type === 'workout' ? <Dumbbell size={16} /> : <Bookmark size={16} />}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate font-semibold text-ink">{item.title}</p>
              <p className="text-sm text-muted">{item.subtitle}</p>
            </div>
            <time className="shrink-0 text-xs text-muted">{timeAgo(item.created_at)}</time>
          </li>
        ))}
      </ul>
      <Link to="/activity" className="mt-4 inline-block text-sm font-bold text-accent hover:text-primary">
        View all activity →
      </Link>
    </div>
  );
}
