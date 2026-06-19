import type { LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  actionTo?: string;
  onAction?: () => void;
}

export default function EmptyState({
  icon: Icon,
  title,
  description,
  actionLabel,
  actionTo,
  onAction,
}: EmptyStateProps) {
  return (
    <div className="card-modern flex flex-col items-center rounded-2xl p-12 text-center">
      <div className="gradient-primary mb-4 flex h-16 w-16 items-center justify-center rounded-2xl text-white shadow-lg">
        <Icon size={32} />
      </div>
      <h3 className="font-display text-xl font-bold text-ink">{title}</h3>
      <p className="mt-2 max-w-sm text-muted">{description}</p>
      {actionLabel && actionTo && (
        <Link to={actionTo} className="btn-accent mt-6 inline-flex rounded-full px-6 py-2.5 text-sm">
          {actionLabel}
        </Link>
      )}
      {actionLabel && onAction && !actionTo && (
        <button type="button" onClick={onAction} className="btn-accent mt-6 rounded-full px-6 py-2.5 text-sm">
          {actionLabel}
        </button>
      )}
    </div>
  );
}
