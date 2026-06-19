import { Link } from 'react-router-dom';

interface ProfileCompletionProps {
  percent: number;
  missing: string[];
  compact?: boolean;
}

export default function ProfileCompletion({ percent, missing, compact = false }: ProfileCompletionProps) {
  const radius = compact ? 20 : 28;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percent / 100) * circumference;

  return (
    <div className={`card-modern flex items-center gap-4 rounded-2xl ${compact ? 'p-4' : 'p-5'}`}>
      <div className="relative shrink-0">
        <svg width={(radius + 8) * 2} height={(radius + 8) * 2} className="-rotate-90">
          <circle
            cx={radius + 8}
            cy={radius + 8}
            r={radius}
            fill="none"
            stroke="var(--color-border)"
            strokeWidth="6"
          />
          <circle
            cx={radius + 8}
            cy={radius + 8}
            r={radius}
            fill="none"
            stroke="url(#profileGrad)"
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-700"
          />
          <defs>
            <linearGradient id="profileGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#7c3aed" />
              <stop offset="100%" stopColor="#14b8a6" />
            </linearGradient>
          </defs>
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-primary">
          {percent}%
        </span>
      </div>
      <div className="min-w-0 flex-1">
        <p className="font-display font-bold text-ink">Profile {percent === 100 ? 'complete' : 'incomplete'}</p>
        {percent < 100 ? (
          <p className="mt-1 text-sm text-muted">
            Add {missing.slice(0, 2).join(', ')}
            {missing.length > 2 ? ` +${missing.length - 2} more` : ''} for better AI plans.
          </p>
        ) : (
          <p className="mt-1 text-sm text-muted">Your AI coach has full context.</p>
        )}
        {percent < 100 && (
          <Link to="/ai-coach" className="mt-2 inline-block text-sm font-bold text-accent hover:text-primary">
            Complete profile →
          </Link>
        )}
      </div>
    </div>
  );
}
