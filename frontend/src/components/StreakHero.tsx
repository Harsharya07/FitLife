import { Flame } from 'lucide-react';
import { Link } from 'react-router-dom';

interface StreakHeroProps {
  streak: number;
}

export default function StreakHero({ streak }: StreakHeroProps) {
  return (
    <div className="relative overflow-hidden rounded-2xl gradient-primary p-6 text-white shadow-lg">
      <div className="pointer-events-none absolute -right-8 -top-8 h-32 w-32 rounded-full bg-white/10 blur-2xl" />
      <div className="relative flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-white/20 backdrop-blur-sm">
            <Flame size={36} className={streak > 0 ? 'animate-pulse text-orange-300' : 'text-white/60'} />
          </div>
          <div>
            <p className="text-sm font-semibold text-white/80">Current streak</p>
            <p className="font-display text-4xl font-extrabold">
              {streak} <span className="text-xl font-bold text-white/90">day{streak !== 1 ? 's' : ''}</span>
            </p>
          </div>
        </div>
        <Link
          to="/exercises"
          className="rounded-xl bg-white/20 px-5 py-2.5 text-sm font-bold backdrop-blur-sm transition hover:bg-white/30"
        >
          {streak > 0 ? "Don't break it — log today" : 'Start your streak'}
        </Link>
      </div>
    </div>
  );
}
