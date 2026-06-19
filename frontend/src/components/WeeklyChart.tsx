import { motion } from 'framer-motion';
import type { WeeklyActivity } from '../types';

interface WeeklyChartProps {
  data: WeeklyActivity[];
}

export default function WeeklyChart({ data }: WeeklyChartProps) {
  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="rounded-2xl bg-white p-6 shadow-lg">
      <h3 className="font-display mb-4 font-bold text-primary">Workouts This Week</h3>
      <div className="flex items-end justify-between gap-2" style={{ height: 120 }}>
        {data.map((d, i) => {
          const height = (d.count / max) * 100;
          const day = new Date(d.date + 'T12:00:00').toLocaleDateString(undefined, { weekday: 'short' });
          return (
            <div key={d.date} className="flex flex-1 flex-col items-center gap-2">
              <motion.div
                initial={{ height: 0 }}
                animate={{ height: `${Math.max(height, d.count > 0 ? 8 : 4)}%` }}
                transition={{ delay: i * 0.08, duration: 0.5 }}
                className={`w-full max-w-[40px] rounded-t-lg ${
                  d.count > 0 ? 'gradient-accent' : 'bg-slate-100'
                }`}
                title={`${d.count} workout${d.count !== 1 ? 's' : ''}`}
              />
              <span className="text-xs font-semibold text-muted">{day}</span>
              {d.count > 0 && (
                <span className="text-xs font-bold text-accent">{d.count}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
