import type { CalendarDay } from '../types';

interface CalendarHeatmapProps {
  days: CalendarDay[];
}

export default function CalendarHeatmap({ days }: CalendarHeatmapProps) {
  const maxWorkouts = Math.max(1, ...days.map((d) => d.workouts));

  return (
    <div className="card-modern p-5">
      <h3 className="font-display font-bold text-ink">Activity calendar</h3>
      <p className="mt-1 text-sm text-muted">Workout intensity over the last {days.length} days</p>
      <div className="mt-4 grid grid-cols-7 gap-1.5 sm:grid-cols-10">
        {days.map((d) => {
          const intensity = d.workouts / maxWorkouts;
          const bg =
            d.workouts === 0
              ? 'bg-surface-2'
              : intensity > 0.66
                ? 'bg-primary'
                : intensity > 0.33
                  ? 'bg-primary/60'
                  : 'bg-primary/30';
          return (
            <div
              key={d.date}
              title={`${d.date}: ${d.workouts} workout(s), ${d.water_glasses} water`}
              className={`aspect-square rounded-md ${bg}`}
            />
          );
        })}
      </div>
      <div className="mt-3 flex items-center gap-2 text-xs text-muted">
        <span>Less</span>
        <div className="flex gap-1">
          {['bg-surface-2', 'bg-primary/30', 'bg-primary/60', 'bg-primary'].map((c) => (
            <div key={c} className={`h-3 w-3 rounded-sm ${c}`} />
          ))}
        </div>
        <span>More</span>
      </div>
    </div>
  );
}
