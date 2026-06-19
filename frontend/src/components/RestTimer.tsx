import { Pause, Play, RotateCcw } from 'lucide-react';
import { useEffect, useState } from 'react';

interface RestTimerProps {
  seconds?: number;
  onComplete?: () => void;
}

export default function RestTimer({ seconds = 60, onComplete }: RestTimerProps) {
  const [remaining, setRemaining] = useState(seconds);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    setRemaining(seconds);
    setRunning(false);
  }, [seconds]);

  useEffect(() => {
    if (!running || remaining <= 0) return;
    const id = setInterval(() => {
      setRemaining((r) => {
        if (r <= 1) {
          setRunning(false);
          onComplete?.();
          return 0;
        }
        return r - 1;
      });
    }, 1000);
    return () => clearInterval(id);
  }, [running, remaining, onComplete]);

  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;
  const pct = ((seconds - remaining) / seconds) * 100;

  return (
    <div className="rounded-2xl bg-surface-2 p-4">
      <p className="text-xs font-bold uppercase tracking-wide text-muted">Rest timer</p>
      <p className="font-display mt-1 text-3xl font-extrabold tabular-nums text-primary">
        {mins}:{secs.toString().padStart(2, '0')}
      </p>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-border">
        <div className="h-full bg-accent transition-all" style={{ width: `${pct}%` }} />
      </div>
      <div className="mt-3 flex gap-2">
        <button
          onClick={() => setRunning(!running)}
          className="btn-accent flex flex-1 items-center justify-center gap-1 py-2 text-sm"
        >
          {running ? <Pause size={16} /> : <Play size={16} />}
          {running ? 'Pause' : 'Start'}
        </button>
        <button
          onClick={() => { setRemaining(seconds); setRunning(false); }}
          className="rounded-xl bg-card px-3 py-2 text-sm font-bold text-ink hover:bg-border"
        >
          <RotateCcw size={16} />
        </button>
      </div>
    </div>
  );
}
