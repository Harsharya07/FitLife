import { Droplets, Plus } from 'lucide-react';
import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { wellnessApi } from '../lib/api';
import type { WaterToday } from '../types';

export default function WaterTracker() {
  const [data, setData] = useState<WaterToday | null>(null);
  const [loading, setLoading] = useState(false);

  const load = () => wellnessApi.waterToday().then(setData).catch(() => null);

  useEffect(() => { load(); }, []);

  const addGlass = async () => {
    setLoading(true);
    try {
      const updated = await wellnessApi.logWater(1);
      setData(updated);
      if (updated.glasses >= updated.goal) toast.success('Daily water goal reached! 🎉');
    } catch {
      toast.error('Failed to log water');
    } finally {
      setLoading(false);
    }
  };

  if (!data) return null;
  const pct = Math.min(100, (data.glasses / data.goal) * 100);

  return (
    <div className="card-modern p-5">
      <div className="flex items-center justify-between">
        <h3 className="font-display flex items-center gap-2 font-bold text-ink">
          <Droplets className="text-sky-500" size={20} /> Water today
        </h3>
        <button
          onClick={addGlass}
          disabled={loading}
          className="btn-accent flex items-center gap-1 rounded-xl px-3 py-1.5 text-sm disabled:opacity-60"
        >
          <Plus size={14} /> Glass
        </button>
      </div>
      <p className="mt-2 text-2xl font-extrabold text-primary">
        {data.glasses} <span className="text-base font-medium text-muted">/ {data.goal} glasses</span>
      </p>
      <div className="mt-3 h-3 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full bg-sky-400 transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
