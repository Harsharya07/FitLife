import { motion } from 'framer-motion';
import { useEffect, useMemo, useState } from 'react';
import {
  Bookmark,
  CalendarDays,
  ClipboardList,
  Dumbbell,
  GitCompare,
  Link2,
  Pencil,
  Printer,
  Search,
  Trash2,
  UtensilsCrossed,
} from 'lucide-react';
import toast from 'react-hot-toast';
import PageHero from '../components/PageHero';
import AiMarkdown from '../components/AiMarkdown';
import EmptyState from '../components/EmptyState';
import { ListSkeleton } from '../components/Skeleton';
import { plansApi } from '../lib/api';
import { IMAGES } from '../lib/images';
import type { SavedPlan } from '../types';

const TYPE_ICONS: Record<string, React.ReactNode> = {
  'diet-plan': <UtensilsCrossed size={18} />,
  'diet-chart': <CalendarDays size={18} />,
  'workout-plan': <Dumbbell size={18} />,
};

const TYPE_COLORS: Record<string, string> = {
  'diet-plan': 'border-l-emerald-500',
  'diet-chart': 'border-l-orange-400',
  'workout-plan': 'border-l-purple-500',
};

export default function MyPlansPage() {
  const [plans, setPlans] = useState<SavedPlan[]>([]);
  const [selected, setSelected] = useState<SavedPlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [compareIds, setCompareIds] = useState<number[]>([]);
  const [compareMode, setCompareMode] = useState(false);

  useEffect(() => {
    setLoading(true);
    plansApi
      .list(filter === 'all' ? undefined : filter)
      .then((data) => {
        setPlans(data);
        if (data.length && !selected) setSelected(data[0]);
      })
      .finally(() => setLoading(false));
  }, [filter]);

  const filtered = useMemo(() => {
    if (!search.trim()) return plans;
    const q = search.toLowerCase();
    return plans.filter((p) => p.title.toLowerCase().includes(q) || p.content.toLowerCase().includes(q));
  }, [plans, search]);

  const handleDelete = async (id: number) => {
    try {
      await plansApi.delete(id);
      setPlans((prev) => prev.filter((p) => p.id !== id));
      if (selected?.id === id) setSelected(null);
      toast.success('Plan deleted');
    } catch {
      toast.error('Failed to delete');
    }
  };

  const handleRename = async () => {
    if (!selected || !editTitle.trim()) return;
    try {
      const updated = await plansApi.rename(selected.id, editTitle.trim());
      setPlans((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
      setSelected(updated);
      setEditing(false);
      toast.success('Plan renamed');
    } catch {
      toast.error('Failed to rename');
    }
  };

  const printPlan = () => {
    if (!selected) return;
    const w = window.open('', '_blank');
    if (!w) return;
    w.document.write(`<html><head><title>${selected.title}</title></head><body><pre>${selected.content}</pre></body></html>`);
    w.document.close();
    w.print();
  };

  const sharePlan = async () => {
    if (!selected) return;
    try {
      const { share_url } = await plansApi.share(selected.id);
      const fullUrl = `${window.location.origin}${share_url}`;
      await navigator.clipboard.writeText(fullUrl);
      toast.success('Share link copied!');
    } catch {
      toast.error('Failed to share plan');
    }
  };

  const toggleCompare = (id: number) => {
    setCompareIds((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= 2) return [prev[1], id];
      return [...prev, id];
    });
  };

  const comparePlans = compareIds.map((id) => plans.find((p) => p.id === id)).filter(Boolean) as SavedPlan[];

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="My Saved Plans"
        subtitle="AI-generated diet and workout plans, saved automatically."
        icon={<Bookmark className="text-white" />}
        image={IMAGES.heroes.aiCoach}
      />

      <div className="mx-auto mt-8 max-w-6xl px-4 sm:px-6">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-2">
            {[
              { id: 'all', label: 'All' },
              { id: 'diet-plan', label: 'Diet' },
              { id: 'diet-chart', label: 'Charts' },
              { id: 'workout-plan', label: 'Workouts' },
            ].map(({ id, label }) => (
              <button
                key={id}
                onClick={() => setFilter(id)}
                className={`rounded-xl px-4 py-2 text-sm font-bold transition ${filter === id ? 'gradient-primary text-white' : 'bg-card text-primary'}`}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search plans..."
              className="w-full rounded-xl border-2 border-border bg-input-bg py-2 pl-9 pr-4 text-sm outline-none focus:border-primary sm:w-64"
            />
          </div>
          <button
            onClick={() => { setCompareMode(!compareMode); setCompareIds([]); }}
            className={`flex items-center gap-1 rounded-xl px-4 py-2 text-sm font-bold ${compareMode ? 'gradient-primary text-white' : 'bg-card text-primary'}`}
          >
            <GitCompare size={16} /> Compare
          </button>
        </div>

        {compareMode && comparePlans.length === 2 && (
          <div className="mb-6 grid gap-4 lg:grid-cols-2">
            {comparePlans.map((plan) => (
              <div key={plan.id} className="card-modern max-h-[60vh] overflow-y-auto p-5">
                <h3 className="font-display font-bold text-primary">{plan.title}</h3>
                <p className="mb-3 text-xs text-muted">{plan.plan_type} · {new Date(plan.created_at).toLocaleDateString()}</p>
                <AiMarkdown content={plan.content} />
              </div>
            ))}
          </div>
        )}

        {loading ? (
          <ListSkeleton count={5} />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={ClipboardList}
            title="No saved plans"
            description="Generate a plan in AI Coach — it saves automatically."
            actionLabel="Go to AI Coach"
            actionTo="/ai-coach"
          />
        ) : (
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="max-h-[70vh] space-y-2 overflow-y-auto lg:col-span-1">
              {filtered.map((plan, i) => (
                <motion.button
                  key={plan.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                  onClick={() => { if (!compareMode) { setSelected(plan); setEditing(false); } }}
                  className={`w-full rounded-xl border-l-4 p-4 text-left transition ${TYPE_COLORS[plan.plan_type] || 'border-l-primary'} ${selected?.id === plan.id && !compareMode ? 'gradient-primary text-white shadow-lg' : 'bg-card shadow hover:shadow-md'} ${compareIds.includes(plan.id) ? 'ring-2 ring-accent' : ''}`}
                >
                  <div className="flex items-center gap-2">
                    {compareMode && (
                      <input
                        type="checkbox"
                        checked={compareIds.includes(plan.id)}
                        onChange={() => toggleCompare(plan.id)}
                        onClick={(e) => e.stopPropagation()}
                        className="rounded"
                      />
                    )}
                    {TYPE_ICONS[plan.plan_type]}
                    <span className="font-display truncate font-bold">{plan.title}</span>
                  </div>
                  <p className={`mt-1 text-xs ${selected?.id === plan.id && !compareMode ? 'text-white/80' : 'text-muted'}`}>
                    {new Date(plan.created_at).toLocaleDateString()}
                  </p>
                </motion.button>
              ))}
            </div>

            <div className="lg:col-span-2">
              {selected ? (
                <div className="card-modern p-6">
                  <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                    {editing ? (
                      <div className="flex flex-1 gap-2">
                        <input
                          value={editTitle}
                          onChange={(e) => setEditTitle(e.target.value)}
                          className="flex-1 rounded-lg border-2 border-border bg-input-bg px-3 py-2 text-sm outline-none focus:border-primary"
                        />
                        <button onClick={handleRename} className="btn-accent px-4 py-2 text-sm">Save</button>
                        <button onClick={() => setEditing(false)} className="px-4 py-2 text-sm text-muted">Cancel</button>
                      </div>
                    ) : (
                      <div>
                        <h2 className="font-display text-xl font-bold text-primary">{selected.title}</h2>
                        <p className="text-sm text-muted">{new Date(selected.created_at).toLocaleString()}</p>
                      </div>
                    )}
                    {!editing && (
                      <div className="flex gap-1">
                        <button onClick={() => { setEditTitle(selected.title); setEditing(true); }} className="rounded-lg p-2 text-primary hover:bg-surface-2" title="Rename">
                          <Pencil size={18} />
                        </button>
                        <button onClick={sharePlan} className="rounded-lg p-2 text-primary hover:bg-surface-2" title="Share">
                          <Link2 size={18} />
                        </button>
                        <button onClick={printPlan} className="rounded-lg p-2 text-primary hover:bg-surface-2" title="Print">
                          <Printer size={18} />
                        </button>
                        <button onClick={() => handleDelete(selected.id)} className="rounded-lg p-2 text-red-500 hover:bg-red-50" title="Delete">
                          <Trash2 size={18} />
                        </button>
                      </div>
                    )}
                  </div>
                  <AiMarkdown content={selected.content} />
                </div>
              ) : (
                <div className="card-modern flex h-64 items-center justify-center">
                  <p className="text-muted">Select a plan</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
