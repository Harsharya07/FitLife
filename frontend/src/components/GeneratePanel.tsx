import { motion } from 'framer-motion';
import { Copy, ExternalLink, Sparkles, Wand2 } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import axios from 'axios';
import type { AiStatus } from '../types';
import AiMarkdown from './AiMarkdown';

interface GeneratePanelProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  aiStatus: AiStatus | null;
  onGenerate: (notes: string, days: number) => Promise<{ content: string; plan_id?: number | null }>;
  gradient: string;
}

export default function GeneratePanel({
  title,
  description,
  icon,
  aiStatus,
  onGenerate,
  gradient,
}: GeneratePanelProps) {
  const [notes, setNotes] = useState('');
  const [days, setDays] = useState(7);
  const [result, setResult] = useState('');
  const [planId, setPlanId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    if (!aiStatus?.configured) {
      toast.error('Add your API key to .env to enable AI features');
      return;
    }
    setLoading(true);
    setResult('');
    setPlanId(null);
    try {
      const { content, plan_id } = await onGenerate(notes, days);
      setResult(content);
      setPlanId(plan_id ?? null);
      toast.success(`${title} generated & saved!`);
    } catch (err) {
      const msg = axios.isAxiosError(err) ? err.response?.data?.detail : 'Generation failed';
      toast.error(typeof msg === 'string' ? msg : 'Failed to generate');
    } finally {
      setLoading(false);
    }
  };

  const copyResult = () => {
    navigator.clipboard.writeText(result);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="space-y-6">
      <div className={`rounded-2xl p-6 text-white shadow-lg ${gradient}`}>
        <div className="flex items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-white/20">
            {icon}
          </div>
          <div>
            <h3 className="font-display text-xl font-bold">{title}</h3>
            <p className="mt-1 text-sm text-white/90">{description}</p>
          </div>
        </div>
      </div>

      <div className="rounded-2xl bg-white p-6 shadow-lg">
        <label className="mb-2 block text-sm font-semibold text-ink">Extra preferences (optional)</label>
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="e.g. low budget meals, no seafood, prefer home workouts, knee injury..."
          rows={3}
          className="w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-4 py-3 text-sm outline-none focus:border-primary"
        />

        <div className="mt-4 flex flex-wrap items-end gap-4">
          <div>
            <label className="mb-1 block text-sm font-semibold text-ink">Plan duration (days)</label>
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-4 py-2.5 text-sm outline-none focus:border-primary"
            >
              {[3, 5, 7, 10, 14].map((d) => (
                <option key={d} value={d}>{d} days</option>
              ))}
            </select>
          </div>
          <button
            onClick={handleGenerate}
            disabled={loading || !aiStatus?.configured}
            className="flex items-center gap-2 rounded-xl gradient-primary px-6 py-2.5 font-bold text-white shadow-md transition hover:shadow-lg disabled:opacity-60"
          >
            {loading ? (
              <>
                <Sparkles className="animate-spin" size={18} />
                Generating...
              </>
            ) : (
              <>
                <Wand2 size={18} />
                Generate with AI
              </>
            )}
          </button>
        </div>

        {!aiStatus?.configured && (
          <p className="mt-4 rounded-xl bg-amber-50 px-4 py-3 text-sm text-amber-800">
            Add <code className="rounded bg-amber-100 px-1">GEMINI_API_KEY</code> or{' '}
            <code className="rounded bg-amber-100 px-1">OPENAI_API_KEY</code> to your{' '}
            <code className="rounded bg-amber-100 px-1">.env</code> file and restart the backend.
          </p>
        )}
      </div>

      {loading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="rounded-2xl bg-white p-8 shadow-lg"
        >
          <div className="flex flex-col items-center gap-4">
            <div className="relative h-16 w-16">
              <div className="absolute inset-0 animate-ping rounded-full bg-primary/20" />
              <div className="relative flex h-16 w-16 items-center justify-center rounded-full gradient-primary">
                <Sparkles className="animate-pulse text-white" size={28} />
              </div>
            </div>
            <p className="font-display font-bold text-primary">AI is crafting your plan...</p>
            <p className="text-sm text-muted">This may take 10–30 seconds</p>
          </div>
        </motion.div>
      )}

      {result && !loading && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-white p-6 shadow-lg"
        >
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <h4 className="font-display font-bold text-primary">Your Personalized Plan</h4>
            <div className="flex items-center gap-2">
              {planId && (
                <Link
                  to="/my-plans"
                  className="flex items-center gap-1 rounded-lg bg-accent/10 px-3 py-1.5 text-sm font-semibold text-accent transition hover:bg-accent/20"
                >
                  <ExternalLink size={14} /> View in My Plans
                </Link>
              )}
              <button
                onClick={copyResult}
                className="flex items-center gap-1 rounded-lg bg-[#f8f6fc] px-3 py-1.5 text-sm font-semibold text-primary transition hover:bg-[#e0c3fc]/40"
              >
                <Copy size={14} /> Copy
              </button>
            </div>
          </div>
          <AiMarkdown content={result} />
        </motion.div>
      )}
    </div>
  );
}
