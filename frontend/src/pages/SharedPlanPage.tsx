import { motion } from 'framer-motion';
import { Bookmark, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import AiMarkdown from '../components/AiMarkdown';
import FitLifeLogo from '../components/FitLifeLogo';
import { publicApi } from '../lib/api';
import type { PublicPlan } from '../types';

export default function SharedPlanPage() {
  const { token } = useParams<{ token: string }>();
  const [plan, setPlan] = useState<PublicPlan | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    publicApi
      .sharedPlan(token)
      .then(setPlan)
      .catch(() => setError('Plan not found or link expired'))
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) {
    return (
      <div className="page-bg flex min-h-screen items-center justify-center">
        <Loader2 className="animate-spin text-primary" size={40} />
      </div>
    );
  }

  if (error || !plan) {
    return (
      <div className="page-bg flex min-h-screen flex-col items-center justify-center px-4">
        <p className="text-lg font-bold text-ink">{error || 'Not found'}</p>
        <Link to="/" className="btn-primary mt-4 rounded-xl px-6 py-2">Go home</Link>
      </div>
    );
  }

  return (
    <div className="page-bg min-h-screen">
      <header className="gradient-nav px-4 py-4 sm:px-6">
        <div className="mx-auto flex max-w-3xl items-center justify-between">
          <FitLifeLogo to="/" ring textClassName="text-white" />
          <Link to="/signup" className="btn-accent rounded-xl px-4 py-2 text-sm font-bold">Join FitLife</Link>
        </div>
      </header>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mx-auto max-w-3xl px-4 py-10 sm:px-6"
      >
        <div className="mb-6 flex items-center gap-3">
          <Bookmark className="text-primary" size={28} />
          <div>
            <h1 className="font-display text-2xl font-extrabold text-ink">{plan.title}</h1>
            <p className="text-sm capitalize text-muted">{plan.plan_type.replace('-', ' ')} · Shared plan</p>
          </div>
        </div>
        <div className="card-modern p-6">
          <AiMarkdown content={plan.content} />
        </div>
      </motion.div>
    </div>
  );
}
