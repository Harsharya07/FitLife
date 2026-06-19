import { motion } from 'framer-motion';
import { BarChart3, Bot, Dumbbell, Shield, UserPlus, Users } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import PageHero from '../components/PageHero';
import StatCard from '../components/StatCard';
import { adminApi } from '../lib/api';
import { IMAGES } from '../lib/images';
import type { AdminAnalytics } from '../types';

export default function AdminAnalyticsPage() {
  const [data, setData] = useState<AdminAnalytics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    adminApi
      .analytics()
      .then(setData)
      .catch(() => toast.error('Admin access required'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="pb-12">
      <PageHero
        title="Admin Analytics"
        subtitle="Platform usage overview and growth metrics."
        icon={<Shield className="text-white" />}
        image={IMAGES.heroes.dashboard}
      />

      <div className="mx-auto mt-8 max-w-6xl px-4 sm:px-6">
        <Link to="/admin/contacts" className="mb-6 inline-flex text-sm font-bold text-primary hover:text-accent">
          ← Contact inbox
        </Link>

        {loading ? (
          <div className="flex justify-center py-20">
            <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary/20 border-t-primary" />
          </div>
        ) : data ? (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid grid-cols-2 gap-4 lg:grid-cols-3">
            <StatCard label="Total Users" value="—" numericValue={data.total_users} icon={<Users size={22} />} />
            <StatCard label="Workouts Logged" value="—" numericValue={data.total_workouts} icon={<Dumbbell size={22} />} />
            <StatCard label="Saved Plans" value="—" numericValue={data.total_plans} icon={<BarChart3 size={22} />} />
            <StatCard label="AI Chats" value="—" numericValue={data.total_ai_chats} icon={<Bot size={22} />} />
            <StatCard label="Signups (7d)" value="—" numericValue={data.signups_last_7_days} icon={<UserPlus size={22} />} />
          </motion.div>
        ) : null}
      </div>
    </div>
  );
}
