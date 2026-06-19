import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  BookOpen,
  Bot,
  Bookmark,
  Carrot,
  CheckCircle2,
  Dumbbell,
  Flame,
  Mail,
  Sparkles,
  Target,
  Timer,
  Users,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import StatCard from '../components/StatCard';
import WeeklyChart from '../components/WeeklyChart';
import ActivityFeed from '../components/ActivityFeed';
import StreakHero from '../components/StreakHero';
import ProfileCompletion from '../components/ProfileCompletion';
import { StatSkeleton } from '../components/Skeleton';
import { activityApi, aiApi } from '../lib/api';
import { getProfileCompletion } from '../lib/profileCompletion';
import { IMAGES } from '../lib/images';
import type { ActivityFeedItem, DashboardStats, UserProfile, WeeklyActivity } from '../types';

const cards = [
  { to: '/ai-coach', icon: Bot, title: 'AI Coach', desc: 'Chat, diet plans, workout routines.', color: 'from-violet-500 to-purple-600' },
  { to: '/workout-session', icon: Timer, title: 'Session Mode', desc: 'Guided workout with rest timer.', color: 'from-rose-500 to-orange-500' },
  { to: '/my-plans', icon: Bookmark, title: 'My Plans', desc: 'Saved AI-generated plans.', color: 'from-fuchsia-500 to-pink-500' },
  { to: '/activity', icon: Flame, title: 'Activity', desc: 'History, PRs, and progress charts.', color: 'from-orange-400 to-red-500' },
  { to: '/exercises', icon: Dumbbell, title: 'Exercises', desc: 'Browse and log workouts.', color: 'from-purple-500 to-indigo-500' },
  { to: '/articles', icon: BookOpen, title: 'Articles', desc: 'Expert fitness advice.', color: 'from-indigo-500 to-blue-500' },
  { to: '/recipes', icon: Carrot, title: 'Recipes', desc: 'Healthy meal ideas.', color: 'from-orange-400 to-amber-500' },
  { to: '/blogs', icon: Users, title: 'Blogs', desc: 'Community inspiration.', color: 'from-teal-500 to-emerald-500' },
  { to: '/contact', icon: Mail, title: 'Contact', desc: 'Reach our team.', color: 'from-pink-500 to-rose-500' },
];

export default function DashboardPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [weekly, setWeekly] = useState<WeeklyActivity[]>([]);
  const [feed, setFeed] = useState<ActivityFeedItem[]>([]);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      activityApi.dashboard(),
      activityApi.weekly(),
      activityApi.feed(8),
      aiApi.getProfile(),
    ])
      .then(([s, w, f, p]) => {
        setStats(s);
        setWeekly(w);
        setFeed(f);
        setProfile(p);
      })
      .finally(() => setLoading(false));
  }, []);

  const completion = getProfileCompletion(profile);
  const today = new Date().toLocaleDateString(undefined, {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return (
    <div className="pb-24 lg:pb-12">
      <section
        className="relative mx-4 mt-0 overflow-hidden sm:mx-auto sm:max-w-6xl sm:rounded-b-3xl"
        style={{
          backgroundImage: `linear-gradient(135deg, rgba(109,40,217,0.88) 0%, rgba(99,102,241,0.82) 45%, rgba(20,184,166,0.7) 100%), url('${IMAGES.heroes.dashboard}')`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
        }}
      >
        <div className="gradient-mesh-overlay pointer-events-none absolute inset-0" />
        <div className="relative px-6 py-16 sm:px-12 sm:py-20">
          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}>
            <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/15 px-4 py-2 text-sm font-semibold text-white backdrop-blur-md">
              <Sparkles size={14} className="text-teal-300" /> Welcome back, {user?.username}
            </span>
            <h1 className="font-display mt-5 text-3xl font-extrabold leading-tight tracking-tight text-white sm:text-5xl">
              Elevate Your <span className="text-teal-300">Wellness</span> Journey
            </h1>
            <p className="mt-4 max-w-xl text-lg font-medium leading-relaxed text-white/85">
              Today is {today}.
            </p>
            <Link to="/ai-coach" className="btn-accent mt-8 inline-flex items-center gap-2 rounded-full px-8 py-3.5">
              <Sparkles size={18} /> Try AI Coach <ArrowRight size={18} />
            </Link>
          </motion.div>
        </div>
        <svg className="relative block w-full" viewBox="0 0 1440 80" preserveAspectRatio="none">
          <path fill="var(--color-surface, #f8fafc)" d="M0,64L1440,64L1440,80L0,80Z" />
        </svg>
      </section>

      <div className="mx-auto mt-8 max-w-6xl space-y-8 px-4 sm:px-6">
        {loading ? (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <StatSkeleton key={i} />
            ))}
          </div>
        ) : (
          <>
            {stats && stats.current_streak >= 0 && <StreakHero streak={stats.current_streak} />}

            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatCard label="Workouts" value="—" numericValue={stats?.total_workouts} icon={<Dumbbell size={22} />} delay={0.1} />
              <StatCard label="This Week" value="—" numericValue={stats?.workouts_this_week} icon={<Target size={22} />} delay={0.2} />
              <StatCard
                label="Streak"
                value={stats ? `${stats.current_streak}d` : '—'}
                icon={<Flame size={22} />}
                delay={0.3}
              />
              <StatCard label="Saved Plans" value="—" numericValue={stats?.saved_plans} icon={<Bookmark size={22} />} delay={0.4} />
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <ActivityFeed items={feed} />
              {completion.percent < 100 && (
                <ProfileCompletion percent={completion.percent} missing={completion.missing} />
              )}
            </div>

            {weekly.length > 0 && <WeeklyChart data={weekly} />}
          </>
        )}

        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {cards.map(({ to, icon: Icon, title, desc, color }, i) => (
            <motion.div key={to} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
              <Link to={to} className="card-modern group block h-full p-5 card-hover">
                <div className={`mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br ${color} text-white shadow-lg transition group-hover:scale-110`}>
                  <Icon size={22} />
                </div>
                <h3 className="font-display font-bold text-ink">{title}</h3>
                <p className="mt-1 text-sm text-muted">{desc}</p>
              </Link>
            </motion.div>
          ))}
        </div>

        <section className="glass-card rounded-3xl p-6">
          <h2 className="font-display flex items-center gap-2 text-xl font-extrabold text-teal-600">
            <Target size={22} /> Quick Actions
          </h2>
          <ul className="mt-4 space-y-2">
            {[
              { text: 'Start workout session', link: '/workout-session' },
              { text: 'Log a workout', link: '/exercises' },
              { text: 'Generate AI plan', link: '/ai-coach' },
              { text: 'View progress', link: '/activity' },
            ].map(({ text, link }) => (
              <li key={link} className="flex items-center gap-2 text-muted">
                <CheckCircle2 className="shrink-0 text-accent" size={18} />
                <Link to={link} className="font-bold text-primary hover:text-accent">{text}</Link>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
