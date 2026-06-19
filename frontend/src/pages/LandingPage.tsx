import { motion } from 'framer-motion';
import { ArrowRight, Bot, Dumbbell, Flame, Sparkles, Target, Users } from 'lucide-react';
import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import FitLifeLogo from '../components/FitLifeLogo';
import { IMAGES } from '../lib/images';

const features = [
  { icon: Bot, title: 'AI Coach', desc: 'Personalized diet plans, workout routines, and streaming chat powered by LLMs.' },
  { icon: Dumbbell, title: 'Exercise Library', desc: 'Browse 100+ exercises with video demos, tips, and one-tap logging.' },
  { icon: Flame, title: 'Streaks & PRs', desc: 'Track workouts, personal records, and build consistency with badges.' },
  { icon: Target, title: 'Goals & Metrics', desc: 'Set fitness goals, log body metrics, and monitor water intake daily.' },
];

export default function LandingPage() {
  const { user, loading } = useAuth();
  if (!loading && user) return <Navigate to="/dashboard" replace />;

  return (
    <div className="page-bg min-h-screen">
      <header className="gradient-nav sticky top-0 z-50 shadow-lg">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
          <FitLifeLogo to="/" ring textClassName="text-white" />
          <div className="flex items-center gap-3">
            <Link to="/login" className="rounded-xl px-4 py-2 text-sm font-bold text-white/90 hover:bg-white/10">
              Sign in
            </Link>
            <Link to="/signup" className="btn-accent rounded-xl px-5 py-2 text-sm font-bold">
              Get started
            </Link>
          </div>
        </div>
      </header>

      <section
        className="relative overflow-hidden px-4 py-20 sm:px-6 sm:py-28"
        style={{
          backgroundImage: `linear-gradient(135deg, rgba(109,40,217,0.92) 0%, rgba(99,102,241,0.85) 50%, rgba(20,184,166,0.75) 100%), url('${IMAGES.heroes.dashboard}')`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
        }}
      >
        <div className="gradient-mesh-overlay pointer-events-none absolute inset-0" />
        <div className="relative mx-auto max-w-4xl text-center">
          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}>
            <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/15 px-4 py-2 text-sm font-semibold text-white backdrop-blur-md">
              <Sparkles size={14} className="text-teal-300" /> Your complete wellness platform
            </span>
            <h1 className="font-display mt-6 text-4xl font-extrabold leading-tight tracking-tight text-white sm:text-6xl">
              Train smarter. Eat better. <span className="text-teal-300">Live healthier.</span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-lg font-medium text-white/85">
              FitLife combines AI coaching, workout tracking, nutrition plans, and community inspiration — all in one place.
            </p>
            <div className="mt-10 flex flex-wrap justify-center gap-4">
              <Link to="/signup" className="btn-accent inline-flex items-center gap-2 rounded-full px-8 py-3.5 text-base font-bold">
                Start free <ArrowRight size={18} />
              </Link>
              <Link to="/login" className="inline-flex items-center gap-2 rounded-full border-2 border-white/40 px-8 py-3.5 text-base font-bold text-white transition hover:bg-white/10">
                Sign in
              </Link>
            </div>
          </motion.div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
        <h2 className="font-display text-center text-3xl font-extrabold text-ink">Everything you need</h2>
        <p className="mx-auto mt-3 max-w-xl text-center text-muted">From first workout to personal bests — FitLife grows with you.</p>
        <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map(({ icon: Icon, title, desc }, i) => (
            <motion.div
              key={title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
              className="card-modern p-6"
            >
              <div className="gradient-primary mb-4 flex h-12 w-12 items-center justify-center rounded-xl text-white">
                <Icon size={22} />
              </div>
              <h3 className="font-display font-bold text-ink">{title}</h3>
              <p className="mt-2 text-sm text-muted">{desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-4xl px-4 py-16 text-center sm:px-6">
        <Users className="mx-auto text-primary" size={40} />
        <h2 className="font-display mt-4 text-2xl font-extrabold text-ink">Join thousands building healthier habits</h2>
        <Link to="/signup" className="btn-primary mt-8 inline-flex items-center gap-2 rounded-full px-8 py-3.5">
          Create your account <ArrowRight size={18} />
        </Link>
      </section>

      <footer className="border-t border-border py-8 text-center text-sm text-muted">
        <p>© {new Date().getFullYear()} FitLife. Built for wellness.</p>
      </footer>
    </div>
  );
}
