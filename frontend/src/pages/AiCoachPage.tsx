import { motion } from 'framer-motion';
import {
  Bot,
  CalendarDays,
  ClipboardList,
  Dumbbell,
  Sparkles,
  UserCircle,
  UtensilsCrossed,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { aiApi } from '../lib/api';
import { getProfileCompletion } from '../lib/profileCompletion';
import type { AiStatus, UserProfile } from '../types';
import PageHero from '../components/PageHero';
import ProfileCompletion from '../components/ProfileCompletion';
import { IMAGES } from '../lib/images';
import ProfileForm from '../components/ProfileForm';
import ChatPanel from '../components/ChatPanel';
import GeneratePanel from '../components/GeneratePanel';

type Tab = 'chat' | 'profile' | 'diet-plan' | 'diet-chart' | 'workout';

const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'chat', label: 'AI Chat', icon: <Bot size={18} /> },
  { id: 'profile', label: 'My Profile', icon: <UserCircle size={18} /> },
  { id: 'diet-plan', label: 'Diet Plan', icon: <UtensilsCrossed size={18} /> },
  { id: 'diet-chart', label: 'Diet Chart', icon: <CalendarDays size={18} /> },
  { id: 'workout', label: 'Workout Plan', icon: <Dumbbell size={18} /> },
];

export default function AiCoachPage() {
  const [tab, setTab] = useState<Tab>('chat');
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [digestLoading, setDigestLoading] = useState(false);

  useEffect(() => {
    aiApi.status().then(setAiStatus).catch(() => null);
    aiApi.getProfile().then(setProfile).catch(() => null);
  }, []);

  const runDigest = async () => {
    if (!aiStatus?.configured) {
      toast.error('Configure API key first');
      return;
    }
    setDigestLoading(true);
    try {
      const { content } = await aiApi.digest();
      toast.success('Weekly digest ready — check AI Chat');
      setTab('chat');
      // Digest is saved server-side; user can see it in chat history on refresh
      if (content) toast(content.slice(0, 120) + '…', { duration: 5000 });
    } catch {
      toast.error('Digest failed');
    } finally {
      setDigestLoading(false);
    }
  };

  const completion = getProfileCompletion(profile);

  const panel = (
    <>
      {tab === 'chat' && <ChatPanel aiStatus={aiStatus} />}
      {tab === 'profile' && <ProfileForm onSaved={() => aiApi.getProfile().then(setProfile)} />}
      {tab === 'diet-plan' && (
        <GeneratePanel
          title="Personalized Diet Plan"
          description="Full meal plan with macros, portions, and grocery tips."
          icon={<UtensilsCrossed size={24} />}
          aiStatus={aiStatus}
          gradient="bg-gradient-to-br from-emerald-500 to-teal-600"
          onGenerate={async (notes, days) => aiApi.generateDietPlan(notes || undefined, days)}
        />
      )}
      {tab === 'diet-chart' && (
        <GeneratePanel
          title="Weekly Diet Chart"
          description="Table-style chart for breakfast, lunch, dinner, and snacks."
          icon={<ClipboardList size={24} />}
          aiStatus={aiStatus}
          gradient="bg-gradient-to-br from-orange-400 to-amber-500"
          onGenerate={async (notes, days) => aiApi.generateDietChart(notes || undefined, days)}
        />
      )}
      {tab === 'workout' && (
        <GeneratePanel
          title="Workout Routine"
          description="Custom weekly schedule with sets, reps, and progression."
          icon={<Dumbbell size={24} />}
          aiStatus={aiStatus}
          gradient="bg-gradient-to-br from-purple-500 to-indigo-600"
          onGenerate={async (notes, days) => aiApi.generateWorkoutPlan(notes || undefined, days)}
        />
      )}
    </>
  );

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="AI Fitness Coach"
        subtitle="Personalized chat, diet plans, weekly charts, and workout routines."
        icon={<Sparkles className="text-white" />}
        image={IMAGES.heroes.aiCoach}
      >
        {aiStatus && (
          <span className={`inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-sm font-semibold ${aiStatus.configured ? 'bg-accent/90 text-white' : 'bg-amber-400/90 text-ink'}`}>
            {aiStatus.configured ? `Connected · ${aiStatus.provider}` : 'Set GROQ_API_KEY in .env'}
          </span>
        )}
        {aiStatus?.configured && (
          <button
            onClick={runDigest}
            disabled={digestLoading}
            className="mt-3 inline-flex items-center gap-2 rounded-full border border-white/30 bg-white/15 px-4 py-2 text-sm font-bold text-white backdrop-blur-md disabled:opacity-60"
          >
            {digestLoading ? 'Generating…' : 'Weekly digest'}
          </button>
        )}
      </PageHero>

      <div className="mx-auto mt-8 max-w-6xl px-4 sm:px-6">
        {completion.percent < 100 && (
          <div className="mb-6">
            <ProfileCompletion percent={completion.percent} missing={completion.missing} compact />
          </div>
        )}

        {/* Mobile tabs */}
        <div className="mb-6 flex gap-2 overflow-x-auto pb-2 lg:hidden">
          {tabs.map(({ id, label, icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex shrink-0 items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-bold transition ${tab === id ? 'gradient-primary text-white shadow-md' : 'bg-card text-primary'}`}
            >
              {icon}{label}
            </button>
          ))}
        </div>

        {/* Desktop sidebar layout */}
        <div className="hidden gap-6 lg:grid lg:grid-cols-[220px_1fr]">
          <nav className="space-y-1">
            {tabs.map(({ id, label, icon }) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`flex w-full items-center gap-2 rounded-xl px-4 py-3 text-sm font-bold transition ${tab === id ? 'gradient-primary text-white shadow-md' : 'bg-card text-ink hover:bg-surface-2'}`}
              >
                {icon}{label}
              </button>
            ))}
          </nav>
          <motion.div key={tab} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
            {panel}
          </motion.div>
        </div>

        <motion.div key={tab} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="lg:hidden">
          {panel}
        </motion.div>
      </div>
    </div>
  );
}
