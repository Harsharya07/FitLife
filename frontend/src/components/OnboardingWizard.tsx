import { AnimatePresence, motion } from 'framer-motion';
import { ArrowRight, Bot, Dumbbell, Sparkles, UserCircle } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { markOnboardingDone } from '../lib/profileCompletion';
import ProfileForm from './ProfileForm';

interface OnboardingWizardProps {
  userId: number;
  onComplete: () => void;
}

const STEPS = [
  { title: 'Welcome to FitLife', desc: 'Your AI-powered fitness companion. Let\'s set you up in 3 quick steps.' },
  { title: 'Your fitness profile', desc: 'Help the AI coach personalize diet and workout plans for you.' },
  { title: 'You\'re all set!', desc: 'Log workouts, chat with AI, and track your streak on the dashboard.' },
];

export default function OnboardingWizard({ userId, onComplete }: OnboardingWizardProps) {
  const [step, setStep] = useState(0);
  const navigate = useNavigate();

  const finish = () => {
    markOnboardingDone(userId);
    onComplete();
  };

  const skip = () => {
    markOnboardingDone(userId);
    onComplete();
  };

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      >
        <motion.div
          initial={{ scale: 0.95, y: 20 }}
          animate={{ scale: 1, y: 0 }}
          className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-3xl bg-card p-6 shadow-2xl sm:p-8"
          role="dialog"
          aria-labelledby="onboarding-title"
        >
          <div className="mb-6 flex items-center justify-between">
            <div className="flex gap-1.5">
              {STEPS.map((_, i) => (
                <span
                  key={i}
                  className={`h-1.5 w-8 rounded-full transition ${i <= step ? 'gradient-accent' : 'bg-border'}`}
                />
              ))}
            </div>
            <button onClick={skip} className="text-sm font-semibold text-muted hover:text-primary">
              Skip
            </button>
          </div>

          {step === 0 && (
            <div className="text-center">
              <div className="gradient-primary mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl text-white">
                <Sparkles size={32} />
              </div>
              <h2 id="onboarding-title" className="font-display text-2xl font-bold text-ink">
                {STEPS[0].title}
              </h2>
              <p className="mt-2 text-muted">{STEPS[0].desc}</p>
              <div className="mt-8 grid gap-3 text-left">
                {[
                  { icon: UserCircle, text: 'Set your fitness profile' },
                  { icon: Bot, text: 'Get AI diet & workout plans' },
                  { icon: Dumbbell, text: 'Log workouts & build streaks' },
                ].map(({ icon: Icon, text }) => (
                  <div key={text} className="flex items-center gap-3 rounded-xl bg-surface-2 p-3">
                    <Icon size={20} className="text-primary" />
                    <span className="font-medium text-ink">{text}</span>
                  </div>
                ))}
              </div>
              <button onClick={() => setStep(1)} className="btn-primary mt-8 inline-flex items-center gap-2 px-8 py-3">
                Get started <ArrowRight size={18} />
              </button>
            </div>
          )}

          {step === 1 && (
            <div>
              <h2 className="font-display text-xl font-bold text-ink">{STEPS[1].title}</h2>
              <p className="mt-1 text-sm text-muted">{STEPS[1].desc}</p>
              <div className="mt-4">
                <ProfileForm compact onSaved={() => setStep(2)} />
              </div>
              <button onClick={() => setStep(2)} className="mt-4 text-sm font-bold text-muted hover:text-primary">
                Skip for now →
              </button>
            </div>
          )}

          {step === 2 && (
            <div className="text-center">
              <div className="gradient-accent mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl text-white text-3xl">
                🎉
              </div>
              <h2 className="font-display text-2xl font-bold text-ink">{STEPS[2].title}</h2>
              <p className="mt-2 text-muted">{STEPS[2].desc}</p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
                <button
                  onClick={() => {
                    finish();
                    navigate('/exercises');
                  }}
                  className="btn-accent px-6 py-3"
                >
                  Log first workout
                </button>
                <button
                  onClick={() => {
                    finish();
                    navigate('/ai-coach');
                  }}
                  className="btn-primary px-6 py-3"
                >
                  Try AI Coach
                </button>
              </div>
              <button onClick={finish} className="mt-4 text-sm font-bold text-muted hover:text-primary">
                Go to dashboard
              </button>
            </div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
