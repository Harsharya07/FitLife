import { motion } from 'framer-motion';
import {
  Activity,
  ArrowUp,
  CheckCircle2,
  Dumbbell,
  Footprints,
  Hand,
  HeartPulse,
  Info,
  MoveVertical,
  Plus,
  Star,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { contentApi, activityApi } from '../lib/api';
import type { Exercise, ExerciseCategory } from '../types';
import PageHero from '../components/PageHero';
import AppImage from '../components/AppImage';
import LogWorkoutModal from '../components/LogWorkoutModal';
import ExerciseDetailModal from '../components/ExerciseDetailModal';
import FavoriteButton from '../components/FavoriteButton';
import { CardGridSkeleton } from '../components/Skeleton';
import { celebrate } from '../lib/celebrate';
import { IMAGES } from '../lib/images';

const iconMap: Record<string, React.ReactNode> = {
  'heart-pulse': <HeartPulse size={22} />,
  'arrow-up': <ArrowUp size={22} />,
  'move-vertical': <MoveVertical size={22} />,
  hand: <Hand size={22} />,
  star: <Star size={22} />,
  footprints: <Footprints size={22} />,
  activity: <Activity size={22} />,
};

function ExerciseCard({
  exercise,
  category,
  related,
}: {
  exercise: Exercise;
  category: ExerciseCategory;
  related: Exercise[];
}) {
  const [showTip, setShowTip] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const [showDetail, setShowDetail] = useState(false);
  const [logCount, setLogCount] = useState(0);

  useEffect(() => {
    activityApi.exerciseCount(exercise.id).then(setLogCount).catch(() => null);
  }, [exercise.id]);

  return (
    <>
      <motion.div layout className="group overflow-hidden rounded-2xl card-modern card-hover">
        <button
          type="button"
          onClick={() => setShowDetail(true)}
          className="relative block aspect-[4/3] w-full overflow-hidden bg-gradient-to-br from-slate-100 to-violet-50/80 dark:from-slate-800 dark:to-violet-950/30"
        >
          <AppImage
            src={exercise.image}
            alt={exercise.name}
            className="h-full w-full object-contain p-1 transition duration-300 group-hover:scale-[1.02]"
          />
          {logCount > 0 && (
            <span className="absolute left-2 top-2 flex items-center gap-1 rounded-full bg-accent/90 px-2 py-0.5 text-xs font-bold text-white">
              <CheckCircle2 size={12} /> {logCount}×
            </span>
          )}
          <div className="absolute right-2 top-2 rounded-full bg-card/90">
            <FavoriteButton itemType="exercise" itemId={exercise.id} />
          </div>
        </button>
        <div className="p-4">
          <h3 className="font-display text-lg font-bold text-primary">{exercise.name}</h3>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {exercise.tags.map((tag) => (
              <span key={tag} className="chip chip-inactive text-xs">{tag}</span>
            ))}
          </div>
          <p className="mt-2 line-clamp-2 text-sm text-muted">{exercise.description}</p>

          {/* Mobile + desktop actions */}
          <div className="mt-3 flex flex-wrap gap-2 sm:hidden">
            <button onClick={() => setShowDetail(true)} className="flex-1 rounded-lg bg-surface-2 px-3 py-2 text-xs font-bold text-primary">
              Details
            </button>
            <button onClick={() => setShowLog(true)} className="btn-accent flex-1 px-3 py-2 text-xs">
              Log
            </button>
          </div>

          <div className="mt-3 hidden gap-2 sm:flex">
            <button
              onClick={() => setShowTip(!showTip)}
              className="flex items-center gap-1 rounded-lg bg-surface-2 px-3 py-1.5 text-xs font-bold text-primary"
            >
              <Info size={14} /> Tips
            </button>
            <button onClick={() => setShowLog(true)} className="btn-accent flex items-center gap-1 px-3 py-1.5 text-xs">
              <Plus size={14} /> Log
            </button>
          </div>

          {showTip && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3 rounded-xl border-l-4 border-primary bg-surface-2 p-3 text-sm">
              <span className="font-bold text-accent">Tip: </span>{exercise.tip}
            </motion.div>
          )}
        </div>
      </motion.div>

      {showLog && (
        <LogWorkoutModal
          exercise={exercise}
          onClose={() => setShowLog(false)}
          onLogged={() => {
            setLogCount((c) => c + 1);
            celebrate('Workout logged!');
          }}
        />
      )}
      {showDetail && (
        <ExerciseDetailModal
          exercise={exercise}
          category={category}
          related={related.filter((e) => e.id !== exercise.id)}
          onClose={() => setShowDetail(false)}
        />
      )}
    </>
  );
}

function CategorySection({ category }: { category: ExerciseCategory }) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) setVisible(true);
    }, { threshold: 0.1 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 40 }}
      animate={visible ? { opacity: 1, y: 0 } : {}}
      className="mb-10 rounded-3xl bg-surface-2/50 p-4 sm:p-6"
    >
      <div className="mb-6 inline-flex items-center gap-2 rounded-xl gradient-primary px-4 py-2.5 font-display text-sm font-bold text-white shadow-md">
        {iconMap[category.icon] || <Dumbbell size={22} />}
        {category.name}
      </div>
      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {category.exercises.map((ex) => (
          <ExerciseCard key={ex.id} exercise={ex} category={category} related={category.exercises} />
        ))}
      </div>
    </motion.div>
  );
}

export default function ExercisesPage() {
  const [categories, setCategories] = useState<ExerciseCategory[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    contentApi.exercises().then(setCategories).finally(() => setLoading(false));
  }, []);

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="Exercises by Muscle Group"
        subtitle='Browse, view details, and log workouts to build your streak.'
        icon={<Dumbbell className="text-white" />}
        image={IMAGES.heroes.exercises}
      />
      <div className="mx-auto mt-8 max-w-7xl px-4 sm:px-6">
        {loading ? <CardGridSkeleton count={8} /> : categories.map((cat) => <CategorySection key={cat.id} category={cat} />)}
      </div>
    </div>
  );
}
