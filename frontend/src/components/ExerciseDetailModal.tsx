import { AnimatePresence, motion } from 'framer-motion';
import { Info, Plus, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { activityApi } from '../lib/api';
import type { Exercise, ExerciseCategory } from '../types';
import AppImage from './AppImage';
import LogWorkoutModal from './LogWorkoutModal';

interface ExerciseDetailModalProps {
  exercise: Exercise;
  category?: ExerciseCategory;
  related?: Exercise[];
  onClose: () => void;
}

export default function ExerciseDetailModal({
  exercise,
  category,
  related = [],
  onClose,
}: ExerciseDetailModalProps) {
  const [logCount, setLogCount] = useState(0);
  const [showLog, setShowLog] = useState(false);

  useEffect(() => {
    activityApi.exerciseCount(exercise.id).then(setLogCount).catch(() => null);
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, [exercise.id]);

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[70] flex items-end justify-center bg-black/50 p-0 backdrop-blur-sm sm:items-center sm:p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ y: '100%' }}
          animate={{ y: 0 }}
          exit={{ y: '100%' }}
          onClick={(e) => e.stopPropagation()}
          className="max-h-[92vh] w-full max-w-2xl overflow-y-auto rounded-t-3xl bg-card sm:rounded-3xl"
          role="dialog"
          aria-labelledby="exercise-title"
        >
          <div className="relative aspect-video bg-surface-2">
            {exercise.video_url ? (
              <iframe
                src={exercise.video_url}
                title={`${exercise.name} demo`}
                className="h-full w-full"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
              />
            ) : (
              <AppImage src={exercise.image} alt={exercise.name} className="h-full w-full object-contain p-4" />
            )}
            <button
              onClick={onClose}
              className="absolute right-4 top-4 rounded-full bg-card/90 p-2 shadow-lg"
              aria-label="Close"
            >
              <X size={20} />
            </button>
          </div>

          <div className="p-6">
            {category && (
              <span className="text-xs font-bold uppercase tracking-wide text-accent">{category.name}</span>
            )}
            <h2 id="exercise-title" className="font-display text-2xl font-bold text-ink">
              {exercise.name}
            </h2>
            {logCount > 0 && (
              <p className="mt-1 text-sm font-semibold text-accent">Logged {logCount} time{logCount !== 1 ? 's' : ''}</p>
            )}
            <div className="mt-3 flex flex-wrap gap-2">
              {exercise.tags.map((tag) => (
                <span key={tag} className="chip chip-inactive text-xs">
                  {tag}
                </span>
              ))}
            </div>
            <p className="mt-4 text-muted">{exercise.description}</p>
            <div className="mt-4 rounded-xl border-l-4 border-primary bg-surface-2 p-4">
              <p className="flex items-start gap-2 text-sm">
                <Info size={16} className="mt-0.5 shrink-0 text-accent" />
                <span>
                  <strong className="text-ink">Tip:</strong> {exercise.tip}
                </span>
              </p>
              <p className="mt-2 text-sm text-muted">
                <strong>Equipment:</strong> {exercise.equipment}
              </p>
            </div>

            <div className="mt-6 flex flex-wrap gap-3">
              <button onClick={() => setShowLog(true)} className="btn-accent inline-flex items-center gap-2 px-6 py-3">
                <Plus size={18} /> Log workout
              </button>
              <Link to="/ai-coach" onClick={onClose} className="btn-primary inline-flex items-center gap-2 px-6 py-3">
                Ask AI Coach
              </Link>
            </div>

            {related.length > 0 && (
              <div className="mt-8">
                <h3 className="font-display font-bold text-ink">Related exercises</h3>
                <div className="mt-3 flex flex-wrap gap-2">
                  {related.slice(0, 4).map((ex) => (
                    <span key={ex.id} className="rounded-lg bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink">
                      {ex.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>

      {showLog && (
        <LogWorkoutModal
          exercise={exercise}
          onClose={() => setShowLog(false)}
          onLogged={() => setLogCount((c) => c + 1)}
        />
      )}
    </AnimatePresence>
  );
}
