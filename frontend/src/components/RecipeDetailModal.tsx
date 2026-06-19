import { AnimatePresence, motion } from 'framer-motion';
import { Clock, ExternalLink, Flame, List, Utensils, X } from 'lucide-react';
import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import type { Recipe } from '../types';
import AppImage from './AppImage';

interface RecipeDetailModalProps {
  recipe: Recipe;
  onClose: () => void;
}

export default function RecipeDetailModal({ recipe, onClose }: RecipeDetailModalProps) {
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl bg-card shadow-2xl"
          role="dialog"
        >
          <AppImage src={recipe.image} alt={recipe.name} className="h-48 w-full object-cover" />
          <div className="p-6">
            <div className="flex items-start justify-between gap-4">
              <h2 className="font-display text-2xl font-bold text-ink">{recipe.name}</h2>
              <button onClick={onClose} className="rounded-lg p-1 hover:bg-surface-2" aria-label="Close">
                <X size={20} />
              </button>
            </div>
            <div className="mt-2 flex gap-4 text-sm font-semibold text-muted">
              <span className="flex items-center gap-1">
                <Clock size={14} className="text-accent" /> {recipe.prep_time}
              </span>
              <span className="flex items-center gap-1">
                <Flame size={14} className="text-orange-500" /> {recipe.calories}
              </span>
            </div>
            <p className="mt-3 text-muted">{recipe.description}</p>

            <div className="mt-6">
              <h3 className="flex items-center gap-2 font-bold text-accent">
                <List size={16} /> Ingredients
              </h3>
              <ul className="mt-2 space-y-1">
                {recipe.ingredients.map((ing) => (
                  <li key={ing} className="flex items-center gap-2 text-sm text-ink">
                    <span className="h-1.5 w-1.5 rounded-full bg-accent" />
                    {ing}
                  </li>
                ))}
              </ul>
            </div>

            <div className="mt-6">
              <h3 className="flex items-center gap-2 font-bold text-accent">
                <Utensils size={16} /> Steps
              </h3>
              <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm text-muted">
                {recipe.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </div>

            <Link
              to="/ai-coach"
              onClick={onClose}
              className="btn-accent mt-6 inline-flex w-full items-center justify-center gap-2 py-3"
            >
              Add to meal plan via AI Coach <ExternalLink size={16} />
            </Link>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
