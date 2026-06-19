import { motion } from 'framer-motion';
import { Carrot, Clock, Flame, Utensils } from 'lucide-react';
import { useEffect, useState } from 'react';
import { contentApi } from '../lib/api';
import type { Recipe } from '../types';
import PageHero from '../components/PageHero';
import AppImage from '../components/AppImage';
import RecipeDetailModal from '../components/RecipeDetailModal';
import { CardGridSkeleton } from '../components/Skeleton';
import EmptyState from '../components/EmptyState';
import { IMAGES } from '../lib/images';

function RecipeCard({ recipe, onOpen }: { recipe: Recipe; onOpen: () => void }) {
  return (
    <motion.button
      type="button"
      onClick={onOpen}
      className="card-modern card-hover overflow-hidden text-left"
    >
      <AppImage src={recipe.image} alt={recipe.name} className="h-44 w-full object-cover" />
      <div className="p-5">
        <h3 className="font-display text-xl font-bold text-primary">{recipe.name}</h3>
        <div className="mt-2 flex gap-3 text-xs font-semibold text-muted">
          <span className="flex items-center gap-1"><Clock size={14} className="text-accent" /> {recipe.prep_time}</span>
          <span className="flex items-center gap-1"><Flame size={14} className="text-orange-500" /> {recipe.calories}</span>
        </div>
        <p className="mt-2 line-clamp-2 text-sm text-muted">{recipe.description}</p>
        <span className="mt-4 inline-flex items-center gap-2 text-sm font-bold text-accent">
          <Utensils size={16} /> View recipe
        </span>
      </div>
    </motion.button>
  );
}

export default function RecipesPage() {
  const [recipes, setRecipes] = useState<Recipe[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Recipe | null>(null);

  useEffect(() => {
    contentApi.recipes().then(setRecipes).finally(() => setLoading(false));
  }, []);

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="Healthy Recipes"
        subtitle="Discover delicious, nutritious recipes to fuel your body."
        icon={<Carrot className="text-white" />}
        image={IMAGES.heroes.recipes}
      />
      <div className="mx-auto mt-10 grid max-w-6xl gap-6 px-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 sm:px-6">
        {loading ? (
          <div className="col-span-full"><CardGridSkeleton count={8} /></div>
        ) : recipes.length === 0 ? (
          <div className="col-span-full">
            <EmptyState icon={Carrot} title="No recipes" description="Check back soon for healthy meal ideas." />
          </div>
        ) : (
          recipes.map((recipe) => (
            <RecipeCard key={recipe.id} recipe={recipe} onOpen={() => setSelected(recipe)} />
          ))
        )}
      </div>
      {selected && <RecipeDetailModal recipe={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
