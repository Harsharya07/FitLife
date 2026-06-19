import { motion } from 'framer-motion';
import { BookOpen, Calendar, Search, User } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { contentApi } from '../lib/api';
import type { Article } from '../types';
import PageHero from '../components/PageHero';
import AppImage from '../components/AppImage';
import ArticlePreviewModal from '../components/ArticlePreviewModal';
import { CardGridSkeleton } from '../components/Skeleton';
import EmptyState from '../components/EmptyState';
import { IMAGES } from '../lib/images';

const CATEGORIES = ['All', 'Motivation', 'Nutrition', 'Training', 'Wellness', 'Latest'];

const badgeColors: Record<string, string> = {
  Motivation: 'bg-accent text-white',
  Training: 'bg-secondary text-white',
  Wellness: 'bg-primary text-white',
  Latest: 'bg-amber-400 text-ink',
  Nutrition: 'bg-emerald-500 text-white',
};

export default function ArticlesPage() {
  const [articles, setArticles] = useState<Article[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('All');
  const [preview, setPreview] = useState<Article | null>(null);

  useEffect(() => {
    setLoading(true);
    contentApi
      .articles(search || undefined, category !== 'All' ? category : undefined)
      .then(setArticles)
      .finally(() => setLoading(false));
  }, [search, category]);

  const filtered = useMemo(() => articles, [articles]);

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="Fitness Articles"
        subtitle="Expert advice, wellness tips, and motivational reads."
        icon={<BookOpen className="text-white" />}
        image={IMAGES.heroes.articles}
      >
        <div className="mx-auto flex max-w-md overflow-hidden rounded-full bg-white shadow-lg">
          <input
            type="search"
            placeholder="Search articles..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 border-0 px-5 py-3 text-ink outline-none"
            aria-label="Search articles"
          />
          <span className="gradient-accent flex items-center px-5 text-white">
            <Search size={20} />
          </span>
        </div>
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={`rounded-full px-4 py-1.5 text-sm font-bold transition ${category === cat ? 'chip chip-active' : 'chip chip-inactive'}`}
            >
              {cat}
            </button>
          ))}
        </div>
      </PageHero>

      <div className="mx-auto mt-10 grid max-w-6xl gap-6 px-4 sm:grid-cols-2 lg:grid-cols-3 sm:px-6">
        {loading ? (
          <div className="col-span-full"><CardGridSkeleton count={6} /></div>
        ) : filtered.length === 0 ? (
          <div className="col-span-full">
            <EmptyState icon={BookOpen} title="No articles found" description="Try a different search or category." />
          </div>
        ) : (
          filtered.map((article, i) => (
            <motion.article
              key={article.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="card-modern card-hover cursor-pointer overflow-hidden"
              onClick={() => setPreview(article)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && setPreview(article)}
            >
              <AppImage src={article.image} alt={article.title} className="h-40 w-full object-cover" />
              <div className="p-5">
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {article.categories.map((cat) => (
                    <span key={cat} className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${badgeColors[cat] || 'bg-gray-200'}`}>
                      {cat}
                    </span>
                  ))}
                </div>
                <h3 className="font-display text-lg font-bold text-primary">{article.title}</h3>
                <div className="mt-2 flex gap-3 text-xs text-muted">
                  <span className="flex items-center gap-1"><User size={12} /> {article.author}</span>
                  <span className="flex items-center gap-1"><Calendar size={12} /> {article.date}</span>
                </div>
                <p className="mt-3 line-clamp-3 text-sm text-muted">{article.excerpt}</p>
                <span className="mt-4 inline-block text-sm font-bold text-accent">Preview article →</span>
              </div>
            </motion.article>
          ))
        )}
      </div>
      {preview && <ArticlePreviewModal article={preview} onClose={() => setPreview(null)} />}
    </div>
  );
}
