import { AnimatePresence, motion } from 'framer-motion';
import { Calendar, ExternalLink, User, X } from 'lucide-react';
import { useEffect } from 'react';
import type { Article } from '../types';
import AppImage from './AppImage';

interface ArticlePreviewModalProps {
  article: Article;
  onClose: () => void;
}

export default function ArticlePreviewModal({ article, onClose }: ArticlePreviewModalProps) {
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
        <motion.article
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl bg-card shadow-2xl"
        >
          <AppImage src={article.image} alt={article.title} className="h-44 w-full object-cover" />
          <div className="p-6">
            <div className="flex items-start justify-between gap-2">
              <div className="flex flex-wrap gap-1.5">
                {article.categories.map((cat) => (
                  <span key={cat} className="chip chip-active text-xs">
                    {cat}
                  </span>
                ))}
              </div>
              <button onClick={onClose} className="rounded-lg p-1 hover:bg-surface-2" aria-label="Close">
                <X size={20} />
              </button>
            </div>
            <h2 className="font-display mt-3 text-xl font-bold text-ink">{article.title}</h2>
            <div className="mt-2 flex gap-4 text-xs text-muted">
              <span className="flex items-center gap-1">
                <User size={12} /> {article.author}
              </span>
              <span className="flex items-center gap-1">
                <Calendar size={12} /> {article.date}
              </span>
            </div>
            <p className="mt-4 leading-relaxed text-muted">{article.excerpt}</p>
            <a
              href={article.url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary mt-6 inline-flex w-full items-center justify-center gap-2 py-3"
            >
              Read full article <ExternalLink size={16} />
            </a>
          </div>
        </motion.article>
      </motion.div>
    </AnimatePresence>
  );
}
