import { motion } from 'framer-motion';
import { ArrowRight, Heart, Users } from 'lucide-react';
import { useEffect, useState } from 'react';
import { contentApi, extrasApi } from '../lib/api';
import type { Blog } from '../types';
import PageHero from '../components/PageHero';
import AppImage from '../components/AppImage';
import { IMAGES } from '../lib/images';

const CATEGORIES = ['All', 'Motivation', 'Nutrition', 'Community', 'Wellness'];

const tagColors: Record<string, string> = {
  Motivation: 'bg-accent',
  Nutrition: 'bg-primary',
  Community: 'bg-secondary',
  Wellness: 'bg-amber-400 text-ink',
};

export default function BlogsPage() {
  const [blogs, setBlogs] = useState<Blog[]>([]);
  const [category, setCategory] = useState('All');
  const [loading, setLoading] = useState(true);
  const [reactions, setReactions] = useState<Record<string, { count: number; user_reacted: boolean }>>({});

  useEffect(() => {
    setLoading(true);
    contentApi
      .blogs(category !== 'All' ? category : undefined)
      .then((data) => {
        setBlogs(data);
        data.forEach((b) => {
          extrasApi.getBlogReaction(b.id).then((r) => {
            setReactions((prev) => ({ ...prev, [b.id]: r }));
          }).catch(() => null);
        });
      })
      .finally(() => setLoading(false));
  }, [category]);

  const toggleReaction = async (blogId: string) => {
    try {
      const r = await extrasApi.blogReaction(blogId);
      setReactions((prev) => ({ ...prev, [blogId]: r }));
    } catch {
      /* ignore if not logged in */
    }
  };

  return (
    <div className="pb-12">
      <PageHero
        title="Healthy Blogs"
        subtitle="Real stories, expert tips, and community inspiration to keep you motivated."
        icon={<Users className="text-white" />}
        image={IMAGES.heroes.blogs}
      >
        <div className="flex flex-wrap justify-center gap-2">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={`rounded-full px-4 py-1.5 text-sm font-bold transition ${
                category === cat ? 'chip chip-active' : 'chip chip-inactive'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </PageHero>

      <div className="mx-auto mt-10 grid max-w-6xl gap-6 px-4 sm:grid-cols-2 lg:grid-cols-2 sm:px-6">
        {loading ? (
          <div className="col-span-full flex justify-center py-16">
            <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary/20 border-t-primary" />
          </div>
        ) : (
          blogs.map((blog, i) => (
            <motion.article
              key={blog.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
              className="group overflow-hidden rounded-2xl bg-white shadow-lg card-hover"
            >
              <AppImage
                src={blog.image}
                alt={blog.title}
                className="h-44 w-full object-cover transition group-hover:scale-105"
              />
              <div className="p-5">
                <div className="flex items-center gap-3">
                  <AppImage
                    src={blog.avatar}
                    alt={blog.title}
                    className="h-10 w-10 rounded-full border-2 border-[#e0c3fc] object-cover"
                  />
                  <div className="flex-1">
                    <span className="block text-sm font-bold text-primary">{blog.rank}</span>
                    <span className="text-xs text-muted">{blog.mentions}</span>
                  </div>
                  <span
                    className={`rounded-lg px-2.5 py-1 text-xs font-bold text-white ${tagColors[blog.category] || 'bg-gray-400'}`}
                  >
                    {blog.category}
                  </span>
                </div>
                <h3 className="font-display mt-3 text-xl font-bold text-primary">{blog.title}</h3>
                <p className="mt-2 text-sm text-muted">{blog.excerpt}</p>
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <button
                    onClick={() => toggleReaction(blog.id)}
                    className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-2 text-sm font-bold transition ${
                      reactions[blog.id]?.user_reacted ? 'bg-red-100 text-red-600' : 'bg-surface-2 text-muted hover:text-red-500'
                    }`}
                  >
                    <Heart size={16} className={reactions[blog.id]?.user_reacted ? 'fill-current' : ''} />
                    {reactions[blog.id]?.count ?? 0}
                  </button>
                  <a
                  href={blog.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-4 inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-bold text-white transition hover:bg-primary"
                >
                  Read More <ArrowRight size={16} />
                </a>
                </div>
              </div>
            </motion.article>
          ))
        )}
      </div>
    </div>
  );
}
