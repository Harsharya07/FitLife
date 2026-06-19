import { motion } from 'framer-motion';
import { Mail, Shield } from 'lucide-react';
import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import PageHero from '../components/PageHero';
import { adminApi } from '../lib/api';
import { IMAGES } from '../lib/images';
import type { ContactRecord } from '../types';

export default function AdminContactsPage() {
  const [contacts, setContacts] = useState<ContactRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    adminApi
      .contacts()
      .then(setContacts)
      .catch(() => toast.error('Admin access required'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="pb-12">
      <PageHero
        title="Admin — Contact Inbox"
        subtitle="View messages submitted through the contact form."
        icon={<Shield className="text-white" />}
        image={IMAGES.heroes.dashboard}
      />

      <div className="mx-auto mt-8 max-w-4xl px-4 sm:px-6">
        {loading ? (
          <div className="flex justify-center py-20">
            <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary/20 border-t-primary" />
          </div>
        ) : contacts.length === 0 ? (
          <div className="rounded-2xl bg-white p-12 text-center shadow-lg">
            <Mail className="mx-auto text-primary/40" size={48} />
            <p className="mt-4 text-muted">No contact messages yet.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {contacts.map((c, i) => (
              <motion.div
                key={c.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="rounded-2xl bg-white p-6 shadow-lg"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <h3 className="font-display font-bold text-primary">{c.name}</h3>
                    <a href={`mailto:${c.email}`} className="text-sm text-accent hover:underline">
                      {c.email}
                    </a>
                  </div>
                  <time className="text-xs text-muted">
                    {new Date(c.created_at).toLocaleString()}
                  </time>
                </div>
                <p className="mt-4 whitespace-pre-wrap text-sm leading-relaxed text-ink">{c.message}</p>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
