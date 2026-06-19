import { motion } from 'framer-motion';
import { Download, Moon, Sun, Monitor, Trash2, User } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import PageHero from '../components/PageHero';
import { useAuth } from '../context/AuthContext';
import { useTheme, type Theme } from '../context/ThemeContext';
import { aiApi, extrasApi } from '../lib/api';
import { IMAGES } from '../lib/images';

const themes: { id: Theme; label: string; icon: React.ReactNode }[] = [
  { id: 'light', label: 'Light', icon: <Sun size={18} /> },
  { id: 'dark', label: 'Dark', icon: <Moon size={18} /> },
  { id: 'system', label: 'System', icon: <Monitor size={18} /> },
];

export default function SettingsPage() {
  const { user } = useAuth();
  const { theme, setTheme } = useTheme();
  const [clearing, setClearing] = useState(false);
  const [exporting, setExporting] = useState(false);

  const clearChat = async () => {
    setClearing(true);
    try {
      await aiApi.clearChat();
      toast.success('Chat history cleared');
    } catch {
      toast.error('Failed to clear chat');
    } finally {
      setClearing(false);
    }
  };

  const exportData = async () => {
    setExporting(true);
    try {
      const data = await extrasApi.exportData();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fitlife-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Data exported');
    } catch {
      toast.error('Export failed');
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="Settings"
        subtitle="Customize appearance and manage your account preferences."
        icon={<User className="text-white" />}
        image={IMAGES.heroes.dashboard}
      />

      <div className="mx-auto mt-8 max-w-2xl space-y-6 px-4 sm:px-6">
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="card-modern p-6"
        >
          <h2 className="font-display font-bold text-ink">Account</h2>
          <p className="mt-2 text-sm text-muted">
            Signed in as <strong className="text-ink">{user?.username}</strong>
            {user?.is_admin && (
              <span className="ml-2 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-bold text-primary">
                Admin
              </span>
            )}
          </p>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="card-modern p-6"
        >
          <h2 className="font-display font-bold text-ink">Appearance</h2>
          <p className="mt-1 text-sm text-muted">Choose light, dark, or match your system.</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {themes.map(({ id, label, icon }) => (
              <button
                key={id}
                onClick={() => setTheme(id)}
                className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-bold transition focus-visible:ring-2 focus-visible:ring-primary ${
                  theme === id ? 'gradient-primary text-white shadow-md' : 'bg-surface-2 text-ink hover:bg-border'
                }`}
              >
                {icon}
                {label}
              </button>
            ))}
          </div>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="card-modern p-6"
        >
          <h2 className="font-display font-bold text-ink">Data</h2>
          <p className="mt-1 text-sm text-muted">Export your data or clear AI chat history.</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <button
              onClick={exportData}
              disabled={exporting}
              className="flex items-center gap-2 rounded-xl border-2 border-primary/30 px-4 py-2.5 text-sm font-bold text-primary transition hover:bg-primary/5 disabled:opacity-60"
            >
              <Download size={16} />
              {exporting ? 'Exporting...' : 'Export my data'}
            </button>
            <button
              onClick={clearChat}
              disabled={clearing}
              className="flex items-center gap-2 rounded-xl border-2 border-red-200 px-4 py-2.5 text-sm font-bold text-red-600 transition hover:bg-red-50 disabled:opacity-60"
            >
              <Trash2 size={16} />
              {clearing ? 'Clearing...' : 'Clear chat history'}
            </button>
          </div>
        </motion.section>
      </div>
    </div>
  );
}
