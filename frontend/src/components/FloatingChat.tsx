import { AnimatePresence, motion } from 'framer-motion';
import { Bot, Maximize2, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { aiApi } from '../lib/api';
import type { AiStatus } from '../types';
import ChatPanel from './ChatPanel';

export default function FloatingChat() {
  const [open, setOpen] = useState(false);
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);

  useEffect(() => {
    aiApi.status().then(setAiStatus).catch(() => null);
  }, []);

  return (
    <>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="fixed bottom-24 right-4 z-[60] w-[calc(100vw-2rem)] max-w-md sm:bottom-28 sm:right-6"
          >
            <div className="relative">
              <div className="absolute -top-3 right-12 flex gap-1">
                <Link
                  to="/ai-coach"
                  onClick={() => setOpen(false)}
                  className="rounded-lg bg-white p-1.5 text-primary shadow-md transition hover:bg-[#f0ebf8]"
                  title="Open full AI Coach"
                >
                  <Maximize2 size={16} />
                </Link>
                <button
                  onClick={() => setOpen(false)}
                  className="rounded-lg bg-white p-1.5 text-primary shadow-md transition hover:bg-[#f0ebf8]"
                >
                  <X size={16} />
                </button>
              </div>
              <ChatPanel aiStatus={aiStatus} compact />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <motion.button
        onClick={() => setOpen(!open)}
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.95 }}
        className="gradient-primary animate-pulse-glow fixed bottom-6 right-4 z-[60] flex h-14 w-14 items-center justify-center rounded-2xl text-white shadow-2xl sm:bottom-8 sm:right-6 sm:h-16 sm:w-16"
        aria-label="Open AI chat"
      >
        {open ? <X size={26} /> : <Bot size={26} />}
        {!open && aiStatus?.configured && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-75" />
            <span className="relative inline-flex h-4 w-4 rounded-full bg-accent" />
          </span>
        )}
      </motion.button>
    </>
  );
}
