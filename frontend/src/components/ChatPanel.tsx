import { AnimatePresence, motion } from 'framer-motion';
import { Bot, Copy, RefreshCw, Send, Sparkles, Square, ThumbsDown, ThumbsUp, Trash2, User } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import axios from 'axios';
import { aiApi } from '../lib/api';
import type { AiStatus, ChatMessage } from '../types';
import AiMarkdown from './AiMarkdown';
import { ListSkeleton } from './Skeleton';
import VoiceInput from './VoiceInput';

const SUGGESTIONS = [
  'What should I eat before a morning workout?',
  'How can I lose weight safely?',
  'Best exercises for beginners at home?',
  'How much protein do I need daily?',
];

interface ChatPanelProps {
  aiStatus: AiStatus | null;
  compact?: boolean;
}

export default function ChatPanel({ aiStatus, compact = false }: ChatPanelProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [initialLoad, setInitialLoad] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const lastUserRef = useRef('');

  useEffect(() => {
    aiApi.chatHistory().then(setMessages).finally(() => setInitialLoad(false));
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, streaming]);

  const stopStream = () => {
    abortRef.current?.abort();
    setStreaming(false);
  };

  const send = async (text: string) => {
    if (!text.trim() || streaming) return;
    if (!aiStatus?.configured) {
      toast.error('Add your API key to .env to enable AI chat');
      return;
    }

    lastUserRef.current = text.trim();
    const userMsg: ChatMessage = {
      id: Date.now(),
      role: 'user',
      content: text.trim(),
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setStreaming(true);

    const streamingId = Date.now() + 1;
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      let streamedContent = '';
      setMessages((prev) => [
        ...prev,
        { id: streamingId, role: 'assistant', content: '', created_at: new Date().toISOString() },
      ]);

      const { message_id } = await aiApi.chatStream(
        text.trim(),
        (chunk) => {
          streamedContent += chunk;
          setMessages((prev) =>
            prev.map((m) => (m.id === streamingId ? { ...m, content: streamedContent } : m)),
          );
        },
        controller.signal,
      );

      setMessages((prev) =>
        prev.map((m) =>
          m.id === streamingId ? { ...m, id: message_id || streamingId, content: streamedContent } : m,
        ),
      );
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        toast('Generation stopped');
      } else {
        setMessages((prev) => prev.filter((m) => m.id !== userMsg.id && m.id !== streamingId));
        const msg =
          err instanceof Error && err.message
            ? err.message
            : axios.isAxiosError(err)
              ? (typeof err.response?.data?.detail === 'string' ? err.response.data.detail : 'Chat failed')
              : 'Chat failed';
        toast.error(msg);
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const regenerate = () => {
    if (lastUserRef.current) send(lastUserRef.current);
  };

  const copyMessage = (content: string) => {
    navigator.clipboard.writeText(content);
    toast.success('Copied');
  };

  const clearHistory = async () => {
    try {
      await aiApi.clearChat();
      setMessages([]);
      toast.success('Chat cleared');
    } catch {
      toast.error('Failed to clear chat');
    }
  };

  if (initialLoad) {
    return (
      <div className="card-modern p-4">
        <ListSkeleton count={3} />
      </div>
    );
  }

  return (
    <div className={`flex flex-col overflow-hidden rounded-2xl bg-card shadow-lg ${compact ? 'h-[420px]' : 'min-h-[500px] lg:min-h-[560px]'}`}>
      <div className="flex items-center justify-between border-b border-border px-4 py-3.5 gradient-primary">
        <div className="flex items-center gap-2 text-white">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white/20">
            <Bot size={20} />
          </div>
          <div>
            <p className="font-display font-bold">FitLife AI Coach</p>
            <p className="text-xs text-white/80">
              {aiStatus?.configured ? `${aiStatus.provider} · streaming` : 'API key not configured'}
            </p>
          </div>
        </div>
        <div className="flex gap-1">
          {streaming && (
            <button onClick={stopStream} className="rounded-lg p-2 text-white/90 hover:bg-white/20" title="Stop">
              <Square size={16} fill="currentColor" />
            </button>
          )}
          {messages.length > 0 && !streaming && (
            <button onClick={regenerate} className="rounded-lg p-2 text-white/80 hover:bg-white/20" title="Regenerate last">
              <RefreshCw size={18} />
            </button>
          )}
          {messages.length > 0 && (
            <button onClick={clearHistory} className="rounded-lg p-2 text-white/80 hover:bg-white/20" title="Clear">
              <Trash2 size={18} />
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-4">
        {messages.length === 0 && (
          <div className="flex h-full flex-col items-center justify-center text-center">
            <Sparkles className="mb-4 text-primary" size={32} />
            <h3 className="font-display text-lg font-bold text-primary">Ask anything about fitness</h3>
            <div className="mt-6 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => send(s)} className="chip chip-inactive text-xs">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        <AnimatePresence>
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={`mb-4 flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
            >
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${msg.role === 'user' ? 'bg-primary text-white' : 'gradient-accent text-white'}`}>
                {msg.role === 'user' ? <User size={16} /> : <Bot size={16} />}
              </div>
              <div className={`group max-w-[85%] rounded-2xl px-4 py-3 ${msg.role === 'user' ? 'rounded-tr-sm bg-primary text-white' : 'rounded-tl-sm bg-surface-2 text-ink'}`}>
                {msg.role === 'assistant' ? (
                  <>
                    <AiMarkdown content={msg.content} />
                    {!msg.content && streaming && (
                      <span className="inline-block h-4 w-0.5 animate-pulse bg-primary" aria-hidden="true" />
                    )}
                    {msg.content && (
                      <div className="mt-2 flex gap-1 opacity-0 transition group-hover:opacity-100">
                        <button onClick={() => copyMessage(msg.content)} className="rounded p-1 hover:bg-border" title="Copy">
                          <Copy size={14} />
                        </button>
                        <button onClick={() => toast.success('Thanks for the feedback!')} className="rounded p-1 hover:bg-border" title="Helpful">
                          <ThumbsUp size={14} />
                        </button>
                        <button onClick={() => toast('We\'ll improve!')} className="rounded p-1 hover:bg-border" title="Not helpful">
                          <ThumbsDown size={14} />
                        </button>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="text-sm leading-relaxed">{msg.content}</p>
                )}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        <div ref={bottomRef} />
      </div>

      <form
        onSubmit={(e) => { e.preventDefault(); send(input); }}
        className="border-t border-border p-3"
      >
        <div className="flex gap-2">
          <VoiceInput onResult={(text) => setInput(text)} disabled={!aiStatus?.configured || streaming} />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={aiStatus?.configured ? 'Ask your fitness coach...' : 'Configure API key first'}
            disabled={!aiStatus?.configured || streaming}
            className="flex-1 rounded-xl border-2 border-border bg-input-bg px-4 py-2.5 text-sm outline-none focus:border-primary disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={!input.trim() || streaming || !aiStatus?.configured}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl gradient-accent text-white disabled:opacity-50"
          >
            <Send size={18} />
          </button>
        </div>
      </form>
    </div>
  );
}
