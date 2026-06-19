import { Mic, MicOff } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';

interface VoiceInputProps {
  onResult: (text: string) => void;
  disabled?: boolean;
}

type SpeechRecognitionLike = {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  onresult: ((e: { results: { [index: number]: { [index: number]: { transcript: string } } } }) => void) | null;
  onerror: (() => void) | null;
  onend: (() => void) | null;
  start: () => void;
  stop: () => void;
};

export default function VoiceInput({ onResult, disabled }: VoiceInputProps) {
  const [listening, setListening] = useState(false);
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);

  useEffect(() => {
    const w = window as Window & { SpeechRecognition?: new () => SpeechRecognitionLike; webkitSpeechRecognition?: new () => SpeechRecognitionLike };
    const SR = w.SpeechRecognition || w.webkitSpeechRecognition;
    if (!SR) return;
    const rec = new SR();
    rec.continuous = false;
    rec.interimResults = false;
    rec.lang = 'en-US';
    rec.onresult = (e) => {
      const text = e.results[0]?.[0]?.transcript;
      if (text) onResult(text);
      setListening(false);
    };
    rec.onerror = () => {
      toast.error('Voice input failed');
      setListening(false);
    };
    rec.onend = () => setListening(false);
    recognitionRef.current = rec;
  }, [onResult]);

  const toggle = () => {
    if (disabled) return;
    if (!recognitionRef.current) {
      toast.error('Voice input not supported in this browser');
      return;
    }
    if (listening) {
      recognitionRef.current.stop();
      setListening(false);
    } else {
      recognitionRef.current.start();
      setListening(true);
    }
  };

  return (
    <button
      type="button"
      onClick={toggle}
      disabled={disabled}
      className={`rounded-xl p-2 transition ${listening ? 'bg-red-100 text-red-600' : 'text-muted hover:bg-surface-2 hover:text-primary'} disabled:opacity-50`}
      aria-label={listening ? 'Stop listening' : 'Voice input'}
    >
      {listening ? <MicOff size={18} /> : <Mic size={18} />}
    </button>
  );
}
