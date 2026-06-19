import { motion } from 'framer-motion';
import { ArrowLeft, User } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import axios from 'axios';
import { authApi } from '../lib/api';
import FitLifeLogo from '../components/FitLifeLogo';

export default function ForgotPasswordPage() {
  const [username, setUsername] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [resetToken, setResetToken] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await authApi.forgotPassword(username.trim());
      toast.success(res.message);
      if (res.reset_token) {
        setResetToken(res.reset_token);
      }
    } catch (err) {
      const msg = axios.isAxiosError(err) ? err.response?.data?.detail : 'Request failed';
      toast.error(typeof msg === 'string' ? msg : 'Could not process request');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-bg relative flex min-h-screen items-center justify-center px-4 py-10">
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-panel w-full max-w-md rounded-3xl p-8"
      >
        <div className="mx-auto mb-5 flex justify-center">
          <FitLifeLogo to="/" size="lg" showText={false} />
        </div>
        <h1 className="font-display text-center text-2xl font-extrabold text-ink">Forgot password</h1>
        <p className="mt-2 text-center text-sm text-muted">Enter your username and we&apos;ll send reset instructions.</p>

        <form onSubmit={handleSubmit} className="mt-8 space-y-4">
          <div className="relative">
            <User className="absolute left-3.5 top-1/2 -translate-y-1/2 text-primary" size={18} />
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="input-field"
            />
          </div>
          <button type="submit" disabled={submitting} className="btn-primary w-full py-3 disabled:opacity-60">
            {submitting ? 'Sending...' : 'Send reset link'}
          </button>
        </form>

        {resetToken && (
          <div className="mt-4 rounded-xl bg-surface-2 p-4 text-sm">
            <p className="font-semibold text-ink">Dev mode — reset token:</p>
            <Link to={`/reset-password?token=${resetToken}`} className="mt-1 break-all text-primary hover:underline">
              {resetToken}
            </Link>
          </div>
        )}

        <Link to="/login" className="mt-6 flex items-center justify-center gap-1 text-sm font-bold text-primary hover:text-accent">
          <ArrowLeft size={16} /> Back to sign in
        </Link>
      </motion.div>
    </div>
  );
}
