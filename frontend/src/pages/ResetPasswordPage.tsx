import { motion } from 'framer-motion';
import { Eye, EyeOff, Lock } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import axios from 'axios';
import { authApi } from '../lib/api';
import FitLifeLogo from '../components/FitLifeLogo';

export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [token, setToken] = useState(params.get('token') || '');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) {
      toast.error('Passwords do not match');
      return;
    }
    setSubmitting(true);
    try {
      await authApi.resetPassword(token.trim(), password, confirm);
      toast.success('Password updated! Sign in with your new password.');
      navigate('/login');
    } catch (err) {
      const msg = axios.isAxiosError(err) ? err.response?.data?.detail : 'Reset failed';
      toast.error(typeof msg === 'string' ? msg : 'Invalid or expired token');
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
        <h1 className="font-display text-center text-2xl font-extrabold text-ink">Reset password</h1>
        <p className="mt-2 text-center text-sm text-muted">Choose a new password for your account.</p>

        <form onSubmit={handleSubmit} className="mt-8 space-y-4">
          <input
            type="text"
            placeholder="Reset token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            required
            className="input-field"
          />
          <div className="relative">
            <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 text-primary" size={18} />
            <input
              type={show ? 'text' : 'password'}
              placeholder="New password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={6}
              className="input-field pr-12"
            />
            <button type="button" onClick={() => setShow(!show)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted">
              {show ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
          <input
            type="password"
            placeholder="Confirm password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            minLength={6}
            className="input-field"
          />
          <button type="submit" disabled={submitting} className="btn-primary w-full py-3 disabled:opacity-60">
            {submitting ? 'Updating...' : 'Update password'}
          </button>
        </form>

        <Link to="/login" className="mt-6 block text-center text-sm font-bold text-primary hover:text-accent">
          Back to sign in
        </Link>
      </motion.div>
    </div>
  );
}
