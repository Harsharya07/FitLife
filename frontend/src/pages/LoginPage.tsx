import { motion } from 'framer-motion';
import { Eye, EyeOff, Lock, User } from 'lucide-react';
import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { ensureBackendAwake, formatApiError } from '../lib/api';
import FitLifeLogo from '../components/FitLifeLogo';

export default function LoginPage() {
  const { login, user, loading } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState('');

  if (!loading && user) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setStatus('');
    try {
      await ensureBackendAwake(setStatus);
      await login(username, password);
      toast.success('Logged in successfully!');
      navigate('/dashboard');
    } catch (err) {
      toast.error(formatApiError(err, 'Login failed'));
    } finally {
      setSubmitting(false);
      setStatus('');
    }
  };

  return (
    <div className="auth-bg relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10">
      <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-violet-500/30 blur-[100px]" />
      <div className="pointer-events-none absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-teal-500/25 blur-[100px]" />
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-64 w-64 -translate-x-1/2 -translate-y-1/2 rounded-full bg-indigo-500/20 blur-[80px]" />

      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="glass-panel relative w-full max-w-md rounded-3xl p-8 sm:p-10"
      >
        <motion.div
          animate={{ scale: [1, 1.06, 1] }}
          transition={{ repeat: Infinity, duration: 3, ease: 'easeInOut' }}
          className="mx-auto mb-5 flex justify-center"
        >
          <FitLifeLogo to="/" size="lg" showText={false} />
        </motion.div>

        <h1 className="font-display text-center text-2xl font-extrabold tracking-tight text-ink">
          Welcome to <span className="gradient-text">FitLife</span>
        </h1>
        <p className="mt-2 text-center text-sm font-medium text-muted">
          Your wellness journey starts here
        </p>

        <form onSubmit={handleSubmit} className="mt-8 space-y-4">
          <div className="relative">
            <User className="absolute left-3.5 top-1/2 z-10 -translate-y-1/2 text-primary" size={18} />
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
              className="input-field"
            />
          </div>

          <div className="relative">
            <Lock className="absolute left-3.5 top-1/2 z-10 -translate-y-1/2 text-primary" size={18} />
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              className="input-field pr-12"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted transition hover:text-primary"
              aria-label="Toggle password"
            >
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>

          <button type="submit" disabled={submitting} className="btn-primary w-full py-3.5 disabled:opacity-60">
            {submitting ? status || 'Signing in…' : 'Sign In'}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-muted">
          Don&apos;t have an account?{' '}
          <Link to="/signup" className="font-bold text-primary transition hover:text-accent">
            Create one
          </Link>
        </p>
        <p className="mt-2 text-center text-sm">
          <Link to="/forgot-password" className="font-bold text-muted transition hover:text-primary">
            Forgot password?
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
