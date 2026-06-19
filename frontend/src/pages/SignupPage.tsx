import { motion } from 'framer-motion';
import { Eye, EyeOff, Lock, User } from 'lucide-react';
import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import FitLifeLogo from '../components/FitLifeLogo';

function getPasswordStrength(password: string): { label: string; color: string; width: string } {
  if (!password) return { label: '', color: '', width: '0%' };
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[\W]/.test(password)) score++;
  if (score <= 1) return { label: 'Weak password', color: 'bg-red-500', width: '33%' };
  if (score <= 3) return { label: 'Medium password', color: 'bg-amber-500', width: '66%' };
  return { label: 'Strong password', color: 'bg-teal-500', width: '100%' };
}

export default function SignupPage() {
  const { signup, login, user, loading } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const strength = getPasswordStrength(password);

  if (!loading && user) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    setSubmitting(true);
    try {
      await signup(username, password, confirmPassword);
      await login(username, password);
      toast.success('Account created!');
      navigate('/dashboard');
    } catch (err) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || 'Signup failed'
        : 'Signup failed';
      toast.error(typeof msg === 'string' ? msg : 'Could not create account');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-bg relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10">
      <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-violet-500/30 blur-[100px]" />
      <div className="pointer-events-none absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-teal-500/25 blur-[100px]" />

      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-panel relative w-full max-w-md rounded-3xl p-8 sm:p-10"
      >
        <motion.div
          animate={{ scale: [1, 1.06, 1] }}
          transition={{ repeat: Infinity, duration: 3 }}
          className="mx-auto mb-5 flex justify-center"
        >
          <FitLifeLogo to="/" size="lg" showText={false} />
        </motion.div>

        <h1 className="font-display text-center text-2xl font-extrabold tracking-tight text-ink">
          Join <span className="gradient-text">FitLife</span>
        </h1>
        <p className="mt-2 text-center text-sm font-medium text-muted">
          Start your personalized fitness journey
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
              minLength={3}
              className="input-field"
            />
          </div>

          <div>
            <div className="relative">
              <Lock className="absolute left-3.5 top-1/2 z-10 -translate-y-1/2 text-primary" size={18} />
              <input
                type={showPassword ? 'text' : 'password'}
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={6}
                className="input-field pr-12"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted"
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {password && (
              <div className="mt-2">
                <div className="h-1.5 overflow-hidden rounded-full bg-slate-200">
                  <div className={`h-full transition-all duration-300 ${strength.color}`} style={{ width: strength.width }} />
                </div>
                <p className="mt-1 text-xs font-semibold text-muted">{strength.label}</p>
              </div>
            )}
          </div>

          <div className="relative">
            <Lock className="absolute left-3.5 top-1/2 z-10 -translate-y-1/2 text-primary" size={18} />
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              className="input-field"
            />
          </div>

          <button type="submit" disabled={submitting} className="btn-primary w-full py-3.5 disabled:opacity-60">
            {submitting ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-muted">
          Already have an account?{' '}
          <Link to="/login" className="font-bold text-primary transition hover:text-accent">
            Sign In
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
