import { Link } from 'react-router-dom';
import { Mail } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import FitLifeLogo from './FitLifeLogo';

export default function Footer() {
  const [email, setEmail] = useState('');

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    toast.success('Thank you for subscribing!');
    setEmail('');
  };

  return (
    <footer className="gradient-footer relative mt-auto overflow-hidden text-white">
      <div className="gradient-mesh-overlay pointer-events-none absolute inset-0 opacity-40" />
      <div className="relative mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="mb-8 flex justify-center">
          <FitLifeLogo to="/dashboard" ring textClassName="text-white" />
        </div>
        <form
          onSubmit={handleSubscribe}
          className="mb-10 flex flex-col items-center justify-center gap-3 sm:flex-row"
        >
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Subscribe to our newsletter"
            required
            className="w-full max-w-sm rounded-full border border-white/20 bg-white/10 px-5 py-3 text-white placeholder:text-white/50 outline-none backdrop-blur-sm focus:border-teal-300 focus:ring-2 focus:ring-teal-300/30 sm:w-auto"
          />
          <button type="submit" className="btn-accent flex items-center gap-2 rounded-full px-7 py-3">
            <Mail size={16} />
            Subscribe
          </button>
        </form>

        <div className="mb-6 flex flex-wrap justify-center gap-x-5 gap-y-2 text-sm font-medium">
          {[
            { to: '/dashboard', label: 'Home' },
            { to: '/ai-coach', label: 'AI Coach' },
            { to: '/exercises', label: 'Exercises' },
            { to: '/articles', label: 'Articles' },
            { to: '/blogs', label: 'Blogs' },
            { to: '/recipes', label: 'Recipes' },
            { to: '/contact', label: 'Contact' },
          ].map(({ to, label }) => (
            <Link
              key={to}
              to={to}
              className="text-white/75 transition hover:text-teal-300"
            >
              {label}
            </Link>
          ))}
        </div>

        <p className="text-center text-sm text-white/50">
          &copy; {new Date().getFullYear()} FitLife. All rights reserved.
        </p>
      </div>
    </footer>
  );
}
