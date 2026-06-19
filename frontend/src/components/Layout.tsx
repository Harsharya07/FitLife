import { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { isOnboardingDone } from '../lib/profileCompletion';
import { activityApi } from '../lib/api';
import Navbar from './Navbar';
import Footer from './Footer';
import FloatingChat from './FloatingChat';
import BottomNav from './BottomNav';
import PageTransition from './PageTransition';
import OnboardingWizard from './OnboardingWizard';

export default function Layout() {
  const { user, loading } = useAuth();
  const [streak, setStreak] = useState(0);
  const [showOnboarding, setShowOnboarding] = useState(false);

  useEffect(() => {
    if (user && !isOnboardingDone(user.id)) {
      setShowOnboarding(true);
    }
  }, [user]);

  useEffect(() => {
    if (user) {
      activityApi.dashboard().then((s) => setStreak(s.current_streak)).catch(() => null);
    }
  }, [user]);

  if (loading) {
    return (
      <div className="page-bg flex min-h-screen items-center justify-center">
        <div className="relative">
          <div className="h-14 w-14 animate-spin rounded-full border-[3px] border-primary/15 border-t-primary" />
        </div>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;

  return (
    <div className="page-bg flex min-h-screen flex-col">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <Navbar streak={streak} />
      <main id="main-content" className="flex-1" tabIndex={-1}>
        <PageTransition />
      </main>
      <Footer />
      <FloatingChat />
      <BottomNav />
      {showOnboarding && (
        <OnboardingWizard userId={user.id} onComplete={() => setShowOnboarding(false)} />
      )}
    </div>
  );
}
