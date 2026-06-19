import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import Layout from './components/Layout';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import SharedPlanPage from './pages/SharedPlanPage';
import DashboardPage from './pages/DashboardPage';
import ExercisesPage from './pages/ExercisesPage';
import ArticlesPage from './pages/ArticlesPage';
import BlogsPage from './pages/BlogsPage';
import RecipesPage from './pages/RecipesPage';
import AiCoachPage from './pages/AiCoachPage';
import MyPlansPage from './pages/MyPlansPage';
import ActivityPage from './pages/ActivityPage';
import WorkoutSessionPage from './pages/WorkoutSessionPage';
import SettingsPage from './pages/SettingsPage';
import AdminContactsPage from './pages/AdminContactsPage';
import AdminAnalyticsPage from './pages/AdminAnalyticsPage';
import ContactPage from './pages/ContactPage';

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <Toaster
            position="top-center"
            toastOptions={{
              style: {
                borderRadius: '14px',
                fontWeight: 600,
                fontFamily: "'Inter', system-ui, sans-serif",
              },
              success: { iconTheme: { primary: '#14b8a6', secondary: '#fff' } },
              error: { iconTheme: { primary: '#7c3aed', secondary: '#fff' } },
            }}
          />
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/share/plan/:token" element={<SharedPlanPage />} />
            <Route element={<Layout />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/ai-coach" element={<AiCoachPage />} />
              <Route path="/my-plans" element={<MyPlansPage />} />
              <Route path="/activity" element={<ActivityPage />} />
              <Route path="/workout-session" element={<WorkoutSessionPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/exercises" element={<ExercisesPage />} />
              <Route path="/articles" element={<ArticlesPage />} />
              <Route path="/blogs" element={<BlogsPage />} />
              <Route path="/recipes" element={<RecipesPage />} />
              <Route path="/contact" element={<ContactPage />} />
              <Route path="/admin/contacts" element={<AdminContactsPage />} />
              <Route path="/admin/analytics" element={<AdminAnalyticsPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}
