export interface User {
  id: number;
  username: string;
  is_admin: boolean;
}

export interface Exercise {
  id: string;
  name: string;
  image: string;
  description: string;
  tags: string[];
  equipment: string;
  tip: string;
  video_url?: string | null;
}

export interface ExerciseCategory {
  id: string;
  name: string;
  icon: string;
  exercises: Exercise[];
}

export interface Article {
  id: string;
  title: string;
  url: string;
  image: string;
  author: string;
  date: string;
  excerpt: string;
  categories: string[];
}

export interface Blog {
  id: string;
  title: string;
  url: string;
  image: string;
  avatar: string;
  rank: string;
  mentions: string;
  excerpt: string;
  category: string;
}

export interface Recipe {
  id: string;
  name: string;
  image: string;
  description: string;
  ingredients: string[];
  steps: string[];
  prep_time: string;
  calories: string;
}

export interface ContactForm {
  name: string;
  email: string;
  message: string;
}

export interface UserProfile {
  age?: number | null;
  gender?: string | null;
  height_cm?: number | null;
  weight_kg?: number | null;
  goal?: string | null;
  activity_level?: string | null;
  dietary_preference?: string | null;
  allergies?: string | null;
  health_conditions?: string | null;
  target_calories?: number | null;
  workout_days_per_week?: number | null;
  experience_level?: string | null;
}

export interface AiStatus {
  configured: boolean;
  provider: string;
  model: string;
}

export interface ChatMessage {
  id: number;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
}

export interface AiGenerateResult {
  content: string;
  type: string;
  plan_id?: number | null;
}

export interface SavedPlan {
  id: number;
  title: string;
  plan_type: string;
  content: string;
  created_at: string;
}

export interface WorkoutLog {
  id: number;
  exercise_id: string;
  exercise_name: string;
  sets: number | null;
  reps: number | null;
  weight_kg: number | null;
  duration_min: number | null;
  notes: string | null;
  logged_at: string;
}

export interface WorkoutLogInput {
  exercise_id: string;
  exercise_name: string;
  sets?: number | null;
  reps?: number | null;
  weight_kg?: number | null;
  duration_min?: number | null;
  notes?: string | null;
}

export interface DashboardStats {
  total_workouts: number;
  workouts_this_week: number;
  current_streak: number;
  saved_plans: number;
  chat_messages: number;
  content_totals: {
    exercises: number;
    recipes: number;
    articles: number;
    blogs: number;
  };
}

export interface WeeklyActivity {
  date: string;
  count: number;
}

export interface ContactRecord {
  id: number;
  name: string;
  email: string;
  message: string;
  created_at: string;
}

export interface ActivityFeedItem {
  id: number;
  type: 'workout' | 'plan';
  title: string;
  subtitle: string;
  created_at: string;
}

export interface ExercisePR {
  exercise_id: string;
  exercise_name: string;
  best_sets: number | null;
  best_reps: number | null;
  best_weight_kg: number | null;
  total_sessions: number;
}

export interface MonthlyActivity {
  date: string;
  count: number;
}

export interface BodyMetric {
  id: number;
  weight_kg?: number | null;
  body_fat_pct?: number | null;
  waist_cm?: number | null;
  notes?: string | null;
  logged_at: string;
}

export interface WorkoutSession {
  id: number;
  name: string;
  status: string;
  started_at: string;
  ended_at?: string | null;
  notes?: string | null;
  exercise_count: number;
}

export interface Goal {
  id: number;
  title: string;
  goal_type: string;
  target_value: number;
  current_value: number;
  unit?: string | null;
  deadline?: string | null;
  completed: boolean;
  created_at: string;
}

export interface BadgeInfo {
  badge_id: string;
  title: string;
  description: string;
  earned: boolean;
  earned_at?: string | null;
}

export interface WaterToday {
  glasses: number;
  goal: number;
}

export interface Favorite {
  id: number;
  item_type: string;
  item_id: string;
  created_at: string;
}

export interface AppNotification {
  id: number;
  type: string;
  title: string;
  body: string;
  read: boolean;
  created_at: string;
}

export interface CalendarDay {
  date: string;
  workouts: number;
  water_glasses: number;
}

export interface AdminAnalytics {
  total_users: number;
  total_workouts: number;
  total_plans: number;
  total_ai_chats: number;
  signups_last_7_days: number;
}

export interface PublicPlan {
  title: string;
  plan_type: string;
  content: string;
  created_at: string;
}

export interface ExportData {
  profile: Record<string, unknown> | null;
  workouts: unknown[];
  plans: unknown[];
  metrics: unknown[];
  goals: unknown[];
  badges: unknown[];
}
