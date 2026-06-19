import axios, { type AxiosError } from 'axios';
import type {
  ActivityFeedItem,
  AiGenerateResult,
  AiStatus,
  Article,
  Blog,
  ChatMessage,
  ContactForm,
  ContactRecord,
  DashboardStats,
  ExerciseCategory,
  ExercisePR,
  MonthlyActivity,
  Recipe,
  SavedPlan,
  BodyMetric,
  WorkoutSession,
  Goal,
  BadgeInfo,
  WaterToday,
  Favorite,
  AppNotification,
  CalendarDay,
  AdminAnalytics,
  PublicPlan,
  ExportData,
  User,
  UserProfile,
  WeeklyActivity,
  WorkoutLog,
  WorkoutLogInput,
} from '../types';

/** Turn axios/FastAPI errors into a user-facing string. */
export function formatApiError(err: unknown, fallback = 'Request failed'): string {
  if (!axios.isAxiosError(err)) return fallback;
  if (err.code === 'ECONNABORTED') {
    return 'Server is waking up — wait 60 seconds and try again';
  }
  if (!err.response) {
    return 'Cannot reach API — check backend is running and VITE_API_URL is set';
  }
  const detail = err.response.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0];
    if (typeof first?.msg === 'string') return first.msg;
  }
  return fallback;
}

/** API root: set VITE_API_URL at build time for production (e.g. https://fitlife-api.onrender.com). */
export function apiBase(): string {
  const root = import.meta.env.VITE_API_URL?.replace(/\/$/, '') ?? '';
  return root ? `${root}/api` : '/api';
}

const api = axios.create({
  baseURL: apiBase(),
  headers: { 'Content-Type': 'application/json' },
  timeout: 90_000, // Render free tier cold starts can take ~60s
});

let refreshPromise: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  const refreshToken = localStorage.getItem('fitlife_refresh_token');
  if (!refreshToken) throw new Error('No refresh token');

  const { data } = await axios.post<{ access_token: string; refresh_token: string }>(
    `${apiBase()}/auth/refresh`,
    { refresh_token: refreshToken },
    { timeout: 90_000 },
  );
  localStorage.setItem('fitlife_token', data.access_token);
  localStorage.setItem('fitlife_refresh_token', data.refresh_token);
  return data.access_token;
}

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('fitlife_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config;
    if (
      error.response?.status === 401 &&
      original &&
      !original.url?.includes('/auth/login') &&
      !original.url?.includes('/auth/refresh')
    ) {
      try {
        if (!refreshPromise) {
          refreshPromise = refreshAccessToken().finally(() => {
            refreshPromise = null;
          });
        }
        const newToken = await refreshPromise;
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      } catch {
        localStorage.removeItem('fitlife_token');
        localStorage.removeItem('fitlife_refresh_token');
      }
    }
    return Promise.reject(error);
  },
);

export const authApi = {
  login: async (username: string, password: string) => {
    const { data } = await api.post<{ access_token: string; refresh_token: string }>('/auth/login', {
      username,
      password,
    });
    return data;
  },
  signup: async (username: string, password: string, confirm_password: string) => {
    const { data } = await api.post<{ message: string }>('/auth/signup', {
      username,
      password,
      confirm_password,
    });
    return data;
  },
  me: async () => {
    const { data } = await api.get<User>('/auth/me');
    return data;
  },
  logout: async () => {
    const refresh_token = localStorage.getItem('fitlife_refresh_token') || '';
    const { data } = await api.post<{ message: string }>('/auth/logout', { refresh_token });
    return data;
  },
  forgotPassword: async (username: string) => {
    const { data } = await api.post<{ message: string; reset_token?: string }>('/auth/forgot-password', { username });
    return data;
  },
  resetPassword: async (token: string, new_password: string, confirm_password: string) => {
    const { data } = await api.post<{ message: string }>('/auth/reset-password', {
      token,
      new_password,
      confirm_password,
    });
    return data;
  },
};

export const contentApi = {
  exercises: async () => {
    const { data } = await api.get<ExerciseCategory[]>('/content/exercises');
    return data;
  },
  articles: async (q?: string, category?: string) => {
    const { data } = await api.get<Article[]>('/content/articles', { params: { q, category } });
    return data;
  },
  blogs: async (category?: string) => {
    const { data } = await api.get<Blog[]>('/content/blogs', { params: { category } });
    return data;
  },
  recipes: async () => {
    const { data } = await api.get<Recipe[]>('/content/recipes');
    return data;
  },
};

export const contactApi = {
  submit: async (form: ContactForm) => {
    const { data } = await api.post<{ message: string }>('/contact', form);
    return data;
  },
};

export const aiApi = {
  status: async () => {
    const { data } = await api.get<AiStatus>('/ai/status');
    return data;
  },
  getProfile: async () => {
    const { data } = await api.get<UserProfile | null>('/ai/profile');
    return data;
  },
  saveProfile: async (profile: UserProfile) => {
    const { data } = await api.put<UserProfile>('/ai/profile', profile);
    return data;
  },
  chatHistory: async () => {
    const { data } = await api.get<ChatMessage[]>('/ai/chat/history');
    return data;
  },
  clearChat: async () => {
    const { data } = await api.delete<{ message: string }>('/ai/chat/history');
    return data;
  },
  chat: async (message: string) => {
    const { data } = await api.post<{ reply: string; message_id: number }>('/ai/chat', { message });
    return data;
  },
  chatStream: async (
    message: string,
    onChunk: (text: string) => void,
    signal?: AbortSignal,
  ): Promise<{ message_id: number }> => {
    const token = localStorage.getItem('fitlife_token');
    const response = await fetch(`${apiBase()}/ai/chat/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ message }),
      signal,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Stream failed' }));
      throw new Error(typeof err.detail === 'string' ? err.detail : 'Stream failed');
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';
    let messageId = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const event = JSON.parse(line.slice(6)) as {
            type: string;
            content?: string;
            message_id?: number;
          };
          if (event.type === 'chunk' && event.content) onChunk(event.content);
          if (event.type === 'done' && event.message_id) messageId = event.message_id;
          if (event.type === 'error') throw new Error(event.content || 'Stream error');
        } catch (e) {
          if (e instanceof SyntaxError) continue;
          throw e;
        }
      }
    }

    return { message_id: messageId };
  },
  generateDietPlan: async (extra_notes?: string, days = 7) => {
    const { data } = await api.post<AiGenerateResult>('/ai/generate/diet-plan', { extra_notes, days });
    return data;
  },
  generateDietChart: async (extra_notes?: string, days = 7) => {
    const { data } = await api.post<AiGenerateResult>('/ai/generate/diet-chart', { extra_notes, days });
    return data;
  },
  generateWorkoutPlan: async (extra_notes?: string, days = 7) => {
    const { data } = await api.post<AiGenerateResult>('/ai/generate/workout-plan', { extra_notes, days });
    return data;
  },
  digest: async () => {
    const { data } = await api.post<{ content: string }>('/ai/digest');
    return data;
  },
};

export const plansApi = {
  list: async (plan_type?: string) => {
    const { data } = await api.get<SavedPlan[]>('/plans', { params: { plan_type } });
    return data;
  },
  get: async (id: number) => {
    const { data } = await api.get<SavedPlan>(`/plans/${id}`);
    return data;
  },
  save: async (plan: { title: string; plan_type: string; content: string }) => {
    const { data } = await api.post<SavedPlan>('/plans', plan);
    return data;
  },
  delete: async (id: number) => {
    const { data } = await api.delete<{ message: string }>(`/plans/${id}`);
    return data;
  },
  rename: async (id: number, title: string) => {
    const { data } = await api.patch<SavedPlan>(`/plans/${id}`, { title });
    return data;
  },
  share: async (id: number) => {
    const { data } = await api.post<{ share_token: string; share_url: string }>(`/plans/${id}/share`);
    return data;
  },
};

export const activityApi = {
  dashboard: async () => {
    const { data } = await api.get<DashboardStats>('/activity/dashboard');
    return data;
  },
  weekly: async () => {
    const { data } = await api.get<WeeklyActivity[]>('/activity/weekly');
    return data;
  },
  workouts: async (limit = 50) => {
    const { data } = await api.get<WorkoutLog[]>('/activity/workouts', { params: { limit } });
    return data;
  },
  logWorkout: async (log: WorkoutLogInput) => {
    const { data } = await api.post<WorkoutLog>('/activity/workouts', log);
    return data;
  },
  exerciseCount: async (exerciseId: string) => {
    const { data } = await api.get<{ exercise_id: string; count: number }>(
      `/activity/workouts/exercise/${exerciseId}/count`,
    );
    return data.count;
  },
  feed: async (limit = 15) => {
    const { data } = await api.get<ActivityFeedItem[]>('/activity/feed', { params: { limit } });
    return data;
  },
  prs: async () => {
    const { data } = await api.get<ExercisePR[]>('/activity/prs');
    return data;
  },
  monthly: async () => {
    const { data } = await api.get<MonthlyActivity[]>('/activity/monthly');
    return data;
  },
};

export const adminApi = {
  contacts: async () => {
    const { data } = await api.get<ContactRecord[]>('/admin/contacts');
    return data;
  },
  analytics: async () => {
    const { data } = await api.get<AdminAnalytics>('/admin/analytics');
    return data;
  },
};

export const wellnessApi = {
  metrics: async () => {
    const { data } = await api.get<BodyMetric[]>('/wellness/metrics');
    return data;
  },
  logMetric: async (payload: Partial<BodyMetric>) => {
    const { data } = await api.post<BodyMetric>('/wellness/metrics', payload);
    return data;
  },
  waterToday: async () => {
    const { data } = await api.get<WaterToday>('/wellness/water/today');
    return data;
  },
  logWater: async (glasses = 1) => {
    const { data } = await api.post<WaterToday>('/wellness/water', { glasses });
    return data;
  },
  goals: async () => {
    const { data } = await api.get<Goal[]>('/wellness/goals');
    return data;
  },
  createGoal: async (goal: Omit<Goal, 'id' | 'current_value' | 'completed' | 'created_at'>) => {
    const { data } = await api.post<Goal>('/wellness/goals', goal);
    return data;
  },
  updateGoal: async (id: number, patch: { current_value?: number; completed?: boolean }) => {
    const { data } = await api.patch<Goal>(`/wellness/goals/${id}`, patch);
    return data;
  },
  deleteGoal: async (id: number) => api.delete(`/wellness/goals/${id}`),
  badges: async () => {
    const { data } = await api.get<BadgeInfo[]>('/wellness/badges');
    return data;
  },
  calendar: async (days = 30) => {
    const { data } = await api.get<CalendarDay[]>('/wellness/calendar', { params: { days } });
    return data;
  },
};

export const sessionsApi = {
  start: async (name = 'Workout Session') => {
    const { data } = await api.post<WorkoutSession>('/sessions/start', { name });
    return data;
  },
  active: async () => {
    const { data } = await api.get<WorkoutSession | null>('/sessions/active');
    return data;
  },
  list: async () => {
    const { data } = await api.get<WorkoutSession[]>('/sessions');
    return data;
  },
  log: async (sessionId: number, log: WorkoutLogInput) => {
    const { data } = await api.post<WorkoutLog>(`/sessions/${sessionId}/log`, log);
    return data;
  },
  finish: async (sessionId: number) => {
    const { data } = await api.post<WorkoutSession>(`/sessions/${sessionId}/finish`);
    return data;
  },
  cancel: async (sessionId: number) => api.delete(`/sessions/${sessionId}`),
};

export const extrasApi = {
  favorites: async () => {
    const { data } = await api.get<Favorite[]>('/favorites');
    return data;
  },
  addFavorite: async (item_type: string, item_id: string) => {
    const { data } = await api.post<Favorite>('/favorites', { item_type, item_id });
    return data;
  },
  removeFavorite: async (item_type: string, item_id: string) => {
    await api.delete(`/favorites/${item_type}/${item_id}`);
  },
  isFavorite: async (item_type: string, item_id: string) => {
    const { data } = await api.get<{ favorited: boolean }>(`/favorites/check/${item_type}/${item_id}`);
    return data.favorited;
  },
  notifications: async () => {
    const { data } = await api.get<AppNotification[]>('/notifications');
    return data;
  },
  markAllRead: async () => api.post('/notifications/read-all'),
  exportData: async () => {
    const { data } = await api.get<ExportData>('/export');
    return data;
  },
  blogReaction: async (blogId: string) => {
    const { data } = await api.post<{ count: number; user_reacted: boolean }>(`/content/blogs/${blogId}/react`);
    return data;
  },
  getBlogReaction: async (blogId: string) => {
    const { data } = await api.get<{ count: number; user_reacted: boolean }>(`/content/blogs/${blogId}/reactions`);
    return data;
  },
};

export const publicApi = {
  sharedPlan: async (token: string) => {
    const { data } = await axios.get<PublicPlan>(`/api/public/plans/${token}`);
    return data;
  },
};

export default api;
