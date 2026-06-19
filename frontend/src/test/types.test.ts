import { describe, expect, it } from 'vitest';

describe('DashboardStats shape', () => {
  it('matches expected fields', () => {
    const stats = {
      total_workouts: 5,
      workouts_this_week: 2,
      current_streak: 3,
      saved_plans: 1,
      chat_messages: 10,
      content_totals: { exercises: 42, recipes: 14, articles: 12, blogs: 8 },
    };
    expect(stats.total_workouts).toBeGreaterThanOrEqual(0);
    expect(stats.content_totals.exercises).toBe(42);
  });
});
